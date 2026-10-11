//! The code pane: where the program is at `t`. In a fragment, the translated words
//! around the offset with their provenance; in user code, the original text.

use std::collections::BTreeSet;

use ratatui::layout::Rect;
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

use super::fmt::{dim, disasm_layout, disasm_word, fit, same_pc_bg, selection, tag, tag_style};
use super::Cursor;
use crate::session::{LayoutRegion, LayoutWord, Session, StepAt, TranslationRecord};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ctx {
    Fragment { fragment: usize, translation: usize },
    User,
}

/// What the code pane lists at the cursor: the words of the fragment's layout, or the
/// original text, with the rows the cursor sits on.
#[derive(Clone, Copy, Debug)]
pub struct CodeView {
    pub ctx: Ctx,
    /// Number of rows (layout words / text words).
    pub len: usize,
    /// The row of the next instruction to execute (the last executed one at the end
    /// of the recording).
    pub cursor: usize,
    /// The row of the instruction executed last, when it is in the same listing.
    pub last: Option<usize>,
    /// Whether `cursor` is the next instruction (false: the recording ended).
    pub cursor_is_next: bool,
}

fn row_of(session: &Session, at: StepAt) -> (Ctx, usize, usize) {
    match at {
        StepAt::User { pc } => {
            let config = session.config();
            let index = pc
                .checked_sub(config.text_base)
                .expect("a user step executes text")
                / 4;
            (Ctx::User, config.text.len() / 4, index as usize)
        }
        StepAt::Fragment { fragment, offset } => {
            let translation = session
                .translation_of(fragment)
                .expect("a fragment that executed was installed by a translation");
            (
                Ctx::Fragment {
                    fragment,
                    translation,
                },
                session.translations()[translation].layout.len(),
                offset / 4,
            )
        }
    }
}

impl CodeView {
    /// `None` when the session has no ticks.
    pub fn of(session: &Session, cursor: &Cursor) -> Option<Self> {
        let anchor = cursor.next.or(cursor.last)?;
        let (ctx, len, index) = row_of(session, anchor.at);
        let last = cursor.last.and_then(|last| {
            let (last_ctx, _, last_index) = row_of(session, last.at);
            (last_ctx == ctx).then_some(last_index)
        });
        Some(Self {
            ctx,
            len,
            cursor: index,
            last,
            cursor_is_next: cursor.next.is_some(),
        })
    }

    /// The row the selection is on: `sel`, else the cursor row.
    pub fn selected(&self, sel: Option<usize>) -> usize {
        sel.unwrap_or(self.cursor).min(self.len - 1)
    }

    /// The original pc of row `index`.
    pub fn ori_pc(&self, session: &Session, index: usize) -> Option<u64> {
        match self.ctx {
            Ctx::User => Some(session.config().text_base + 4 * index as u64),
            Ctx::Fragment { translation, .. } => {
                session.translations()[translation].layout[index].ori_pc
            }
        }
    }
}

fn region_char(region: LayoutRegion) -> char {
    match region {
        LayoutRegion::Prologue => 'P',
        LayoutRegion::Body => 'B',
        LayoutRegion::Cold => 'C',
        LayoutRegion::Epilogue => 'E',
    }
}

/// Whether two adjacent layout words belong to one group: the words one original
/// instruction was translated into, or the words of the prologue or the epilogue.
fn same_group(a: &LayoutWord, b: &LayoutWord) -> bool {
    a.ori_pc == b.ori_pc && a.region == b.region
}

/// The gutter character that joins the words of one group.
fn bracket(layout: &[LayoutWord], index: usize) -> char {
    let joined_before = index > 0 && same_group(&layout[index - 1], &layout[index]);
    let joined_after = layout
        .get(index + 1)
        .is_some_and(|next| same_group(&layout[index], next));
    match (joined_before, joined_after) {
        (false, false) => '─',
        (false, true) => '┌',
        (true, true) => '│',
        (true, false) => '└',
    }
}

/// The word of the original text at `pc`.
pub fn text_word(session: &Session, pc: u64) -> Option<u32> {
    let config = session.config();
    let start = usize::try_from(pc.checked_sub(config.text_base)?).ok()?;
    let bytes: [u8; 4] = config.text.get(start..start.checked_add(4)?)?.try_into().ok()?;
    Some(u32::from_le_bytes(bytes))
}

/// The original instruction at `pc`, disassembled from the text (not from the CFG:
/// an `Unsupported` exit belongs to a word the CFG does not hold).
pub fn original_text(session: &Session, pc: u64) -> String {
    match text_word(session, pc) {
        Some(word) => disasm_word(word, pc),
        // A translation only carries pcs of text it read, so this is a pc outside the
        // text: show that instead of a guess.
        None => "(not in the text)".to_string(),
    }
}

fn gutter(bp: bool, mark: char, bracket: char) -> Vec<Span<'static>> {
    vec![
        Span::styled(
            if bp { "*" } else { " " },
            Style::default().fg(Color::Red),
        ),
        Span::styled(mark.to_string(), Style::default().fg(Color::Yellow)),
        Span::styled(bracket.to_string(), dim()),
        Span::raw(" "),
    ]
}

/// The row of the cursor and of the last executed word, as gutter marks.
fn mark_of(view: &CodeView, index: usize) -> char {
    if index == view.cursor && view.cursor_is_next {
        '>'
    } else if index == view.cursor || Some(index) == view.last {
        '<'
    } else {
        ' '
    }
}

fn layout_row(
    session: &Session,
    record: &TranslationRecord,
    view: &CodeView,
    index: usize,
    selected: usize,
    breakpoints: &BTreeSet<u64>,
) -> Line<'static> {
    let layout = &record.layout;
    let word = &layout[index];
    // The breakpoint mark sits on the first word of each group, not on all of them.
    let group_start = index == 0 || !same_group(&layout[index - 1], word);
    let mut spans = gutter(
        group_start && word.ori_pc.is_some_and(|pc| breakpoints.contains(&pc)),
        mark_of(view, index),
        bracket(layout, index),
    );
    spans.push(Span::styled(
        format!("{} {:#06x} {:08x} ", region_char(word.region), word.offset, word.word),
        dim(),
    ));
    spans.push(Span::raw(fit(&disasm_layout(word.insn, word.offset), 30)));
    match (word.kind, word.ori_pc) {
        (Some(kind), Some(pc)) => {
            spans.push(Span::styled(format!("{:<5} ", tag(kind)), tag_style(kind)));
            spans.push(Span::raw(format!("{pc:<#10x} ")));
            spans.push(Span::raw(original_text(session, pc)));
        }
        _ => {
            let wrapper = match word.region {
                LayoutRegion::Prologue => "(prologue)",
                LayoutRegion::Epilogue => "(epilogue)",
                LayoutRegion::Body | LayoutRegion::Cold => {
                    unreachable!("a body or cold word has a kind and an original pc")
                }
            };
            spans.push(Span::styled(format!("{:<5} {:<10} {wrapper}", "-", "-"), dim()));
        }
    }
    let mut line = Line::from(spans);
    let selected_pc = layout[selected].ori_pc;
    if index == selected {
        line = line.style(selection());
    } else if selected_pc.is_some() && word.ori_pc == selected_pc {
        line = line.style(same_pc_bg());
    }
    line
}

fn user_row(
    session: &Session,
    view: &CodeView,
    index: usize,
    selected: usize,
    breakpoints: &BTreeSet<u64>,
) -> Line<'static> {
    let pc = session.config().text_base + 4 * index as u64;
    let word = text_word(session, pc).expect("a row of the listing is a word of the text");
    let mut spans = gutter(breakpoints.contains(&pc), mark_of(view, index), '─');
    spans.push(Span::styled(format!("{pc:<#10x} {word:08x} "), dim()));
    spans.push(Span::raw(disasm_word(word, pc)));
    let mut line = Line::from(spans);
    if index == selected {
        line = line.style(selection());
    }
    line
}

pub fn draw(
    frame: &mut Frame,
    area: Rect,
    session: &Session,
    view: Option<&CodeView>,
    sel: Option<usize>,
    breakpoints: &BTreeSet<u64>,
) {
    let Some(view) = view else {
        frame.render_widget(
            Paragraph::new("the session has no ticks")
                .block(Block::default().borders(Borders::ALL).title(" code ")),
            area,
        );
        return;
    };
    let title = match view.ctx {
        Ctx::Fragment {
            fragment,
            translation,
        } => {
            let record = &session.translations()[translation];
            format!(
                " code: fragment f{fragment} (T{translation}, entry {:#x}, {} words)   > next  < last ",
                record.entry_pc,
                record.layout.len()
            )
        }
        Ctx::User => format!(
            " code: user text at {:#x} ({} words)   > next  < last ",
            session.config().text_base,
            view.len
        ),
    };
    let block = Block::default().borders(Borders::ALL).title(title);
    let inner = block.inner(area);
    let height = inner.height as usize;
    let selected = view.selected(sel);
    let start = selected
        .saturating_sub(height / 2)
        .min(view.len.saturating_sub(height));
    let end = (start + height).min(view.len);

    let lines: Vec<Line> = (start..end)
        .map(|index| match view.ctx {
            Ctx::Fragment { translation, .. } => layout_row(
                session,
                &session.translations()[translation],
                view,
                index,
                selected,
                breakpoints,
            ),
            Ctx::User => user_row(session, view, index, selected, breakpoints),
        })
        .collect();
    frame.render_widget(Paragraph::new(lines).block(block), area);
}

/// The unstyled summary of the next/last place, for the status line.
pub fn place_text(at: StepAt) -> String {
    match at {
        StepAt::User { pc } => format!("user {pc:#x}"),
        StepAt::Fragment { fragment, offset } => format!("f{fragment}+{offset:#x}"),
    }
}
