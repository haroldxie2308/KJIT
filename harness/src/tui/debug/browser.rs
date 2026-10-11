//! The translation browser: the recorded translations, and for one of them every pass
//! (decoded, rephrased, virtualized, layout) side by side, grouped by original pc.

use std::collections::BTreeMap;

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph};
use ratatui::Frame;

use super::code::original_text;
use super::fmt::{bold, dim, disasm_layout, disasm_pass, group_bg, tagged};
use crate::a64_pretty::pretty_insn;
use crate::session::{LayoutRegion, PassBlock, Rejection, Session, TranslationRecord, Trigger};

/// The four pass columns of one translation, one `Line` per row and the same number of
/// rows in each: the rows of one original pc form a group.
struct Columns {
    decoded: Vec<Line<'static>>,
    rephrased: Vec<Line<'static>>,
    virtualized: Vec<Line<'static>>,
    layout: Vec<Line<'static>>,
    rows: usize,
    counts: [usize; 4],
}

pub struct Browser {
    selected: usize,
    scroll: usize,
    list: ListState,
    /// The columns of translation `.0`.
    columns: Option<(usize, Columns)>,
}

/// What a group of rows stands for.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Key {
    Prologue,
    Pc(u64),
    Epilogue,
}

fn pass_cells(blocks: &[PassBlock]) -> BTreeMap<u64, Vec<Line<'static>>> {
    let mut cells: BTreeMap<u64, Vec<Line<'static>>> = BTreeMap::new();
    for block in blocks {
        for (cold, insns) in [(false, &block.insns), (true, &block.cold)] {
            for (index, insn) in insns.iter().enumerate() {
                let mut spans = vec![Span::styled(
                    format!("b{}.{}{} ", block.index, index, if cold { "c" } else { "" }),
                    dim(),
                )];
                spans.extend(tagged(insn.kind, disasm_pass(insn)));
                cells.entry(insn.ori_pc).or_default().push(Line::from(spans));
            }
        }
    }
    cells
}

impl Columns {
    fn build(session: &Session, record: &TranslationRecord) -> Self {
        let mut decoded_cells: BTreeMap<u64, Line<'static>> = BTreeMap::new();
        let mut keys = Vec::new();
        for insn in &record.decoded {
            let block_start = record
                .cfg
                .iter()
                .find(|block| block.start_pc == insn.pc)
                .map_or("   ".to_string(), |block| format!("b{:<2}", block.index));
            decoded_cells.insert(
                insn.pc,
                Line::from(vec![
                    Span::styled(format!("{block_start} {:#x} ", insn.pc), dim()),
                    Span::raw(pretty_insn(insn.inner, Some(insn.pc))),
                ]),
            );
            keys.push(Key::Pc(insn.pc));
        }
        let rephrased = pass_cells(&record.rephrased);
        let virtualized = pass_cells(&record.virtualized);
        let mut layout_cells: BTreeMap<u64, Vec<Line<'static>>> = BTreeMap::new();
        let mut prologue = Vec::new();
        let mut epilogue = Vec::new();
        for word in &record.layout {
            let mut spans = vec![Span::styled(
                format!("{:#06x} {:08x} ", word.offset, word.word),
                dim(),
            )];
            match word.kind {
                Some(kind) => spans.extend(tagged(kind, disasm_layout(word.insn, word.offset))),
                None => spans.push(Span::raw(disasm_layout(word.insn, word.offset))),
            }
            let line = Line::from(spans);
            match word.ori_pc {
                Some(pc) => layout_cells.entry(pc).or_default().push(line),
                None => match word.region {
                    LayoutRegion::Prologue => prologue.push(line),
                    LayoutRegion::Epilogue => epilogue.push(line),
                    LayoutRegion::Body | LayoutRegion::Cold => {
                        unreachable!("a body or cold word has an original pc")
                    }
                },
            }
        }
        // pcs the passes carry that the CFG did not decode (an `Unsupported` exit's
        // word): their own groups, after the decoded ones.
        for pc in rephrased
            .keys()
            .chain(virtualized.keys())
            .chain(layout_cells.keys())
        {
            if !decoded_cells.contains_key(pc) && !keys.contains(&Key::Pc(*pc)) {
                keys.push(Key::Pc(*pc));
            }
        }
        // The wrapper groups come last: the passes' own output is what is compared.
        if !prologue.is_empty() {
            keys.push(Key::Prologue);
        }
        if !epilogue.is_empty() {
            keys.push(Key::Epilogue);
        }

        let mut columns = Self {
            decoded: Vec::new(),
            rephrased: Vec::new(),
            virtualized: Vec::new(),
            layout: Vec::new(),
            rows: 0,
            counts: [
                record.decoded.len(),
                rephrased.values().map(Vec::len).sum(),
                virtualized.values().map(Vec::len).sum(),
                record.layout.len(),
            ],
        };
        for (group, key) in keys.iter().enumerate() {
            let (decoded, rephrased_cell, virtualized_cell, layout_cell) = match *key {
                Key::Prologue => (
                    vec![Line::styled("(prologue)", dim())],
                    Vec::new(),
                    Vec::new(),
                    prologue.clone(),
                ),
                Key::Epilogue => (
                    vec![Line::styled("(epilogue)", dim())],
                    Vec::new(),
                    Vec::new(),
                    epilogue.clone(),
                ),
                Key::Pc(pc) => (
                    vec![decoded_cells.get(&pc).cloned().unwrap_or_else(|| {
                        Line::from(vec![
                            Span::styled(format!("    {pc:#x} "), dim()),
                            Span::raw(original_text(session, pc)),
                            Span::styled(" (not decoded)", dim()),
                        ])
                    })],
                    rephrased.get(&pc).cloned().unwrap_or_default(),
                    virtualized.get(&pc).cloned().unwrap_or_default(),
                    layout_cells.get(&pc).cloned().unwrap_or_default(),
                ),
            };
            let height = decoded
                .len()
                .max(rephrased_cell.len())
                .max(virtualized_cell.len())
                .max(layout_cell.len());
            let shade = group % 2 == 1;
            for (column, cell) in [
                (&mut columns.decoded, decoded),
                (&mut columns.rephrased, rephrased_cell),
                (&mut columns.virtualized, virtualized_cell),
                (&mut columns.layout, layout_cell),
            ] {
                let mut cell = cell;
                cell.resize(height, Line::default());
                column.extend(cell.into_iter().map(|line| {
                    if shade {
                        line.style(group_bg())
                    } else {
                        line
                    }
                }));
            }
            columns.rows += height;
        }
        columns
    }
}

fn trigger_name(trigger: Trigger) -> &'static str {
    match trigger {
        Trigger::SvcResume => "svc-resume",
        Trigger::ExitTarget => "exit-target",
    }
}

fn outcome_text(record: &TranslationRecord) -> String {
    match (record.installed, &record.rejection) {
        (Some(fragment), None) => format!("installed as f{fragment}"),
        (None, Some(Rejection::EntryUnsupported(exit))) => format!("REJECTED: entry unsupported ({exit:?})"),
        (None, Some(Rejection::Compile { pass, message })) => {
            format!("REJECTED: {pass:?} pass: {message}")
        }
        (None, Some(Rejection::Encode(message))) => format!("REJECTED: encode: {message}"),
        (None, Some(Rejection::Verify(error))) => format!("REJECTED: verifier: {error:?}"),
        (installed, rejection) => {
            unreachable!("a finished record is installed xor rejected: {installed:?} {rejection:?}")
        }
    }
}

impl Browser {
    pub fn new() -> Self {
        Self {
            selected: 0,
            scroll: 0,
            list: ListState::default(),
            columns: None,
        }
    }

    pub fn selected(&self) -> usize {
        self.selected
    }

    /// Selects translation `index` (clamped) and shows it from the top.
    pub fn select(&mut self, session: &Session, index: usize) {
        let count = session.translations().len();
        self.selected = index.min(count.saturating_sub(1));
        self.scroll = 0;
    }

    pub fn step(&mut self, session: &Session, forward: bool) {
        let next = if forward {
            self.selected.saturating_add(1)
        } else {
            self.selected.saturating_sub(1)
        };
        self.select(session, next);
    }

    pub fn scroll_by(&mut self, session: &Session, delta: isize) {
        let rows = self.columns_of(session).map_or(0, |columns| columns.rows);
        self.scroll = self
            .scroll
            .saturating_add_signed(delta)
            .min(rows.saturating_sub(1));
    }

    fn columns_of(&mut self, session: &Session) -> Option<&Columns> {
        let record = session.translations().get(self.selected)?;
        if self.columns.as_ref().map(|(index, _)| *index) != Some(self.selected) {
            self.columns = Some((self.selected, Columns::build(session, record)));
        }
        self.columns.as_ref().map(|(_, columns)| columns)
    }

    pub fn draw(&mut self, frame: &mut Frame, area: Rect, session: &Session) {
        let translations = session.translations();
        if translations.is_empty() {
            frame.render_widget(
                Paragraph::new("the session made no translations").block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title(" translations "),
                ),
                area,
            );
            return;
        }
        let [list_area, detail] = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Length(38), Constraint::Min(20)])
            .areas(area);

        let items: Vec<ListItem> = translations
            .iter()
            .map(|record| {
                let result = match (record.installed, &record.rejection) {
                    (Some(fragment), _) => format!("f{fragment}"),
                    (None, _) => "REJECTED".to_string(),
                };
                ListItem::new(format!(
                    "T{:<3} t={:<6} {:#x} {} {result}",
                    record.index,
                    record.t,
                    record.entry_pc,
                    match record.trigger {
                        Trigger::SvcResume => "svc",
                        Trigger::ExitTarget => "exit",
                    },
                ))
            })
            .collect();
        self.list.select(Some(self.selected));
        frame.render_stateful_widget(
            List::new(items)
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title(" translations "),
                )
                .highlight_style(
                    Style::default()
                        .fg(Color::Black)
                        .bg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ),
            list_area,
            &mut self.list,
        );

        let record = &translations[self.selected];
        let [summary, headers, body] = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(5),
                Constraint::Length(1),
                Constraint::Min(1),
            ])
            .areas(detail);
        let verdict = match record.verdict {
            Some(verdict) => format!("{verdict:?}"),
            None => "not reached".to_string(),
        };
        let summary_lines = vec![
            Line::from(vec![
                Span::styled(format!("T{} ", record.index), bold()),
                Span::raw(format!(
                    "entry {:#x}  {} from {:#x}  requested at t={}",
                    record.entry_pc,
                    trigger_name(record.trigger),
                    record.source_pc,
                    record.t
                )),
            ]),
            Line::from(outcome_text(record)),
            Line::from(format!(
                "verdict {verdict}  entry offset {:#x}  link sites {}  fault sites {}",
                record.entry_offset,
                record.link_sites.len(),
                record.fault_sites.len()
            )),
        ];
        frame.render_widget(
            Paragraph::new(summary_lines)
                .block(Block::default().borders(Borders::ALL).title(" translation ")),
            summary,
        );

        let scroll = self.scroll;
        let Some(columns) = self.columns_of(session) else {
            return;
        };
        let constraints = [
            Constraint::Percentage(20),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Percentage(30),
        ];
        let header_cells = Layout::default()
            .direction(Direction::Horizontal)
            .constraints(constraints)
            .split(headers);
        let body_cells = Layout::default()
            .direction(Direction::Horizontal)
            .constraints(constraints)
            .split(body);
        let titles = ["1 decoded", "2 rephrased", "3 virtualized", "4 layout"];
        let passes = [
            &columns.decoded,
            &columns.rephrased,
            &columns.virtualized,
            &columns.layout,
        ];
        let separator = || Block::default().borders(Borders::LEFT).border_style(dim());
        for index in 0..4 {
            frame.render_widget(
                Paragraph::new(Line::styled(
                    format!("{} ({})", titles[index], columns.counts[index]),
                    bold().fg(Color::Cyan),
                ))
                .block(separator()),
                header_cells[index],
            );
            let visible: Vec<Line<'static>> = passes[index]
                .iter()
                .skip(scroll)
                .take(body.height as usize)
                .cloned()
                .collect();
            frame.render_widget(Paragraph::new(visible).block(separator()), body_cells[index]);
        }
    }
}
