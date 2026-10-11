//! The lineage pane: how the selected word came to be, pass by pass, from the decoded
//! instruction to the layout word (`Session::origin`).

use ratatui::layout::Rect;
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

use super::code::{original_text, text_word, CodeView, Ctx};
use super::fmt::{bold, dim, disasm_pass, disasm_word, labelled, tag, tagged};
use super::Cursor;
use crate::session::{InsnPos, PassBlock, Session, StepAt, TranslationRecord};
use crate::shared::trans::rephrase::RephrasedInsn;

const LABEL: usize = 13;
/// Instructions listed per pass before "+n more".
const PER_PASS: usize = 4;

fn pass_insn<'a>(blocks: &'a [PassBlock], pos: &InsnPos) -> &'a RephrasedInsn {
    let block = &blocks[pos.block];
    let insns = if pos.cold { &block.cold } else { &block.insns };
    &insns[pos.index]
}

fn pos_name(pos: &InsnPos) -> String {
    format!("b{}.{}{}", pos.block, pos.index, if pos.cold { "c" } else { "" })
}

/// One pass: the instructions at `positions`, the one at `current` marked.
fn pass_lines(
    label: &str,
    blocks: &[PassBlock],
    positions: &[InsnPos],
    current: Option<InsnPos>,
) -> Vec<Line<'static>> {
    if positions.is_empty() {
        return vec![labelled(label, LABEL, vec![Span::styled("-", dim())])];
    }
    let mut lines = Vec::new();
    for (shown, pos) in positions.iter().take(PER_PASS).enumerate() {
        let insn = pass_insn(blocks, pos);
        let mut spans = vec![Span::styled(format!("{:<7}", pos_name(pos)), dim())];
        spans.extend(tagged(insn.kind, disasm_pass(insn)));
        if current == Some(*pos) {
            spans.push(Span::styled("  <- this word", Style::default().fg(Color::Yellow)));
        }
        lines.push(labelled(if shown == 0 { label } else { "" }, LABEL, spans));
    }
    if positions.len() > PER_PASS {
        // The current word may be past the listed ones: say so rather than hide it.
        let hidden = positions.len() - PER_PASS;
        let current_hidden = current.is_some_and(|c| positions[PER_PASS..].contains(&c));
        lines.push(labelled(
            "",
            LABEL,
            vec![Span::styled(
                format!(
                    "+{hidden} more{}",
                    if current_hidden { " (including this word)" } else { "" }
                ),
                dim(),
            )],
        ));
    }
    lines
}

fn fragment_lines(
    session: &Session,
    record: &TranslationRecord,
    fragment: usize,
    index: usize,
    cursor: &Cursor,
) -> Vec<Line<'static>> {
    let offset = index * 4;
    let origin = session
        .origin(fragment, offset)
        .expect("a row of the listing is a word of its fragment");
    let word = &record.layout[index];
    let mut lines = Vec::new();

    let mut head = vec![
        Span::styled(format!("{offset:#06x} {:08x}  ", word.word), dim()),
        Span::styled(
            super::fmt::disasm_layout(word.insn, offset),
            bold(),
        ),
        Span::styled(format!("   {:?} T{}", origin.region, origin.translation), dim()),
    ];
    if let Some(kind) = origin.kind {
        head.push(Span::styled(format!(" [{}]", tag(kind)), dim()));
    }
    lines.push(labelled("layout word", LABEL, head));

    // A link slot is a `nop` in the translation; the cache patches `b <label>` into it.
    if let Some(place) = cursor.next.or(cursor.last) {
        if place.at == (StepAt::Fragment { fragment, offset }) && place.word != word.word {
            lines.push(labelled(
                "executed",
                LABEL,
                vec![Span::raw(format!(
                    "{:08x}  {} (patched by the cache)",
                    place.word,
                    disasm_word(place.word, offset as u64)
                ))],
            ));
        }
    }

    let Some(ori_pc) = origin.ori_pc else {
        lines.push(labelled(
            "origin",
            LABEL,
            vec![Span::styled(
                "none: the fragment's wrapper, not a translated instruction",
                dim(),
            )],
        ));
        return lines;
    };

    let lineage = &origin.lineage;
    let decoded = match lineage.decoded {
        Some(i) => {
            let insn = &record.decoded[i];
            vec![
                Span::styled(format!("{:#x} {:08x}  ", insn.pc, insn.word), dim()),
                Span::raw(crate::a64_pretty::pretty_insn(insn.inner, Some(insn.pc))),
            ]
        }
        // The pc is not in the CFG: an `Unsupported` exit's word, which the passes
        // carry as an exit group and never decode.
        None => vec![
            Span::styled(format!("{ori_pc:#x} "), dim()),
            Span::raw(original_text(session, ori_pc)),
            Span::styled("  (not decoded: unsupported exit)", dim()),
        ],
    };
    lines.push(labelled("decoded", LABEL, decoded));

    let block = match lineage.cfg_block {
        Some(b) => {
            let block = &record.cfg[b];
            let pcs = |pcs: &[u64]| {
                pcs.iter()
                    .map(|pc| format!("{pc:#x}"))
                    .collect::<Vec<_>>()
                    .join(",")
            };
            let mut text = format!(
                "#{b} {:#x}..{:#x}  prev [{}] next [{}]",
                block.start_pc,
                block.end_pc,
                pcs(&block.prev),
                pcs(&block.next)
            );
            if let Some(exit) = block.unsupported_exit {
                text.push_str(&format!("  ends in {exit:?}"));
            }
            text
        }
        None => "-".to_string(),
    };
    lines.push(labelled("cfg block", LABEL, vec![Span::raw(block)]));

    lines.extend(pass_lines(
        "rephrased",
        &record.rephrased,
        &lineage.rephrased,
        None,
    ));
    let virtualized: Vec<InsnPos> = lineage.virtualized.into_iter().collect();
    lines.extend(pass_lines(
        "virtualized",
        &record.virtualized,
        &virtualized,
        lineage.virtualized,
    ));

    let group = session.words_for(fragment, ori_pc);
    let listed: Vec<String> = group.iter().take(8).map(|o| format!("{o:#x}")).collect();
    lines.push(labelled(
        "layout group",
        LABEL,
        vec![Span::raw(format!(
            "{} word(s) at {}{}",
            group.len(),
            listed.join(" "),
            if group.len() > listed.len() { " ..." } else { "" }
        ))],
    ));
    lines
}

fn user_lines(session: &Session, pc: u64) -> Vec<Line<'static>> {
    let word = text_word(session, pc).expect("a row of the listing is a word of the text");
    let mut lines = vec![labelled(
        "user text",
        LABEL,
        vec![
            Span::styled(format!("{pc:#x} {word:08x}  "), dim()),
            Span::styled(disasm_word(word, pc), bold()),
            Span::styled("   runs natively in userspace", dim()),
        ],
    )];
    // Where the pc lives in the code cache: every translation that kept it.
    let mut found = false;
    for record in session.translations() {
        let Some(fragment) = record.installed else {
            continue;
        };
        let offsets = session.words_for(fragment, pc);
        if offsets.is_empty() {
            continue;
        }
        found = true;
        let listed: Vec<String> = offsets.iter().take(8).map(|o| format!("{o:#x}")).collect();
        lines.push(labelled(
            if lines.len() == 1 { "translated in" } else { "" },
            LABEL,
            vec![Span::raw(format!(
                "T{} as f{fragment}: {}{}",
                record.index,
                listed.join(" "),
                if offsets.len() > listed.len() { " ..." } else { "" }
            ))],
        ));
    }
    if !found {
        lines.push(labelled(
            "translated in",
            LABEL,
            vec![Span::styled("no translation carries this pc", dim())],
        ));
    }
    lines
}

pub fn draw(
    frame: &mut Frame,
    area: Rect,
    session: &Session,
    cursor: &Cursor,
    view: Option<&CodeView>,
    sel: Option<usize>,
) {
    let lines = match view {
        None => vec![Line::from("no ticks")],
        Some(view) => {
            let index = view.selected(sel);
            match view.ctx {
                Ctx::Fragment {
                    fragment,
                    translation,
                } => fragment_lines(
                    session,
                    &session.translations()[translation],
                    fragment,
                    index,
                    cursor,
                ),
                Ctx::User => user_lines(session, view.ori_pc(session, index).expect("user rows have a pc")),
            }
        }
    };
    let title = match sel {
        Some(_) => " lineage (selected word) ",
        None => " lineage (cursor word) ",
    };
    frame.render_widget(
        Paragraph::new(lines).block(Block::default().borders(Borders::ALL).title(title)),
        area,
    );
}
