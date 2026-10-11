//! Text and style helpers shared by the debug panes.

use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};

use crate::a64_pretty::pretty_insn;
use crate::model::Flags;
use crate::session::{Loc, RegId};
use crate::shared::arm64::{decode_word, A64Insn};
use crate::shared::trans::rephrase::{RephrasedInsn, RephrasedInsnKind};

pub fn dim() -> Style {
    Style::default().fg(Color::DarkGray)
}

pub fn bold() -> Style {
    Style::default().add_modifier(Modifier::BOLD)
}

/// Background of every other group in a column, and of the words that share the
/// selected word's original pc.
pub fn group_bg() -> Style {
    Style::default().bg(Color::Indexed(235))
}

pub fn same_pc_bg() -> Style {
    Style::default().bg(Color::Indexed(238))
}

pub fn selection() -> Style {
    Style::default().add_modifier(Modifier::REVERSED)
}

/// Pads `text` with spaces to `width` characters, or cuts it there with an ellipsis.
pub fn fit(text: &str, width: usize) -> String {
    let count = text.chars().count();
    if count <= width {
        return format!("{text:<width$}");
    }
    let mut cut: String = text.chars().take(width.saturating_sub(1)).collect();
    if width > 0 {
        cut.push('…');
    }
    cut
}

pub fn hex64(value: u64) -> String {
    format!("{value:#018x}")
}

pub fn hex128(value: u128) -> String {
    format!("{value:#034x}")
}

pub fn loc(location: Loc) -> String {
    format!("f{}+{:#x}", location.fragment, location.offset)
}

/// `NzCv`: an upper-case letter is a set flag.
pub fn flags(flags: Flags) -> String {
    [
        (flags.n, 'N', 'n'),
        (flags.z, 'Z', 'z'),
        (flags.c, 'C', 'c'),
        (flags.v, 'V', 'v'),
    ]
    .iter()
    .map(|&(set, on, off)| if set { on } else { off })
    .collect()
}

pub fn reg_name(reg: RegId) -> String {
    match reg {
        RegId::X(index) => format!("x{index}"),
        RegId::Sp => "sp".to_string(),
        RegId::V(index) => format!("v{index}"),
        RegId::Fpcr => "fpcr".to_string(),
        RegId::Fpsr => "fpsr".to_string(),
    }
}

/// A text word at `pc` as the disassembler prints it.
pub fn disasm_word(word: u32, pc: u64) -> String {
    match decode_word(word, pc) {
        Ok(decoded) => pretty_insn(decoded.inner, Some(pc)),
        // The text holds a word outside the supported subset (data, or a form the
        // translator would take the `Unsupported` exit on): show it raw.
        Err(_) => format!(".word {word:#010x}"),
    }
}

/// A pass instruction. Only user-semantic ones have branch offsets that mean original
/// pcs; the others are runtime-owned and their offsets are resolved by the layout.
pub fn disasm_pass(insn: &RephrasedInsn) -> String {
    let pc = insn.kind.is_user_semantic().then_some(insn.ori_pc);
    pretty_insn(insn.insn, pc)
}

/// A laid-out word: its branch targets are fragment offsets.
pub fn disasm_layout(insn: A64Insn, offset: usize) -> String {
    pretty_insn(insn, Some(offset as u64))
}

/// A short tag for the kind of a translated instruction.
pub fn tag(kind: RephrasedInsnKind) -> &'static str {
    match kind {
        RephrasedInsnKind::Original => "orig",
        RephrasedInsnKind::UserSynthetic => "synth",
        RephrasedInsnKind::RegVirtHelper => "rv",
        RephrasedInsnKind::UserAccess => "uacc",
        RephrasedInsnKind::BudgetCheck => "budg",
        RephrasedInsnKind::AlignCheck => "algn",
        RephrasedInsnKind::RangeCheck => "rng",
        RephrasedInsnKind::WindowAccess => "win",
        RephrasedInsnKind::DispatchTarget => "dtgt",
        RephrasedInsnKind::DispatchLookup => "dlkp",
        RephrasedInsnKind::LinkSlot { .. } => "link",
        RephrasedInsnKind::RuntimeExitPayload => "xpay",
        RephrasedInsnKind::RuntimeExitBranch => "xbr",
    }
}

pub fn tag_style(kind: RephrasedInsnKind) -> Style {
    let color = match kind {
        RephrasedInsnKind::Original | RephrasedInsnKind::UserSynthetic => Color::Green,
        RephrasedInsnKind::RegVirtHelper => Color::Cyan,
        RephrasedInsnKind::UserAccess | RephrasedInsnKind::WindowAccess => Color::Yellow,
        RephrasedInsnKind::BudgetCheck
        | RephrasedInsnKind::AlignCheck
        | RephrasedInsnKind::RangeCheck => Color::Blue,
        RephrasedInsnKind::DispatchTarget
        | RephrasedInsnKind::DispatchLookup
        | RephrasedInsnKind::LinkSlot { .. }
        | RephrasedInsnKind::RuntimeExitPayload
        | RephrasedInsnKind::RuntimeExitBranch => Color::Magenta,
    };
    Style::default().fg(color)
}

/// `[tag] text`, the tag in the color of its kind.
pub fn tagged(kind: RephrasedInsnKind, text: String) -> Vec<Span<'static>> {
    vec![
        Span::styled(format!("{:<5}", tag(kind)), tag_style(kind)),
        Span::raw(text),
    ]
}

/// A titled line: `label` in the dim style, then `text`.
pub fn labelled(label: &str, width: usize, rest: Vec<Span<'static>>) -> Line<'static> {
    let mut spans = vec![Span::styled(fit(label, width), dim())];
    spans.extend(rest);
    Line::from(spans)
}
