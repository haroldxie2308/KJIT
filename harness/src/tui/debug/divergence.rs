//! The divergence view: the reference world against the KJIT world where they
//! disagreed (`Outcome::Divergence`, `Session::reference_at_syscall`).

use ratatui::layout::Rect;
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

use super::fmt::{bold, dim, flags, hex128, hex64, reg_name};
use crate::session::{Divergence, Outcome, RegId, Session};

fn red() -> Style {
    Style::default().fg(Color::LightRed)
}

/// The divergence of the outcome, if any.
pub fn divergence_of(session: &Session) -> Option<&Divergence> {
    match session.outcome() {
        Outcome::Divergence(divergence) => Some(divergence),
        _ => None,
    }
}

fn lines(session: &Session, t: u64) -> Vec<Line<'static>> {
    let Some(divergence) = divergence_of(session) else {
        return vec![
            Line::styled("no divergence", bold()),
            Line::from(format!(
                "the reference and KJIT worlds agreed at all {} syscalls and at the end ({})",
                session.syscalls().len(),
                crate::tui::outcome_summary(session)
            )),
        ];
    };
    let mut out = Vec::new();
    let place = match divergence.syscall {
        Some(k) => format!("syscall #{k}"),
        None => "the end of the program".to_string(),
    };
    out.push(Line::from(vec![
        Span::styled("DIVERGED at ", red()),
        Span::styled(place, red()),
        Span::raw(format!("  tick {} (cursor t = {t})", divergence.t)),
    ]));
    out.push(Line::from(format!("kind: {:?}", divergence.kind)));

    let diff = &divergence.diff;
    out.push(Line::default());
    out.push(Line::styled(
        format!("differing registers ({})", diff.regs.len()),
        bold(),
    ));
    for entry in &diff.regs {
        let wide = matches!(entry.reg, RegId::V(_));
        let (reference, kjit) = if wide {
            (hex128(entry.reference), hex128(entry.kjit))
        } else {
            (hex64(entry.reference as u64), hex64(entry.kjit as u64))
        };
        out.push(Line::from(vec![
            Span::styled(format!("{:<5}", reg_name(entry.reg)), red()),
            Span::raw(format!("ref {reference}  kjit {kjit}")),
            Span::styled(format!("  xor {:#x}", entry.reference ^ entry.kjit), dim()),
        ]));
    }
    if let Some((reference, kjit)) = diff.flags {
        out.push(Line::from(vec![
            Span::styled("nzcv ", red()),
            Span::raw(format!("ref {}  kjit {}", flags(reference), flags(kjit))),
        ]));
    }
    if !diff.mem.is_empty() {
        out.push(Line::styled(
            format!("differing memory bytes ({})", diff.mem.len()),
            bold(),
        ));
        for entry in &diff.mem {
            out.push(Line::from(vec![
                Span::styled(format!("{:#x} ", entry.addr), red()),
                Span::raw(format!("ref {:#04x}  kjit {:#04x}", entry.reference, entry.kjit)),
            ]));
        }
    }
    for other in &diff.other {
        out.push(Line::from(vec![Span::styled("other ", red()), Span::raw(other.clone())]));
    }

    // Both states side by side; the registers `diff` lists are marked.
    let reference = match divergence.syscall {
        Some(k) => session
            .reference_at_syscall(k)
            .expect("the syscall of a divergence is in the run"),
        None => divergence.reference.clone(),
    };
    let differs = |reg: RegId| diff.regs.iter().any(|entry| entry.reg == reg);
    out.push(Line::default());
    out.push(Line::styled("reference | kjit", bold()));
    let mut row = |reg: RegId, reference: u64, kjit: u64| {
        let style = if differs(reg) { red() } else { Style::default() };
        out.push(Line::from(vec![
            Span::styled(if differs(reg) { "! " } else { "  " }, red()),
            Span::styled(format!("{:<4}", reg_name(reg)), style),
            Span::styled(hex64(reference), style),
            Span::styled(" | ", dim()),
            Span::styled(hex64(kjit), style),
        ]));
    };
    for index in 0..31u8 {
        row(
            RegId::X(index),
            reference.read_x(index),
            divergence.kjit.read_x(index),
        );
    }
    row(RegId::Sp, reference.sp(), divergence.kjit.sp());
    out
}

pub fn row_count(session: &Session, t: u64) -> usize {
    lines(session, t).len()
}

pub fn draw(frame: &mut Frame, area: Rect, session: &Session, t: u64, scroll: usize) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" divergence: reference vs KJIT ");
    let height = block.inner(area).height as usize;
    let visible: Vec<Line<'static>> = lines(session, t)
        .into_iter()
        .skip(scroll)
        .take(height)
        .collect();
    frame.render_widget(Paragraph::new(visible).block(block), area);
}
