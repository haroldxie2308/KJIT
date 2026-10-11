//! The events pane: the recorded events around `t`, the cursor marked.

use ratatui::layout::Rect;
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

use super::fmt::{bold, dim, loc};
use super::index::EventClass;
use crate::session::{Event, EventKind, Session};

/// One event in a line.
pub fn describe(kind: &EventKind) -> String {
    match *kind {
        EventKind::UserSpan {
            from_pc,
            to_pc,
            steps,
        } => format!("user {from_pc:#x} -> {to_pc:#x} ({steps} steps)"),
        EventKind::Syscall { k, pc } => format!("syscall #{k} at {pc:#x}"),
        EventKind::ProfileHit { pc, kind, count } => {
            format!("profile {pc:#x} {kind:?} count {count}")
        }
        EventKind::Hot { pc } => format!("hot {pc:#x}"),
        EventKind::Translated { translation } => format!("translated T{translation}"),
        EventKind::Installed {
            fragment,
            translation,
        } => format!("installed f{fragment} (T{translation})"),
        EventKind::Published {
            table,
            slot,
            pc,
            fragment,
            replaced,
        } => format!(
            "publish {table:?}[{slot}] {pc:#x} -> f{fragment}{}",
            if replaced.is_some() { " (replaced)" } else { "" }
        ),
        EventKind::Linked {
            fragment,
            slot_offset,
            target,
        } => format!(
            "link f{fragment}+{slot_offset:#x} -> f{}:{:#x}",
            target.fragment, target.pc
        ),
        EventKind::Restored {
            fragment,
            slot_offset,
            target,
        } => format!(
            "unlink f{fragment}+{slot_offset:#x} (was f{}:{:#x})",
            target.fragment, target.pc
        ),
        EventKind::Retired { fragment } => format!("retired f{fragment}"),
        EventKind::RunBegin { fragment, entry_pc } => {
            format!("run begin f{fragment} entry {entry_pc:#x}")
        }
        EventKind::Transfer { from, to, via } => {
            format!("transfer {} -> {} via {via:?}", loc(from), loc(to))
        }
        EventKind::Exit {
            fragment,
            offset,
            status,
            param0,
            param1,
        } => format!("exit f{fragment}+{offset:#x} {status:?} p0={param0:#x} p1={param1:#x}"),
        EventKind::FaultRedirect {
            fragment,
            access_offset,
            stub_offset,
        } => format!("fault f{fragment}+{access_offset:#x} -> stub {stub_offset:#x}"),
        EventKind::RunEnd {
            user_pc,
            entries,
            chain_capped,
        } => format!(
            "run end -> user {user_pc:#x} ({entries} entries{})",
            if chain_capped { ", chain capped" } else { "" }
        ),
        EventKind::Divergence => "DIVERGENCE".to_string(),
    }
}

fn class_style(class: EventClass) -> Style {
    let color = match class {
        EventClass::Syscall => Color::Yellow,
        EventClass::Exit | EventClass::Fault => Color::Red,
        EventClass::Transfer | EventClass::RunBegin | EventClass::RunEnd => Color::Cyan,
        EventClass::Translation | EventClass::Hot | EventClass::Cache => Color::Magenta,
        EventClass::Profile | EventClass::UserSpan => Color::DarkGray,
        EventClass::Divergence => Color::LightRed,
    };
    Style::default().fg(color)
}

fn event_line(event: &Event, here: bool, highlighted: EventClass) -> Line<'static> {
    let class = EventClass::of(&event.kind);
    let mut style = class_style(class);
    if class == highlighted {
        style = style.add_modifier(ratatui::style::Modifier::BOLD);
    }
    Line::from(vec![
        Span::styled(if here { "> " } else { "  " }, bold()),
        Span::styled(format!("{:>6} ", event.t), dim()),
        Span::styled(describe(&event.kind), style),
    ])
}

/// The events around `t` that fit `height` lines. Events with `Event::t == t` follow
/// the machine's state at `t`: they are marked `>`, and a rule marks the cursor when
/// there are none.
pub fn draw(frame: &mut Frame, area: Rect, session: &Session, t: u64, highlighted: EventClass) {
    let events = session.events();
    let block = Block::default()
        .borders(Borders::ALL)
        .title(format!(" events near t={t} (bold: {}) ", highlighted.label()));
    let height = block.inner(area).height as usize;

    let first_here = events.partition_point(|event| event.t < t);
    let after_here = events.partition_point(|event| event.t <= t);
    let here = after_here - first_here;
    // When nothing happens at `t` the cursor rule takes a line.
    let budget = height.saturating_sub(usize::from(here == 0));
    let before = (budget.saturating_sub(here) / 2).min(first_here);
    let start = first_here - before;
    let end = (start + budget).min(events.len());

    let mut lines = Vec::new();
    for (index, event) in events.iter().enumerate().take(end).skip(start) {
        if here == 0 && index == first_here {
            lines.push(cursor_rule(t));
        }
        lines.push(event_line(event, event.t == t, highlighted));
    }
    if here == 0 && end <= first_here {
        lines.push(cursor_rule(t));
    }
    frame.render_widget(Paragraph::new(lines).block(block), area);
}

fn cursor_rule(t: u64) -> Line<'static> {
    Line::styled(format!("> ---- t = {t} ----"), bold())
}
