//! One line per event, for the event log.

use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};

use crate::session::{Event, EventKind, Loc, Session, TransferVia};

fn loc(loc: Loc) -> String {
    format!("f{}+{:#x}", loc.fragment, loc.offset)
}

fn via(via: TransferVia) -> (&'static str, Color) {
    match via {
        TransferVia::Dispatch => ("dispatch", Color::Yellow),
        TransferVia::Link => ("link", Color::Magenta),
        TransferVia::Runtime => ("runtime", Color::Red),
    }
}

/// The event as a log line: `t`, a tag colored by what kind of event it is, details.
pub(super) fn event_line(session: &Session, event: &Event, cursor_t: u64) -> Line<'static> {
    let (tag, color, detail) = match event.kind {
        EventKind::UserSpan {
            from_pc,
            to_pc,
            steps,
        } => (
            "user",
            Color::Cyan,
            format!("{steps} ticks {from_pc:#x} -> {to_pc:#x}"),
        ),
        EventKind::Syscall { k, pc } => ("svc", Color::Cyan, format!("syscall {k} at {pc:#x}")),
        EventKind::ProfileHit { pc, kind, count } => (
            "prof",
            Color::Yellow,
            format!(
                "hit {pc:#x} {count}/{} ({kind:?})",
                session.config().policy.hot_threshold
            ),
        ),
        EventKind::Hot { pc } => ("prof", Color::Yellow, format!("HOT {pc:#x}")),
        EventKind::Translated { translation } => {
            let record = &session.translations()[translation];
            let outcome = match record.installed {
                Some(fragment) => format!("installed as f{fragment}"),
                None => "REJECTED".to_string(),
            };
            (
                "trans",
                Color::Yellow,
                format!("#{translation} entry {:#x}: {outcome}", record.entry_pc),
            )
        }
        EventKind::Installed {
            fragment,
            translation,
        } => (
            "cache",
            Color::Green,
            format!("install f{fragment} (translation #{translation})"),
        ),
        EventKind::Published {
            table,
            slot,
            pc,
            fragment,
            replaced,
        } => {
            let replaced = match replaced {
                Some(old) => format!(", replaces f{} ({:#x})", old.fragment, old.pc),
                None => String::new(),
            };
            (
                "cache",
                Color::Green,
                format!("publish {table:?}[{slot}] {pc:#x} -> f{fragment}{replaced}"),
            )
        }
        EventKind::Linked {
            fragment,
            slot_offset,
            target,
        } => (
            "cache",
            Color::Green,
            format!(
                "link f{fragment}+{slot_offset:#x} -> f{} ({:#x})",
                target.fragment, target.pc
            ),
        ),
        EventKind::Restored {
            fragment,
            slot_offset,
            target,
        } => (
            "cache",
            Color::Green,
            format!(
                "unlink f{fragment}+{slot_offset:#x} (was f{})",
                target.fragment
            ),
        ),
        EventKind::Retired { fragment } => ("cache", Color::Green, format!("retire f{fragment}")),
        EventKind::RunBegin { fragment, entry_pc } => (
            "run",
            Color::Blue,
            format!("begin f{fragment} for {entry_pc:#x}"),
        ),
        EventKind::Transfer { from, to, via: how } => {
            let (name, color) = via(how);
            (
                "xfer",
                color,
                format!("{name} {} -> {}", loc(from), loc(to)),
            )
        }
        EventKind::Exit {
            fragment,
            offset,
            status,
            ..
        } => (
            "exit",
            Color::Red,
            format!("f{fragment}+{offset:#x} {status:?}"),
        ),
        EventKind::FaultRedirect {
            fragment,
            access_offset,
            stub_offset,
        } => (
            "fault",
            Color::Red,
            format!("f{fragment}+{access_offset:#x} -> stub +{stub_offset:#x}"),
        ),
        EventKind::RunEnd {
            user_pc,
            entries,
            chain_capped,
        } => (
            "run",
            Color::Blue,
            format!(
                "end, user resumes at {user_pc:#x} ({entries} entries{})",
                if chain_capped { ", chain capped" } else { "" }
            ),
        ),
        EventKind::Divergence => ("DIVERGE", Color::Red, "the worlds disagree".to_string()),
    };
    let weight = if event.t == cursor_t {
        Style::default().add_modifier(ratatui::style::Modifier::BOLD)
    } else {
        Style::default()
    };
    Line::from(vec![
        Span::styled(
            format!("{:>8} ", event.t),
            Style::default().fg(Color::DarkGray),
        ),
        Span::styled(format!("{tag:<6}"), Style::default().fg(color)),
        Span::styled(detail, weight),
    ])
}
