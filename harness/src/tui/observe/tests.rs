use std::collections::BTreeMap;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::backend::TestBackend;
use ratatui::Terminal;

use super::index::{Filter, Index, Timeline};
use super::ObserveMode;
use crate::session::tests::session;
use crate::session::{Event, EventKind, Session, StepAt, TransferVia};
use crate::tui::{Cx, Mode};

const PROGRAMS: [&str; 3] = [
    "session_svc_loop",
    "session_call_loop",
    "session_indirect_loop",
];

fn render(mode: &mut ObserveMode, cx: &Cx, width: u16, height: u16) -> String {
    let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
    terminal
        .draw(|frame| mode.draw(frame, frame.size(), cx))
        .unwrap();
    let buffer = terminal.backend().buffer();
    buffer
        .content
        .chunks(width as usize)
        .map(|row| row.iter().map(|cell| cell.symbol()).collect::<String>())
        .collect::<Vec<_>>()
        .join("\n")
}

fn press(mode: &mut ObserveMode, cx: &mut Cx, code: KeyCode) -> bool {
    mode.on_key(KeyEvent::new(code, KeyModifiers::NONE), cx)
}

fn events_upto(session: &Session, t: u64) -> impl Iterator<Item = &Event> {
    session.events().iter().filter(move |event| event.t <= t)
}

/// Observe mode draws every tick kind of the session programs at two sizes without
/// panicking, and what it draws names the cursor and the panels.
#[test]
fn draws_the_session_programs_at_start_middle_and_end() {
    for name in PROGRAMS {
        let session = session(name);
        let mut mode = ObserveMode::new(&session);
        for (width, height) in [(80, 24), (200, 60)] {
            for t in [0, session.ticks() / 2, session.ticks()] {
                let mut cx = Cx::new(&session);
                cx.set_t(t);
                let screen = render(&mut mode, &cx, width, height);
                for text in ["timeline", "cache", "profiler", "events up to t"] {
                    assert!(
                        screen.contains(text),
                        "{name} {width}x{height} t={t} lacks {text}:\n{screen}"
                    );
                }
                assert!(
                    screen.contains(&format!("t {t}/{}", session.ticks())),
                    "{name} {width}x{height} t={t}:\n{screen}"
                );
            }
        }
    }
}

/// Terminals too small for the layout still draw.
#[test]
fn draws_in_tiny_areas() {
    let session = session("session_call_loop");
    let mut mode = ObserveMode::new(&session);
    let mut cx = Cx::new(&session);
    cx.set_t(session.ticks() / 2);
    for (width, height) in [(1, 1), (10, 3), (20, 8), (40, 12)] {
        render(&mut mode, &cx, width, height);
    }
}

#[test]
fn playback_advances_by_the_speed_and_stops_at_the_end() {
    let session = session("session_svc_loop");
    let ticks = session.ticks();
    let mut mode = ObserveMode::new(&session);
    let mut cx = Cx::new(&session);

    mode.tick(&mut cx);
    assert_eq!(cx.t, 0, "paused: tick does nothing");

    assert!(press(&mut mode, &mut cx, KeyCode::Char(' ')));
    mode.tick(&mut cx);
    assert_eq!(cx.t, 1);

    for _ in 0..3 {
        press(&mut mode, &mut cx, KeyCode::Char('+'));
    }
    assert_eq!(mode.speed(), 8);
    mode.tick(&mut cx);
    assert_eq!(cx.t, 9);

    // The speed is bounded at 4096x and at 1x.
    for _ in 0..40 {
        press(&mut mode, &mut cx, KeyCode::Char('+'));
    }
    assert_eq!(mode.speed(), 4096);
    for _ in 0..40 {
        press(&mut mode, &mut cx, KeyCode::Char('-'));
    }
    assert_eq!(mode.speed(), 1);

    // Pause stops it.
    press(&mut mode, &mut cx, KeyCode::Char(' '));
    mode.tick(&mut cx);
    assert_eq!(cx.t, 9);

    // Playing into the end clamps to `ticks` and stops.
    cx.set_t(ticks - 3);
    for _ in 0..3 {
        press(&mut mode, &mut cx, KeyCode::Char('+'));
    }
    press(&mut mode, &mut cx, KeyCode::Char(' '));
    assert!(mode.playing);
    mode.tick(&mut cx);
    assert_eq!(cx.t, ticks);
    assert!(!mode.playing);
    mode.tick(&mut cx);
    assert_eq!(cx.t, ticks);

    // Play at the end starts over.
    press(&mut mode, &mut cx, KeyCode::Char(' '));
    assert_eq!(cx.t, 0);
    assert!(mode.playing);
}

#[test]
fn scrubbing_jumps_and_navigation_keys() {
    let session = session("session_call_loop");
    let ticks = session.ticks();
    let large = ticks / 100;
    let mut mode = ObserveMode::new(&session);
    let mut cx = Cx::new(&session);

    press(&mut mode, &mut cx, KeyCode::Right);
    assert_eq!(cx.t, 1);
    press(&mut mode, &mut cx, KeyCode::PageDown);
    assert_eq!(cx.t, 1 + large);
    mode.on_key(KeyEvent::new(KeyCode::Right, KeyModifiers::SHIFT), &mut cx);
    assert_eq!(cx.t, 1 + 2 * large);
    mode.on_key(KeyEvent::new(KeyCode::Left, KeyModifiers::SHIFT), &mut cx);
    press(&mut mode, &mut cx, KeyCode::PageUp);
    press(&mut mode, &mut cx, KeyCode::Left);
    assert_eq!(cx.t, 0);
    press(&mut mode, &mut cx, KeyCode::Left);
    assert_eq!(cx.t, 0);
    press(&mut mode, &mut cx, KeyCode::End);
    assert_eq!(cx.t, ticks);
    press(&mut mode, &mut cx, KeyCode::Right);
    assert_eq!(cx.t, ticks);
    press(&mut mode, &mut cx, KeyCode::Home);
    assert_eq!(cx.t, 0);

    // n / p walk the translations in order.
    let moments: Vec<u64> = session
        .translations()
        .iter()
        .map(|record| record.t)
        .collect();
    assert!(moments.len() >= 3);
    for &moment in &moments {
        press(&mut mode, &mut cx, KeyCode::Char('n'));
        assert_eq!(cx.t, moment);
    }
    press(&mut mode, &mut cx, KeyCode::Char('n'));
    assert_eq!(
        cx.t,
        *moments.last().unwrap(),
        "no translation after the last"
    );
    press(&mut mode, &mut cx, KeyCode::Char('p'));
    assert_eq!(cx.t, moments[moments.len() - 2]);

    // f cycles through every filter and back.
    let first = mode.filter;
    let mut seen = vec![first];
    loop {
        press(&mut mode, &mut cx, KeyCode::Char('f'));
        if mode.filter == first {
            break;
        }
        seen.push(mode.filter);
    }
    assert_eq!(seen.len(), 6);

    // Keys the mode does not own go to the shell.
    for code in [
        KeyCode::Tab,
        KeyCode::Char('q'),
        KeyCode::Char('1'),
        KeyCode::Char('?'),
        KeyCode::Esc,
    ] {
        assert!(!press(&mut mode, &mut cx, code), "{code:?}");
    }
}

/// The prefix sums, counted straight from the events and the step log.
#[test]
fn counts_up_to_t_equal_counts_over_the_events() {
    for name in PROGRAMS {
        let session = session(name);
        let index = Index::new(&session);
        let ticks = session.ticks();
        for t in [0, 1, ticks / 3, ticks / 2, ticks - 1, ticks] {
            let counts = index.counts(t);
            let count = |matches: &dyn Fn(&EventKind) -> bool| {
                events_upto(&session, t)
                    .filter(|event| matches(&event.kind))
                    .count() as u64
            };
            let via = |wanted: TransferVia| {
                count(&|kind| matches!(kind, EventKind::Transfer { via, .. } if *via == wanted))
            };
            let at = format!("{name} t={t}");
            assert_eq!(
                counts.syscalls,
                count(&|k| matches!(k, EventKind::Syscall { .. })),
                "{at}"
            );
            assert_eq!(
                counts.translations,
                count(&|k| matches!(k, EventKind::Translated { .. })),
                "{at}"
            );
            assert_eq!(
                counts.hot,
                count(&|k| matches!(k, EventKind::Hot { .. })),
                "{at}"
            );
            assert_eq!(
                counts.exits,
                count(&|k| matches!(k, EventKind::Exit { .. })),
                "{at}"
            );
            assert_eq!(counts.dispatch, via(TransferVia::Dispatch), "{at}");
            assert_eq!(counts.link, via(TransferVia::Link), "{at}");
            assert_eq!(counts.runtime, via(TransferVia::Runtime), "{at}");
            let rejected = events_upto(&session, t)
                .filter(|event| match event.kind {
                    EventKind::Translated { translation } => {
                        session.translations()[translation].installed.is_none()
                    }
                    _ => false,
                })
                .count() as u64;
            assert_eq!(counts.rejected, rejected, "{at}");

            let in_fragments = session
                .steps()
                .take(t as usize)
                .filter(|step| matches!(step.at, StepAt::Fragment { .. }))
                .count() as u64;
            assert_eq!(index.fragment_ticks(t), in_fragments, "{at}");
        }
        // The recorded run, as the session programs promise.
        let end = index.counts(ticks);
        assert_eq!(end.syscalls, 301, "{name}");
        assert_eq!(end.syscalls, session.syscalls().len() as u64);
        assert!(
            end.translations > 0 && end.hot == end.translations,
            "{name}"
        );
    }
}

/// A timeline's columns partition the run: summed over columns they equal the totals,
/// at widths below, near and above the number of ticks.
#[test]
fn timeline_columns_partition_the_run() {
    for name in PROGRAMS {
        let session = session(name);
        let index = Index::new(&session);
        let ticks = session.ticks();
        let end = index.counts(ticks);
        for width in [1, 7, 100, 1000, ticks as usize + 5] {
            let at = format!("{name} width {width}");
            let timeline = Timeline::build(&index, ticks, width);
            assert_eq!(timeline.fragment_share.len(), width);
            let sum = |values: &[u32]| values.iter().map(|&v| u64::from(v)).sum::<u64>();
            assert_eq!(sum(&timeline.syscalls), end.syscalls, "{at}");
            assert_eq!(sum(&timeline.round_trips), end.runtime, "{at}");
            assert_eq!(sum(&timeline.direct), end.dispatch + end.link, "{at}");
            let marked = timeline
                .installed
                .iter()
                .zip(&timeline.rejected)
                .filter(|(installed, rejected)| **installed || **rejected)
                .count();
            assert!(marked > 0 && marked as u64 <= end.translations, "{at}");

            // Every tick is in the column `column_of` says, and each column's fragment
            // share is its ticks in fragments over its ticks.
            let mut ticks_in = vec![0u64; width];
            let mut in_fragment = vec![0u64; width];
            for step in session.steps() {
                let column = timeline.column_of(step.tick);
                ticks_in[column] += 1;
                in_fragment[column] += u64::from(matches!(step.at, StepAt::Fragment { .. }));
            }
            for column in 0..width {
                match timeline.fragment_share[column] {
                    None => assert_eq!(ticks_in[column], 0, "{at} column {column}"),
                    Some(share) => {
                        let expected = in_fragment[column] as f64 / ticks_in[column] as f64;
                        assert!((share - expected).abs() < 1e-9, "{at} column {column}");
                    }
                }
            }
            assert_eq!(timeline.column_of(0), 0);
            // With more columns than ticks the tail columns hold no tick.
            if width as u64 <= ticks {
                assert_eq!(timeline.column_of(ticks), width - 1, "{at}");
            } else {
                assert!(timeline.column_of(ticks) < width, "{at}");
            }
        }
    }
}

/// The snapshots plus replay give the same state as folding the events from scratch,
/// whatever the snapshot spacing.
#[test]
fn transfer_edges_and_profiler_state_match_a_direct_fold() {
    for name in PROGRAMS {
        let session = session(name);
        let threshold = session.config().policy.hot_threshold;
        let events = session.events();
        for every in [1, 7, 64, 100_000] {
            let index = Index::with_snapshot_every(&session, every);
            for n in (0..=events.len()).step_by(13).chain([events.len()]) {
                let at = format!("{name} every {every} n {n}");
                let accum = index.accum_after(&session, n);

                let mut edges: BTreeMap<(usize, usize), [u64; 3]> = BTreeMap::new();
                let mut counts: BTreeMap<u64, u32> = BTreeMap::new();
                let mut translated: BTreeMap<u64, usize> = BTreeMap::new();
                for event in &events[..n] {
                    match event.kind {
                        EventKind::Transfer { from, to, via } => {
                            let slot = match via {
                                TransferVia::Dispatch => 0,
                                TransferVia::Link => 1,
                                TransferVia::Runtime => 2,
                            };
                            edges.entry((from.fragment, to.fragment)).or_default()[slot] += 1;
                        }
                        EventKind::ProfileHit { pc, count, .. } => {
                            assert!(count <= threshold);
                            counts.insert(pc, count);
                        }
                        EventKind::Hot { pc } => {
                            counts.insert(pc, 0);
                        }
                        EventKind::Translated { translation } => {
                            translated
                                .insert(session.translations()[translation].entry_pc, translation);
                        }
                        _ => {}
                    }
                }
                assert_eq!(accum.edges, edges, "{at}");
                let got: BTreeMap<u64, u32> =
                    accum.pcs.iter().map(|(pc, s)| (*pc, s.count)).collect();
                assert_eq!(got, counts, "{at}");
                let got: BTreeMap<u64, usize> = accum
                    .pcs
                    .iter()
                    .filter_map(|(pc, s)| s.translation.map(|t| (*pc, t)))
                    .collect();
                assert_eq!(got, translated, "{at}");
            }
        }
    }
}

/// The edges at the end add up to the transfer counts.
#[test]
fn edge_totals_equal_transfer_totals() {
    let session = session("session_call_loop");
    let index = Index::new(&session);
    let accum = index.accum_after(&session, session.events().len());
    let end = index.counts(session.ticks());
    let sum = |slot: usize| accum.edges.values().map(|counts| counts[slot]).sum::<u64>();
    assert_eq!(
        (sum(0), sum(1), sum(2)),
        (end.dispatch, end.link, end.runtime)
    );
    assert!(sum(1) > 0, "session_call_loop links its BL");
}

/// The view at the last cache event is the view at any later tick up to the next cache
/// event, so `cache_key` can stand for `t`.
#[test]
fn the_cache_view_at_the_cache_key_is_the_view_at_t() {
    for name in PROGRAMS {
        let session = session(name);
        let index = Index::new(&session);
        for t in (0..=session.ticks()).step_by(97).chain([session.ticks()]) {
            let direct = session.cache_at(t).unwrap();
            let keyed = session.cache_at(index.cache_key(t)).unwrap();
            assert_eq!(direct.fragments, keyed.fragments, "{name} t={t}");
            assert_eq!(direct.table_all, keyed.table_all, "{name} t={t}");
            assert_eq!(direct.table_nofp, keyed.table_nofp, "{name} t={t}");
            assert_eq!(direct.links, keyed.links, "{name} t={t}");
        }
    }
}

/// The log window is the newest matching events at or before `t`, in order, and `back`
/// scrolls older.
#[test]
fn log_windows_follow_t_and_the_filter() {
    let session = session("session_call_loop");
    let index = Index::new(&session);
    let filters = [
        Filter::All,
        Filter::User,
        Filter::Profiler,
        Filter::Cache,
        Filter::Runs,
        Filter::Transfers,
    ];
    for filter in filters {
        for t in [0, 500, session.ticks() / 2, session.ticks()] {
            let matching: Vec<_> = events_upto(&session, t)
                .filter(|event| filter == Filter::All || Filter::of(&event.kind) == filter)
                .collect();
            for (rows, back) in [(5, 0), (5, 3), (12, 0), (5, 10_000)] {
                let window = index.log_window(&session, filter, t, back, rows);
                assert_eq!(window.max_back, matching.len().saturating_sub(rows));
                let end = matching.len() - back.min(window.max_back);
                let expected = &matching[end.saturating_sub(rows)..end];
                assert_eq!(window.events.len(), expected.len(), "{filter:?} t={t}");
                for (got, want) in window.events.iter().zip(expected) {
                    assert!(std::ptr::eq(*got, *want), "{filter:?} t={t}");
                }
            }
        }
    }
}
