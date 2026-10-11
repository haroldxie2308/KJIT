//! Debug mode over the three session programs: it renders every kind of tick and every
//! sub-view without panicking, and its navigation lands where it says.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::backend::TestBackend;
use ratatui::Terminal;

use super::index::{ori_pc_of, EventClass};
use super::{DebugMode, Screen};
use crate::session::tests::session;
use crate::session::{
    Divergence, DivergenceKind, EventKind, Outcome, RegDiff, RegId, Session, StateDiff, StepAt,
};
use crate::tui::tests::screen;
use crate::tui::{Cx, Mode};

const PROGRAMS: [&str; 3] = [
    "session_svc_loop",
    "session_call_loop",
    "session_indirect_loop",
];

struct Rig<'a> {
    mode: DebugMode,
    cx: Cx<'a>,
    terminal: Terminal<TestBackend>,
}

impl<'a> Rig<'a> {
    fn new(session: &'a Session, width: u16, height: u16) -> Self {
        Self {
            mode: DebugMode::new(session),
            cx: Cx::new(session),
            terminal: Terminal::new(TestBackend::new(width, height)).unwrap(),
        }
    }

    fn key(&mut self, code: KeyCode) -> bool {
        self.mode
            .on_key(KeyEvent::new(code, KeyModifiers::NONE), &mut self.cx)
    }

    fn press(&mut self, c: char) {
        assert!(self.key(KeyCode::Char(c)), "debug mode ignored {c}");
    }

    fn draw(&mut self) -> String {
        let (mode, cx) = (&mut self.mode, &self.cx);
        self.terminal
            .draw(|frame| mode.draw(frame, frame.size(), cx))
            .unwrap();
        screen(&self.terminal)
    }
}

/// Ticks that put the cursor in each kind of place: the ends, the first user and
/// fragment ticks, both sides of every run boundary, every translation request, and
/// the ticks around each syscall.
fn interesting_ticks(session: &Session) -> Vec<u64> {
    let mut ticks = vec![0, 1, session.ticks().saturating_sub(1), session.ticks()];
    let first_fragment = session
        .steps()
        .find(|step| matches!(step.at, StepAt::Fragment { .. }))
        .expect("every program ends up running fragments")
        .tick;
    ticks.extend([first_fragment - 1, first_fragment, first_fragment + 1]);
    for event in session.events() {
        if matches!(
            event.kind,
            EventKind::RunBegin { .. }
                | EventKind::RunEnd { .. }
                | EventKind::Exit { .. }
                | EventKind::Transfer { .. }
                | EventKind::Hot { .. }
                | EventKind::Syscall { .. }
        ) {
            ticks.extend([event.t.saturating_sub(1), event.t, event.t + 1]);
        }
    }
    ticks.extend(session.translations().iter().map(|record| record.t));
    ticks.retain(|&t| t <= session.ticks());
    ticks.sort_unstable();
    ticks.dedup();
    ticks
}

/// A copy of `session` whose outcome is a divergence at its last tick: x20 differs
/// at syscall 5 (the recorder's own divergences are covered in the session tests).
fn diverged(name: &str) -> Session {
    let mut session = session(name);
    let reference = session.state_at(session.syscalls()[4].t).unwrap();
    let mut kjit = reference.clone();
    kjit.write_x(20, reference.read_x(20) ^ 1);
    session.outcome = Outcome::Divergence(Box::new(Divergence {
        t: session.ticks(),
        syscall: Some(5),
        kind: DivergenceKind::State,
        reference: reference.clone(),
        kjit,
        diff: StateDiff {
            regs: vec![RegDiff {
                reg: RegId::X(20),
                reference: u128::from(reference.read_x(20)),
                kjit: u128::from(reference.read_x(20) ^ 1),
            }],
            ..StateDiff::default()
        },
    }));
    session
}

#[test]
fn the_ticks_of_every_program_render() {
    for name in PROGRAMS {
        let session = session(name);
        let mut rig = Rig::new(&session, 120, 40);
        // The first stretch tick by tick, then every 11th: each frame replays up to a
        // checkpoint interval of steps.
        for t in (0..=session.ticks()).filter(|&t| t < 600 || t % 11 == 0) {
            rig.cx.set_t(t);
            rig.draw();
        }
    }
}

#[test]
fn interesting_ticks_render_at_every_size_and_screen() {
    for name in PROGRAMS {
        let session = session(name);
        let ticks = interesting_ticks(&session);
        for (width, height) in [(160, 48), (100, 30), (60, 16), (20, 5), (1, 1)] {
            let mut rig = Rig::new(&session, width, height);
            for screen in [None, Some('T'), Some('v')] {
                if let Some(key) = screen {
                    rig.press(key);
                }
                for &t in &ticks {
                    rig.cx.set_t(t);
                    rig.draw();
                }
                if screen.is_some() {
                    rig.press(screen.unwrap());
                }
            }
        }
    }
}

#[test]
fn the_panes_show_the_place_at_the_cursor() {
    let session = session("session_call_loop");
    let mut rig = Rig::new(&session, 160, 48);

    // The first tick runs user text.
    let text = rig.draw();
    for expected in ["debug mode, t = 0", "code: user text", "lineage", "registers @ t=0", "events near t=0"] {
        assert!(text.contains(expected), "lacks {expected}:\n{text}");
    }

    // A fragment tick lists words with their kind tags and original pcs, and a lineage.
    let (fragment_tick, _) = first_fragment_pc(&session);
    rig.cx.set_t(fragment_tick);
    let text = rig.draw();
    for expected in ["code: fragment f0", "orig", "layout group", "rephrased", "virtualized", "cfg block"] {
        assert!(text.contains(expected), "lacks {expected}:\n{text}");
    }
}

#[test]
fn stepping_keys_move_and_clamp_the_cursor() {
    let session = session("session_svc_loop");
    let mut rig = Rig::new(&session, 100, 30);
    rig.press('l');
    rig.key(KeyCode::Right);
    rig.press('h');
    assert_eq!(rig.cx.t, 1);
    rig.press('L');
    assert_eq!(rig.cx.t, 11);
    rig.press('s');
    rig.press('L');
    assert_eq!(rig.cx.t, 111);
    rig.press('H');
    assert_eq!(rig.cx.t, 11);
    rig.key(KeyCode::End);
    assert_eq!(rig.cx.t, session.ticks());
    rig.press('l');
    assert_eq!(rig.cx.t, session.ticks());
    rig.key(KeyCode::Home);
    rig.press('h');
    assert_eq!(rig.cx.t, 0);
}

#[test]
fn next_event_of_a_kind_lands_on_an_event_tick_of_that_kind() {
    for name in PROGRAMS {
        let session = session(name);
        for class in EventClass::ALL {
            let mut rig = Rig::new(&session, 100, 30);
            while rig.mode.kind != class {
                rig.press('c');
            }
            let expected: Vec<u64> = {
                let mut ticks: Vec<u64> = session
                    .events()
                    .iter()
                    .filter(|event| EventClass::of(&event.kind) == class)
                    .map(|event| event.t)
                    .collect();
                ticks.dedup();
                ticks
            };

            let mut forward = Vec::new();
            loop {
                let before = rig.cx.t;
                rig.press('n');
                if rig.cx.t == before {
                    break;
                }
                assert!(rig.cx.t > before, "{name}/{class:?}");
                forward.push(rig.cx.t);
            }
            // `n` from t = 0 skips an event at t = 0 itself (it is "next" after t).
            let after_zero: Vec<u64> = expected.iter().copied().filter(|&t| t > 0).collect();
            assert_eq!(forward, after_zero, "{name}/{class:?}");

            rig.cx.set_t(session.ticks());
            let mut backward = Vec::new();
            loop {
                let before = rig.cx.t;
                rig.press('N');
                if rig.cx.t == before {
                    break;
                }
                backward.push(rig.cx.t);
            }
            let mut before_end: Vec<u64> = expected
                .iter()
                .copied()
                .filter(|&t| t < session.ticks())
                .collect();
            before_end.reverse();
            assert_eq!(backward, before_end, "{name}/{class:?}");
        }
    }
}

#[test]
fn a_missing_event_keeps_the_cursor_and_says_so() {
    let session = session("session_svc_loop");
    let mut rig = Rig::new(&session, 160, 48);
    while rig.mode.kind != EventClass::Divergence {
        rig.press('c');
    }
    rig.cx.set_t(3);
    rig.press('n');
    assert_eq!(rig.cx.t, 3);
    assert!(rig.draw().contains("no later divergence event"));
    rig.press('d');
    assert_eq!(rig.cx.t, 3);
    assert!(rig.draw().contains("no divergence"));
}

#[test]
fn the_kind_cycle_visits_every_class_and_returns() {
    let mut kind = EventClass::Syscall;
    for _ in 0..EventClass::ALL.len() {
        kind = kind.cycled(true);
    }
    assert_eq!(kind, EventClass::Syscall);
    assert_eq!(EventClass::Syscall.cycled(false).cycled(true), EventClass::Syscall);
}

/// The first tick at which the next instruction is a translated word of an original
/// pc, with that pc.
fn first_fragment_pc(session: &Session) -> (u64, u64) {
    let step = session
        .steps()
        .find(|step| matches!(step.at, StepAt::Fragment { .. }) && ori_pc_of(session, step.at).is_some())
        .expect("a fragment executes a translated instruction");
    (step.tick - 1, ori_pc_of(session, step.at).unwrap())
}

#[test]
fn continuing_lands_before_a_step_of_the_breakpoint_pc() {
    for name in PROGRAMS {
        let session = session(name);
        let (t, pc) = first_fragment_pc(&session);
        let mut rig = Rig::new(&session, 100, 30);
        rig.cx.set_t(t);
        rig.draw();
        rig.press('b');
        assert!(rig.mode.breakpoints.contains(&pc));

        // Forward from the start: every landing is before a step of the pc, the
        // landings increase, and each is the first word of a group.
        rig.cx.set_t(0);
        let mut landings = vec![];
        loop {
            let before = rig.cx.t;
            rig.press('r');
            if rig.cx.t == before {
                break;
            }
            assert!(rig.cx.t > before);
            let next = session.step(rig.cx.t + 1).expect("a landing has a next step");
            assert_eq!(ori_pc_of(&session, next.at), Some(pc), "{name} at t={}", rig.cx.t);
            if let Some(last) = session.step(rig.cx.t) {
                let continues = matches!(
                    (last.at, next.at),
                    (StepAt::Fragment { fragment: a, offset: x }, StepAt::Fragment { fragment: b, offset: y })
                        if a == b && x + 4 == y && ori_pc_of(&session, last.at) == Some(pc)
                );
                assert!(!continues, "{name}: landed inside a group at t={}", rig.cx.t);
            }
            landings.push(rig.cx.t);
        }
        assert!(landings.len() > 10, "{name}: the loop reaches the pc often");
        assert!(landings.contains(&t) || landings[0] > t, "{name}");

        // Backward from the end visits the same ticks.
        rig.cx.set_t(session.ticks());
        let mut back = vec![];
        loop {
            let before = rig.cx.t;
            rig.press('R');
            if rig.cx.t == before {
                break;
            }
            back.push(rig.cx.t);
        }
        back.reverse();
        let reachable: Vec<u64> = landings
            .iter()
            .copied()
            .filter(|&t| t < session.ticks())
            .collect();
        assert_eq!(back, reachable, "{name}");
    }
}

#[test]
fn continuing_without_a_breakpoint_or_a_hit_says_so() {
    let session = session("session_svc_loop");
    let mut rig = Rig::new(&session, 160, 48);
    rig.press('r');
    assert_eq!(rig.cx.t, 0);
    assert!(rig.draw().contains("no breakpoints"));

    let (t, _) = first_fragment_pc(&session);
    rig.cx.set_t(t);
    rig.draw();
    rig.press('b');
    rig.cx.set_t(session.ticks());
    rig.press('r');
    assert_eq!(rig.cx.t, session.ticks());
    assert!(rig.draw().contains("no later breakpoint hit"));
    rig.press('B');
    assert!(rig.mode.breakpoints.is_empty());
}

#[test]
fn a_breakpoint_can_be_set_on_a_selected_user_pc() {
    let session = session("session_svc_loop");
    let mut rig = Rig::new(&session, 100, 30);
    rig.draw();
    rig.press('j');
    rig.press('j');
    let pc = session.config().entry_pc + 8;
    rig.press('b');
    assert!(rig.mode.breakpoints.contains(&pc));
    rig.press('r');
    // The first time the user code is about to execute the pc.
    let next = session.step(rig.cx.t + 1).unwrap();
    assert_eq!(ori_pc_of(&session, next.at), Some(pc));
    // Toggling again clears it.
    rig.cx.set_t(0);
    rig.draw();
    rig.press('j');
    rig.press('j');
    rig.press('b');
    assert!(rig.mode.breakpoints.is_empty());
}

#[test]
fn the_selection_moves_inside_the_listing_and_follows_the_cursor_again_on_a_step() {
    let session = session("session_call_loop");
    let (t, _) = first_fragment_pc(&session);
    let mut rig = Rig::new(&session, 160, 48);
    rig.cx.set_t(t);
    rig.draw();
    let cursor_row = rig.mode.code.unwrap().cursor;
    assert_eq!(rig.mode.sel, None);
    rig.key(KeyCode::Down);
    rig.press('j');
    assert_eq!(rig.mode.sel, Some(cursor_row + 2));
    rig.key(KeyCode::Up);
    assert_eq!(rig.mode.sel, Some(cursor_row + 1));
    assert!(rig.draw().contains("lineage (selected word)"));
    for _ in 0..1000 {
        rig.press('j');
    }
    assert_eq!(rig.mode.sel, Some(rig.mode.code.unwrap().len - 1));
    rig.draw();
    for _ in 0..2000 {
        rig.press('k');
    }
    assert_eq!(rig.mode.sel, Some(0));
    rig.draw();

    rig.press('l');
    rig.draw();
    assert_eq!(rig.mode.sel, None);
    assert!(rig.draw().contains("lineage (cursor word)"));
}

#[test]
fn go_to_takes_a_number_clamps_and_owns_the_keyboard() {
    let session = session("session_call_loop");
    let mut rig = Rig::new(&session, 160, 48);

    rig.press('g');
    assert!(rig.draw().contains("go to tick: _"));
    // 1, 2, q and ? are digits or noise inside the prompt, not shell keys.
    rig.press('1');
    rig.press('2');
    assert!(rig.key(KeyCode::Char('q')));
    assert!(rig.draw().contains("go to tick: 12_"));
    rig.key(KeyCode::Backspace);
    rig.key(KeyCode::Enter);
    assert_eq!(rig.cx.t, 1);

    rig.press('g');
    for _ in 0..40 {
        rig.press('9');
    }
    rig.key(KeyCode::Enter);
    assert_eq!(rig.cx.t, session.ticks());

    rig.press('g');
    rig.press('7');
    rig.key(KeyCode::Esc);
    assert_eq!(rig.cx.t, session.ticks());
    assert!(rig.mode.prompt.is_none());

    rig.press('g');
    rig.key(KeyCode::Enter);
    assert_eq!(rig.cx.t, session.ticks());
    assert!(rig.draw().contains("type a tick number"));

    // Without a prompt the shell's keys are not ours.
    assert!(!rig.key(KeyCode::Char('q')));
    assert!(!rig.key(KeyCode::Tab));
    assert!(!rig.key(KeyCode::Esc));
    assert!(!rig.key(KeyCode::Char('1')));
    assert!(!rig.key(KeyCode::Char('?')));
}

#[test]
fn the_translation_browser_lists_every_translation_and_their_passes() {
    for name in PROGRAMS {
        let session = session(name);
        let mut rig = Rig::new(&session, 160, 48);
        // Cursor in user code before any translation: the first one is shown.
        rig.press('T');
        assert_eq!(rig.mode.screen, Screen::Browser);
        let text = rig.draw();
        for expected in ["translations", "1 decoded", "2 rephrased", "3 virtualized", "4 layout", "T0"] {
            assert!(text.contains(expected), "{name} lacks {expected}:\n{text}");
        }
        assert_eq!(rig.mode.browser.selected(), 0);

        for index in 0..session.translations().len() {
            assert_eq!(rig.mode.browser.selected(), index);
            for _ in 0..30 {
                rig.key(KeyCode::PageDown);
                rig.draw();
            }
            for _ in 0..30 {
                rig.key(KeyCode::PageUp);
            }
            rig.press(']');
        }
        // `]` stays on the last one.
        assert_eq!(rig.mode.browser.selected(), session.translations().len() - 1);
        rig.press('[');
        rig.draw();

        // Enter goes to the tick of the request and closes the browser.
        let selected = rig.mode.browser.selected();
        rig.key(KeyCode::Enter);
        assert_eq!(rig.cx.t, session.translations()[selected].t);
        assert_eq!(rig.mode.screen, Screen::Code);
    }
}

#[test]
fn the_browser_opens_on_the_translation_of_the_fragment_at_the_cursor() {
    let session = session("session_call_loop");
    assert!(session.translations().len() >= 2, "the call loop translates the loop and the callee");
    let step = session
        .steps()
        .filter(|step| matches!(step.at, StepAt::Fragment { .. }))
        .last()
        .unwrap();
    let StepAt::Fragment { fragment, .. } = step.at else {
        unreachable!()
    };
    let expected = session.translation_of(fragment).unwrap();
    let mut rig = Rig::new(&session, 160, 48);
    rig.cx.set_t(step.tick - 1);
    rig.press('T');
    assert_eq!(rig.mode.browser.selected(), expected);
    let text = rig.draw();
    assert!(text.contains(&format!("T{expected} ")), "{text}");
    rig.press('T');
    assert_eq!(rig.mode.screen, Screen::Code);
}

#[test]
fn the_divergence_view_shows_both_worlds_when_they_disagree() {
    let session = diverged("session_call_loop");
    let mut rig = Rig::new(&session, 160, 48);
    rig.press('d');
    assert_eq!(rig.cx.t, session.ticks());
    rig.press('v');
    let text = rig.draw();
    for expected in ["DIVERGED at syscall #5", "differing registers (1)", "x20", "reference | kjit", "! x20"] {
        assert!(text.contains(expected), "lacks {expected}:\n{text}");
    }
    for _ in 0..50 {
        rig.press('j');
        rig.draw();
    }
    rig.key(KeyCode::PageUp);
    rig.draw();
    rig.press('v');
    assert_eq!(rig.mode.screen, Screen::Code);
    // The code pane works at the divergence too.
    rig.draw();
}

#[test]
fn the_divergence_view_of_a_clean_run_says_there_is_none() {
    let session = session("session_call_loop");
    let mut rig = Rig::new(&session, 160, 48);
    rig.press('v');
    let text = rig.draw();
    assert!(text.contains("no divergence"), "{text}");
    assert!(text.contains("agreed at all 301 syscalls"), "{text}");
}

#[test]
fn the_events_pane_marks_the_cursor() {
    let session = session("session_call_loop");
    let mut rig = Rig::new(&session, 160, 48);
    // A tick with events: the run's first Syscall.
    let syscall = session.syscalls()[0].t;
    rig.cx.set_t(syscall);
    assert!(rig.draw().contains("syscall #1"));
    // A tick with none: the cursor rule.
    let quiet = (1..session.ticks())
        .find(|&t| session.events_between(t, t + 1).is_empty())
        .expect("most ticks have no event");
    rig.cx.set_t(quiet);
    assert!(rig.draw().contains(&format!("---- t = {quiet} ----")));
}
