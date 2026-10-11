use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::backend::TestBackend;
use ratatui::Terminal;

use super::Shell;
use crate::session::tests::session;

fn press(shell: &mut Shell<'_>, code: KeyCode) {
    shell.on_key(KeyEvent::new(code, KeyModifiers::NONE));
}

pub(super) fn screen(terminal: &Terminal<TestBackend>) -> String {
    let buffer = terminal.backend().buffer();
    let width = buffer.area.width as usize;
    buffer
        .content
        .chunks(width)
        .map(|row| row.iter().map(|cell| cell.symbol()).collect::<String>())
        .collect::<Vec<_>>()
        .join("\n")
}

fn draw(shell: &mut Shell<'_>, terminal: &mut Terminal<TestBackend>) -> String {
    terminal.draw(|frame| shell.draw(frame)).unwrap();
    screen(terminal)
}

/// Both modes draw on a `TestBackend`, `Tab` and the digits switch between them, and
/// the shared cursor `t` is the same on both sides of a switch.
#[test]
fn modes_draw_and_the_cursor_survives_a_switch() {
    let session = session("session_call_loop");
    let mut shell = Shell::new(&session, "session_call_loop");
    let mut terminal = Terminal::new(TestBackend::new(100, 30)).unwrap();

    let screen = draw(&mut shell, &mut terminal);
    assert!(screen.contains("debug mode, t = 0"), "{screen}");
    for field in ["session_call_loop", "exited", "ticks", "translations"] {
        assert!(screen.contains(field), "header lacks {field}:\n{screen}");
    }
    assert!(screen.contains(&session.ticks().to_string()));

    for _ in 0..5 {
        press(&mut shell, KeyCode::Right);
    }
    press(&mut shell, KeyCode::Left);
    assert_eq!(shell.t(), 4);

    press(&mut shell, KeyCode::Tab);
    assert_eq!(shell.active_name(), "observe");
    assert_eq!(shell.t(), 4);
    let screen = draw(&mut shell, &mut terminal);
    assert!(screen.contains("observe mode, t = 4"), "{screen}");

    press(&mut shell, KeyCode::Right);
    press(&mut shell, KeyCode::Char('1'));
    assert_eq!(shell.active_name(), "debug");
    let screen = draw(&mut shell, &mut terminal);
    assert!(screen.contains("debug mode, t = 5"), "{screen}");
    press(&mut shell, KeyCode::Char('2'));
    assert_eq!(shell.active_name(), "observe");
    assert_eq!(shell.t(), 5);

    // The help overlay lists the shell's keys and the active mode's.
    press(&mut shell, KeyCode::Char('?'));
    let screen = draw(&mut shell, &mut terminal);
    for text in ["next mode", "quit", "step t by"] {
        assert!(screen.contains(text), "help lacks {text}:\n{screen}");
    }
    press(&mut shell, KeyCode::Esc);
    assert!(!shell.help_open());
    assert!(!shell.should_quit());
    press(&mut shell, KeyCode::Char('q'));
    assert!(shell.should_quit());
}

#[test]
fn the_cursor_stays_inside_the_recording() {
    let session = session("session_svc_loop");
    let mut shell = Shell::new(&session, "x");
    press(&mut shell, KeyCode::Left);
    assert_eq!(shell.t(), 0);
    shell.set_t(u64::MAX);
    assert_eq!(shell.t(), session.ticks());
    press(&mut shell, KeyCode::Right);
    assert_eq!(shell.t(), session.ticks());
}
