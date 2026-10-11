//! The TUI shell (docs/pipeline.md, "TUI: debug and observe modes"): terminal setup
//! and restore, header, mode tabs, help overlay, key routing and the one shared cursor
//! `Cx::t`. It only reads a recorded `Session`. The modes (`debug`, `observe`) draw
//! into the area the shell gives them.

use std::io;

use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::{Backend, CrosstermBackend};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Tabs};
use ratatui::{Frame, Terminal};

use crate::session::{Outcome, Session};

pub mod debug;
pub mod observe;

/// What a mode sees: the recorded session and the shared cursor.
///
/// `t` is a tick count, the same clock as `Session::state_at(t)`: `t == 0` is before
/// the first step (the initial state) and `t == n` is just after tick `n`, the step
/// that `Session::step(n)` returns (`step` is 1-based). So the step that took the
/// session to `t` is `step(t)`, and there is none at `t == 0`; the step that executes
/// next is `step(t + 1)`, and there is none at `t == ticks`.
pub struct Cx<'a> {
    pub session: &'a Session,
    /// Owned by the shell; change it with `set_t` so it stays in `0..=ticks`.
    pub t: u64,
}

impl<'a> Cx<'a> {
    pub fn new(session: &'a Session) -> Self {
        Self { session, t: 0 }
    }

    /// Moves the cursor to `t`, clamped to `0..=session.ticks()`.
    pub fn set_t(&mut self, t: u64) {
        self.t = t.min(self.session.ticks());
    }
}

/// One view of the session.
pub trait Mode {
    fn name(&self) -> &'static str;
    /// The keys the mode handles, as (key, what it does), for the help overlay.
    fn keys(&self) -> &[(&str, &str)];
    /// Handles a key; returns whether it used it. The shell sees the keys a mode did
    /// not use.
    fn on_key(&mut self, key: KeyEvent, cx: &mut Cx) -> bool;
    fn draw(&mut self, frame: &mut Frame, area: Rect, cx: &Cx);
    /// Called on the active mode every `TICK` while no key arrives (playback).
    fn tick(&mut self, _cx: &mut Cx) {}
}

/// The shell's clock: how often the active mode's `tick` runs.
pub const TICK: std::time::Duration = std::time::Duration::from_millis(50);

/// The keys the shell itself handles, after the active mode declined them.
const SHELL_KEYS: [(&str, &str); 5] = [
    ("Tab", "next mode"),
    ("1 / 2", "debug / observe"),
    ("?", "this help"),
    ("Esc", "close help"),
    ("q", "quit"),
];

pub struct Shell<'a> {
    cx: Cx<'a>,
    label: String,
    modes: Vec<Box<dyn Mode + 'a>>,
    active: usize,
    help: bool,
    quit: bool,
}

impl<'a> Shell<'a> {
    /// A shell over `session` with the debug and observe modes. `label` names the
    /// program in the header.
    pub fn new(session: &'a Session, label: impl Into<String>) -> Self {
        let modes: Vec<Box<dyn Mode + 'a>> = vec![
            Box::new(debug::DebugMode::new(session)),
            Box::new(observe::ObserveMode::new(session)),
        ];
        Self::with_modes(session, label, modes)
    }

    pub fn with_modes(
        session: &'a Session,
        label: impl Into<String>,
        modes: Vec<Box<dyn Mode + 'a>>,
    ) -> Self {
        assert!(!modes.is_empty(), "a shell needs at least one mode");
        Self {
            cx: Cx::new(session),
            label: label.into(),
            modes,
            active: 0,
            help: false,
            quit: false,
        }
    }

    pub fn t(&self) -> u64 {
        self.cx.t
    }

    pub fn set_t(&mut self, t: u64) {
        self.cx.set_t(t);
    }

    /// Index of the active mode.
    pub fn active(&self) -> usize {
        self.active
    }

    pub fn active_name(&self) -> &'static str {
        self.modes[self.active].name()
    }

    pub fn help_open(&self) -> bool {
        self.help
    }

    pub fn should_quit(&self) -> bool {
        self.quit
    }

    /// One `TICK` with no key: the active mode's `tick`.
    pub fn tick(&mut self) {
        self.modes[self.active].tick(&mut self.cx);
    }

    /// Routes one key: the help overlay first, then the active mode, then the shell.
    pub fn on_key(&mut self, key: KeyEvent) {
        if self.help {
            match key.code {
                KeyCode::Char('?') | KeyCode::Esc => self.help = false,
                KeyCode::Char('q') => self.quit = true,
                _ => {}
            }
            return;
        }
        if self.modes[self.active].on_key(key, &mut self.cx) {
            return;
        }
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            self.quit = true;
            return;
        }
        match key.code {
            KeyCode::Char('q') => self.quit = true,
            KeyCode::Char('?') => self.help = true,
            KeyCode::Tab => self.active = (self.active + 1) % self.modes.len(),
            KeyCode::Char(digit @ '1'..='9') => {
                let index = digit as usize - '1' as usize;
                if index < self.modes.len() {
                    self.active = index;
                }
            }
            _ => {}
        }
    }

    pub fn draw(&mut self, frame: &mut Frame) {
        let [header, tabs, body, footer] = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),
                Constraint::Length(1),
                Constraint::Min(1),
                Constraint::Length(1),
            ])
            .areas(frame.size());

        frame.render_widget(
            Paragraph::new(header_line(&self.label, self.cx.session, self.cx.t))
                .block(Block::default().borders(Borders::ALL).title(" kjit ")),
            header,
        );
        let titles = self
            .modes
            .iter()
            .enumerate()
            .map(|(index, mode)| format!("{} {}", index + 1, mode.name()))
            .collect::<Vec<_>>();
        frame.render_widget(
            Tabs::new(titles)
                .select(self.active)
                .highlight_style(
                    Style::default()
                        .fg(Color::Black)
                        .bg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                )
                .divider(" "),
            tabs,
        );
        self.modes[self.active].draw(frame, body, &self.cx);
        frame.render_widget(
            Paragraph::new("Tab/1/2 mode   ? help   q quit")
                .style(Style::default().fg(Color::DarkGray)),
            footer,
        );
        if self.help {
            self.draw_help(frame);
        }
    }

    fn draw_help(&self, frame: &mut Frame) {
        let mode = &self.modes[self.active];
        let mut lines = vec![Line::styled(
            "shell",
            Style::default().add_modifier(Modifier::BOLD),
        )];
        lines.extend(SHELL_KEYS.iter().map(|(key, what)| key_line(key, what)));
        lines.push(Line::default());
        lines.push(Line::styled(
            mode.name(),
            Style::default().add_modifier(Modifier::BOLD),
        ));
        lines.extend(mode.keys().iter().map(|(key, what)| key_line(key, what)));

        let area = centered(frame.size(), 60, lines.len() as u16 + 2);
        frame.render_widget(Clear, area);
        frame.render_widget(
            Paragraph::new(lines).block(Block::default().borders(Borders::ALL).title(" help ")),
            area,
        );
    }
}

fn key_line(key: &str, what: &str) -> Line<'static> {
    Line::from(vec![
        Span::styled(
            format!("{key:<12}"),
            Style::default().fg(Color::Yellow),
        ),
        Span::raw(what.to_string()),
    ])
}

/// A `width` x `height` rectangle in the middle of `area` (or all of it if smaller).
fn centered(area: Rect, width: u16, height: u16) -> Rect {
    let width = width.min(area.width);
    let height = height.min(area.height);
    Rect {
        x: area.x + (area.width - width) / 2,
        y: area.y + (area.height - height) / 2,
        width,
        height,
    }
}

/// How the recording ended, in a few words.
pub fn outcome_summary(session: &Session) -> String {
    match session.outcome() {
        Outcome::Exited => "exited".to_string(),
        Outcome::Halted(halt) => format!("halted ({halt})"),
        Outcome::StepLimit => "step limit".to_string(),
        Outcome::Divergence(divergence) => match divergence.syscall {
            Some(k) => format!("DIVERGED at syscall {k}"),
            None => "DIVERGED at the end".to_string(),
        },
    }
}

fn header_line(label: &str, session: &Session, t: u64) -> Line<'static> {
    let key = |text: &str| Span::styled(text.to_string(), Style::default().fg(Color::DarkGray));
    Line::from(vec![
        key("fixture "),
        Span::raw(label.to_string()),
        key("  outcome "),
        Span::raw(outcome_summary(session)),
        key("  ticks "),
        Span::raw(session.ticks().to_string()),
        key("  translations "),
        Span::raw(session.translations().len().to_string()),
        key("  t "),
        Span::styled(t.to_string(), Style::default().add_modifier(Modifier::BOLD)),
    ])
}

/// Puts the terminal back: cooked mode, the main screen, the cursor.
fn restore_terminal() {
    // Best effort: this runs on the way out, possibly from a panic hook, where there
    // is nobody to report a failure to.
    let _ = disable_raw_mode();
    let _ = execute!(io::stdout(), LeaveAlternateScreen, crossterm::cursor::Show);
}

/// Restores the terminal when dropped, also while unwinding.
struct TerminalGuard;

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        restore_terminal();
    }
}

/// Runs the shell on the real terminal until `q`. The terminal is restored on return,
/// on an error and on a panic (the panic message is printed after the restore).
pub fn run(session: &Session, label: &str) -> io::Result<()> {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        restore_terminal();
        previous(info);
    }));

    enable_raw_mode()?;
    let _guard = TerminalGuard;
    execute!(io::stdout(), EnterAlternateScreen)?;
    let mut terminal = Terminal::new(CrosstermBackend::new(io::stdout()))?;
    event_loop(&mut terminal, Shell::new(session, label))
}

fn event_loop<B: Backend>(terminal: &mut Terminal<B>, mut shell: Shell<'_>) -> io::Result<()> {
    while !shell.should_quit() {
        terminal.draw(|frame| shell.draw(frame))?;
        if !event::poll(TICK)? {
            shell.tick();
            continue;
        }
        if let Event::Key(key) = event::read()? {
            if key.kind == KeyEventKind::Press {
                shell.on_key(key);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
