//! Debug mode: instruction-level, where the program is at `t` and why
//! (docs/pipeline.md, "TUI: debug and observe modes").
//!
//! The panes: the code at `t` (the translated words around the offset when in a
//! fragment, the original text in user code), the lineage of the selected word, the
//! registers and the stores of the last tick, and the events near `t`. A translation
//! browser and a divergence view replace them on request. All of it is read from the
//! `Session`; the mode only indexes it (event ticks per class, ticks per original pc)
//! and caches what it derives per `t`.

mod browser;
mod code;
mod divergence;
mod events;
mod fmt;
mod index;
mod lineage;
mod regs;

#[cfg(test)]
mod tests;

use std::collections::BTreeSet;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;

use self::browser::Browser;
use self::code::{place_text, CodeView, Ctx};
use self::fmt::{bold, dim};
use self::index::{EventClass, Index};
use super::{Cx, Mode};
use crate::model::MachineState;
use crate::session::{Session, StepAt};

/// The values `s` cycles the step size N through.
const STRIDES: [u64; 3] = [10, 100, 1000];
/// Lines a page key scrolls in the sub-views.
const PAGE: isize = 10;

const KEYS: [(&str, &str); 16] = [
    ("h / l", "step t by -1 / +1 (also Left / Right)"),
    ("H L PgUp/Dn", "step t by -N / +N"),
    ("s", "cycle N: 10, 100, 1000"),
    ("Home End", "first / last tick"),
    ("g", "go to tick (digits, Enter; Esc cancels)"),
    ("c C", "event kind: next / previous"),
    ("n N", "next / previous event of the kind"),
    ("j k", "select the word below / above (also Down / Up)"),
    ("b B", "toggle breakpoint at the selected pc / clear all"),
    ("r R", "continue forward / backward to a breakpoint"),
    ("d", "jump to the divergence"),
    ("T", "translation browser on / off"),
    ("v", "divergence view on / off"),
    ("[ ]", "browser: previous / next translation"),
    ("Enter", "browser: go to the tick of its request"),
    ("j k PgUp/Dn", "browser, divergence: scroll"),
];

/// The step the cursor sits between: the one that took the session to `t` and the
/// one that executes next.
#[derive(Clone, Copy, Debug)]
struct Place {
    at: StepAt,
    word: u32,
}

#[derive(Clone, Copy, Debug)]
struct Cursor {
    t: u64,
    last: Option<Place>,
    next: Option<Place>,
}

impl Cursor {
    fn of(session: &Session, t: u64) -> Self {
        let place = |tick: u64| {
            session.step(tick).map(|step| Place {
                at: step.at,
                word: step.word,
            })
        };
        Self {
            t,
            last: place(t),
            next: place(t + 1),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Screen {
    Code,
    Browser,
    Divergence,
}

pub struct DebugMode {
    index: Index,
    cursor: Cursor,
    code: Option<CodeView>,
    /// The selected row of the code pane; `None` follows the cursor. Reset whenever `t`
    /// changes.
    sel: Option<usize>,
    screen: Screen,
    kind: EventClass,
    stride: usize,
    breakpoints: BTreeSet<u64>,
    /// The `g` prompt's digits while it is open.
    prompt: Option<String>,
    message: Option<String>,
    browser: Browser,
    scroll: usize,
    /// The machine state after tick `.0`, replayed once per `t`.
    state: Option<(u64, MachineState)>,
}

impl DebugMode {
    pub fn new(session: &Session) -> Self {
        let cursor = Cursor::of(session, 0);
        Self {
            index: Index::new(session),
            code: CodeView::of(session, &cursor),
            cursor,
            sel: None,
            screen: Screen::Code,
            kind: EventClass::Syscall,
            stride: 0,
            breakpoints: BTreeSet::new(),
            prompt: None,
            message: None,
            browser: Browser::new(),
            scroll: 0,
            state: None,
        }
    }

    fn step_size(&self) -> u64 {
        STRIDES[self.stride]
    }

    /// Brings the cursor caches to `t`; the selection follows the cursor again.
    fn sync(&mut self, session: &Session, t: u64) {
        if self.cursor.t != t {
            self.cursor = Cursor::of(session, t);
            self.code = CodeView::of(session, &self.cursor);
            self.sel = None;
        }
    }

    /// The original pc of the selected word.
    fn selected_pc(&self, session: &Session) -> Option<u64> {
        let view = self.code.as_ref()?;
        view.ori_pc(session, view.selected(self.sel))
    }

    fn jump(&mut self, cx: &mut Cx, target: Option<u64>, nothing: &str) {
        match target {
            Some(t) => cx.set_t(t),
            None => self.message = Some(nothing.to_string()),
        }
    }

    fn step_by(&self, cx: &mut Cx, forward: bool, amount: u64) {
        cx.set_t(if forward {
            cx.t.saturating_add(amount)
        } else {
            cx.t.saturating_sub(amount)
        });
    }

    fn move_selection(&mut self, down: bool) {
        let Some(view) = self.code.as_ref() else {
            return;
        };
        let current = view.selected(self.sel);
        let next = if down {
            (current + 1).min(view.len - 1)
        } else {
            current.saturating_sub(1)
        };
        self.sel = Some(next);
    }

    fn toggle_breakpoint(&mut self, session: &Session) {
        let Some(pc) = self.selected_pc(session) else {
            self.message = Some("the selected word has no original pc".to_string());
            return;
        };
        if self.breakpoints.remove(&pc) {
            self.message = Some(format!("breakpoint at {pc:#x} cleared"));
        } else {
            self.breakpoints.insert(pc);
            self.message = Some(if self.index.is_reached(pc) {
                format!("breakpoint at {pc:#x} set")
            } else {
                format!("breakpoint at {pc:#x} set (the session never reaches it)")
            });
        }
    }

    fn continue_to_breakpoint(&mut self, cx: &mut Cx, forward: bool) {
        if self.breakpoints.is_empty() {
            self.message = Some("no breakpoints (b sets one at the selected pc)".to_string());
            return;
        }
        let pcs = self.breakpoints.iter().copied();
        let target = if forward {
            self.index.next_reached(pcs, cx.t)
        } else {
            self.index.prev_reached(pcs, cx.t)
        };
        self.jump(
            cx,
            target,
            if forward {
                "no later breakpoint hit"
            } else {
                "no earlier breakpoint hit"
            },
        );
    }

    fn open_browser(&mut self, cx: &Cx) {
        let translations = cx.session.translations();
        let focus = match self.code.map(|view| view.ctx) {
            Some(Ctx::Fragment { translation, .. }) => translation,
            // In user code: the latest translation requested so far. Before any ran,
            // the first one is the one to look at.
            _ => translations
                .iter()
                .rposition(|record| record.t <= cx.t)
                .unwrap_or(0),
        };
        self.browser.select(cx.session, focus);
        self.screen = Screen::Browser;
    }

    fn toggle_screen(&mut self, cx: &Cx, screen: Screen) {
        if self.screen == screen {
            self.screen = Screen::Code;
            return;
        }
        self.scroll = 0;
        if screen == Screen::Browser {
            self.open_browser(cx);
        } else {
            self.screen = screen;
        }
    }

    fn scroll_view(&mut self, cx: &Cx, delta: isize) {
        match self.screen {
            Screen::Browser => self.browser.scroll_by(cx.session, delta),
            Screen::Divergence => {
                let rows = divergence::row_count(cx.session, cx.t);
                self.scroll = self
                    .scroll
                    .saturating_add_signed(delta)
                    .min(rows.saturating_sub(1));
            }
            Screen::Code => {}
        }
    }

    fn prompt_key(&mut self, key: KeyEvent, cx: &mut Cx) {
        let digits = self
            .prompt
            .as_mut()
            .expect("the prompt is open while it takes keys");
        match key.code {
            KeyCode::Char(digit) if digit.is_ascii_digit() => digits.push(digit),
            KeyCode::Backspace => {
                digits.pop();
            }
            KeyCode::Esc => self.prompt = None,
            KeyCode::Enter => {
                let parsed = digits.parse::<u64>();
                self.prompt = None;
                match parsed {
                    Ok(tick) => cx.set_t(tick),
                    // Past u64: the nearest tick is the last one, as for any tick
                    // beyond the recording (`set_t` clamps).
                    Err(err) if *err.kind() == std::num::IntErrorKind::PosOverflow => {
                        cx.set_t(u64::MAX)
                    }
                    Err(_) => self.message = Some("go to: type a tick number".to_string()),
                }
            }
            // The prompt owns the keyboard until Enter or Esc, so a stray `1`, `2`
            // or `q` does not switch mode or quit.
            _ => {}
        }
    }

    fn handle_key(&mut self, key: KeyEvent, cx: &mut Cx) -> bool {
        // Ctrl-C and friends are the shell's.
        if key.modifiers.contains(KeyModifiers::CONTROL) {
            return false;
        }
        if self.prompt.is_some() {
            self.prompt_key(key, cx);
            return true;
        }
        self.message = None;

        let in_subview = self.screen != Screen::Code;
        match key.code {
            KeyCode::Left | KeyCode::Char('h') => self.step_by(cx, false, 1),
            KeyCode::Right | KeyCode::Char('l') => self.step_by(cx, true, 1),
            KeyCode::Char('H') => self.step_by(cx, false, self.step_size()),
            KeyCode::Char('L') => self.step_by(cx, true, self.step_size()),
            KeyCode::PageUp if in_subview => self.scroll_view(cx, -PAGE),
            KeyCode::PageDown if in_subview => self.scroll_view(cx, PAGE),
            KeyCode::PageUp => self.step_by(cx, false, self.step_size()),
            KeyCode::PageDown => self.step_by(cx, true, self.step_size()),
            KeyCode::Char('s') => self.stride = (self.stride + 1) % STRIDES.len(),
            KeyCode::Home => cx.set_t(0),
            KeyCode::End => cx.set_t(cx.session.ticks()),
            KeyCode::Char('g') => self.prompt = Some(String::new()),
            KeyCode::Char('c') => self.kind = self.kind.cycled(true),
            KeyCode::Char('C') => self.kind = self.kind.cycled(false),
            KeyCode::Char('n') => {
                let target = self.index.next_event(self.kind, cx.t);
                self.jump(cx, target, &format!("no later {} event", self.kind.label()));
            }
            KeyCode::Char('N') => {
                let target = self.index.prev_event(self.kind, cx.t);
                self.jump(cx, target, &format!("no earlier {} event", self.kind.label()));
            }
            KeyCode::Down | KeyCode::Char('j') => match self.screen {
                Screen::Code => self.move_selection(true),
                Screen::Browser | Screen::Divergence => self.scroll_view(cx, 1),
            },
            KeyCode::Up | KeyCode::Char('k') => match self.screen {
                Screen::Code => self.move_selection(false),
                Screen::Browser | Screen::Divergence => self.scroll_view(cx, -1),
            },
            KeyCode::Char('b') if self.screen == Screen::Code => {
                self.toggle_breakpoint(cx.session)
            }
            KeyCode::Char('B') => {
                self.breakpoints.clear();
                self.message = Some("breakpoints cleared".to_string());
            }
            KeyCode::Char('r') => self.continue_to_breakpoint(cx, true),
            KeyCode::Char('R') => self.continue_to_breakpoint(cx, false),
            KeyCode::Char('d') => {
                let target = divergence::divergence_of(cx.session).map(|d| d.t);
                self.jump(cx, target, "the session has no divergence");
            }
            KeyCode::Char('T') => self.toggle_screen(cx, Screen::Browser),
            KeyCode::Char('v') => self.toggle_screen(cx, Screen::Divergence),
            KeyCode::Char('[') if self.screen == Screen::Browser => {
                self.browser.step(cx.session, false)
            }
            KeyCode::Char(']') if self.screen == Screen::Browser => {
                self.browser.step(cx.session, true)
            }
            KeyCode::Enter if self.screen == Screen::Browser => {
                let record = &cx.session.translations()[self.browser.selected()];
                cx.set_t(record.t);
                self.screen = Screen::Code;
            }
            _ => return false,
        }
        true
    }


    fn status_line(&self, cx: &Cx) -> Line<'static> {
        if let Some(digits) = &self.prompt {
            return Line::from(vec![
                Span::styled("go to tick: ", bold()),
                Span::raw(digits.clone()),
                Span::styled("_", Style::default().fg(Color::Yellow)),
                Span::styled("   Enter go, Esc cancel", dim()),
            ]);
        }
        let place = |p: Option<Place>| p.map_or("-".to_string(), |p| place_text(p.at));
        let mut spans = vec![
            Span::styled(format!("debug mode, t = {}", cx.t), bold()),
            Span::styled(format!("/{}", cx.session.ticks()), dim()),
            Span::styled(
                format!(
                    "  next {}  last {}  kind {}  N {}  bp {}",
                    place(self.cursor.next),
                    place(self.cursor.last),
                    self.kind.label(),
                    self.step_size(),
                    self.breakpoints.len()
                ),
                dim(),
            ),
        ];
        if let Some(message) = &self.message {
            spans.push(Span::styled(
                format!("  | {message}"),
                Style::default().fg(Color::Yellow),
            ));
        }
        Line::from(spans)
    }

    fn draw_code_screen(&mut self, frame: &mut Frame, area: Rect, cx: &Cx) {
        let session = cx.session;
        let [left, right] = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
            .areas(area);
        let [code_area, lineage_area] = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(6), Constraint::Length(14)])
            .areas(left);
        let [regs_area, mem_area, events_area] = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Percentage(55),
                Constraint::Length(5),
                Constraint::Min(4),
            ])
            .areas(right);

        code::draw(
            frame,
            code_area,
            session,
            self.code.as_ref(),
            self.sel,
            &self.breakpoints,
        );
        lineage::draw(
            frame,
            lineage_area,
            session,
            &self.cursor,
            self.code.as_ref(),
            self.sel,
        );

        if self.state.as_ref().map(|(t, _)| *t) != Some(cx.t) {
            let state = session
                .state_at(cx.t)
                .expect("the shell keeps t inside the recording");
            self.state = Some((cx.t, state));
        }
        let (_, state) = self.state.as_ref().expect("the state was just replayed");
        let last = session.step(cx.t);
        regs::draw_regs(frame, regs_area, cx.t, state, last.as_ref());
        regs::draw_mem(frame, mem_area, cx.t, last.as_ref());
        events::draw(frame, events_area, session, cx.t, self.kind);
    }
}

impl Mode for DebugMode {
    fn name(&self) -> &'static str {
        "debug"
    }

    fn keys(&self) -> &[(&str, &str)] {
        &KEYS
    }

    fn on_key(&mut self, key: KeyEvent, cx: &mut Cx) -> bool {
        self.sync(cx.session, cx.t);
        let used = self.handle_key(key, cx);
        // The key may have moved the cursor: the selection follows it from here.
        self.sync(cx.session, cx.t);
        used
    }

    fn draw(&mut self, frame: &mut Frame, area: Rect, cx: &Cx) {
        self.sync(cx.session, cx.t);
        let [main, status] = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(1), Constraint::Length(1)])
            .areas(area);
        match self.screen {
            Screen::Code => self.draw_code_screen(frame, main, cx),
            Screen::Browser => self.browser.draw(frame, main, cx.session),
            Screen::Divergence => {
                divergence::draw(frame, main, cx.session, cx.t, self.scroll)
            }
        }
        frame.render_widget(Paragraph::new(self.status_line(cx)), status);
    }
}
