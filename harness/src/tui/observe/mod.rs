//! Observe mode: system-level, what the JIT is doing over time (docs/pipeline.md,
//! "TUI: debug and observe modes"). A timeline over all ticks, the cache, the
//! transfer graph and the profiler at `t`, an event log following `t`, a summary up
//! to `t`, and playback. It reads the session and the shared cursor only; every figure
//! is a count over the events and steps, indexed once in `ObserveMode::new`.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::Frame;

use super::{Cx, Mode};
use crate::session::{CacheView, Session};
use index::{Accum, Filter, Index, Timeline};

mod index;
mod log;
mod panels;
#[cfg(test)]
mod tests;

/// Speeds are `1 << exp` ticks per `Mode::tick`, `exp` in `0..=MAX_SPEED_EXP`.
const MAX_SPEED_EXP: u32 = 12;
/// A "large" scrub is this fraction of the run: `ticks / LARGE_STEP_DIV`.
const LARGE_STEP_DIV: u64 = 100;

const KEYS: [(&str, &str); 8] = [
    ("Space", "play / pause (at the end: from the start)"),
    (
        "+ / -",
        "playback speed x2 / /2 (1x to 4096x ticks per 50 ms)",
    ),
    ("Left / Right", "scrub t by -1 / +1 tick"),
    (
        "Shift+Left/Right",
        "scrub by 1% of the run (also PgUp / PgDn)",
    ),
    ("Home / End", "jump to the start / the end"),
    ("n / p", "next / previous translation"),
    ("f", "cycle the event-log filter"),
    ("Up / Down", "scroll the event log back / forward"),
];

pub struct ObserveMode {
    index: Index,
    playing: bool,
    speed_exp: u32,
    filter: Filter,
    /// Event-log rows scrolled back from the newest event at `t`; reset when `t` moves.
    log_back: usize,
    /// The cache view for the cache event tick `.0`: valid for every `t` until the
    /// next cache event.
    cache: Option<(u64, CacheView)>,
    /// The accumulated state after `.0` events.
    accum: Option<(usize, Accum)>,
    timeline: Option<Timeline>,
}

impl ObserveMode {
    pub fn new(session: &Session) -> Self {
        Self {
            index: Index::new(session),
            playing: false,
            speed_exp: 0,
            filter: Filter::All,
            log_back: 0,
            cache: None,
            accum: None,
            timeline: None,
        }
    }

    fn speed(&self) -> u64 {
        1 << self.speed_exp
    }

    fn goto(&mut self, cx: &mut Cx, t: u64) {
        let before = cx.t;
        cx.set_t(t);
        if cx.t != before {
            self.log_back = 0;
        }
    }
}

impl Mode for ObserveMode {
    fn name(&self) -> &'static str {
        "observe"
    }

    fn keys(&self) -> &[(&str, &str)] {
        &KEYS
    }

    fn on_key(&mut self, key: KeyEvent, cx: &mut Cx) -> bool {
        if key.modifiers.contains(KeyModifiers::CONTROL) {
            return false;
        }
        let ticks = cx.session.ticks();
        let large = (ticks / LARGE_STEP_DIV).max(1);
        let shift = key.modifiers.contains(KeyModifiers::SHIFT);
        match key.code {
            KeyCode::Char(' ') => {
                if self.playing {
                    self.playing = false;
                } else {
                    if cx.t == ticks {
                        self.goto(cx, 0);
                    }
                    self.playing = true;
                }
            }
            KeyCode::Char('+' | '=') => self.speed_exp = (self.speed_exp + 1).min(MAX_SPEED_EXP),
            KeyCode::Char('-' | '_') => self.speed_exp = self.speed_exp.saturating_sub(1),
            KeyCode::Left => {
                let step = if shift { large } else { 1 };
                self.goto(cx, cx.t.saturating_sub(step));
            }
            KeyCode::Right => {
                let step = if shift { large } else { 1 };
                self.goto(cx, cx.t.saturating_add(step));
            }
            KeyCode::PageUp => self.goto(cx, cx.t.saturating_sub(large)),
            KeyCode::PageDown => self.goto(cx, cx.t.saturating_add(large)),
            KeyCode::Home => self.goto(cx, 0),
            KeyCode::End => self.goto(cx, ticks),
            KeyCode::Char('n') => {
                if let Some(t) = self.index.translations.next_after(cx.t) {
                    self.goto(cx, t);
                }
            }
            KeyCode::Char('p') => {
                if let Some(t) = self.index.translations.prev_before(cx.t) {
                    self.goto(cx, t);
                }
            }
            KeyCode::Char('f') => {
                self.filter = self.filter.next();
                self.log_back = 0;
            }
            KeyCode::Up => self.log_back = self.log_back.saturating_add(1),
            KeyCode::Down => self.log_back = self.log_back.saturating_sub(1),
            _ => return false,
        }
        true
    }

    fn tick(&mut self, cx: &mut Cx) {
        if !self.playing {
            return;
        }
        self.goto(cx, cx.t.saturating_add(self.speed()));
        if cx.t == cx.session.ticks() {
            self.playing = false;
        }
    }

    fn draw(&mut self, frame: &mut Frame, area: Rect, cx: &Cx) {
        let session = cx.session;
        let t = cx.t;
        let ticks = session.ticks();

        // Layout. Tall terminals get a bordered summary and the full timeline; short
        // ones the fragment share, the markers and the cursor only.
        let tall = area.height >= 34;
        let summary_height = if tall { 4 } else { 2 };
        let timeline_height = if tall { 8 } else { 4 };
        let [status, summary, timeline_area, rest] = Layout::vertical([
            Constraint::Length(1),
            Constraint::Length(summary_height),
            Constraint::Length(timeline_height),
            Constraint::Min(0),
        ])
        .areas(area);
        let log_height = (rest.height * 2 / 5).max(4).min(rest.height / 2);
        let [middle, log] =
            Layout::vertical([Constraint::Min(0), Constraint::Length(log_height)]).areas(rest);
        let [left, profiler] =
            Layout::horizontal([Constraint::Percentage(55), Constraint::Percentage(45)])
                .areas(middle);
        let [fragments, edges] =
            Layout::vertical([Constraint::Percentage(55), Constraint::Percentage(45)]).areas(left);

        // Memos: recomputed only when the cursor crossed what they depend on.
        let cache_key = self.index.cache_key(t);
        if self.cache.as_ref().map(|(key, _)| *key) != Some(cache_key) {
            let view = session
                .cache_at(cache_key)
                .expect("the cursor is clamped to the recording");
            self.cache = Some((cache_key, view));
        }
        let events_upto = index::events_upto(session, t);
        if self.accum.as_ref().map(|(n, _)| *n) != Some(events_upto) {
            self.accum = Some((events_upto, self.index.accum_after(session, events_upto)));
        }
        let columns = (timeline_area.width as usize)
            .saturating_sub(2)
            .saturating_sub(panels::GUTTER);
        if columns > 0 && self.timeline.as_ref().map(|timeline| timeline.width) != Some(columns) {
            self.timeline = Some(Timeline::build(&self.index, ticks, columns));
        }
        let (_, view) = self.cache.as_ref().expect("set above");
        let (_, accum) = self.accum.as_ref().expect("set above");

        panels::status(
            frame,
            status,
            &panels::Status {
                playing: self.playing,
                speed: self.speed(),
                t,
                ticks,
                filter: self.filter.label(),
            },
        );
        panels::summary(
            frame,
            summary,
            tall,
            panels::summary_lines(
                area.width,
                t,
                self.index.fragment_ticks(t),
                &self.index.counts(t),
            ),
        );
        if columns > 0 {
            let timeline_data = self.timeline.as_ref().expect("built above");
            panels::timeline(frame, timeline_area, timeline_data, t, !tall);
        }
        panels::fragments(frame, fragments, session, view);
        panels::edges(frame, edges, accum, view);
        panels::profiler(frame, profiler, session, accum);

        let rows = (log.height as usize).saturating_sub(2);
        let window = self
            .index
            .log_window(session, self.filter, t, self.log_back, rows);
        self.log_back = self.log_back.min(window.max_back);
        let lines = window
            .events
            .iter()
            .map(|event| log::event_line(session, event, t))
            .collect();
        panels::log(
            frame,
            log,
            format!(
                " events up to t  filter: {}{} ",
                self.filter.label(),
                if self.log_back > 0 {
                    format!("  (scrolled back {})", self.log_back)
                } else {
                    String::new()
                }
            ),
            lines,
        );
    }
}
