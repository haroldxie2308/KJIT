//! Observe mode: system-level, what the JIT is doing over time. A seam: this is the
//! placeholder the mode replaces.

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::layout::Rect;
use ratatui::widgets::Paragraph;
use ratatui::Frame;

use super::{Cx, Mode};
use crate::session::Session;

pub struct ObserveMode;

impl ObserveMode {
    /// `_session` is there for a mode that indexes the session once, up front.
    pub fn new(_session: &Session) -> Self {
        Self
    }
}

impl Mode for ObserveMode {
    fn name(&self) -> &'static str {
        "observe"
    }

    fn keys(&self) -> &[(&str, &str)] {
        &[("Left / Right", "step t by -1 / +1")]
    }

    fn on_key(&mut self, key: KeyEvent, cx: &mut Cx) -> bool {
        match key.code {
            KeyCode::Left => cx.set_t(cx.t.saturating_sub(1)),
            KeyCode::Right => cx.set_t(cx.t.saturating_add(1)),
            _ => return false,
        }
        true
    }

    fn draw(&mut self, frame: &mut Frame, area: Rect, cx: &Cx) {
        frame.render_widget(Paragraph::new(format!("observe mode, t = {}", cx.t)), area);
    }
}
