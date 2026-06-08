//! Backend-neutral explorer state, key handling, and text builders for the harness UI.

use std::path::PathBuf;

use crate::a64_pretty::pretty_runtime_exit;
use crate::active_step::{
    memory_comparison, register_comparison, ActiveStepEvent, ActiveStepHalt, ActiveStepOrigin,
    ActiveStepSession, ComparisonValue, MemoryComparisonRow, OriginalSideState, StateSnapshot,
    TranslatedSideState,
};
use crate::model::{Flags, MachineState};
use crate::shared::trans::rephrase::RephrasedInsnKind;
use crate::trace::{PipelineTrace, PcIndexEntry, TraceLayoutInsn};
use crate::CaseReport;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Selection {
    Pc(u64),
    Offset(usize),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Explore,
    ActiveStep,
}

impl Mode {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Explore => "explore",
            Self::ActiveStep => "active-step",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StepDetailMode {
    Compact,
    Registers,
    Memory,
}

impl StepDetailMode {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Compact => "compact",
            Self::Registers => "registers",
            Self::Memory => "memory",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FocusPanel {
    Cfg,
    Rephrase,
    Layout,
}

impl FocusPanel {
    pub const fn next(self) -> Self {
        match self {
            Self::Cfg => Self::Rephrase,
            Self::Rephrase => Self::Layout,
            Self::Layout => Self::Cfg,
        }
    }

    pub const fn prev(self) -> Self {
        match self {
            Self::Cfg => Self::Layout,
            Self::Rephrase => Self::Cfg,
            Self::Layout => Self::Rephrase,
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::Cfg => "Program",
            Self::Rephrase => "Translation",
            Self::Layout => "Result",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExplorerKey {
    Char(char),
    Esc,
    Enter,
    Backspace,
    Up,
    Down,
    Left,
    Right,
    PageUp,
    PageDown,
    Tab,
    BackTab,
    F1,
    Ignored,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Control {
    Continue,
    Quit,
}

#[derive(Clone, Debug)]
pub struct ExplorerLine {
    pub text: String,
}

impl From<String> for ExplorerLine {
    fn from(text: String) -> Self {
        Self { text }
    }
}

impl From<&str> for ExplorerLine {
    fn from(text: &str) -> Self {
        Self {
            text: text.to_string(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct PanelExport {
    pub title: String,
    pub lines: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct PipelineCheckPass {
    pub original_steps: usize,
    pub fragment_steps: usize,
    pub encoded_bytes: usize,
    pub halt: String,
}

impl PipelineCheckPass {
    pub fn from_report(report: &CaseReport) -> Self {
        Self {
            original_steps: report.original.steps,
            fragment_steps: report.fragment_steps,
            encoded_bytes: report.encoded_fragment.len(),
            halt: format!("{:?}", report.fragment_halt),
        }
    }
}

#[derive(Clone, Debug)]
pub enum PipelineCheck {
    NotRun,
    Passed(PipelineCheckPass),
    Failed { message: String },
}

impl PipelineCheck {
    pub fn from_report(report: &CaseReport) -> Self {
        Self::Passed(PipelineCheckPass::from_report(report))
    }

    pub fn metadata(&self) -> String {
        match self {
            Self::NotRun => "check=not-run".to_string(),
            Self::Passed(pass) => format!(
                "check=pass original_steps={} fragment_steps={} encoded_bytes={} halt={}",
                pass.original_steps, pass.fragment_steps, pass.encoded_bytes, pass.halt
            ),
            Self::Failed { message } => format!("check=fail {}", first_line(message)),
        }
    }

    pub fn initial_status(&self) -> String {
        match self {
            Self::Failed { message } => format!("pipeline check failed: {}", first_line(message)),
            _ => "s step mode | Tab focus | p/t/r jump panels | Up/Down move or scroll".to_string(),
        }
    }
}

pub struct ExplorerState<'a> {
    trace: &'a PipelineTrace,
    check: PipelineCheck,
    text_bytes: Vec<u8>,
    initial_state: MachineState,
    mode: Mode,
    selection: Selection,
    active_step: Option<ActiveStepSession>,
    step_detail: StepDetailMode,
    command: String,
    command_mode: bool,
    show_raw_only: bool,
    focus: FocusPanel,
    raw_scroll: u16,
    rephrase_scroll: u16,
    layout_scroll: u16,
    status: String,
}

impl<'a> ExplorerState<'a> {
    pub fn new(
        trace: &'a PipelineTrace,
        entry_pc: u64,
        check: PipelineCheck,
        text_bytes: Vec<u8>,
        initial_state: MachineState,
    ) -> Self {
        Self {
            trace,
            mode: Mode::Explore,
            selection: Selection::Pc(entry_pc),
            text_bytes,
            initial_state,
            active_step: None,
            step_detail: StepDetailMode::Compact,
            command: String::new(),
            command_mode: false,
            show_raw_only: false,
            focus: FocusPanel::Cfg,
            raw_scroll: 0,
            rephrase_scroll: 0,
            layout_scroll: 0,
            status: check.initial_status(),
            check,
        }
    }

    pub fn trace(&self) -> &PipelineTrace {
        self.trace
    }

    pub fn mode(&self) -> Mode {
        self.mode
    }

    pub fn selection(&self) -> Selection {
        self.selection
    }

    pub fn focus(&self) -> FocusPanel {
        self.focus
    }

    pub fn status(&self) -> &str {
        &self.status
    }

    pub fn check(&self) -> &PipelineCheck {
        &self.check
    }

    pub fn handle_key(&mut self, key: ExplorerKey) -> Control {
        if self.command_mode {
            return self.handle_command_key(key);
        }

        match key {
            ExplorerKey::Char('q') => Control::Quit,
            ExplorerKey::Esc if self.mode == Mode::ActiveStep => {
                self.leave_step_mode();
                Control::Continue
            }
            ExplorerKey::Char(':') => {
                self.command.clear();
                self.command_mode = true;
                self.status = "enter command".to_string();
                Control::Continue
            }
            ExplorerKey::Char('y') => {
                self.export_panel_text();
                Control::Continue
            }
            ExplorerKey::Char('s') => {
                self.toggle_mode();
                Control::Continue
            }
            ExplorerKey::Char(' ') if self.mode == Mode::ActiveStep => {
                self.step_group();
                Control::Continue
            }
            ExplorerKey::Char('j') if self.mode == Mode::ActiveStep => {
                self.step_translated();
                Control::Continue
            }
            ExplorerKey::Down if self.mode == Mode::ActiveStep => {
                self.active_step_down();
                Control::Continue
            }
            ExplorerKey::Char('r') if self.mode == Mode::ActiveStep => {
                self.toggle_step_detail(StepDetailMode::Registers);
                Control::Continue
            }
            ExplorerKey::Char('m') if self.mode == Mode::ActiveStep => {
                self.toggle_step_detail(StepDetailMode::Memory);
                Control::Continue
            }
            ExplorerKey::Char('c') if self.mode == Mode::ActiveStep => {
                self.step_detail = StepDetailMode::Compact;
                self.status = "comparison=compact".to_string();
                Control::Continue
            }
            ExplorerKey::Char('R') if self.mode == Mode::ActiveStep => {
                self.reset_step_mode();
                Control::Continue
            }
            ExplorerKey::Up if self.mode == Mode::ActiveStep => {
                self.active_step_up();
                Control::Continue
            }
            ExplorerKey::Tab => {
                self.focus = self.focus.next();
                self.status = format!("focused {}", self.focus.name());
                Control::Continue
            }
            ExplorerKey::BackTab => {
                self.focus = self.focus.prev();
                self.status = format!("focused {}", self.focus.name());
                Control::Continue
            }
            ExplorerKey::Char('p') => {
                self.set_focus(FocusPanel::Cfg);
                Control::Continue
            }
            ExplorerKey::Char('t') => {
                self.set_focus(FocusPanel::Rephrase);
                Control::Continue
            }
            ExplorerKey::Char('r') => {
                self.set_focus(FocusPanel::Layout);
                Control::Continue
            }
            ExplorerKey::Char('n') if self.mode == Mode::Explore => {
                self.select_next_pc(1);
                Control::Continue
            }
            ExplorerKey::Right if self.mode == Mode::Explore => {
                self.select_next_pc(1);
                Control::Continue
            }
            ExplorerKey::Left if self.mode == Mode::Explore => {
                self.select_next_pc(-1);
                Control::Continue
            }
            ExplorerKey::Down if self.mode == Mode::Explore => {
                if self.focus == FocusPanel::Cfg {
                    self.select_next_pc(1);
                } else {
                    self.scroll_focus(1);
                }
                Control::Continue
            }
            ExplorerKey::Up if self.mode == Mode::Explore => {
                if self.focus == FocusPanel::Cfg {
                    self.select_next_pc(-1);
                } else {
                    self.scroll_focus(-1);
                }
                Control::Continue
            }
            ExplorerKey::PageDown | ExplorerKey::Char('d') => {
                if self.mode == Mode::ActiveStep {
                    self.scroll_step_detail(5);
                } else {
                    self.scroll_focus(5);
                }
                Control::Continue
            }
            ExplorerKey::PageUp | ExplorerKey::Char('u') => {
                if self.mode == Mode::ActiveStep {
                    self.scroll_step_detail(-5);
                } else {
                    self.scroll_focus(-5);
                }
                Control::Continue
            }
            ExplorerKey::Char('a') => {
                self.show_raw_only = !self.show_raw_only;
                self.status = if self.show_raw_only {
                    "Program view=all".to_string()
                } else {
                    "Program view=cfg".to_string()
                };
                Control::Continue
            }
            ExplorerKey::Char('?') | ExplorerKey::F1 => {
                self.status = self.help_status();
                Control::Continue
            }
            ExplorerKey::Ignored
            | ExplorerKey::Esc
            | ExplorerKey::Enter
            | ExplorerKey::Backspace
            | ExplorerKey::Up
            | ExplorerKey::Down
            | ExplorerKey::Left
            | ExplorerKey::Right
            | ExplorerKey::Char(_) => Control::Continue,
        }
    }

    pub fn current_panel_export(&self) -> Result<PanelExport, String> {
        match self.mode {
            Mode::Explore => self.explore_panel_export(),
            Mode::ActiveStep => self.active_step_panel_export(),
        }
    }

    pub fn export_current_panel_text(&self) -> Result<String, String> {
        let export = self.current_panel_export()?;
        write_panel_export(export)
    }

    pub fn header_lines(&self) -> Vec<ExplorerLine> {
        let runtime = self
            .trace
            .run
            .as_ref()
            .map(|run| format!("runtime: steps={} halt={:?}", run.steps, run.halt))
            .unwrap_or_else(|| "runtime: not-run".to_string());
        vec![
            ExplorerLine::from(format!(
                "KJIT Explorer  mode={} entry={:#x} text_base={:#x} fragment_entry={:#x} view={}",
                self.mode.name(),
                self.trace.input.entry_pc,
                self.trace.input.text_base,
                self.trace.fragment.entry_offset,
                if self.show_raw_only { "all" } else { "cfg" },
            )),
            ExplorerLine::from(format!(
                "raw={} cfg_blocks={} translated={} fragment_insns={}",
                self.trace.raw.len(),
                self.trace.cfg.blocks.len(),
                self.trace.translated.len(),
                self.trace.fragment.insns.len(),
            )),
            ExplorerLine::from(runtime),
            ExplorerLine::from(format!("pipeline_check: {}", self.check.metadata())),
        ]
    }

    pub fn footer_lines(&self) -> Vec<ExplorerLine> {
        if self.command_mode {
            return vec![
                ExplorerLine::from(format!(":{}", self.command)),
                ExplorerLine::from("Enter submit | Esc cancel"),
            ];
        }

        vec![
            ExplorerLine::from(self.status.clone()),
            ExplorerLine::from(match self.mode {
                Mode::Explore => {
                    "Explore: s step | Tab focus | p/t/r panels | y export | a cfg/all | Up/Down move/scroll | q quit"
                }
                Mode::ActiveStep => match self.step_detail {
                    StepDetailMode::Compact => {
                        "Step: Esc/s explore | Space group | j insn | y export | r registers | m memory | R reset | q quit"
                    }
                    StepDetailMode::Registers | StepDetailMode::Memory => {
                        "Step: Up/Down scroll comparison | d/u page | y export | j insn | Space group | c compact | R reset | q quit"
                    }
                },
            }),
        ]
    }

    pub fn program_lines(&self) -> Vec<ExplorerLine> {
        let selected_pc = self.selected_pc();
        visible_pc_entries(self.trace, self.show_raw_only)
            .into_iter()
            .map(|entry| {
                let marker = if Some(entry.pc) == selected_pc {
                    ">"
                } else {
                    " "
                };
                ExplorerLine::from(format!(
                    "{marker} {:#010x} {:<8} {}",
                    entry.pc,
                    pc_stage_label(entry),
                    pc_brief(self.trace, entry.pc)
                ))
            })
            .collect()
    }

    pub fn detail_lines(&self) -> Vec<ExplorerLine> {
        match self.selection {
            Selection::Pc(pc) => self.translation_detail_lines(pc),
            Selection::Offset(offset) => self.layout_neighborhood_lines(offset),
        }
    }

    pub fn translation_detail_lines(&self, pc: u64) -> Vec<ExplorerLine> {
        let (rephrased, virtualized) = aligned_translation_lines(self.trace, pc);
        let mut lines = Vec::with_capacity(rephrased.len() + virtualized.len() + 3);
        lines.push(ExplorerLine::from("Rephrased"));
        lines.extend(rephrased);
        lines.push(ExplorerLine::from(""));
        lines.push(ExplorerLine::from("Virtualized"));
        lines.extend(virtualized);
        lines
    }

    pub fn layout_for_pc_lines(&self, pc: u64) -> Vec<ExplorerLine> {
        let lines = self
            .trace
            .fragment
            .insns
            .iter()
            .filter(|insn| insn.ori_pc == Some(pc))
            .map(layout_line)
            .collect::<Vec<_>>();
        if lines.is_empty() {
            vec![ExplorerLine::from(
                "no layout instruction with this original PC",
            )]
        } else {
            lines
        }
    }

    pub fn active_step_lines(&self) -> Vec<ExplorerLine> {
        let Some(session) = self.active_step.as_ref() else {
            return vec![ExplorerLine::from("active session is not initialized")];
        };

        let mut lines = Vec::new();
        if let Some(step) = session.current_original() {
            append_original_step_lines(&mut lines, self, step);
        } else if let Some(pc) = session.current_origin_pc() {
            lines.push(ExplorerLine::from(format!(
                "pinned ori_pc={pc:#x}; original not advanced by last key"
            )));
            append_raw_line(&mut lines, self, pc);
        } else {
            lines.push(ExplorerLine::from("original step: none"));
        }

        lines.push(ExplorerLine::from(""));

        let mut translated_lines = Vec::new();
        translated_lines.push(ExplorerLine::from(format!(
            "cursor pc={:#x} offset={} current_ori_pc={}",
            session.translated_pc(),
            opt_offset_label(session.translated_offset()),
            ori_pc_label(session.current_origin_pc())
        )));
        if let Some(offset) = session.translated_offset() {
            if let Some(insn) = layout_for_offset(self.trace, offset) {
                translated_lines.push(ExplorerLine::from(format!(
                    "next off={:#x} idx={} {:?} {}",
                    insn.offset, insn.index, insn.region, insn.pretty
                )));
            }
        }
        if let Some(step) = session.current_translated() {
            append_translated_step_lines(&mut translated_lines, self, step);
        } else {
            translated_lines.push(ExplorerLine::from("last translated step: none"));
        }
        translated_lines.push(ExplorerLine::from(format!(
            "translated_steps={} halt={}",
            session.translated_steps(),
            active_halt_label(&session.halt())
        )));

        lines.extend(translated_lines);
        lines
    }

    pub fn compact_comparison_lines(&self) -> Vec<ExplorerLine> {
        let Some(session) = self.active_step.as_ref() else {
            return vec![ExplorerLine::from("active session is not initialized")];
        };

        let original = &session.original_snapshot().current;
        let translated = &session.translated_snapshot().current;
        let mut lines = vec![
            ExplorerLine::from(format!(
                "state_equal={} halt={}",
                original == translated,
                active_halt_label(&session.halt())
            )),
            ExplorerLine::from(format!(
                "original_steps={} translated_steps={} translated_cursor_offset={} current_ori_pc={}",
                session.original_steps(),
                session.translated_steps(),
                opt_offset_label(session.translated_offset()),
                ori_pc_label(session.current_origin_pc())
            )),
        ];
        let diff_count = register_comparison(original, translated)
            .into_iter()
            .filter(|row| !row.equal)
            .count();
        let memory_count = memory_comparison(
            &session.original_snapshot().previous,
            original,
            translated,
            &session.runtime_owned_ranges(),
        )
        .len();
        lines.push(ExplorerLine::from(format!(
            "different_register_rows={} changed_memory_rows={}",
            diff_count, memory_count
        )));
        lines
    }

    pub fn register_comparison_lines(&self) -> Vec<ExplorerLine> {
        let Some(session) = self.active_step.as_ref() else {
            return vec![ExplorerLine::from("active session is not initialized")];
        };

        let mut lines = vec![ExplorerLine::from(
            "reg   original             translated           status",
        )];
        for row in register_comparison(
            &session.original_snapshot().current,
            &session.translated_snapshot().current,
        ) {
            lines.push(ExplorerLine::from(format!(
                "{:<5} {:<20} {:<20} {}",
                row.name,
                comparison_value_label(&row.original),
                comparison_value_label(&row.translated),
                if row.equal { "=" } else { "!" }
            )));
        }
        lines
    }

    pub fn memory_comparison_lines(&self) -> Vec<ExplorerLine> {
        let Some(session) = self.active_step.as_ref() else {
            return vec![ExplorerLine::from("active session is not initialized")];
        };

        let mut lines = vec![ExplorerLine::from(
            "addr               before original translated status",
        )];
        let rows = memory_comparison(
            &self.initial_state,
            &session.original_snapshot().current,
            &session.translated_snapshot().current,
            &session.runtime_owned_ranges(),
        );
        if rows.is_empty() {
            lines.push(ExplorerLine::from("no user-memory differences"));
            return lines;
        }
        for row in rows.iter().take(200) {
            lines.push(memory_row_line(row));
        }
        if rows.len() > 200 {
            lines.push(ExplorerLine::from(format!(
                "... +{} more rows",
                rows.len() - 200
            )));
        }
        lines
    }

    pub fn translation_export_lines(&self, pc: u64) -> Vec<ExplorerLine> {
        let (rephrased, virtualized) = aligned_translation_lines(self.trace, pc);
        let mut lines = Vec::with_capacity(rephrased.len() + virtualized.len() + 3);
        lines.push(ExplorerLine::from("Rephrased"));
        lines.extend(rephrased);
        lines.push(ExplorerLine::from(""));
        lines.push(ExplorerLine::from("Virtualized"));
        lines.extend(virtualized);
        lines
    }

    pub fn layout_neighborhood_lines(&self, offset: usize) -> Vec<ExplorerLine> {
        let center = offset / 4;
        let start = center.saturating_sub(8);
        let end = (center + 9).min(self.trace.fragment.insns.len());
        self.trace.fragment.insns[start..end]
            .iter()
            .map(layout_line)
            .collect()
    }

    pub fn selected_pc(&self) -> Option<u64> {
        selected_pc(self.trace, self.selection)
    }

    pub fn next_pc(&self, delta: isize) -> Option<u64> {
        next_pc(self.trace, self.selection, delta)
    }

    pub fn next_visible_pc(&self, delta: isize) -> Option<u64> {
        next_visible_pc(self.trace, self.selection, delta, self.show_raw_only)
    }

    pub fn visible_pc_entries(&self) -> Vec<&PcIndexEntry> {
        visible_pc_entries(self.trace, self.show_raw_only)
    }

    fn handle_command_key(&mut self, key: ExplorerKey) -> Control {
        match key {
            ExplorerKey::Esc => {
                self.command.clear();
                self.command_mode = false;
                self.status = "command cancelled".to_string();
                Control::Continue
            }
            ExplorerKey::Enter => {
                let command = self.command.clone();
                self.command.clear();
                self.command_mode = false;
                self.apply_command(&command)
            }
            ExplorerKey::Backspace => {
                self.command.pop();
                Control::Continue
            }
            ExplorerKey::Char(ch) => {
                self.command.push(ch);
                Control::Continue
            }
            _ => Control::Continue,
        }
    }

    fn apply_command(&mut self, line: &str) -> Control {
        match parse_command(line, self.trace, self.selection) {
            Command::Select(next) => {
                self.set_selection(next);
                self.status = if self.mode == Mode::ActiveStep {
                    "selection updated; active step session remains at its live cursor".to_string()
                } else {
                    format!("selected {next:?}")
                };
                Control::Continue
            }
            Command::Help => {
                self.status =
                    "commands: :pc <addr>, :off <offset>, :q; keys: Tab, p/t/r, Up/Down"
                        .to_string();
                Control::Continue
            }
            Command::Quit => Control::Quit,
            Command::Invalid(message) => {
                self.status = message;
                Control::Continue
            }
        }
    }

    fn set_selection(&mut self, selection: Selection) {
        self.selection = selection;
        self.raw_scroll = 0;
        self.rephrase_scroll = 0;
        self.layout_scroll = 0;
    }

    fn set_focus(&mut self, focus: FocusPanel) {
        self.focus = focus;
        self.status = format!("focused {}", self.focus.name());
    }

    fn select_next_pc(&mut self, delta: isize) {
        if let Some(pc) = next_visible_pc(self.trace, self.selection, delta, self.show_raw_only) {
            self.set_selection(Selection::Pc(pc));
            self.status = format!("selected pc {pc:#x}");
        } else {
            self.status = "no PC in that direction".to_string();
        }
    }

    fn scroll_focus(&mut self, delta: i16) {
        let panel = self.focus;
        let scroll = match panel {
            FocusPanel::Cfg => {
                if delta >= 0 {
                    self.select_next_pc(1);
                } else {
                    self.select_next_pc(-1);
                }
                return;
            }
            FocusPanel::Rephrase => &mut self.rephrase_scroll,
            FocusPanel::Layout => &mut self.layout_scroll,
        };

        if delta < 0 {
            *scroll = scroll.saturating_sub(delta.unsigned_abs());
        } else {
            *scroll = scroll.saturating_add(delta as u16);
        }
        self.status = format!("{} scroll={}", panel.name(), *scroll);
    }

    fn scroll_step_detail(&mut self, delta: i16) {
        if delta < 0 {
            self.layout_scroll = self.layout_scroll.saturating_sub(delta.unsigned_abs());
        } else {
            self.layout_scroll = self.layout_scroll.saturating_add(delta as u16);
        }
        self.status = format!("{} scroll={}", self.step_detail.name(), self.layout_scroll);
    }

    fn export_panel_text(&mut self) {
        match self.current_panel_export().and_then(write_panel_export) {
            Ok(status) => self.status = status,
            Err(message) => self.status = format!("export failed: {message}"),
        }
    }

    fn toggle_mode(&mut self) {
        match self.mode {
            Mode::Explore => self.enter_step_mode(),
            Mode::ActiveStep => self.leave_step_mode(),
        }
    }

    fn enter_step_mode(&mut self) {
        match ActiveStepSession::new(
            self.trace.input.text_base,
            self.text_bytes.clone(),
            self.trace.input.entry_pc,
            self.initial_state.clone(),
            &self.trace.execution_fragment,
            ActiveStepOrigin::from_trace_fragment(&self.trace.fragment),
        ) {
            Ok(session) => {
                self.active_step = Some(session);
                self.mode = Mode::ActiveStep;
                self.step_detail = StepDetailMode::Compact;
                self.raw_scroll = 0;
                self.rephrase_scroll = 0;
                self.layout_scroll = 0;
                self.status =
                    "mode=active-step start=entry; selected explore PC is not replayed yet"
                        .to_string();
            }
            Err(message) => {
                self.status = format!("step mode unavailable: {message}");
            }
        }
    }

    fn leave_step_mode(&mut self) {
        if let Some(session) = &self.active_step {
            self.selection = session
                .current_translated()
                .and_then(|step| step.ori_pc.map(Selection::Pc))
                .or_else(|| session.translated_offset().map(Selection::Offset))
                .unwrap_or(self.selection);
        }
        self.active_step = None;
        self.mode = Mode::Explore;
        self.raw_scroll = 0;
        self.rephrase_scroll = 0;
        self.layout_scroll = 0;
        self.status = "mode=explore".to_string();
    }

    fn step_translated(&mut self) {
        let Some(session) = self.active_step.as_mut() else {
            self.status = "step mode unavailable".to_string();
            return;
        };
        let event = session.step_translated();
        self.status = active_event_status(session, &event);
    }

    fn step_group(&mut self) {
        let Some(session) = self.active_step.as_mut() else {
            self.status = "step mode unavailable".to_string();
            return;
        };
        let event = session.step_group();
        self.status = active_event_status(session, &event);
    }

    fn reset_step_mode(&mut self) {
        let Some(session) = self.active_step.as_mut() else {
            self.status = "step mode unavailable".to_string();
            return;
        };
        match session.reset() {
            Ok(()) => {
                self.raw_scroll = 0;
                self.rephrase_scroll = 0;
                self.layout_scroll = 0;
                self.status = "active step reset to entry".to_string();
            }
            Err(message) => {
                self.status = format!("reset failed: {message}");
            }
        }
    }

    fn active_step_down(&mut self) {
        match self.step_detail {
            StepDetailMode::Compact => {
                self.status = "Down is disabled in compact mode; use j for one instruction"
                    .to_string();
            }
            StepDetailMode::Registers | StepDetailMode::Memory => self.scroll_step_detail(1),
        }
    }

    fn active_step_up(&mut self) {
        match self.step_detail {
            StepDetailMode::Compact => {
                self.status = "reverse execution is not supported; use R to reset".to_string();
            }
            StepDetailMode::Registers | StepDetailMode::Memory => self.scroll_step_detail(-1),
        }
    }

    fn toggle_step_detail(&mut self, detail: StepDetailMode) {
        self.step_detail = if self.step_detail == detail {
            StepDetailMode::Compact
        } else {
            detail
        };
        self.layout_scroll = 0;
        self.status = format!("comparison={}", self.step_detail.name());
    }

    fn help_status(&self) -> String {
        match self.mode {
            Mode::Explore => {
                "Explore: s step | p/t/r panels | y export panel | Up/Down move or scroll"
                    .to_string()
            }
            Mode::ActiveStep => {
                "Step: Esc/s explore | Space group | j insn | r/m/c panes | y export | R reset"
                    .to_string()
            }
        }
    }

    fn explore_panel_export(&self) -> Result<PanelExport, String> {
        let title = self.focus.name().to_string();
        let lines = match self.focus {
            FocusPanel::Cfg => self.program_lines(),
            FocusPanel::Rephrase => match self.selection {
                Selection::Pc(pc) => self.translation_export_lines(pc),
                Selection::Offset(_) => {
                    vec![ExplorerLine::from(
                        "select an original PC to inspect rephrase",
                    )]
                }
            },
            FocusPanel::Layout => match self.selection {
                Selection::Pc(pc) => self.layout_for_pc_lines(pc),
                Selection::Offset(offset) => self.layout_neighborhood_lines(offset),
            },
        };

        Ok(PanelExport {
            title,
            lines: plain_lines(lines),
        })
    }

    fn active_step_panel_export(&self) -> Result<PanelExport, String> {
        let Some(session) = self.active_step.as_ref() else {
            return Err("active session is not initialized".to_string());
        };
        let title = format!("Comparison {}", self.step_detail.name());
        let lines = match self.step_detail {
            StepDetailMode::Compact => self.compact_comparison_lines(),
            StepDetailMode::Registers => self.register_comparison_lines(),
            StepDetailMode::Memory => self.memory_comparison_lines(),
        };

        if session.halt() == ActiveStepHalt::Running && lines.is_empty() {
            return Err("comparison view is empty".to_string());
        }

        Ok(PanelExport {
            title,
            lines: plain_lines(lines),
        })
    }
}

fn first_line(message: &str) -> String {
    message
        .lines()
        .next()
        .unwrap_or("no detail")
        .trim()
        .to_string()
}

fn parse_u64(value: &str) -> Result<u64, String> {
    if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        u64::from_str_radix(hex, 16).map_err(|err| err.to_string())
    } else {
        value.parse::<u64>().map_err(|err| err.to_string())
    }
}

fn parse_usize(value: &str) -> Result<usize, String> {
    let parsed = parse_u64(value)?;
    usize::try_from(parsed).map_err(|err| err.to_string())
}

fn write_panel_export(export: PanelExport) -> Result<String, String> {
    let path = copy_export_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|err| err.to_string())?;
    }
    let mut text = export.lines.join("\n");
    text.push('\n');
    std::fs::write(&path, text).map_err(|err| err.to_string())?;
    Ok(format!(
        "exported {} panel to {}",
        export.title,
        path.display()
    ))
}

fn copy_export_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("harness crate has a parent repo directory")
        .join("tmp/trace-copy.txt")
}

fn plain_lines(lines: Vec<ExplorerLine>) -> Vec<String> {
    lines.into_iter().map(|line| line.text).collect()
}

fn parse_command(line: &str, trace: &PipelineTrace, current: Selection) -> Command {
    let mut parts = line.split_whitespace();
    let Some(command) = parts.next() else {
        return Command::Select(current);
    };

    match command {
        "q" | "quit" => Command::Quit,
        "h" | "help" | "?" => Command::Help,
        "pc" => match parts.next().map(parse_u64) {
            Some(Ok(pc)) => Command::Select(Selection::Pc(pc)),
            Some(Err(err)) => Command::Invalid(err),
            None => Command::Invalid("usage: pc <addr>".to_string()),
        },
        "off" | "offset" => match parts.next().map(parse_usize) {
            Some(Ok(offset)) => Command::Select(Selection::Offset(offset)),
            Some(Err(err)) => Command::Invalid(err),
            None => Command::Invalid("usage: off <fragment-offset>".to_string()),
        },
        "n" | "next" => next_pc(trace, current, 1)
            .map(Selection::Pc)
            .map(Command::Select)
            .unwrap_or_else(|| Command::Invalid("no next PC".to_string())),
        "p" | "prev" => next_pc(trace, current, -1)
            .map(Selection::Pc)
            .map(Command::Select)
            .unwrap_or_else(|| Command::Invalid("no previous PC".to_string())),
        _ => Command::Invalid(format!("unknown command `{command}`")),
    }
}

fn next_pc(trace: &PipelineTrace, current: Selection, delta: isize) -> Option<u64> {
    let current_pc = match current {
        Selection::Pc(pc) => pc,
        Selection::Offset(offset) => trace.selected_offset(offset)?.ori_pc?,
    };
    let index = trace
        .pc_index
        .iter()
        .position(|entry| entry.pc == current_pc)?;
    let next = index.checked_add_signed(delta)?;
    trace.pc_index.get(next).map(|entry| entry.pc)
}

fn next_visible_pc(
    trace: &PipelineTrace,
    current: Selection,
    delta: isize,
    show_raw_only: bool,
) -> Option<u64> {
    let current_pc = match current {
        Selection::Pc(pc) => pc,
        Selection::Offset(offset) => trace.selected_offset(offset)?.ori_pc?,
    };
    let visible = visible_pc_entries(trace, show_raw_only);
    let index = visible.iter().position(|entry| entry.pc == current_pc);
    let next = match index {
        Some(index) => index.checked_add_signed(delta)?,
        None if delta >= 0 => visible.iter().position(|entry| entry.pc > current_pc)?,
        None => visible.iter().rposition(|entry| entry.pc < current_pc)?,
    };
    visible.get(next).map(|entry| entry.pc)
}

fn selected_pc(trace: &PipelineTrace, selection: Selection) -> Option<u64> {
    match selection {
        Selection::Pc(pc) => Some(pc),
        Selection::Offset(offset) => trace.selected_offset(offset).and_then(|entry| entry.ori_pc),
    }
}

fn visible_pc_entries<'a>(
    trace: &'a PipelineTrace,
    show_raw_only: bool,
) -> Vec<&'a PcIndexEntry> {
    trace
        .pc_index
        .iter()
        .filter(|entry| show_raw_only || entry.cfg_block.is_some())
        .collect()
}

fn pc_stage_label(entry: &PcIndexEntry) -> String {
    match entry.cfg_block {
        Some(block) => format!("cfg:b{block}"),
        None => "raw-only".to_string(),
    }
}

fn pc_brief(trace: &PipelineTrace, pc: u64) -> String {
    trace
        .raw
        .iter()
        .find(|insn| insn.pc == pc)
        .map(|insn| insn.pretty.clone())
        .or_else(|| {
            trace
                .rephrased
                .iter()
                .flat_map(|block| block.insns.iter())
                .find(|insn| insn.ori_pc == pc)
                .map(|insn| insn.pretty.clone())
        })
        .unwrap_or_default()
}

fn aligned_translation_lines(
    trace: &PipelineTrace,
    pc: u64,
) -> (Vec<ExplorerLine>, Vec<ExplorerLine>) {
    let rephrased = translation_rows(&trace.rephrased, pc);
    let virtualized = translation_rows(&trace.virtualized, pc);
    if rephrased.is_empty() && virtualized.is_empty() {
        return (
            vec![ExplorerLine::from("none")],
            vec![ExplorerLine::from("none")],
        );
    }

    let mut keys = rephrased
        .iter()
        .map(|row| (row.block_index, row.index_in_block))
        .collect::<Vec<_>>();
    for row in &virtualized {
        let key = (row.block_index, row.index_in_block);
        if !keys.contains(&key) {
            keys.push(key);
        }
    }
    keys.sort_unstable();

    let left = keys
        .iter()
        .map(|key| {
            rephrased
                .iter()
                .find(|row| (row.block_index, row.index_in_block) == *key)
                .map(|row| ExplorerLine::from(row.text.clone()))
                .unwrap_or_else(|| ExplorerLine::from(""))
        })
        .collect();
    let right = keys
        .iter()
        .map(|key| {
            virtualized
                .iter()
                .find(|row| (row.block_index, row.index_in_block) == *key)
                .map(|row| ExplorerLine::from(row.text.clone()))
                .unwrap_or_else(|| ExplorerLine::from(""))
        })
        .collect();
    (left, right)
}

#[derive(Clone)]
struct TranslationRow {
    block_index: usize,
    index_in_block: usize,
    text: String,
}

fn translation_rows(
    blocks: &[crate::trace::TraceRephrasedBlock],
    pc: u64,
) -> Vec<TranslationRow> {
    blocks
        .iter()
        .flat_map(|block| block.insns.iter())
        .filter(|insn| insn.ori_pc == pc)
        .map(|insn| TranslationRow {
            block_index: insn.block_index,
            index_in_block: insn.index_in_block,
            text: format!(
                "b#{} i#{} {} {}",
                insn.block_index,
                insn.index_in_block,
                rephrased_kind_label(insn.kind),
                insn.pretty
            ),
        })
        .collect()
}

fn rephrased_kind_label(kind: RephrasedInsnKind) -> &'static str {
    match kind {
        RephrasedInsnKind::Original => "ORI",
        RephrasedInsnKind::UserSynthetic => "USY",
        RephrasedInsnKind::RegVirtHelper => "RVH",
        RephrasedInsnKind::RuntimeExitPayload => "RTP",
        RephrasedInsnKind::RuntimeExitBranch => "REB",
    }
}

fn layout_for_offset(trace: &PipelineTrace, offset: usize) -> Option<&TraceLayoutInsn> {
    trace.fragment.insns.iter().find(|insn| insn.offset == offset)
}

fn layout_line(insn: &TraceLayoutInsn) -> ExplorerLine {
    ExplorerLine::from(format!(
        "off={:#06x} idx={:<3} {:?} ori_pc={} {}",
        insn.offset,
        insn.index,
        insn.region,
        ori_pc_label(insn.ori_pc),
        insn.pretty
    ))
}

fn append_original_step_lines(lines: &mut Vec<ExplorerLine>, state: &ExplorerState<'_>, step: &OriginalSideState) {
    lines.push(ExplorerLine::from(format!(
        "last original pc={:#x} next={} executed={}",
        step.pc,
        ori_pc_label(step.next_pc),
        step.executed
    )));
    append_raw_line(lines, state, step.pc);
    if let Some(exit) = step.runtime_exit {
        lines.push(ExplorerLine::from(pretty_runtime_exit(exit)));
    }
    if let Some(resume_pc) = step.resumed_at {
        lines.push(ExplorerLine::from(format!(
            "mocked continuation resume_pc={resume_pc:#x}"
        )));
    }
    if let Some(halt) = step.halt_reason {
        lines.push(ExplorerLine::from(format!("halt={halt:?}")));
    }
}

fn append_translated_step_lines(
    lines: &mut Vec<ExplorerLine>,
    state: &ExplorerState<'_>,
    step: &TranslatedSideState,
) {
    lines.push(ExplorerLine::from(format!(
        "last off={} idx={} next={} ori_pc={} executed={}",
        opt_offset_label(step.offset),
        opt_usize_label(step.insn_index),
        opt_offset_label(step.next_offset),
        ori_pc_label(step.ori_pc),
        step.executed
    )));
    if let Some(offset) = step.offset {
        if let Some(insn) = layout_for_offset(state.trace, offset) {
            lines.push(layout_line(insn));
        }
    }
    if let Some(transition) = step.runtime_transition {
        lines.push(ExplorerLine::from(format!("runtime_transition={transition:?}")));
    }
    if let Some(halt) = &step.halt {
        lines.push(ExplorerLine::from(format!("halt={halt:?}")));
    }
}

fn append_raw_line(lines: &mut Vec<ExplorerLine>, state: &ExplorerState<'_>, pc: u64) {
    if let Some(raw) = state.trace.raw.iter().find(|insn| insn.pc == pc) {
        lines.push(ExplorerLine::from(format!(
            "raw off={:#x} word={:#010x} {}",
            raw.text_offset, raw.word, raw.pretty
        )));
    }
}

fn active_event_status(session: &ActiveStepSession, event: &ActiveStepEvent) -> String {
    let original = event
        .original
        .as_ref()
        .map(|step| format!(" original_pc={:#x}", step.pc))
        .unwrap_or_default();
    let mismatch = event
        .original_mismatch
        .map(|mismatch| {
            format!(
                " original_mismatch expected={:#x} actual={:#x}",
                mismatch.expected_pc, mismatch.actual_pc
            )
        })
        .unwrap_or_default();
    format!(
        "mode=active-step translated_steps={} original_steps={} last_translated={} group_pc={}{}{} halt={}",
        session.translated_steps(),
        session.original_steps(),
        event.translated.len(),
        ori_pc_label(event.group_pc),
        original,
        mismatch,
        active_halt_label(&event.halt)
    )
}

fn memory_row_line(row: &MemoryComparisonRow) -> ExplorerLine {
    ExplorerLine::from(format!(
        "{:#018x} {:<6} {:<8} {:<10} {}",
        row.addr,
        byte_label(row.before),
        byte_label(row.original),
        byte_label(row.translated),
        if row.equal { "=" } else { "!" }
    ))
}

fn active_halt_label(halt: &ActiveStepHalt) -> String {
    match halt {
        ActiveStepHalt::Running => "running".to_string(),
        ActiveStepHalt::Original(reason) => format!("original:{reason:?}"),
        ActiveStepHalt::Translated(reason) => format!("translated:{reason:?}"),
        ActiveStepHalt::Both {
            original,
            translated,
        } => format!("original:{original:?} translated:{translated:?}"),
        ActiveStepHalt::Error(message) => format!("error:{}", first_line(message)),
    }
}

fn ori_pc_label(ori_pc: Option<u64>) -> String {
    match ori_pc {
        Some(pc) => format!("{pc:#x}"),
        None => "None".to_string(),
    }
}

fn opt_offset_label(offset: Option<usize>) -> String {
    match offset {
        Some(offset) => format!("{offset:#x}"),
        None => "None".to_string(),
    }
}

fn opt_usize_label(value: Option<usize>) -> String {
    match value {
        Some(value) => value.to_string(),
        None => "None".to_string(),
    }
}

fn byte_label(value: Option<u8>) -> String {
    match value {
        Some(value) => format!("{value:#04x}"),
        None => "0".to_string(),
    }
}

fn comparison_value_label(value: &ComparisonValue) -> String {
    match value {
        ComparisonValue::U64(value) => format!("{value:#018x}"),
        ComparisonValue::Flags(flags) => flags_value_label(*flags),
    }
}

fn flags_value_label(flags: Flags) -> String {
    format!(
        "N{}Z{}C{}V{}",
        flags.n as u8, flags.z as u8, flags.c as u8, flags.v as u8
    )
}

fn flags_label(state: &MachineState) -> String {
    flags_value_label(state.flags)
}

fn append_state_diff_lines(
    lines: &mut Vec<ExplorerLine>,
    before: &MachineState,
    after: &MachineState,
) {
    let mut changed_regs = Vec::new();
    for reg in 0..31 {
        let before_value = before.read_x(reg);
        let after_value = after.read_x(reg);
        if before_value != after_value {
            changed_regs.push(format!("x{reg}: {before_value:#x}->{after_value:#x}"));
        }
    }

    if changed_regs.is_empty() {
        lines.push(ExplorerLine::from("regs: unchanged"));
    } else {
        let visible = changed_regs.iter().take(8).cloned().collect::<Vec<_>>();
        let suffix = if changed_regs.len() > visible.len() {
            format!(" ... +{} more", changed_regs.len() - visible.len())
        } else {
            String::new()
        };
        lines.push(ExplorerLine::from(format!(
            "regs: {}{}",
            visible.join(", "),
            suffix
        )));
    }

    if before.sp() != after.sp() {
        lines.push(ExplorerLine::from(format!(
            "sp: {:#x}->{:#x}",
            before.sp(),
            after.sp()
        )));
    }
    if before.flags != after.flags {
        lines.push(ExplorerLine::from(format!(
            "flags: {}->{}",
            flags_label(before),
            flags_label(after)
        )));
    }

    let mut addrs = before
        .memory()
        .keys()
        .chain(after.memory().keys())
        .copied()
        .collect::<Vec<_>>();
    addrs.sort_unstable();
    addrs.dedup();
    let changed_mem = addrs
        .into_iter()
        .filter(|addr| before.memory().get(addr) != after.memory().get(addr))
        .collect::<Vec<_>>();

    if changed_mem.is_empty() {
        lines.push(ExplorerLine::from("memory: unchanged"));
    } else {
        lines.push(ExplorerLine::from(format!(
            "memory_changed_bytes={}",
            changed_mem.len()
        )));
        for addr in changed_mem.iter().take(8) {
            lines.push(ExplorerLine::from(format!(
                "mem[{addr:#x}]: {}->{}",
                byte_label(before.memory().get(addr).copied()),
                byte_label(after.memory().get(addr).copied())
            )));
        }
        if changed_mem.len() > 8 {
            lines.push(ExplorerLine::from(format!(
                "... +{} more memory byte changes",
                changed_mem.len() - 8
            )));
        }
    }

    if before == after {
        lines.push(ExplorerLine::from("state_equal=true"));
    }
}

enum Command {
    Select(Selection),
    Help,
    Quit,
    Invalid(String),
}

pub fn state_summary_lines(snapshot: &StateSnapshot) -> Vec<ExplorerLine> {
    let mut lines = Vec::new();
    append_state_diff_lines(&mut lines, &snapshot.previous, &snapshot.current);
    lines
}

pub fn current_panel_export_path() -> PathBuf {
    copy_export_path()
}
