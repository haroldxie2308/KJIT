use std::io::{self, Stdout, Write};
use std::path::PathBuf;
use std::process::{Command as ProcessCommand, Stdio};
use std::time::Duration;

use crossterm::event::{self, Event, KeyCode, KeyEventKind, MouseButton, MouseEventKind};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use kjit_harness::a64_pretty::pretty_runtime_exit;
use kjit_harness::active_step::{
    memory_comparison, register_comparison, ActiveStepEvent, ActiveStepHalt, ActiveStepOrigin,
    ActiveStepSession, ComparisonValue, MemoryComparisonRow, OriginalSideState, StateSnapshot,
    TranslatedSideState,
};
use kjit_harness::model::{Flags, MachineState};
use kjit_harness::shared::trans::input::TranslationTrigger;
use kjit_harness::shared::trans::rephrase::RephrasedInsnKind;
use kjit_harness::trace::{request_for_trace, PipelineTrace};
use kjit_harness::{run_entry_fixture, CaseReport};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph, Wrap};
use ratatui::{Frame, Terminal};

mod opentui_backend;
use opentui_backend::{OpenTuiBackend, OpenTuiLoadError};

fn main() {
    let config = match CliConfig::parse(std::env::args().skip(1)) {
        Ok(config) => config,
        Err(message) => {
            eprintln!("{message}");
            eprintln!("usage: trace-tui [--dump] [--check] <text-bin> <text-base> <entry-pc>");
            std::process::exit(2);
        }
    };

    let text_bytes = std::fs::read(&config.text_path).unwrap_or_else(|err| {
        eprintln!("failed to read {}: {err}", config.text_path.display());
        std::process::exit(1);
    });

    let initial_state = default_fixture_state();
    let request = request_for_trace(config.entry_pc, TranslationTrigger::HotSvc, &initial_state);
    let trace = PipelineTrace::build(
        config.text_base,
        text_bytes.clone(),
        request,
        &initial_state,
        true,
    )
    .unwrap_or_else(|err| {
        eprintln!("trace build failed: {err}");
        std::process::exit(1);
    });

    let check = if config.check {
        match run_entry_fixture(
            "trace-tui-check",
            config.text_base,
            text_bytes.clone(),
            config.entry_pc,
            &initial_state,
        ) {
            Ok(report) => PipelineCheck::Passed(PipelineCheckPass::from_report(&report)),
            Err(message) => PipelineCheck::Failed { message },
        }
    } else {
        PipelineCheck::NotRun
    };
    let check_failed = matches!(check, PipelineCheck::Failed { .. });

    if config.dump {
        print_trace_view(&trace, Selection::Pc(config.entry_pc), &check);
        if config.check && check_failed {
            std::process::exit(1);
        }
    } else if let Err(err) = run_tui_opentui(&trace, config.entry_pc, check, text_bytes, initial_state) {
        eprintln!("trace-tui failed: {err}");
        std::process::exit(1);
    }
}

#[derive(Clone, Debug)]
enum PipelineCheck {
    NotRun,
    Passed(PipelineCheckPass),
    Failed { message: String },
}

#[derive(Clone, Debug)]
struct PipelineCheckPass {
    original_steps: usize,
    fragment_steps: usize,
    encoded_bytes: usize,
    halt: String,
}

impl PipelineCheckPass {
    fn from_report(report: &CaseReport) -> Self {
        Self {
            original_steps: report.original.steps,
            fragment_steps: report.fragment_steps,
            encoded_bytes: report.encoded_fragment.len(),
            halt: format!("{:?}", report.fragment_halt),
        }
    }
}

impl PipelineCheck {
    fn metadata(&self) -> String {
        match self {
            Self::NotRun => "check=not-run".to_string(),
            Self::Passed(pass) => format!(
                "check=pass original_steps={} fragment_steps={} encoded_bytes={} halt={}",
                pass.original_steps, pass.fragment_steps, pass.encoded_bytes, pass.halt
            ),
            Self::Failed { message } => {
                format!("check=fail {}", first_line(message))
            }
        }
    }

    fn initial_status(&self) -> String {
        match self {
            Self::Failed { message } => format!("pipeline check failed: {}", first_line(message)),
            _ => "s step mode | Tab focus | p/t/r jump panels | Up/Down move or scroll".to_string(),
        }
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

#[derive(Debug)]
struct CliConfig {
    dump: bool,
    check: bool,
    text_path: PathBuf,
    text_base: u64,
    entry_pc: u64,
}

impl CliConfig {
    fn parse(args: impl Iterator<Item = String>) -> Result<Self, String> {
        let mut dump = false;
        let mut check = false;
        let mut positional = Vec::new();
        for arg in args {
            match arg.as_str() {
                "--dump" => dump = true,
                "--check" => check = true,
                _ => positional.push(arg),
            }
        }

        if positional.len() != 3 {
            return Err("expected exactly three positional arguments".to_string());
        }

        Ok(Self {
            dump,
            check,
            text_path: PathBuf::from(&positional[0]),
            text_base: parse_u64(&positional[1])?,
            entry_pc: parse_u64(&positional[2])?,
        })
    }
}

#[derive(Clone, Copy, Debug)]
enum Selection {
    Pc(u64),
    Offset(usize),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Explore,
    ActiveStep,
}

impl Mode {
    const fn name(self) -> &'static str {
        match self {
            Self::Explore => "explore",
            Self::ActiveStep => "active-step",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StepDetailMode {
    Compact,
    Registers,
    Memory,
}

impl StepDetailMode {
    const fn name(self) -> &'static str {
        match self {
            Self::Compact => "compact",
            Self::Registers => "registers",
            Self::Memory => "memory",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FocusPanel {
    Cfg,
    Rephrase,
    Layout,
}

impl FocusPanel {
    const fn next(self) -> Self {
        match self {
            Self::Cfg => Self::Rephrase,
            Self::Rephrase => Self::Layout,
            Self::Layout => Self::Cfg,
        }
    }

    const fn prev(self) -> Self {
        match self {
            Self::Cfg => Self::Layout,
            Self::Rephrase => Self::Cfg,
            Self::Layout => Self::Rephrase,
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Cfg => "Program",
            Self::Rephrase => "Translation",
            Self::Layout => "Result",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MousePanel {
    Program,
    Translation,
    Result,
    ActiveOriginal,
    ActiveTranslated,
    ActiveStateOriginal,
    ActiveStateTranslated,
    ActiveComparison,
}

#[derive(Clone, Copy, Debug)]
struct MouseAnchor {
    panel: MousePanel,
    row: usize,
}

#[derive(Clone, Copy, Debug)]
struct MouseSelection {
    panel: MousePanel,
    start: usize,
    end: usize,
}

impl MouseSelection {
    fn contains(self, panel: MousePanel, row: usize) -> bool {
        self.panel == panel && row >= self.start.min(self.end) && row <= self.start.max(self.end)
    }
}

struct App<'a> {
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
    mouse_anchor: Option<MouseAnchor>,
    mouse_selection: Option<MouseSelection>,
    raw_scroll: u16,
    rephrase_scroll: u16,
    layout_scroll: u16,
    status: String,
}

fn run_tui(
    trace: &PipelineTrace,
    entry_pc: u64,
    check: PipelineCheck,
    text_bytes: Vec<u8>,
    initial_state: MachineState,
) -> io::Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let _guard = TerminalGuard;

    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    let selection = Selection::Pc(entry_pc);
    let mut app = App {
        trace,
        mode: Mode::Explore,
        selection,
        text_bytes,
        initial_state,
        active_step: None,
        step_detail: StepDetailMode::Compact,
        command: String::new(),
        command_mode: false,
        show_raw_only: false,
        focus: FocusPanel::Cfg,
        mouse_anchor: None,
        mouse_selection: None,
        raw_scroll: 0,
        rephrase_scroll: 0,
        layout_scroll: 0,
        status: check.initial_status(),
        check,
    };

    loop {
        terminal.draw(|frame| draw(frame, &app))?;
        if !event::poll(Duration::from_millis(200))? {
            continue;
        }
        let Event::Key(key) = event::read()? else {
            continue;
        };
        if handle_key_event(&mut app, key) {
            break;
        }
    }

    Ok(())
}

fn run_tui_opentui(
    trace: &PipelineTrace,
    entry_pc: u64,
    check: PipelineCheck,
    text_bytes: Vec<u8>,
    initial_state: MachineState,
) -> io::Result<()> {
    enable_raw_mode()?;
    let size = crossterm::terminal::size()?;
    let backend = OpenTuiBackend::load(u32::from(size.0), u32::from(size.1)).map_err(|err| {
        io::Error::other(match err {
            OpenTuiLoadError::MissingPath => format!(
                "{err}; set KJIT_OPENTUI_LIB_PATH or KJIT_OPENTUI_ROOT to a libopentui.dylib path"
            ),
            _ => err.to_string(),
        })
    })?;
    backend.setup_terminal();
    backend.set_title("KJIT Explorer");
    let _guard = OpenTuiGuard { backend };

    let selection = Selection::Pc(entry_pc);
    let mut app = App {
        trace,
        mode: Mode::Explore,
        selection,
        text_bytes,
        initial_state,
        active_step: None,
        step_detail: StepDetailMode::Compact,
        command: String::new(),
        command_mode: false,
        show_raw_only: false,
        focus: FocusPanel::Cfg,
        mouse_anchor: None,
        mouse_selection: None,
        raw_scroll: 0,
        rephrase_scroll: 0,
        layout_scroll: 0,
        status: check.initial_status(),
        check,
    };

    loop {
        let current = crossterm::terminal::size()?;
        _guard.backend.resize(u32::from(current.0), u32::from(current.1));
        draw_opentui_modern(&_guard.backend, &app);

        if !event::poll(Duration::from_millis(200))? {
            continue;
        }

        match event::read()? {
            Event::Key(key) if key.kind == KeyEventKind::Press && handle_key_event(&mut app, key) => {
                break;
            }
            Event::Mouse(mouse) => {
                handle_mouse_event(&mut app, mouse, crossterm::terminal::size()?);
            }
            Event::Resize(width, height) => {
                _guard.backend.resize(u32::from(width), u32::from(height));
            }
            _ => {}
        }
    }

    Ok(())
}

fn handle_key_event(app: &mut App<'_>, key: crossterm::event::KeyEvent) -> bool {
    if key.kind != KeyEventKind::Press {
        return false;
    }

    if app.command_mode {
        match key.code {
            KeyCode::Esc => {
                app.command.clear();
                app.command_mode = false;
                app.status = "command cancelled".to_string();
            }
            KeyCode::Enter => {
                let command = app.command.clone();
                app.command.clear();
                app.command_mode = false;
                if matches!(apply_command(app, &command), Control::Quit) {
                    return true;
                }
            }
            KeyCode::Backspace => {
                app.command.pop();
            }
            KeyCode::Char(ch) => app.command.push(ch),
            _ => {}
        }
        return false;
    }

    match key.code {
        KeyCode::Char('q') => return true,
        KeyCode::Esc if app.mode == Mode::ActiveStep => leave_step_mode(app),
        KeyCode::Char(':') => {
            app.command.clear();
            app.command_mode = true;
            app.status = "enter command".to_string();
        }
        KeyCode::Char('y') => export_panel_text(app),
        KeyCode::Char('s') => toggle_mode(app),
        KeyCode::Char(' ') if app.mode == Mode::ActiveStep => step_group(app),
        KeyCode::Char('j') if app.mode == Mode::ActiveStep => step_translated(app),
        KeyCode::Down if app.mode == Mode::ActiveStep => active_step_down(app),
        KeyCode::Char('r') if app.mode == Mode::ActiveStep => {
            toggle_step_detail(app, StepDetailMode::Registers);
        }
        KeyCode::Char('m') if app.mode == Mode::ActiveStep => {
            toggle_step_detail(app, StepDetailMode::Memory);
        }
        KeyCode::Char('c') if app.mode == Mode::ActiveStep => {
            app.step_detail = StepDetailMode::Compact;
            app.status = "comparison=compact".to_string();
        }
        KeyCode::Char('R') if app.mode == Mode::ActiveStep => reset_step_mode(app),
        KeyCode::Up if app.mode == Mode::ActiveStep => active_step_up(app),
        KeyCode::Tab => {
            app.focus = app.focus.next();
            app.status = format!("focused {}", app.focus.name());
        }
        KeyCode::BackTab => {
            app.focus = app.focus.prev();
            app.status = format!("focused {}", app.focus.name());
        }
        KeyCode::Char('p') => set_focus(app, FocusPanel::Cfg),
        KeyCode::Char('t') => set_focus(app, FocusPanel::Rephrase),
        KeyCode::Char('r') => set_focus(app, FocusPanel::Layout),
        KeyCode::Char('n') if app.mode == Mode::Explore => {
            select_next_pc(app, 1);
        }
        KeyCode::Right if app.mode == Mode::Explore => {
            select_next_pc(app, 1);
        }
        KeyCode::Left if app.mode == Mode::Explore => {
            select_next_pc(app, -1);
        }
        KeyCode::Down if app.mode == Mode::Explore => {
            if app.focus == FocusPanel::Cfg {
                select_next_pc(app, 1);
            } else {
                scroll_focus(app, 1);
            }
        }
        KeyCode::Up if app.mode == Mode::Explore => {
            if app.focus == FocusPanel::Cfg {
                select_next_pc(app, -1);
            } else {
                scroll_focus(app, -1);
            }
        }
        KeyCode::PageDown | KeyCode::Char('d') => {
            if app.mode == Mode::ActiveStep {
                scroll_step_detail(app, 5);
            } else {
                scroll_focus(app, 5);
            }
        }
        KeyCode::PageUp | KeyCode::Char('u') => {
            if app.mode == Mode::ActiveStep {
                scroll_step_detail(app, -5);
            } else {
                scroll_focus(app, -5);
            }
        }
        KeyCode::Char('a') => {
            app.show_raw_only = !app.show_raw_only;
            app.status = if app.show_raw_only {
                "Program view=all".to_string()
            } else {
                "Program view=cfg".to_string()
            };
        }
        KeyCode::Char('?') | KeyCode::F(1) => {
            app.status = match app.mode {
                Mode::Explore => {
                    "Explore: s step | p/t/r panels | y export panel | Up/Down move or scroll"
                        .to_string()
                }
                Mode::ActiveStep => {
                    "Step: Esc/s explore | Space group | j insn | r/m/c panes | y export | R reset"
                        .to_string()
                }
            };
        }
        _ => {}
    }
    false
}

fn handle_mouse_event(
    app: &mut App<'_>,
    mouse: crossterm::event::MouseEvent,
    size: (u16, u16),
) {
    let layout = opentui_layout(usize::from(size.0), usize::from(size.1));
    let x = usize::from(mouse.column);
    let y = usize::from(mouse.row);
    if let Some(scroll_target) = mouse_scroll_target(app, &layout, x, y) {
        match mouse.kind {
            MouseEventKind::ScrollUp => {
                scroll_mouse_target(app, scroll_target, -3);
                return;
            }
            MouseEventKind::ScrollDown => {
                scroll_mouse_target(app, scroll_target, 3);
                return;
            }
            _ => {}
        }
    }

    let Some((panel, row)) = hit_mouse_target(app, &layout, x, y) else {
        if matches!(mouse.kind, MouseEventKind::Down(MouseButton::Left)) {
            clear_mouse_selection(app);
        }
        return;
    };

    match mouse.kind {
        MouseEventKind::Down(MouseButton::Left) => {
            let absolute = panel_absolute_row(app, panel, row);
            set_mouse_anchor(app, panel, absolute);
            update_selection_for_panel(app, panel, absolute);
            set_focus_for_panel(app, panel);
        }
        MouseEventKind::Drag(MouseButton::Left) => {
            let absolute = panel_absolute_row(app, panel, row);
            update_mouse_selection(app, panel, absolute);
            update_selection_for_panel(app, panel, absolute);
            set_focus_for_panel(app, panel);
        }
        MouseEventKind::Up(MouseButton::Left) => {
            let absolute = panel_absolute_row(app, panel, row);
            update_mouse_selection(app, panel, absolute);
            update_selection_for_panel(app, panel, absolute);
            set_focus_for_panel(app, panel);
            copy_panel_text(app);
        }
        _ => {}
    }
}

fn set_focus_for_panel(app: &mut App<'_>, panel: MousePanel) {
    match panel {
        MousePanel::Program => set_focus(app, FocusPanel::Cfg),
        MousePanel::Translation => set_focus(app, FocusPanel::Rephrase),
        MousePanel::Result => set_focus(app, FocusPanel::Layout),
        MousePanel::ActiveOriginal
        | MousePanel::ActiveTranslated
        | MousePanel::ActiveStateOriginal
        | MousePanel::ActiveStateTranslated
        | MousePanel::ActiveComparison => set_focus(app, FocusPanel::Layout),
    }
}

fn clear_in_panel_selection(app: &mut App<'_>) {
    clear_mouse_selection(app);
}

fn clear_mouse_selection(app: &mut App<'_>) {
    app.mouse_anchor = None;
    app.mouse_selection = None;
}

fn set_mouse_anchor(app: &mut App<'_>, panel: MousePanel, row: usize) {
    app.mouse_anchor = Some(MouseAnchor { panel, row });
    app.mouse_selection = Some(MouseSelection {
        panel,
        start: row,
        end: row,
    });
}

fn update_mouse_selection(app: &mut App<'_>, panel: MousePanel, row: usize) {
    match app.mouse_anchor {
        Some(anchor) if anchor.panel == panel => {
            app.mouse_selection = Some(MouseSelection {
                panel,
                start: anchor.row,
                end: row,
            });
        }
        _ => set_mouse_anchor(app, panel, row),
    }
}

fn update_selection_for_panel(app: &mut App<'_>, panel: MousePanel, absolute_row: usize) {
    if panel == MousePanel::Program {
        if let Some(pc) = program_pc_at_row(app, absolute_row) {
            app.selection = Selection::Pc(pc);
            app.raw_scroll = 0;
            app.rephrase_scroll = 0;
            app.layout_scroll = 0;
        }
    }
}

fn mouse_scroll_target(app: &App<'_>, layout: &OpenTuiLayout, x: usize, y: usize) -> Option<MousePanel> {
    let _ = app;
    if layout.program.is_some_and(|rect| rect.contains(x, y)) {
        return Some(MousePanel::Program);
    }
    if layout.translation.is_some_and(|rect| rect.contains(x, y)) {
        return Some(MousePanel::Translation);
    }
    if layout.result.is_some_and(|rect| rect.contains(x, y)) {
        return Some(MousePanel::Result);
    }
    if layout.active_original.is_some_and(|rect| rect.contains(x, y)) {
        return Some(MousePanel::ActiveOriginal);
    }
    if layout.active_translated.is_some_and(|rect| rect.contains(x, y)) {
        return Some(MousePanel::ActiveTranslated);
    }
    if layout.active_state_original.is_some_and(|rect| rect.contains(x, y)) {
        return Some(MousePanel::ActiveStateOriginal);
    }
    if layout.active_state_translated.is_some_and(|rect| rect.contains(x, y)) {
        return Some(MousePanel::ActiveStateTranslated);
    }
    if layout.active_comparison.is_some_and(|rect| rect.contains(x, y)) {
        return Some(MousePanel::ActiveComparison);
    }
    None
}

fn scroll_mouse_target(app: &mut App<'_>, target: MousePanel, delta: i16) {
    match target {
        MousePanel::Program => scroll_focus(app, delta),
        MousePanel::Translation => {
            app.focus = FocusPanel::Rephrase;
            scroll_focus(app, delta);
        }
        MousePanel::Result => {
            app.focus = FocusPanel::Layout;
            scroll_focus(app, delta);
        }
        MousePanel::ActiveOriginal => {
            app.raw_scroll = scroll_delta(app.raw_scroll, delta);
            app.status = format!("Program scroll={}", app.raw_scroll);
        }
        MousePanel::ActiveTranslated => {
            app.rephrase_scroll = scroll_delta(app.rephrase_scroll, delta);
            app.status = format!("Translation scroll={}", app.rephrase_scroll);
        }
        MousePanel::ActiveStateOriginal | MousePanel::ActiveStateTranslated => {
            app.status = "state summaries do not scroll".to_string();
        }
        MousePanel::ActiveComparison => scroll_step_detail(app, delta),
    }
}

fn scroll_delta(current: u16, delta: i16) -> u16 {
    if delta < 0 {
        current.saturating_sub(delta.unsigned_abs())
    } else {
        current.saturating_add(delta as u16)
    }
}

fn panel_absolute_row(app: &App<'_>, panel: MousePanel, row: usize) -> usize {
    match panel {
        MousePanel::Program => app.raw_scroll as usize + row,
        MousePanel::Translation => app.rephrase_scroll as usize + row,
        MousePanel::Result => app.layout_scroll as usize + row,
        MousePanel::ActiveOriginal => app.raw_scroll as usize + row,
        MousePanel::ActiveTranslated => app.rephrase_scroll as usize + row,
        MousePanel::ActiveStateOriginal | MousePanel::ActiveStateTranslated => row,
        MousePanel::ActiveComparison => app.layout_scroll as usize + row,
    }
}

fn program_pc_at_row(app: &App<'_>, absolute_row: usize) -> Option<u64> {
    visible_pc_entries(app.trace, app.show_raw_only)
        .get(absolute_row)
        .map(|entry| entry.pc)
}

fn panel_row_from_mouse(panel: PanelRect, y: usize) -> Option<usize> {
    let top = panel.y.saturating_add(1);
    let bottom = panel.y.saturating_add(panel.height.saturating_sub(1));
    if y < top || y >= bottom {
        None
    } else {
        Some(y - top)
    }
}

fn hit_mouse_target(
    app: &App<'_>,
    layout: &OpenTuiLayout,
    x: usize,
    y: usize,
) -> Option<(MousePanel, usize)> {
    if let Some(panel) = layout.program {
        if panel.contains(x, y) {
            return panel_row_from_mouse(panel, y).map(|row| {
                let _ = app;
                (MousePanel::Program, row)
            });
        }
    }
    if let Some(panel) = layout.translation {
        if panel.contains(x, y) {
            return panel_row_from_mouse(panel, y).map(|row| {
                let _ = app;
                (MousePanel::Translation, row)
            });
        }
    }
    if let Some(panel) = layout.result {
        if panel.contains(x, y) {
            return panel_row_from_mouse(panel, y).map(|row| {
                let _ = app;
                (MousePanel::Result, row)
            });
        }
    }
    if let Some(panel) = layout.active_original {
        if panel.contains(x, y) {
            return panel_row_from_mouse(panel, y).map(|row| {
                let _ = app;
                (MousePanel::ActiveOriginal, row)
            });
        }
    }
    if let Some(panel) = layout.active_translated {
        if panel.contains(x, y) {
            return panel_row_from_mouse(panel, y).map(|row| {
                let _ = app;
                (MousePanel::ActiveTranslated, row)
            });
        }
    }
    if let Some(panel) = layout.active_state_original {
        if panel.contains(x, y) {
            return panel_row_from_mouse(panel, y).map(|row| {
                let _ = app;
                (MousePanel::ActiveStateOriginal, row)
            });
        }
    }
    if let Some(panel) = layout.active_state_translated {
        if panel.contains(x, y) {
            return panel_row_from_mouse(panel, y).map(|row| {
                let _ = app;
                (MousePanel::ActiveStateTranslated, row)
            });
        }
    }
    if let Some(panel) = layout.active_comparison {
        if panel.contains(x, y) {
            return panel_row_from_mouse(panel, y).map(|row| {
                let _ = app;
                (MousePanel::ActiveComparison, row)
            });
        }
    }
    None
}

#[derive(Clone, Copy)]
struct PanelRect {
    x: usize,
    y: usize,
    width: usize,
    height: usize,
}

impl PanelRect {
    fn contains(self, x: usize, y: usize) -> bool {
        x >= self.x
            && y >= self.y
            && x < self.x.saturating_add(self.width)
            && y < self.y.saturating_add(self.height)
    }
}

struct OpenTuiLayout {
    program: Option<PanelRect>,
    translation: Option<PanelRect>,
    result: Option<PanelRect>,
    active_original: Option<PanelRect>,
    active_translated: Option<PanelRect>,
    active_state_original: Option<PanelRect>,
    active_state_translated: Option<PanelRect>,
    active_comparison: Option<PanelRect>,
}

fn opentui_layout(width: usize, height: usize) -> OpenTuiLayout {
    let header_h = 6.min(height.max(1));
    let footer_h = 4.min(height.saturating_sub(header_h).max(1));
    let body_h = height.saturating_sub(header_h + footer_h);
    if body_h == 0 || width == 0 {
        return OpenTuiLayout {
            program: None,
            translation: None,
            result: None,
            active_original: None,
            active_translated: None,
            active_state_original: None,
            active_state_translated: None,
            active_comparison: None,
        };
    }

    let program = PanelRect {
        x: 0,
        y: header_h,
        width: width.saturating_mul(28) / 100,
        height: body_h,
    };
    let left_w = program.width.clamp(24, width.saturating_sub(20).max(24));
    let right_x = left_w;
    let right_w = width.saturating_sub(left_w);
    let top_h = body_h
        .saturating_mul(58)
        / 100;
    let top_h = top_h.clamp(10, body_h.saturating_sub(8).max(10));
    let translation = PanelRect {
        x: right_x,
        y: header_h,
        width: right_w,
        height: top_h,
    };
    let result = PanelRect {
        x: right_x,
        y: header_h + top_h,
        width: right_w,
        height: body_h.saturating_sub(top_h),
    };
    let half = width / 2;
    let state_h = 8.min(body_h.saturating_sub(top_h).max(1));
    let active_original = PanelRect {
        x: 0,
        y: header_h,
        width: half,
        height: top_h,
    };
    let active_translated = PanelRect {
        x: half,
        y: header_h,
        width: width.saturating_sub(half),
        height: top_h,
    };
    let active_state_original = PanelRect {
        x: 0,
        y: header_h + top_h,
        width: half,
        height: state_h,
    };
    let active_state_translated = PanelRect {
        x: half,
        y: header_h + top_h,
        width: width.saturating_sub(half),
        height: state_h,
    };
    let active_comparison = PanelRect {
        x: 0,
        y: header_h + top_h + state_h,
        width,
        height: body_h.saturating_sub(top_h + state_h),
    };

    OpenTuiLayout {
        program: Some(program),
        translation: Some(translation),
        result: Some(result),
        active_original: Some(active_original),
        active_translated: Some(active_translated),
        active_state_original: Some(active_state_original),
        active_state_translated: Some(active_state_translated),
        active_comparison: Some(active_comparison),
    }
}

struct OpenTuiGuard {
    backend: OpenTuiBackend,
}

impl Drop for OpenTuiGuard {
    fn drop(&mut self) {
        self.backend.restore_terminal_modes();
        let _ = disable_raw_mode();
    }
}

fn draw_opentui_modern(ui: &OpenTuiBackend, app: &App<'_>) {
    let buffer = ui.next_buffer();
    ui.clear(buffer);

    let (width, height) = crossterm::terminal::size().unwrap_or((120, 40));
    let width = usize::from(width);
    let height = usize::from(height);
    let header_h = 6.min(height.max(1));
    let footer_h = 4.min(height.saturating_sub(header_h).max(1));
    let body_h = height.saturating_sub(header_h + footer_h);

    draw_opentui_header(ui, buffer, app, 0, 0, width, header_h);

    match app.mode {
        Mode::Explore => draw_opentui_explore(ui, buffer, app, 0, header_h, width, body_h),
        Mode::ActiveStep => draw_opentui_active_step(ui, buffer, app, 0, header_h, width, body_h),
    }

    draw_opentui_footer(ui, buffer, app, 0, header_h + body_h, width, footer_h);
    ui.render(true);
}

fn draw_opentui_header(
    ui: &OpenTuiBackend,
    buffer: opentui_backend::NativeHandle,
    app: &App<'_>,
    x: usize,
    y: usize,
    width: usize,
    height: usize,
) {
    let lines = header_text_lines(app);
    draw_opentui_panel(
        ui,
        buffer,
        x,
        y,
        width,
        height,
        "KJIT Explorer",
        &lines,
        0,
        None,
        MousePanel::Program,
        true,
        false,
    );
}

fn draw_opentui_explore(
    ui: &OpenTuiBackend,
    buffer: opentui_backend::NativeHandle,
    app: &App<'_>,
    x: usize,
    y: usize,
    width: usize,
    height: usize,
) {
    let left_w = width.saturating_mul(28) / 100;
    let left_w = left_w.clamp(24, width.saturating_sub(20).max(24));
    let right_w = width.saturating_sub(left_w);
    let top_h = height.saturating_mul(58) / 100;
    let top_h = top_h.clamp(10, height.saturating_sub(8).max(10));
    let bottom_h = height.saturating_sub(top_h);

    let program = program_text_lines(app);
    let selected_index = selected_program_index(app, &program);
    let program_selection = app.mouse_selection.or_else(|| {
        selected_index.map(|row| MouseSelection {
            panel: MousePanel::Program,
            start: row,
            end: row,
        })
    });
    draw_opentui_panel(
        ui,
        buffer,
        x,
        y,
        left_w,
        height,
        "Program",
        &program,
        app.raw_scroll as usize,
        program_selection,
        MousePanel::Program,
        app.focus == FocusPanel::Cfg,
        false,
    );

    let detail_x = x + left_w;
    let pc = selected_pc(app);
    match pc {
        Some(pc) => {
            let (rephrased, virtualized) = translation_text_columns(app, pc);
            draw_opentui_split_panel(
                ui,
                buffer,
                detail_x,
                y,
                right_w,
                top_h,
                "Translation",
                "Rephrased",
                "Virtualized",
                &rephrased,
                &virtualized,
                app.rephrase_scroll as usize,
                app.mouse_selection,
                MousePanel::Translation,
                app.focus == FocusPanel::Rephrase,
            );
            let result_lines = layout_for_pc_text_lines(app, pc);
            draw_opentui_panel(
                ui,
                buffer,
                detail_x,
                y + top_h,
                right_w,
                bottom_h,
                "Result",
                &result_lines,
                app.layout_scroll as usize,
                app.mouse_selection,
                MousePanel::Result,
                app.focus == FocusPanel::Layout,
                false,
            );
        }
        None => {
            let empty = vec!["select an original PC to inspect translation".to_string()];
            draw_opentui_panel(
                ui,
                buffer,
                detail_x,
                y,
                right_w,
                top_h,
                "Translation",
                &empty,
                0,
                app.mouse_selection,
                MousePanel::Translation,
                app.focus == FocusPanel::Rephrase,
                false,
            );
            let layout_lines = layout_neighborhood_text_lines(app, 0);
            draw_opentui_panel(
                ui,
                buffer,
                detail_x,
                y + top_h,
                right_w,
                bottom_h,
                "Result",
                &layout_lines,
                app.layout_scroll as usize,
                app.mouse_selection,
                MousePanel::Result,
                app.focus == FocusPanel::Layout,
                false,
            );
        }
    }
}

fn draw_opentui_active_step(
    ui: &OpenTuiBackend,
    buffer: opentui_backend::NativeHandle,
    app: &App<'_>,
    x: usize,
    y: usize,
    width: usize,
    height: usize,
) {
    let Some(session) = app.active_step.as_ref() else {
        let empty = vec!["active session is not initialized".to_string()];
        draw_opentui_panel(ui, buffer, x, y, width, height, "Active Step", &empty, 0, None, MousePanel::ActiveComparison, true, false);
        return;
    };

    let top_h = height.saturating_mul(36) / 100;
    let top_h = top_h.clamp(10, height.saturating_sub(10).max(10));
    let state_h = 8.min(height.saturating_sub(top_h));
    let bottom_h = height.saturating_sub(top_h + state_h);
    let half = width / 2;

    let original = active_original_text_lines(app, session);
    let translated = active_translated_text_lines(app, session);
    draw_opentui_panel(
        ui,
        buffer,
        x,
        y,
        half,
        top_h,
        "Original",
        &original,
        app.raw_scroll as usize,
        app.mouse_selection,
        MousePanel::ActiveOriginal,
        false,
        false,
    );
    draw_opentui_panel(
        ui,
        buffer,
        x + half,
        y,
        width - half,
        top_h,
        "Translated",
        &translated,
        app.rephrase_scroll as usize,
        app.mouse_selection,
        MousePanel::ActiveTranslated,
        false,
        false,
    );

    let original_state = state_summary_text_lines("Original State Summary", session.original_snapshot());
    let translated_state = state_summary_text_lines("Translated State Summary", session.translated_snapshot());
    draw_opentui_panel(
        ui,
        buffer,
        x,
        y + top_h,
        half,
        state_h,
        "Original State Summary",
        &original_state,
        0,
        app.mouse_selection,
        MousePanel::ActiveStateOriginal,
        false,
        false,
    );
    draw_opentui_panel(
        ui,
        buffer,
        x + half,
        y + top_h,
        width - half,
        state_h,
        "Translated State Summary",
        &translated_state,
        0,
        app.mouse_selection,
        MousePanel::ActiveStateTranslated,
        false,
        false,
    );

    let comparison = comparison_text_lines(app, session);
    draw_opentui_panel(
        ui,
        buffer,
        x,
        y + top_h + state_h,
        width,
        bottom_h,
        &format!("Comparison {}", app.step_detail.name()),
        &comparison,
        app.layout_scroll as usize,
        app.mouse_selection,
        MousePanel::ActiveComparison,
        false,
        false,
    );
}

fn draw_opentui_footer(
    ui: &OpenTuiBackend,
    buffer: opentui_backend::NativeHandle,
    app: &App<'_>,
    x: usize,
    y: usize,
    width: usize,
    height: usize,
) {
    let lines = if app.command_mode {
        vec![format!(":{}", app.command), "Enter submit | Esc cancel".to_string()]
    } else {
        vec![
            app.status.clone(),
            match app.mode {
                Mode::Explore => "Explore: wheel scrolls pane under pointer | drag selects rows | release copies | s step | Tab focus | p/t/r panels | y export | a cfg/all | Up/Down move/scroll | q quit".to_string(),
                Mode::ActiveStep => match app.step_detail {
                    StepDetailMode::Compact => "Step: wheel scrolls pane under pointer | drag selects rows | release copies | Esc/s explore | Space group | j insn | y export | r registers | m memory | R reset | q quit".to_string(),
                    StepDetailMode::Registers | StepDetailMode::Memory => "Step: wheel scrolls pane under pointer | drag selects rows | release copies | Up/Down scroll comparison | d/u page | y export | j insn | Space group | c compact | R reset | q quit".to_string(),
                },
            },
        ]
    };
    draw_opentui_panel(
        ui,
        buffer,
        x,
        y,
        width,
        height,
        "keys",
        &lines,
        0,
        None,
        MousePanel::Program,
        false,
        false,
    );
}

fn draw_opentui_split_panel(
    ui: &OpenTuiBackend,
    buffer: opentui_backend::NativeHandle,
    x: usize,
    y: usize,
    width: usize,
    height: usize,
    title: &str,
    left_title: &str,
    right_title: &str,
    left_lines: &[String],
    right_lines: &[String],
    scroll: usize,
    selection: Option<MouseSelection>,
    panel: MousePanel,
    focused: bool,
) {
    if width < 4 || height < 4 {
        return;
    }
    let border = if focused { ui.palette().yellow() } else { ui.palette().cyan() };
    ui.draw_box(buffer, x as i32, y as i32, width as u32, height as u32, title, "", true, border, ui.palette().black(), border);
    let inner_w = width.saturating_sub(2);
    let inner_h = height.saturating_sub(2);
    let half = inner_w / 2;
    ui.draw_text(buffer, left_title, (x + 1) as u32, (y + 1) as u32, ui.palette().white(), Some(ui.palette().black()));
    ui.draw_text(buffer, right_title, (x + 1 + half) as u32, (y + 1) as u32, ui.palette().white(), Some(ui.palette().black()));
    for row in 0..inner_h.saturating_sub(1) {
        let row_index = scroll + row;
        let left = left_lines.get(scroll + row).map(|s| truncate_to_width(s, half.saturating_sub(1))).unwrap_or_default();
        let right = right_lines.get(scroll + row).map(|s| truncate_to_width(s, inner_w.saturating_sub(half + 1))).unwrap_or_default();
        if selection.is_some_and(|sel| sel.contains(panel, row_index)) {
            ui.fill_rect(buffer, (x + 1) as u32, (y + 2 + row) as u32, inner_w as u32, 1, ui.palette().yellow());
            ui.draw_text(buffer, &left, (x + 1) as u32, (y + 2 + row) as u32, ui.palette().black(), Some(ui.palette().yellow()));
            ui.draw_text(buffer, &right, (x + 1 + half) as u32, (y + 2 + row) as u32, ui.palette().black(), Some(ui.palette().yellow()));
        } else {
            ui.draw_text(buffer, &left, (x + 1) as u32, (y + 2 + row) as u32, ui.palette().white(), Some(ui.palette().black()));
            ui.draw_text(buffer, &right, (x + 1 + half) as u32, (y + 2 + row) as u32, ui.palette().white(), Some(ui.palette().black()));
        }
    }
}

fn draw_opentui_panel(
    ui: &OpenTuiBackend,
    buffer: opentui_backend::NativeHandle,
    x: usize,
    y: usize,
    width: usize,
    height: usize,
    title: &str,
    lines: &[String],
    scroll: usize,
    selection: Option<MouseSelection>,
    panel: MousePanel,
    focused: bool,
    show_row_numbers: bool,
) {
    if width < 4 || height < 4 {
        return;
    }
    let border = if focused { ui.palette().yellow() } else { ui.palette().cyan() };
    ui.draw_box(buffer, x as i32, y as i32, width as u32, height as u32, title, "", true, border, ui.palette().black(), border);
    let inner_w = width.saturating_sub(2);
    let inner_h = height.saturating_sub(2);
    let visible = inner_h.min(lines.len().saturating_sub(scroll));
    for row in 0..visible {
        let absolute = scroll + row;
        let mut text = lines.get(absolute).cloned().unwrap_or_default();
        if show_row_numbers {
            text = format!("{absolute:>4} {text}");
        }
        if selection.is_some_and(|sel| sel.contains(panel, absolute)) {
            ui.fill_rect(buffer, (x + 1) as u32, (y + 1 + row) as u32, inner_w as u32, 1, ui.palette().yellow());
            ui.draw_text(buffer, &truncate_to_width(&text, inner_w), (x + 1) as u32, (y + 1 + row) as u32, ui.palette().black(), Some(ui.palette().yellow()));
            continue;
        }
        ui.draw_text(buffer, &truncate_to_width(&text, inner_w), (x + 1) as u32, (y + 1 + row) as u32, ui.palette().white(), Some(ui.palette().black()));
    }
}

fn header_text_lines(app: &App<'_>) -> Vec<String> {
    let runtime = app
        .trace
        .run
        .as_ref()
        .map(|run| format!("runtime: steps={} halt={:?}", run.steps, run.halt))
        .unwrap_or_else(|| "runtime: not-run".to_string());
    vec![
        format!(
            "mode={} entry={:#x} text_base={:#x} fragment_entry={:#x} view={}",
            app.mode.name(),
            app.trace.input.entry_pc,
            app.trace.input.text_base,
            app.trace.fragment.entry_offset,
            if app.show_raw_only { "all" } else { "cfg" }
        ),
        format!(
            "raw={} cfg_blocks={} translated={} fragment_insns={}",
            app.trace.raw.len(),
            app.trace.cfg.blocks.len(),
            app.trace.translated.len(),
            app.trace.fragment.insns.len()
        ),
        runtime,
        format!("pipeline_check: {}", app.check.metadata()),
    ]
}

fn program_text_lines(app: &App<'_>) -> Vec<String> {
    plain_lines(program_lines(app))
}

fn selected_program_index(app: &App<'_>, lines: &[String]) -> Option<usize> {
    let selected_pc = selected_pc(app)?;
    visible_pc_entries(app.trace, app.show_raw_only)
        .iter()
        .position(|entry| entry.pc == selected_pc)
        .filter(|index| *index < lines.len())
}

fn translation_text_columns(app: &App<'_>, pc: u64) -> (Vec<String>, Vec<String>) {
    let (left, right) = aligned_translation_lines(app, pc);
    (plain_lines(left), plain_lines(right))
}

fn layout_for_pc_text_lines(app: &App<'_>, pc: u64) -> Vec<String> {
    plain_lines(layout_for_pc_lines(app, pc))
}

fn layout_neighborhood_text_lines(app: &App<'_>, offset: usize) -> Vec<String> {
    plain_lines(layout_neighborhood_lines(app, offset))
}

fn active_original_text_lines(app: &App<'_>, session: &ActiveStepSession) -> Vec<String> {
    let mut lines = Vec::new();
    if let Some(step) = session.current_original() {
        append_original_step_lines(&mut lines, app, step);
    } else if let Some(pc) = session.current_origin_pc() {
        lines.push(Line::from(format!(
            "pinned ori_pc={pc:#x}; original not advanced by last key"
        )));
        append_raw_line(&mut lines, app, pc);
    } else {
        lines.push(Line::from("wrapper/runtime only"));
        lines.push(Line::from(format!(
            "original cursor pc={:#x}",
            session.original_pc()
        )));
        append_raw_line(&mut lines, app, session.original_pc());
    }
    lines.push(Line::from(format!(
        "original_steps={} halt={}",
        session.original_steps(),
        active_halt_label(&session.halt())
    )));
    plain_lines(lines)
}

fn active_translated_text_lines(app: &App<'_>, session: &ActiveStepSession) -> Vec<String> {
    let mut lines = vec![Line::from(format!(
        "cursor pc={:#x} offset={} current_ori_pc={}",
        session.translated_pc(),
        opt_offset_label(session.translated_offset()),
        ori_pc_label(session.current_origin_pc())
    ))];
    if let Some(offset) = session.translated_offset() {
        if let Some(insn) = layout_for_offset(app.trace, offset) {
            lines.push(Line::from(format!(
                "next off={:#x} idx={} {:?} {}",
                insn.offset, insn.index, insn.region, insn.pretty
            )));
        }
    }
    if let Some(step) = session.current_translated() {
        append_translated_step_lines(&mut lines, app, step);
    } else {
        lines.push(Line::from("last translated step: none"));
    }
    lines.push(Line::from(format!(
        "translated_steps={} halt={}",
        session.translated_steps(),
        active_halt_label(&session.halt())
    )));
    plain_lines(lines)
}

fn state_summary_text_lines(title: &str, snapshot: &StateSnapshot) -> Vec<String> {
    let mut lines = Vec::new();
    append_state_diff_lines(&mut lines, &snapshot.previous, &snapshot.current);
    let mut out = vec![title.to_string()];
    out.extend(plain_lines(lines));
    out
}

fn comparison_text_lines(app: &App<'_>, session: &ActiveStepSession) -> Vec<String> {
    plain_lines(match app.step_detail {
        StepDetailMode::Compact => compact_comparison_lines(session),
        StepDetailMode::Registers => register_comparison_lines(session),
        StepDetailMode::Memory => memory_comparison_lines(app, session),
    })
}

fn truncate_to_width(text: &str, width: usize) -> String {
    if width == 0 {
        return String::new();
    }
    let mut out = String::new();
    for ch in text.chars() {
        if out.chars().count() >= width {
            break;
        }
        out.push(ch);
    }
    out
}

struct TerminalGuard;

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let mut stdout: Stdout = io::stdout();
        let _ = execute!(stdout, LeaveAlternateScreen);
    }
}

enum Control {
    Continue,
    Quit,
}

fn apply_command(app: &mut App<'_>, line: &str) -> Control {
    match parse_command(line, app.trace, app.selection) {
        Command::Select(next) => {
            set_selection(app, next);
            app.status = if app.mode == Mode::ActiveStep {
                "selection updated; active step session remains at its live cursor".to_string()
            } else {
                format!("selected {next:?}")
            };
            Control::Continue
        }
        Command::Help => {
            app.status =
                "commands: :pc <addr>, :off <offset>, :q; keys: Tab, p/t/r, Up/Down".to_string();
            Control::Continue
        }
        Command::Quit => Control::Quit,
        Command::Invalid(message) => {
            app.status = message;
            Control::Continue
        }
    }
}

fn select_next_pc(app: &mut App<'_>, delta: isize) {
    if let Some(pc) = next_visible_pc(app.trace, app.selection, delta, app.show_raw_only) {
        set_selection(app, Selection::Pc(pc));
        app.status = format!("selected pc {pc:#x}");
    } else {
        app.status = "no PC in that direction".to_string();
    }
}

fn set_selection(app: &mut App<'_>, selection: Selection) {
    app.selection = selection;
    clear_in_panel_selection(app);
    app.raw_scroll = 0;
    app.rephrase_scroll = 0;
    app.layout_scroll = 0;
}

fn set_focus(app: &mut App<'_>, focus: FocusPanel) {
    app.focus = focus;
    app.status = format!("focused {}", app.focus.name());
}

fn scroll_focus(app: &mut App<'_>, delta: i16) {
    let panel = app.focus;
    let scroll = match panel {
        FocusPanel::Cfg => {
            if delta >= 0 {
                select_next_pc(app, 1);
            } else {
                select_next_pc(app, -1);
            }
            return;
        }
        FocusPanel::Rephrase => &mut app.rephrase_scroll,
        FocusPanel::Layout => &mut app.layout_scroll,
    };

    if delta < 0 {
        *scroll = scroll.saturating_sub(delta.unsigned_abs());
    } else {
        *scroll = scroll.saturating_add(delta as u16);
    }
    app.status = format!("{} scroll={}", panel.name(), *scroll);
}

fn scroll_step_detail(app: &mut App<'_>, delta: i16) {
    if delta < 0 {
        app.layout_scroll = app.layout_scroll.saturating_sub(delta.unsigned_abs());
    } else {
        app.layout_scroll = app.layout_scroll.saturating_add(delta as u16);
    }
    app.status = format!("{} scroll={}", app.step_detail.name(), app.layout_scroll);
}

fn export_panel_text(app: &mut App<'_>) {
    match current_panel_export(app).and_then(copy_and_export_panel_text) {
        Ok(status) => app.status = status,
        Err(message) => app.status = format!("export failed: {message}"),
    }
}

fn copy_panel_text(app: &mut App<'_>) {
    match current_panel_export(app).and_then(copy_and_export_panel_text) {
        Ok(status) => app.status = status,
        Err(message) => app.status = format!("copy failed: {message}"),
    }
}

fn copy_and_export_panel_text(export: PanelExport) -> Result<String, String> {
    let text = export.lines.join("\n");
    let clipboard_status = copy_text_to_clipboard(&text);
    let export_status = write_panel_export(export)?;
    Ok(match clipboard_status {
        Ok(()) => format!("{export_status} | copied to clipboard"),
        Err(message) => format!("{export_status} | clipboard unavailable: {message}"),
    })
}

fn copy_text_to_clipboard(text: &str) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        return copy_text_with_command("pbcopy", &[], text);
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    {
        return copy_text_with_command("wl-copy", &[], text)
            .or_else(|_| copy_text_with_command("xclip", &["-selection", "clipboard"], text))
            .or_else(|_| copy_text_with_command("xsel", &["--clipboard", "--input"], text));
    }

    #[cfg(not(any(unix, target_os = "macos")))]
    {
        Err("clipboard copying is not supported on this platform".to_string())
    }
}

fn copy_text_with_command(command: &str, args: &[&str], text: &str) -> Result<(), String> {
    let mut child = ProcessCommand::new(command)
        .args(args)
        .stdin(Stdio::piped())
        .spawn()
        .map_err(|err| format!("{command}: {err}"))?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(text.as_bytes())
            .map_err(|err| format!("{command}: {err}"))?;
    }
    let status = child.wait().map_err(|err| format!("{command}: {err}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("{command} exited with {status}"))
    }
}

struct PanelExport {
    title: String,
    lines: Vec<String>,
}

fn current_panel_export(app: &App<'_>) -> Result<PanelExport, String> {
    match app.mode {
        Mode::Explore => explore_panel_export(app),
        Mode::ActiveStep => active_step_panel_export(app),
    }
}

fn explore_panel_export(app: &App<'_>) -> Result<PanelExport, String> {
    let title = app.focus.name().to_string();
    let lines = match app.focus {
        FocusPanel::Cfg => export_program_lines(app),
        FocusPanel::Rephrase => match app.selection {
            Selection::Pc(pc) => export_translation_lines(app, pc),
            Selection::Offset(_) => vec!["select an original PC to inspect rephrase".to_string()],
        },
        FocusPanel::Layout => match app.selection {
            Selection::Pc(pc) => export_layout_for_pc_lines(app, pc),
            Selection::Offset(offset) => export_layout_neighborhood_lines(app, offset),
        },
    };

    Ok(PanelExport {
        title,
        lines,
    })
}

fn active_step_panel_export(app: &App<'_>) -> Result<PanelExport, String> {
    let Some(session) = app.active_step.as_ref() else {
        return Err("active session is not initialized".to_string());
    };
    let (title, lines) = match app.mouse_selection.map(|sel| sel.panel) {
        Some(MousePanel::ActiveOriginal) => (
            "Original".to_string(),
            export_selected_lines(active_original_text_lines(app, session), panel_selection_range(app, MousePanel::ActiveOriginal)),
        ),
        Some(MousePanel::ActiveTranslated) => (
            "Translated".to_string(),
            export_selected_lines(active_translated_text_lines(app, session), panel_selection_range(app, MousePanel::ActiveTranslated)),
        ),
        Some(MousePanel::ActiveStateOriginal) => (
            "Original State Summary".to_string(),
            export_selected_lines(state_summary_text_lines("Original State Summary", session.original_snapshot()), panel_selection_range(app, MousePanel::ActiveStateOriginal)),
        ),
        Some(MousePanel::ActiveStateTranslated) => (
            "Translated State Summary".to_string(),
            export_selected_lines(state_summary_text_lines("Translated State Summary", session.translated_snapshot()), panel_selection_range(app, MousePanel::ActiveStateTranslated)),
        ),
        Some(MousePanel::ActiveComparison) | None => {
            let lines = match app.step_detail {
                StepDetailMode::Compact => compact_comparison_lines(session),
                StepDetailMode::Registers => register_comparison_lines(session),
                StepDetailMode::Memory => memory_comparison_lines(app, session),
            };
            (
                format!("Comparison {}", app.step_detail.name()),
                export_selected_lines(
                    plain_lines(lines),
                    panel_selection_range(app, MousePanel::ActiveComparison),
                ),
            )
        }
        Some(MousePanel::Program)
        | Some(MousePanel::Translation)
        | Some(MousePanel::Result) => {
            let lines = match app.step_detail {
                StepDetailMode::Compact => compact_comparison_lines(session),
                StepDetailMode::Registers => register_comparison_lines(session),
                StepDetailMode::Memory => memory_comparison_lines(app, session),
            };
            (
                format!("Comparison {}", app.step_detail.name()),
                plain_lines(lines),
            )
        }
    };

    Ok(PanelExport {
        title,
        lines,
    })
}

fn export_program_lines(app: &App<'_>) -> Vec<String> {
    export_selected_lines(plain_lines(program_lines(app)), panel_selection_range(app, MousePanel::Program))
}

fn export_translation_lines(app: &App<'_>, pc: u64) -> Vec<String> {
    if let Some((start, end)) = panel_selection_range(app, MousePanel::Translation) {
        return translation_selected_lines(app, pc, start, end);
    }
    plain_lines(translation_export_lines(app, pc))
}

fn export_layout_for_pc_lines(app: &App<'_>, pc: u64) -> Vec<String> {
    export_selected_lines(plain_lines(layout_for_pc_lines(app, pc)), panel_selection_range(app, MousePanel::Result))
}

fn export_layout_neighborhood_lines(app: &App<'_>, offset: usize) -> Vec<String> {
    export_selected_lines(plain_lines(layout_neighborhood_lines(app, offset)), panel_selection_range(app, MousePanel::Result))
}

fn translation_selected_lines(app: &App<'_>, pc: u64, start: usize, end: usize) -> Vec<String> {
    let (left, right) = translation_text_columns(app, pc);
    let start = start.min(left.len().saturating_sub(1));
    let end = end.min(left.len().saturating_sub(1));
    let range_start = start.min(end);
    let range_end = start.max(end);
    (range_start..=range_end)
        .map(|idx| {
            let left = left.get(idx).cloned().unwrap_or_default();
            let right = right.get(idx).cloned().unwrap_or_default();
            format!("{left}\t|\t{right}")
        })
        .collect()
}

fn export_selected_lines(lines: Vec<String>, selection: Option<(usize, usize)>) -> Vec<String> {
    let Some((start, end)) = selection else {
        return lines;
    };
    if lines.is_empty() {
        return lines;
    }
    let start = start.min(lines.len() - 1);
    let end = end.min(lines.len() - 1);
    let (start, end) = (start.min(end), start.max(end));
    lines[start..=end].to_vec()
}

fn panel_selection_range(app: &App<'_>, panel: MousePanel) -> Option<(usize, usize)> {
    let selection = app.mouse_selection?;
    if selection.panel == panel {
        Some((selection.start, selection.end))
    } else {
        None
    }
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

fn plain_lines(lines: Vec<Line<'static>>) -> Vec<String> {
    lines.into_iter().map(plain_line).collect()
}

fn plain_line(line: Line<'_>) -> String {
    line.spans
        .iter()
        .map(|span| span.content.as_ref())
        .collect::<Vec<_>>()
        .join("")
}

fn toggle_mode(app: &mut App<'_>) {
    match app.mode {
        Mode::Explore => enter_step_mode(app),
        Mode::ActiveStep => leave_step_mode(app),
    }
}

fn enter_step_mode(app: &mut App<'_>) {
    match ActiveStepSession::new(
        app.trace.input.text_base,
        app.text_bytes.clone(),
        app.trace.input.entry_pc,
        app.initial_state.clone(),
        &app.trace.execution_fragment,
        ActiveStepOrigin::from_trace_fragment(&app.trace.fragment),
    ) {
        Ok(session) => {
            app.active_step = Some(session);
            app.mode = Mode::ActiveStep;
            app.step_detail = StepDetailMode::Compact;
            clear_in_panel_selection(app);
            app.raw_scroll = 0;
            app.rephrase_scroll = 0;
            app.layout_scroll = 0;
            app.status =
                "mode=active-step start=entry; selected explore PC is not replayed yet".to_string();
        }
        Err(message) => {
            app.status = format!("step mode unavailable: {message}");
        }
    }
}

fn leave_step_mode(app: &mut App<'_>) {
    if let Some(session) = &app.active_step {
        app.selection = session
            .current_translated()
            .and_then(|step| step.ori_pc.map(Selection::Pc))
            .or_else(|| session.translated_offset().map(Selection::Offset))
            .unwrap_or(app.selection);
    }
    app.active_step = None;
    app.mode = Mode::Explore;
    clear_in_panel_selection(app);
    app.raw_scroll = 0;
    app.rephrase_scroll = 0;
    app.layout_scroll = 0;
    app.status = "mode=explore".to_string();
}

fn step_translated(app: &mut App<'_>) {
    let Some(session) = app.active_step.as_mut() else {
        app.status = "step mode unavailable".to_string();
        return;
    };
    let event = session.step_translated();
    app.status = active_event_status(session, &event);
}

fn step_group(app: &mut App<'_>) {
    let Some(session) = app.active_step.as_mut() else {
        app.status = "step mode unavailable".to_string();
        return;
    };
    let event = session.step_group();
    app.status = active_event_status(session, &event);
}

fn reset_step_mode(app: &mut App<'_>) {
    let Some(session) = app.active_step.as_mut() else {
        app.status = "step mode unavailable".to_string();
        return;
    };
    match session.reset() {
        Ok(()) => {
            app.raw_scroll = 0;
            app.rephrase_scroll = 0;
            app.layout_scroll = 0;
            app.status = "active step reset to entry".to_string();
        }
        Err(message) => {
            app.status = format!("reset failed: {message}");
        }
    }
}

fn active_step_down(app: &mut App<'_>) {
    match app.step_detail {
        StepDetailMode::Compact => {
            app.status = "Down is disabled in compact mode; use j for one instruction".to_string();
        }
        StepDetailMode::Registers | StepDetailMode::Memory => scroll_step_detail(app, 1),
    }
}

fn active_step_up(app: &mut App<'_>) {
    match app.step_detail {
        StepDetailMode::Compact => {
            app.status = "reverse execution is not supported; use R to reset".to_string();
        }
        StepDetailMode::Registers | StepDetailMode::Memory => scroll_step_detail(app, -1),
    }
}

fn toggle_step_detail(app: &mut App<'_>, detail: StepDetailMode) {
    app.step_detail = if app.step_detail == detail {
        StepDetailMode::Compact
    } else {
        detail
    };
    app.layout_scroll = 0;
    app.status = format!("comparison={}", app.step_detail.name());
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

enum Command {
    Select(Selection),
    Help,
    Quit,
    Invalid(String),
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

fn draw(frame: &mut Frame<'_>, app: &App<'_>) {
    let root = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(6),
            Constraint::Min(8),
            Constraint::Length(4),
        ])
        .split(frame.size());

    draw_header(frame, app, root[0]);

    match app.mode {
        Mode::Explore => {
            let body = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Length(54), Constraint::Min(50)])
                .split(root[1]);
            draw_pc_list(frame, app, body[0]);
            draw_detail(frame, app, body[1]);
        }
        Mode::ActiveStep => draw_active_step(frame, app, root[1]),
    }
    draw_footer(frame, app, root[2]);
}

fn draw_header(frame: &mut Frame<'_>, app: &App<'_>, area: Rect) {
    let runtime = app
        .trace
        .run
        .as_ref()
        .map(|run| format!("runtime: steps={} halt={:?}", run.steps, run.halt))
        .unwrap_or_else(|| "runtime: not-run".to_string());
    let text = vec![
        Line::from(vec![
            Span::styled(
                "KJIT Explorer",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!(
                "  mode={} entry={:#x} text_base={:#x} fragment_entry={:#x} view={}",
                app.mode.name(),
                app.trace.input.entry_pc,
                app.trace.input.text_base,
                app.trace.fragment.entry_offset,
                if app.show_raw_only { "all" } else { "cfg" },
            )),
        ]),
        Line::from(format!(
            "raw={} cfg_blocks={} translated={} fragment_insns={}",
            app.trace.raw.len(),
            app.trace.cfg.blocks.len(),
            app.trace.translated.len(),
            app.trace.fragment.insns.len(),
        )),
        Line::from(runtime),
        Line::from(format!("pipeline_check: {}", app.check.metadata())),
    ];
    frame.render_widget(
        Paragraph::new(text).block(Block::default().borders(Borders::ALL)),
        area,
    );
}

fn draw_pc_list(frame: &mut Frame<'_>, app: &App<'_>, area: Rect) {
    let entries = visible_pc_entries(app.trace, app.show_raw_only);
    let selected_pc = selected_pc(app);
    let selected_index = selected_pc
        .and_then(|pc| entries.iter().position(|entry| entry.pc == pc))
        .unwrap_or(0);
    let visible_rows = usize::from(area.height.saturating_sub(2)).max(1);
    let start = selected_index.saturating_sub(visible_rows / 2);
    let end = (start + visible_rows).min(entries.len());

    let items = entries[start..end]
        .iter()
        .map(|entry| {
            let style = if Some(entry.pc) == selected_pc {
                Style::default().fg(Color::Black).bg(Color::Yellow)
            } else if entry.pc == app.trace.input.entry_pc {
                Style::default().fg(Color::Green)
            } else if entry.cfg_block.is_none() {
                Style::default().fg(Color::DarkGray)
            } else {
                Style::default()
            };
            ListItem::new(format!(
                "{:#010x} {:<8} {}",
                entry.pc,
                pc_stage_label(entry),
                pc_brief(app.trace, entry.pc)
            ))
            .style(style)
        })
        .collect::<Vec<_>>();

    frame.render_widget(
        List::new(items).block(
            Block::default()
                .title("Program")
                .border_style(focus_style(app, FocusPanel::Cfg))
                .borders(Borders::ALL),
        ),
        area,
    );
}

fn program_lines(app: &App<'_>) -> Vec<Line<'static>> {
    let selected_pc = selected_pc(app);
    visible_pc_entries(app.trace, app.show_raw_only)
        .into_iter()
        .map(|entry| {
            let marker = if Some(entry.pc) == selected_pc {
                ">"
            } else {
                " "
            };
            Line::from(format!(
                "{marker} {:#010x} {:<8} {}",
                entry.pc,
                pc_stage_label(entry),
                pc_brief(app.trace, entry.pc)
            ))
        })
        .collect()
}

fn selected_pc(app: &App<'_>) -> Option<u64> {
    match app.selection {
        Selection::Pc(pc) => Some(pc),
        Selection::Offset(offset) => app
            .trace
            .selected_offset(offset)
            .and_then(|entry| entry.ori_pc),
    }
}

fn visible_pc_entries<'a>(
    trace: &'a PipelineTrace,
    show_raw_only: bool,
) -> Vec<&'a kjit_harness::trace::PcIndexEntry> {
    trace
        .pc_index
        .iter()
        .filter(|entry| show_raw_only || entry.cfg_block.is_some())
        .collect()
}

fn pc_stage_label(entry: &kjit_harness::trace::PcIndexEntry) -> String {
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

fn focus_style(app: &App<'_>, panel: FocusPanel) -> Style {
    if app.focus == panel {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default()
    }
}

fn draw_detail(frame: &mut Frame<'_>, app: &App<'_>, area: Rect) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
        .split(area);

    match app.selection {
        Selection::Pc(pc) => {
            draw_rephrase(frame, app, pc, rows[0]);
            draw_layout_for_pc(frame, app, pc, rows[1]);
        }
        Selection::Offset(offset) => {
            draw_empty(
                frame,
                "Translation",
                "select an original PC to inspect rephrase",
                rows[0],
            );
            draw_layout_neighborhood(frame, app, offset, rows[1]);
        }
    }
}

fn draw_active_step(frame: &mut Frame<'_>, app: &App<'_>, area: Rect) {
    let Some(session) = app.active_step.as_ref() else {
        draw_empty(
            frame,
            "Active Step",
            "active session is not initialized",
            area,
        );
        return;
    };

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(8),
            Constraint::Length(8),
            Constraint::Min(8),
        ])
        .split(area);
    let top = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(rows[0]);
    let state = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(rows[1]);

    draw_active_original(frame, app, session, top[0]);
    draw_active_translated(frame, app, session, top[1]);
    draw_state_summary(
        frame,
        "Original State Summary",
        session.original_snapshot(),
        state[0],
    );
    draw_state_summary(
        frame,
        "Translated State Summary",
        session.translated_snapshot(),
        state[1],
    );
    draw_comparison(frame, app, session, rows[2]);
}

fn draw_active_original(
    frame: &mut Frame<'_>,
    app: &App<'_>,
    session: &ActiveStepSession,
    area: Rect,
) {
    let mut lines = Vec::new();
    if let Some(step) = session.current_original() {
        append_original_step_lines(&mut lines, app, step);
    } else if let Some(pc) = session.current_origin_pc() {
        lines.push(Line::from(format!(
            "pinned ori_pc={pc:#x}; original not advanced by last key"
        )));
        append_raw_line(&mut lines, app, pc);
    } else {
        lines.push(Line::from("wrapper/runtime only"));
        lines.push(Line::from(format!(
            "original cursor pc={:#x}",
            session.original_pc()
        )));
        append_raw_line(&mut lines, app, session.original_pc());
    }
    lines.push(Line::from(format!(
        "original_steps={} halt={}",
        session.original_steps(),
        active_halt_label(&session.halt())
    )));

    frame.render_widget(
        Paragraph::new(lines)
            .block(Block::default().title("Original").borders(Borders::ALL))
            .scroll((app.raw_scroll, 0))
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn draw_active_translated(
    frame: &mut Frame<'_>,
    app: &App<'_>,
    session: &ActiveStepSession,
    area: Rect,
) {
    let mut lines = vec![Line::from(format!(
        "cursor pc={:#x} offset={} current_ori_pc={}",
        session.translated_pc(),
        opt_offset_label(session.translated_offset()),
        ori_pc_label(session.current_origin_pc())
    ))];
    if let Some(offset) = session.translated_offset() {
        if let Some(insn) = layout_for_offset(app.trace, offset) {
            lines.push(Line::from(format!(
                "next off={:#x} idx={} {:?} {}",
                insn.offset, insn.index, insn.region, insn.pretty
            )));
        }
    }
    if let Some(step) = session.current_translated() {
        append_translated_step_lines(&mut lines, app, step);
    } else {
        lines.push(Line::from("last translated step: none"));
    }
    lines.push(Line::from(format!(
        "translated_steps={} halt={}",
        session.translated_steps(),
        active_halt_label(&session.halt())
    )));

    frame.render_widget(
        Paragraph::new(lines)
            .block(Block::default().title("Translated").borders(Borders::ALL))
            .scroll((app.rephrase_scroll, 0))
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn append_original_step_lines(
    lines: &mut Vec<Line<'static>>,
    app: &App<'_>,
    step: &OriginalSideState,
) {
    lines.push(Line::from(format!(
        "last original pc={:#x} next={} executed={}",
        step.pc,
        ori_pc_label(step.next_pc),
        step.executed
    )));
    append_raw_line(lines, app, step.pc);
    if let Some(exit) = step.runtime_exit {
        lines.push(Line::from(pretty_runtime_exit(exit)));
    }
    if let Some(resume_pc) = step.resumed_at {
        lines.push(Line::from(format!(
            "mocked continuation resume_pc={resume_pc:#x}"
        )));
    }
    if let Some(halt) = step.halt_reason {
        lines.push(Line::from(format!("halt={halt:?}")));
    }
}

fn append_translated_step_lines(
    lines: &mut Vec<Line<'static>>,
    app: &App<'_>,
    step: &TranslatedSideState,
) {
    lines.push(Line::from(format!(
        "last off={} idx={} next={} ori_pc={} executed={}",
        opt_offset_label(step.offset),
        opt_usize_label(step.insn_index),
        opt_offset_label(step.next_offset),
        ori_pc_label(step.ori_pc),
        step.executed
    )));
    if let Some(offset) = step.offset {
        if let Some(insn) = layout_for_offset(app.trace, offset) {
            lines.push(layout_line(insn));
        }
    }
    if let Some(transition) = step.runtime_transition {
        lines.push(Line::from(format!("runtime_transition={transition:?}")));
    }
    if let Some(halt) = &step.halt {
        lines.push(Line::from(format!("halt={halt:?}")));
    }
}

fn append_raw_line(lines: &mut Vec<Line<'static>>, app: &App<'_>, pc: u64) {
    if let Some(raw) = app.trace.raw.iter().find(|insn| insn.pc == pc) {
        lines.push(Line::from(format!(
            "raw off={:#x} word={:#010x} {}",
            raw.text_offset, raw.word, raw.pretty
        )));
    }
}

fn draw_state_summary(
    frame: &mut Frame<'_>,
    title: &'static str,
    snapshot: &StateSnapshot,
    area: Rect,
) {
    let mut lines = Vec::new();
    append_state_diff_lines(&mut lines, &snapshot.previous, &snapshot.current);
    frame.render_widget(
        Paragraph::new(lines)
            .block(Block::default().title(title).borders(Borders::ALL))
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn draw_comparison(frame: &mut Frame<'_>, app: &App<'_>, session: &ActiveStepSession, area: Rect) {
    let lines = match app.step_detail {
        StepDetailMode::Compact => compact_comparison_lines(session),
        StepDetailMode::Registers => register_comparison_lines(session),
        StepDetailMode::Memory => memory_comparison_lines(app, session),
    };
    frame.render_widget(
        Paragraph::new(lines)
            .block(
                Block::default()
                    .title(format!("Comparison {}", app.step_detail.name()))
                    .borders(Borders::ALL),
            )
            .scroll((app.layout_scroll, 0))
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn compact_comparison_lines(session: &ActiveStepSession) -> Vec<Line<'static>> {
    let original = &session.original_snapshot().current;
    let translated = &session.translated_snapshot().current;
    let mut lines = vec![
        Line::from(format!(
            "state_equal={} halt={}",
            original == translated,
            active_halt_label(&session.halt())
        )),
        Line::from(format!(
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
    lines.push(Line::from(format!(
        "different_register_rows={} changed_memory_rows={}",
        diff_count, memory_count
    )));
    lines
}

fn register_comparison_lines(session: &ActiveStepSession) -> Vec<Line<'static>> {
    let mut lines = vec![Line::from(
        "reg   original             translated           status",
    )];
    for row in register_comparison(
        &session.original_snapshot().current,
        &session.translated_snapshot().current,
    ) {
        lines.push(Line::from(format!(
            "{:<5} {:<20} {:<20} {}",
            row.name,
            comparison_value_label(&row.original),
            comparison_value_label(&row.translated),
            if row.equal { "=" } else { "!" }
        )));
    }
    lines
}

fn memory_comparison_lines(app: &App<'_>, session: &ActiveStepSession) -> Vec<Line<'static>> {
    let mut lines = vec![Line::from(
        "addr               before original translated status",
    )];
    let rows = memory_comparison(
        &app.initial_state,
        &session.original_snapshot().current,
        &session.translated_snapshot().current,
        &session.runtime_owned_ranges(),
    );
    if rows.is_empty() {
        lines.push(Line::from("no user-memory differences"));
        return lines;
    }
    for row in rows.iter().take(200) {
        lines.push(memory_row_line(row));
    }
    if rows.len() > 200 {
        lines.push(Line::from(format!("... +{} more rows", rows.len() - 200)));
    }
    lines
}

fn memory_row_line(row: &MemoryComparisonRow) -> Line<'static> {
    Line::from(format!(
        "{:#018x} {:<6} {:<8} {:<10} {}",
        row.addr,
        byte_label(row.before),
        byte_label(row.original),
        byte_label(row.translated),
        if row.equal { "=" } else { "!" }
    ))
}

fn draw_rephrase(frame: &mut Frame<'_>, app: &App<'_>, pc: u64, area: Rect) {
    let outer = Block::default()
        .title("Translation")
        .border_style(focus_style(app, FocusPanel::Rephrase))
        .borders(Borders::ALL);
    let inner = outer.inner(area);
    frame.render_widget(outer, area);

    let columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(inner);

    let (rephrased, virtualized) = aligned_translation_lines(app, pc);
    render_translation_column(
        frame,
        "Rephrased",
        rephrased,
        app.rephrase_scroll,
        columns[0],
    );
    render_translation_column(
        frame,
        "Virtualized",
        virtualized,
        app.rephrase_scroll,
        columns[1],
    );
}

#[derive(Clone)]
struct TranslationRow {
    block_index: usize,
    index_in_block: usize,
    text: String,
}

fn aligned_translation_lines(app: &App<'_>, pc: u64) -> (Vec<Line<'static>>, Vec<Line<'static>>) {
    let rephrased = translation_rows(&app.trace.rephrased, pc);
    let virtualized = translation_rows(&app.trace.virtualized, pc);
    if rephrased.is_empty() && virtualized.is_empty() {
        return (vec![Line::from("none")], vec![Line::from("none")]);
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
                .map(|row| Line::from(row.text.clone()))
                .unwrap_or_else(|| Line::from(""))
        })
        .collect();
    let right = keys
        .iter()
        .map(|key| {
            virtualized
                .iter()
                .find(|row| (row.block_index, row.index_in_block) == *key)
                .map(|row| Line::from(row.text.clone()))
                .unwrap_or_else(|| Line::from(""))
        })
        .collect();
    (left, right)
}

fn translation_export_lines(app: &App<'_>, pc: u64) -> Vec<Line<'static>> {
    let (rephrased, virtualized) = aligned_translation_lines(app, pc);
    let mut lines = Vec::with_capacity(rephrased.len() + virtualized.len() + 3);
    lines.push(Line::from("Rephrased"));
    lines.extend(rephrased);
    lines.push(Line::from(""));
    lines.push(Line::from("Virtualized"));
    lines.extend(virtualized);
    lines
}

fn translation_rows(
    blocks: &[kjit_harness::trace::TraceRephrasedBlock],
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

fn render_translation_column(
    frame: &mut Frame<'_>,
    title: &'static str,
    lines: Vec<Line<'static>>,
    scroll: u16,
    area: Rect,
) {
    frame.render_widget(
        Paragraph::new(lines)
            .block(Block::default().title(title).borders(Borders::ALL))
            .scroll((scroll, 0))
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn draw_layout_for_pc(frame: &mut Frame<'_>, app: &App<'_>, pc: u64, area: Rect) {
    frame.render_widget(
        Paragraph::new(layout_for_pc_lines(app, pc))
            .block(
                Block::default()
                    .title("Result")
                    .border_style(focus_style(app, FocusPanel::Layout))
                    .borders(Borders::ALL),
            )
            .scroll((app.layout_scroll, 0))
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn layout_for_pc_lines(app: &App<'_>, pc: u64) -> Vec<Line<'static>> {
    let lines = app
        .trace
        .fragment
        .insns
        .iter()
        .filter(|insn| insn.ori_pc == Some(pc))
        .map(layout_line)
        .collect::<Vec<_>>();
    if lines.is_empty() {
        vec![Line::from("no layout instruction with this original PC")]
    } else {
        lines
    }
}

fn draw_layout_neighborhood(frame: &mut Frame<'_>, app: &App<'_>, offset: usize, area: Rect) {
    frame.render_widget(
        Paragraph::new(layout_neighborhood_lines(app, offset))
            .block(
                Block::default()
                    .title("Result")
                    .border_style(focus_style(app, FocusPanel::Layout))
                    .borders(Borders::ALL),
            )
            .scroll((app.layout_scroll, 0))
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn layout_neighborhood_lines(app: &App<'_>, offset: usize) -> Vec<Line<'static>> {
    let center = offset / 4;
    let start = center.saturating_sub(8);
    let end = (center + 9).min(app.trace.fragment.insns.len());
    app.trace.fragment.insns[start..end]
        .iter()
        .map(layout_line)
        .collect()
}

fn draw_empty(frame: &mut Frame<'_>, title: &'static str, message: &'static str, area: Rect) {
    frame.render_widget(
        Paragraph::new(vec![Line::from(message)])
            .block(Block::default().title(title).borders(Borders::ALL)),
        area,
    );
}

fn draw_footer(frame: &mut Frame<'_>, app: &App<'_>, area: Rect) {
    let lines = if app.command_mode {
        vec![
            Line::from(format!(":{}", app.command)),
            Line::from("Enter submit | Esc cancel"),
        ]
    } else {
        let keys = match app.mode {
            Mode::Explore => {
                "Explore: s step | Tab focus | p/t/r panels | y export | a cfg/all | Up/Down move/scroll | q quit"
            }
            Mode::ActiveStep => {
                match app.step_detail {
                    StepDetailMode::Compact => {
                        "Step: Esc/s explore | Space group | j insn | y export | r registers | m memory | R reset | q quit"
                    }
                    StepDetailMode::Registers | StepDetailMode::Memory => {
                        "Step: Up/Down scroll comparison | d/u page | y export | j insn | Space group | c compact | R reset | q quit"
                    }
                }
            }
        };
        vec![Line::from(app.status.clone()), Line::from(keys)]
    };
    frame.render_widget(
        Paragraph::new(lines).block(Block::default().title("keys").borders(Borders::ALL)),
        area,
    );
}

fn layout_for_offset(
    trace: &PipelineTrace,
    offset: usize,
) -> Option<&kjit_harness::trace::TraceLayoutInsn> {
    trace
        .fragment
        .insns
        .iter()
        .find(|insn| insn.offset == offset)
}

fn append_state_diff_lines(
    lines: &mut Vec<Line<'static>>,
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
        lines.push(Line::from("regs: unchanged"));
    } else {
        let visible = changed_regs.iter().take(8).cloned().collect::<Vec<_>>();
        let suffix = if changed_regs.len() > visible.len() {
            format!(" ... +{} more", changed_regs.len() - visible.len())
        } else {
            String::new()
        };
        lines.push(Line::from(format!(
            "regs: {}{}",
            visible.join(", "),
            suffix
        )));
    }

    if before.sp() != after.sp() {
        lines.push(Line::from(format!(
            "sp: {:#x}->{:#x}",
            before.sp(),
            after.sp()
        )));
    }
    if before.flags != after.flags {
        lines.push(Line::from(format!(
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
        lines.push(Line::from("memory: unchanged"));
    } else {
        lines.push(Line::from(format!(
            "memory_changed_bytes={}",
            changed_mem.len()
        )));
        for addr in changed_mem.iter().take(8) {
            lines.push(Line::from(format!(
                "mem[{addr:#x}]: {}->{}",
                byte_label(before.memory().get(addr).copied()),
                byte_label(after.memory().get(addr).copied())
            )));
        }
        if changed_mem.len() > 8 {
            lines.push(Line::from(format!(
                "... +{} more memory byte changes",
                changed_mem.len() - 8
            )));
        }
    }

    if before == after {
        lines.push(Line::from("state_equal=true"));
    }
}

fn layout_line(insn: &kjit_harness::trace::TraceLayoutInsn) -> Line<'static> {
    Line::from(format!(
        "off={:#06x} idx={:<3} {:?} ori_pc={} {}",
        insn.offset,
        insn.index,
        insn.region,
        ori_pc_label(insn.ori_pc),
        insn.pretty
    ))
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

fn flags_label(state: &MachineState) -> String {
    flags_value_label(state.flags)
}

fn flags_value_label(flags: Flags) -> String {
    format!(
        "N{}Z{}C{}V{}",
        flags.n as u8, flags.z as u8, flags.c as u8, flags.v as u8
    )
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

fn print_trace_view(trace: &PipelineTrace, selection: Selection, check: &PipelineCheck) {
    println!("KJIT translation trace");
    println!(
        "text_base={:#x} entry_pc={:#x} text_len={} raw_insns={} cfg_blocks={} fragment_insns={} entry_offset={:#x}",
        trace.input.text_base,
        trace.input.entry_pc,
        trace.input.text_len,
        trace.raw.len(),
        trace.cfg.blocks.len(),
        trace.fragment.insns.len(),
        trace.fragment.entry_offset,
    );
    if let Some(run) = &trace.run {
        println!("runtime: steps={} halt={:?}", run.steps, run.halt);
    }
    println!("pipeline_check: {}", check.metadata());
    if let PipelineCheck::Failed { message } = check {
        println!("pipeline_check_error:\n{message}");
    }
    match selection {
        Selection::Pc(pc) => println!("selected ori_pc: {pc:#x}"),
        Selection::Offset(offset) => println!("selected fragment offset: {offset:#x}"),
    }
}

fn default_fixture_state() -> MachineState {
    let mut state = MachineState::new();
    state.write_x(12, 0x9000);
    state
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
