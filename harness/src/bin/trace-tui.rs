use std::io::{self, Stdout};
use std::path::PathBuf;
use std::time::Duration;

use crossterm::event::{self, Event, KeyCode, KeyEventKind};
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
    } else if let Err(err) = run_tui(&trace, config.entry_pc, check, text_bytes, initial_state) {
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
            _ => {
                "s step mode | Tab focus | p/o/t/r jump panels | Up/Down move or scroll".to_string()
            }
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
    Raw,
    Rephrase,
    Layout,
}

impl FocusPanel {
    const fn next(self) -> Self {
        match self {
            Self::Cfg => Self::Raw,
            Self::Raw => Self::Rephrase,
            Self::Rephrase => Self::Layout,
            Self::Layout => Self::Cfg,
        }
    }

    const fn prev(self) -> Self {
        match self {
            Self::Cfg => Self::Layout,
            Self::Raw => Self::Cfg,
            Self::Rephrase => Self::Raw,
            Self::Layout => Self::Rephrase,
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Cfg => "Program",
            Self::Raw => "Original",
            Self::Rephrase => "Translation",
            Self::Layout => "Result",
        }
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
        if key.kind != KeyEventKind::Press {
            continue;
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
                    if matches!(apply_command(&mut app, &command), Control::Quit) {
                        break;
                    }
                }
                KeyCode::Backspace => {
                    app.command.pop();
                }
                KeyCode::Char(ch) => app.command.push(ch),
                _ => {}
            }
            continue;
        }

        match key.code {
            KeyCode::Char('q') => break,
            KeyCode::Esc if app.mode == Mode::ActiveStep => leave_step_mode(&mut app),
            KeyCode::Char(':') => {
                app.command.clear();
                app.command_mode = true;
                app.status = "enter command".to_string();
            }
            KeyCode::Char('s') => toggle_mode(&mut app),
            KeyCode::Char(' ') if app.mode == Mode::ActiveStep => step_group(&mut app),
            KeyCode::Char('j') if app.mode == Mode::ActiveStep => step_translated(&mut app),
            KeyCode::Down if app.mode == Mode::ActiveStep => active_step_down(&mut app),
            KeyCode::Char('r') if app.mode == Mode::ActiveStep => {
                toggle_step_detail(&mut app, StepDetailMode::Registers);
            }
            KeyCode::Char('m') if app.mode == Mode::ActiveStep => {
                toggle_step_detail(&mut app, StepDetailMode::Memory);
            }
            KeyCode::Char('c') if app.mode == Mode::ActiveStep => {
                app.step_detail = StepDetailMode::Compact;
                app.status = "comparison=compact".to_string();
            }
            KeyCode::Char('R') if app.mode == Mode::ActiveStep => reset_step_mode(&mut app),
            KeyCode::Up if app.mode == Mode::ActiveStep => active_step_up(&mut app),
            KeyCode::Tab => {
                app.focus = app.focus.next();
                app.status = format!("focused {}", app.focus.name());
            }
            KeyCode::BackTab => {
                app.focus = app.focus.prev();
                app.status = format!("focused {}", app.focus.name());
            }
            KeyCode::Char('p') => set_focus(&mut app, FocusPanel::Cfg),
            KeyCode::Char('o') => set_focus(&mut app, FocusPanel::Raw),
            KeyCode::Char('t') => set_focus(&mut app, FocusPanel::Rephrase),
            KeyCode::Char('r') => set_focus(&mut app, FocusPanel::Layout),
            KeyCode::Char('n') if app.mode == Mode::Explore => {
                select_next_pc(&mut app, 1);
            }
            KeyCode::Right if app.mode == Mode::Explore => {
                select_next_pc(&mut app, 1);
            }
            KeyCode::Left if app.mode == Mode::Explore => {
                select_next_pc(&mut app, -1);
            }
            KeyCode::Down if app.mode == Mode::Explore => {
                if app.focus == FocusPanel::Cfg {
                    select_next_pc(&mut app, 1);
                } else {
                    scroll_focus(&mut app, 1);
                }
            }
            KeyCode::Up if app.mode == Mode::Explore => {
                if app.focus == FocusPanel::Cfg {
                    select_next_pc(&mut app, -1);
                } else {
                    scroll_focus(&mut app, -1);
                }
            }
            KeyCode::PageDown | KeyCode::Char('d') => {
                if app.mode == Mode::ActiveStep {
                    scroll_step_detail(&mut app, 5);
                } else {
                    scroll_focus(&mut app, 5);
                }
            }
            KeyCode::PageUp | KeyCode::Char('u') => {
                if app.mode == Mode::ActiveStep {
                    scroll_step_detail(&mut app, -5);
                } else {
                    scroll_focus(&mut app, -5);
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
                        "Explore: s step | p/o/t/r panels | Up/Down move or scroll".to_string()
                    }
                    Mode::ActiveStep => {
                        "Step: Esc/s explore | Space group | j insn | r/m/c panes | R reset"
                            .to_string()
                    }
                };
            }
            _ => {}
        }
    }

    Ok(())
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
                "commands: :pc <addr>, :off <offset>, :q; keys: Tab, p/o/t/r, Up/Down".to_string();
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
        FocusPanel::Raw => &mut app.raw_scroll,
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
    let selected_pc = match app.selection {
        Selection::Pc(pc) => Some(pc),
        Selection::Offset(offset) => app
            .trace
            .selected_offset(offset)
            .and_then(|entry| entry.ori_pc),
    };
    let entries = visible_pc_entries(app.trace, app.show_raw_only);
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

fn addr_list(addrs: &[u64]) -> String {
    let mut out = String::from("[");
    for (index, addr) in addrs.iter().enumerate() {
        if index > 0 {
            out.push_str(", ");
        }
        out.push_str(&format!("{addr:#x}"));
    }
    out.push(']');
    out
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
        .constraints([
            Constraint::Length(8),
            Constraint::Length(10),
            Constraint::Min(8),
        ])
        .split(area);

    match app.selection {
        Selection::Pc(pc) => {
            draw_raw_cfg(frame, app, pc, rows[0]);
            draw_rephrase(frame, app, pc, rows[1]);
            draw_layout_for_pc(frame, app, pc, rows[2]);
        }
        Selection::Offset(offset) => {
            draw_offset(frame, app, offset, rows[0]);
            draw_empty(
                frame,
                "synced stages",
                "select an original PC to inspect rephrase",
                rows[1],
            );
            draw_layout_neighborhood(frame, app, offset, rows[2]);
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

fn draw_raw_cfg(frame: &mut Frame<'_>, app: &App<'_>, pc: u64, area: Rect) {
    let mut lines = Vec::new();
    lines.push(Line::from(format!("selected ori_pc {pc:#x}")));
    for insn in app.trace.raw.iter().filter(|insn| insn.pc == pc) {
        lines.push(Line::from(format!(
            "raw  off={:#x} word={:#010x} {}",
            insn.text_offset, insn.word, insn.pretty
        )));
        if let Some(exit) = insn.runtime_exit {
            lines.push(Line::from(format!("     {}", pretty_runtime_exit(exit))));
        }
        if let Some((taken, fallthrough)) = insn.conditional_targets {
            lines.push(Line::from(format!(
                "     conditional taken={taken:#x} fallthrough={fallthrough:#x}"
            )));
        }
    }
    if let Some(block) = app.trace.cfg_block_for_pc(pc) {
        lines.push(Line::from(format!(
            "cfg  block #{} [{:#x}, {:#x}) prev={} next={}",
            block.index,
            block.start_pc,
            block.end_pc,
            addr_list(&block.prev),
            addr_list(&block.next)
        )));
    } else {
        lines.push(Line::from(format!(
            "cfg  raw-only: not reachable from entry {:#x}",
            app.trace.input.entry_pc
        )));
    }

    frame.render_widget(
        Paragraph::new(lines)
            .block(
                Block::default()
                    .title("Original")
                    .border_style(focus_style(app, FocusPanel::Raw))
                    .borders(Borders::ALL),
            )
            .scroll((app.raw_scroll, 0))
            .wrap(Wrap { trim: false }),
        area,
    );
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
        RephrasedInsnKind::Synthetic => "SYN",
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
    let lines = app
        .trace
        .fragment
        .insns
        .iter()
        .filter(|insn| insn.ori_pc == Some(pc))
        .map(layout_line)
        .collect::<Vec<_>>();
    let lines = if lines.is_empty() {
        vec![Line::from("no layout instruction with this original PC")]
    } else {
        lines
    };

    frame.render_widget(
        Paragraph::new(lines)
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

fn draw_offset(frame: &mut Frame<'_>, app: &App<'_>, offset: usize, area: Rect) {
    let lines = if let Some(entry) = app.trace.selected_offset(offset) {
        vec![Line::from(format!(
            "offset={:#x} runtime_pc={:#x} insn_index={} ori_pc={} region={:?}",
            entry.offset,
            entry.runtime_pc,
            entry.insn_index,
            ori_pc_label(entry.ori_pc),
            entry.region
        ))]
    } else {
        vec![Line::from(format!("offset {offset:#x} is not present"))]
    };
    frame.render_widget(
        Paragraph::new(lines).block(
            Block::default()
                .title("runtime offset")
                .border_style(focus_style(app, FocusPanel::Raw))
                .borders(Borders::ALL),
        ),
        area,
    );
}

fn draw_layout_neighborhood(frame: &mut Frame<'_>, app: &App<'_>, offset: usize, area: Rect) {
    let center = offset / 4;
    let start = center.saturating_sub(8);
    let end = (center + 9).min(app.trace.fragment.insns.len());
    let lines = app.trace.fragment.insns[start..end]
        .iter()
        .map(layout_line)
        .collect::<Vec<_>>();

    frame.render_widget(
        Paragraph::new(lines)
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
                "Explore: s step | Tab focus | p/o/t/r panels | a cfg/all | Up/Down move/scroll | q quit"
            }
            Mode::ActiveStep => {
                match app.step_detail {
                    StepDetailMode::Compact => {
                        "Step: Esc/s explore | Space group | j insn | r registers | m memory | R reset | q quit"
                    }
                    StepDetailMode::Registers | StepDetailMode::Memory => {
                        "Step: Up/Down scroll comparison | d/u page | j insn | Space group | c compact | R reset | q quit"
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
