use std::io::{self, Stdout};
use std::path::PathBuf;
use std::time::Duration;

use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use kjit_harness::a64_pretty::pretty_runtime_exit;
use kjit_harness::model::MachineState;
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
            text_bytes,
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
    } else if let Err(err) = run_tui(&trace, config.entry_pc, check) {
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
    Step,
}

impl Mode {
    const fn name(self) -> &'static str {
        match self {
            Self::Explore => "explore",
            Self::Step => "step",
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
    mode: Mode,
    selection: Selection,
    step_cursor: usize,
    command: String,
    command_mode: bool,
    show_raw_only: bool,
    focus: FocusPanel,
    raw_scroll: u16,
    rephrase_scroll: u16,
    layout_scroll: u16,
    status: String,
}

fn run_tui(trace: &PipelineTrace, entry_pc: u64, check: PipelineCheck) -> io::Result<()> {
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
        step_cursor: step_cursor_for_selection(trace, selection).unwrap_or(0),
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
            KeyCode::Esc if app.mode == Mode::Step => leave_step_mode(&mut app),
            KeyCode::Char(':') => {
                app.command.clear();
                app.command_mode = true;
                app.status = "enter command".to_string();
            }
            KeyCode::Char('s') => toggle_mode(&mut app),
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
            KeyCode::Char(' ') if app.mode == Mode::Step => step_space(&mut app),
            KeyCode::Char('n') if app.mode == Mode::Step => step_next_group(&mut app),
            KeyCode::Right if app.mode == Mode::Step => step_next_group(&mut app),
            KeyCode::Left if app.mode == Mode::Step => step_prev_group(&mut app),
            KeyCode::Down if app.mode == Mode::Step => step_one(&mut app, 1),
            KeyCode::Up if app.mode == Mode::Step => step_one(&mut app, -1),
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
                scroll_focus(&mut app, 5);
            }
            KeyCode::PageUp | KeyCode::Char('u') => {
                scroll_focus(&mut app, -5);
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
                    Mode::Step => {
                        "Step: Esc/s explore | Space group/one | Up/Down insn | Left/Right group"
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
            app.status = if app.mode == Mode::Step {
                step_status(app)
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
    if app.mode == Mode::Step {
        if let Some(cursor) = step_cursor_for_selection(app.trace, selection) {
            app.step_cursor = cursor;
        }
    }
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

fn toggle_mode(app: &mut App<'_>) {
    match app.mode {
        Mode::Explore => enter_step_mode(app),
        Mode::Step => leave_step_mode(app),
    }
}

fn enter_step_mode(app: &mut App<'_>) {
    let Some(execution) = app.trace.execution.as_ref() else {
        app.status = "step mode unavailable: runtime trace was not collected".to_string();
        return;
    };
    if execution.translated_steps.is_empty() {
        app.status = "step mode unavailable: no translated steps".to_string();
        return;
    }

    app.step_cursor = step_cursor_for_selection(app.trace, app.selection)
        .unwrap_or(app.step_cursor.min(execution.translated_steps.len() - 1));
    app.mode = Mode::Step;
    app.raw_scroll = 0;
    app.rephrase_scroll = 0;
    app.layout_scroll = 0;
    app.status = step_status(app);
}

fn leave_step_mode(app: &mut App<'_>) {
    app.selection = selection_for_step(app.trace, app.step_cursor, app.selection);
    app.mode = Mode::Explore;
    app.raw_scroll = 0;
    app.rephrase_scroll = 0;
    app.layout_scroll = 0;
    app.status = "mode=explore".to_string();
}

fn step_space(app: &mut App<'_>) {
    let Some(step) = current_translated_step(app) else {
        app.status = "no translated step".to_string();
        return;
    };
    if step.ori_pc.is_none() {
        step_one(app, 1);
    } else {
        step_next_group(app);
    }
}

fn step_one(app: &mut App<'_>, delta: isize) {
    let Some(execution) = app.trace.execution.as_ref() else {
        app.status = "step mode unavailable".to_string();
        return;
    };
    let Some(next) = app.step_cursor.checked_add_signed(delta) else {
        app.status = "no translated step in that direction".to_string();
        return;
    };
    if next >= execution.translated_steps.len() {
        app.status = "no translated step in that direction".to_string();
        return;
    }
    app.step_cursor = next;
    app.status = step_status(app);
}

fn step_next_group(app: &mut App<'_>) {
    let Some(execution) = app.trace.execution.as_ref() else {
        app.status = "step mode unavailable".to_string();
        return;
    };
    let Some(group_index) = group_index_for_step(execution, app.step_cursor) else {
        app.status = "current step is not grouped".to_string();
        return;
    };
    let Some(group) = execution.groups.get(group_index + 1) else {
        app.status = "already at final step group".to_string();
        return;
    };
    let Some(next) = group.translated_steps.first().copied() else {
        app.status = "next step group is empty".to_string();
        return;
    };
    app.step_cursor = next;
    app.status = step_status(app);
}

fn step_prev_group(app: &mut App<'_>) {
    let Some(execution) = app.trace.execution.as_ref() else {
        app.status = "step mode unavailable".to_string();
        return;
    };
    let Some(group_index) = group_index_for_step(execution, app.step_cursor) else {
        app.status = "current step is not grouped".to_string();
        return;
    };
    let Some(prev_index) = group_index.checked_sub(1) else {
        app.status = "already at first step group".to_string();
        return;
    };
    let Some(group) = execution.groups.get(prev_index) else {
        app.status = "previous step group is missing".to_string();
        return;
    };
    let Some(next) = group.translated_steps.first().copied() else {
        app.status = "previous step group is empty".to_string();
        return;
    };
    app.step_cursor = next;
    app.status = step_status(app);
}

fn step_status(app: &App<'_>) -> String {
    let Some(execution) = app.trace.execution.as_ref() else {
        return "step mode unavailable".to_string();
    };
    let total = execution.translated_steps.len();
    let Some(step) = execution.translated_steps.get(app.step_cursor) else {
        return "no translated step".to_string();
    };
    let group = group_index_for_step(execution, app.step_cursor)
        .map(|index| format!(" group={}/{}", index + 1, execution.groups.len()))
        .unwrap_or_default();
    format!(
        "mode=step step={}/{}{} off={} ori_pc={}",
        app.step_cursor + 1,
        total,
        group,
        opt_offset_label(step.offset),
        ori_pc_label(step.ori_pc)
    )
}

fn current_translated_step<'a>(
    app: &'a App<'_>,
) -> Option<&'a kjit_harness::trace::TraceTranslatedStep> {
    app.trace
        .execution
        .as_ref()?
        .translated_steps
        .get(app.step_cursor)
}

fn step_cursor_for_selection(trace: &PipelineTrace, selection: Selection) -> Option<usize> {
    let execution = trace.execution.as_ref()?;
    match selection {
        Selection::Pc(pc) => execution
            .groups
            .iter()
            .find(|group| group.ori_pc == Some(pc))
            .and_then(|group| group.translated_steps.first().copied())
            .or_else(|| {
                execution
                    .translated_steps
                    .iter()
                    .position(|step| step.ori_pc == Some(pc))
            }),
        Selection::Offset(offset) => execution
            .translated_steps
            .iter()
            .position(|step| step.offset == Some(offset)),
    }
}

fn selection_for_step(trace: &PipelineTrace, cursor: usize, fallback: Selection) -> Selection {
    let Some(step) = trace
        .execution
        .as_ref()
        .and_then(|execution| execution.translated_steps.get(cursor))
    else {
        return fallback;
    };
    if let Some(pc) = step.ori_pc {
        Selection::Pc(pc)
    } else if let Some(offset) = step.offset {
        Selection::Offset(offset)
    } else {
        fallback
    }
}

fn group_index_for_step(
    execution: &kjit_harness::trace::TraceExecution,
    cursor: usize,
) -> Option<usize> {
    execution
        .groups
        .iter()
        .position(|group| group.translated_steps.contains(&cursor))
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

    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(54), Constraint::Min(50)])
        .split(root[1]);
    match app.mode {
        Mode::Explore => {
            draw_pc_list(frame, app, body[0]);
            draw_detail(frame, app, body[1]);
        }
        Mode::Step => {
            draw_step_list(frame, app, body[0]);
            draw_step_detail(frame, app, body[1]);
        }
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

fn draw_step_list(frame: &mut Frame<'_>, app: &App<'_>, area: Rect) {
    let Some(execution) = app.trace.execution.as_ref() else {
        draw_empty(frame, "Execution", "runtime trace was not collected", area);
        return;
    };
    if execution.translated_steps.is_empty() {
        draw_empty(frame, "Execution", "no translated steps", area);
        return;
    }

    let selected_index = app
        .step_cursor
        .min(execution.translated_steps.len().saturating_sub(1));
    let visible_rows = usize::from(area.height.saturating_sub(2)).max(1);
    let start = selected_index.saturating_sub(visible_rows / 2);
    let end = (start + visible_rows).min(execution.translated_steps.len());

    let items = (start..end)
        .map(|index| {
            let style = if index == selected_index {
                Style::default().fg(Color::Black).bg(Color::Yellow)
            } else if execution.translated_steps[index].ori_pc.is_none() {
                Style::default().fg(Color::DarkGray)
            } else {
                Style::default()
            };
            ListItem::new(translated_step_brief(app, index)).style(style)
        })
        .collect::<Vec<_>>();

    frame.render_widget(
        List::new(items).block(
            Block::default()
                .title("Execution")
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

fn draw_step_detail(frame: &mut Frame<'_>, app: &App<'_>, area: Rect) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(8),
            Constraint::Length(12),
            Constraint::Min(8),
        ])
        .split(area);

    draw_step_original(frame, app, rows[0]);
    draw_step_translated_group(frame, app, rows[1]);
    draw_step_state(frame, app, rows[2]);
}

fn draw_step_original(frame: &mut Frame<'_>, app: &App<'_>, area: Rect) {
    let Some((_, group)) = current_step_group(app) else {
        draw_empty(frame, "Original Step", "no execution group", area);
        return;
    };

    let Some(original_index) = group.original_step else {
        let lines = vec![
            Line::from("translated-only wrapper/runtime work"),
            Line::from(format!("ori_pc={}", ori_pc_label(group.ori_pc))),
            Line::from(format!("translated_steps={}", group.translated_steps.len())),
        ];
        frame.render_widget(
            Paragraph::new(lines)
                .block(
                    Block::default()
                        .title("Original Step")
                        .border_style(focus_style(app, FocusPanel::Raw))
                        .borders(Borders::ALL),
                )
                .wrap(Wrap { trim: false }),
            area,
        );
        return;
    };

    let Some(execution) = app.trace.execution.as_ref() else {
        draw_empty(
            frame,
            "Original Step",
            "runtime trace was not collected",
            area,
        );
        return;
    };
    let Some(step) = execution.original_steps.get(original_index) else {
        draw_empty(frame, "Original Step", "original step is missing", area);
        return;
    };

    let mut lines = vec![Line::from(format!(
        "original_step={} pc={:#x}",
        original_index + 1,
        step.pc
    ))];
    if let Some(raw) = app.trace.raw.iter().find(|insn| insn.pc == step.pc) {
        lines.push(Line::from(format!(
            "raw off={:#x} word={:#010x} {}",
            raw.text_offset, raw.word, raw.pretty
        )));
    }
    if let Some(exit) = step.runtime_exit {
        lines.push(Line::from(pretty_runtime_exit(exit)));
    }
    if let Some(halt) = step.halt_reason {
        lines.push(Line::from(format!("halt={halt:?}")));
    }
    if let Some(states_match) = group.states_match {
        lines.push(Line::from(format!("group_state_match={states_match}")));
    }

    frame.render_widget(
        Paragraph::new(lines)
            .block(
                Block::default()
                    .title("Original Step")
                    .border_style(focus_style(app, FocusPanel::Raw))
                    .borders(Borders::ALL),
            )
            .scroll((app.raw_scroll, 0))
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn draw_step_translated_group(frame: &mut Frame<'_>, app: &App<'_>, area: Rect) {
    let Some((group_index, group)) = current_step_group(app) else {
        draw_empty(frame, "Translated Steps", "no execution group", area);
        return;
    };

    let lines = group
        .translated_steps
        .iter()
        .map(|index| {
            let marker = if *index == app.step_cursor { ">" } else { " " };
            Line::from(format!("{marker} {}", translated_step_brief(app, *index)))
        })
        .collect::<Vec<_>>();

    frame.render_widget(
        Paragraph::new(lines)
            .block(
                Block::default()
                    .title(format!("Translated Steps group #{}", group_index + 1))
                    .border_style(focus_style(app, FocusPanel::Rephrase))
                    .borders(Borders::ALL),
            )
            .scroll((app.rephrase_scroll, 0))
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn draw_step_state(frame: &mut Frame<'_>, app: &App<'_>, area: Rect) {
    let Some(execution) = app.trace.execution.as_ref() else {
        draw_empty(frame, "State", "runtime trace was not collected", area);
        return;
    };
    let Some(step) = execution.translated_steps.get(app.step_cursor) else {
        draw_empty(frame, "State", "no translated step", area);
        return;
    };

    let mut lines = vec![Line::from(step_status(app))];
    if let Some(transition) = step.runtime_transition {
        lines.push(Line::from(format!("runtime_transition={transition:?}")));
    }
    if let Some(halt) = &step.halt {
        lines.push(Line::from(format!("halt={halt:?}")));
    }
    if let Some((_, group)) = current_step_group(app) {
        if let Some(states_match) = group.states_match {
            lines.push(Line::from(format!("group_state_match={states_match}")));
        }
    }

    if app.step_cursor == 0 {
        lines.push(Line::from(
            "before-state unavailable for first translated step",
        ));
    } else if let Some(previous) = execution.translated_steps.get(app.step_cursor - 1) {
        append_state_diff_lines(&mut lines, &previous.state, &step.state);
    }

    frame.render_widget(
        Paragraph::new(lines)
            .block(
                Block::default()
                    .title("State")
                    .border_style(focus_style(app, FocusPanel::Layout))
                    .borders(Borders::ALL),
            )
            .scroll((app.layout_scroll, 0))
            .wrap(Wrap { trim: false }),
        area,
    );
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
            Mode::Step => {
                "Step: Esc/s explore | Space group/one | Up/Down insn | Left/Right group | p/o/t/r panels | q quit"
            }
        };
        vec![Line::from(app.status.clone()), Line::from(keys)]
    };
    frame.render_widget(
        Paragraph::new(lines).block(Block::default().title("keys").borders(Borders::ALL)),
        area,
    );
}

fn translated_step_brief(app: &App<'_>, index: usize) -> String {
    let Some(step) = app
        .trace
        .execution
        .as_ref()
        .and_then(|execution| execution.translated_steps.get(index))
    else {
        return format!("#{:<5} <missing>", index + 1);
    };
    let layout = step
        .offset
        .and_then(|offset| layout_for_offset(app.trace, offset));
    let pretty = layout
        .map(|insn| insn.pretty.as_str())
        .unwrap_or("<runtime transition>");
    let region = layout
        .map(|insn| format!("{:?}", insn.region))
        .unwrap_or_else(|| "Runtime".to_string());
    let transition = if step.runtime_transition.is_some() {
        " transition"
    } else if step.halt.is_some() {
        " halt"
    } else {
        ""
    };

    format!(
        "#{:<5} off={} idx={} {:<8} ori_pc={} {}{}",
        index + 1,
        opt_offset_label(step.offset),
        opt_usize_label(step.insn_index),
        region,
        ori_pc_label(step.ori_pc),
        pretty,
        transition
    )
}

fn current_step_group<'a>(
    app: &'a App<'_>,
) -> Option<(usize, &'a kjit_harness::trace::TraceStepGroup)> {
    let execution = app.trace.execution.as_ref()?;
    let group_index = group_index_for_step(execution, app.step_cursor)?;
    execution
        .groups
        .get(group_index)
        .map(|group| (group_index, group))
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

fn flags_label(state: &MachineState) -> String {
    format!(
        "N{}Z{}C{}V{}",
        state.flags.n as u8, state.flags.z as u8, state.flags.c as u8, state.flags.v as u8
    )
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
