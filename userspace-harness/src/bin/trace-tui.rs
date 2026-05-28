use std::io::{self, Stdout};
use std::path::PathBuf;
use std::time::Duration;

use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph, Wrap};
use ratatui::{Frame, Terminal};
use userspace_harness::a64_pretty::pretty_runtime_exit;
use userspace_harness::model::MachineState;
use userspace_harness::run_entry_fixture;
use userspace_harness::shared::trans::input::TranslationTrigger;
use userspace_harness::shared::trans::rephrase::RephrasedInsnKind;
use userspace_harness::trace::{request_for_trace, PipelineTrace};

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

    if config.check {
        run_entry_fixture(
            "trace-tui-check",
            config.text_base,
            text_bytes,
            config.entry_pc,
            &initial_state,
        )
        .unwrap_or_else(|err| {
            eprintln!("full-pipeline check failed:\n{err}");
            std::process::exit(1);
        });
    }

    if config.dump {
        print_trace_view(&trace, Selection::Pc(config.entry_pc));
    } else if let Err(err) = run_tui(&trace, config.entry_pc) {
        eprintln!("trace-tui failed: {err}");
        std::process::exit(1);
    }
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
    selection: Selection,
    command: String,
    command_mode: bool,
    show_raw_only: bool,
    focus: FocusPanel,
    raw_scroll: u16,
    rephrase_scroll: u16,
    layout_scroll: u16,
    status: String,
}

fn run_tui(trace: &PipelineTrace, entry_pc: u64) -> io::Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let _guard = TerminalGuard;

    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    let mut app = App {
        trace,
        selection: Selection::Pc(entry_pc),
        command: String::new(),
        command_mode: false,
        show_raw_only: false,
        focus: FocusPanel::Cfg,
        raw_scroll: 0,
        rephrase_scroll: 0,
        layout_scroll: 0,
        status: "Tab focus | p/o/t/r jump panels | Up/Down move or scroll | a toggles cfg/all"
            .to_string(),
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
            KeyCode::Char(':') => {
                app.command.clear();
                app.command_mode = true;
                app.status = "enter command".to_string();
            }
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
            KeyCode::Char('n') | KeyCode::Right => {
                select_next_pc(&mut app, 1);
            }
            KeyCode::Left => {
                select_next_pc(&mut app, -1);
            }
            KeyCode::Down => {
                if app.focus == FocusPanel::Cfg {
                    select_next_pc(&mut app, 1);
                } else {
                    scroll_focus(&mut app, 1);
                }
            }
            KeyCode::Up => {
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
                app.status =
                    "Tab focus | p Program o Original t Translation r Result | Up/Down move or scroll"
                        .to_string();
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
            app.status = format!("selected {next:?}");
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
        Selection::Offset(offset) => trace.selected_offset(offset)?.original_pc?,
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
        Selection::Offset(offset) => trace.selected_offset(offset)?.original_pc?,
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
            Constraint::Length(3),
            Constraint::Min(8),
            Constraint::Length(4),
        ])
        .split(frame.size());

    draw_header(frame, app, root[0]);

    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(54), Constraint::Min(50)])
        .split(root[1]);
    draw_pc_list(frame, app, body[0]);
    draw_detail(frame, app, body[1]);
    draw_footer(frame, app, root[2]);
}

fn draw_header(frame: &mut Frame<'_>, app: &App<'_>, area: Rect) {
    let runtime = app
        .trace
        .run
        .as_ref()
        .map(|run| format!(" runtime: steps={} halt={:?}", run.steps, run.halt))
        .unwrap_or_default();
    let text = vec![
        Line::from(vec![
            Span::styled(
                "KJIT Explorer",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!(
                "  entry={:#x} text_base={:#x} fragment_entry={:#x} view={}",
                app.trace.input.entry_pc,
                app.trace.input.text_base,
                app.trace.fragment.entry_offset,
                if app.show_raw_only { "all" } else { "cfg" },
            )),
        ]),
        Line::from(format!(
            "raw={} cfg_blocks={} translated={} fragment_insns={}{}",
            app.trace.raw.len(),
            app.trace.cfg.blocks.len(),
            app.trace.translated.len(),
            app.trace.fragment.insns.len(),
            runtime
        )),
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
            .and_then(|entry| entry.original_pc),
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
) -> Vec<&'a userspace_harness::trace::PcIndexEntry> {
    trace
        .pc_index
        .iter()
        .filter(|entry| show_raw_only || entry.cfg_block.is_some())
        .collect()
}

fn pc_stage_label(entry: &userspace_harness::trace::PcIndexEntry) -> String {
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
                .find(|insn| insn.original_pc == pc)
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

fn draw_raw_cfg(frame: &mut Frame<'_>, app: &App<'_>, pc: u64, area: Rect) {
    let mut lines = Vec::new();
    lines.push(Line::from(format!("selected original pc {pc:#x}")));
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
    blocks: &[userspace_harness::trace::TraceRephrasedBlock],
    pc: u64,
) -> Vec<TranslationRow> {
    blocks
        .iter()
        .flat_map(|block| block.insns.iter())
        .filter(|insn| insn.original_pc == pc)
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
        .filter(|insn| insn.original_pc == Some(pc))
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
            "offset={:#x} runtime_pc={:#x} insn_index={} original_pc={} region={:?}",
            entry.offset,
            entry.runtime_pc,
            entry.insn_index,
            original_pc_label(entry.original_pc),
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
        vec![
            Line::from(app.status.clone()),
            Line::from(
                "Tab focus | p Program o Original t Translation r Result | a cfg/all | Up/Down move/scroll | q quit",
            ),
        ]
    };
    frame.render_widget(
        Paragraph::new(lines).block(Block::default().title("keys").borders(Borders::ALL)),
        area,
    );
}

fn layout_line(insn: &userspace_harness::trace::TraceLayoutInsn) -> Line<'static> {
    Line::from(format!(
        "off={:#06x} idx={:<3} {:?} original_pc={} {}",
        insn.offset,
        insn.index,
        insn.region,
        original_pc_label(insn.original_pc),
        insn.pretty
    ))
}

fn original_pc_label(original_pc: Option<u64>) -> String {
    match original_pc {
        Some(pc) => format!("{pc:#x}"),
        None => "None".to_string(),
    }
}

fn print_trace_view(trace: &PipelineTrace, selection: Selection) {
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
    match selection {
        Selection::Pc(pc) => println!("selected original pc: {pc:#x}"),
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
