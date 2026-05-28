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

struct App<'a> {
    trace: &'a PipelineTrace,
    selection: Selection,
    command: String,
    command_mode: bool,
    show_raw_only: bool,
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
        status: "q quit | arrows/n/p move | a toggles raw-only PCs | :pc 0xADDR | :off 0xOFFSET"
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
            KeyCode::Char('n') | KeyCode::Down | KeyCode::Right => {
                select_next_pc(&mut app, 1);
            }
            KeyCode::Char('p') | KeyCode::Up | KeyCode::Left => {
                select_next_pc(&mut app, -1);
            }
            KeyCode::Char('a') => {
                app.show_raw_only = !app.show_raw_only;
                app.status = if app.show_raw_only {
                    "showing all decoded raw PCs".to_string()
                } else {
                    "showing reachable CFG PCs only".to_string()
                };
            }
            KeyCode::Char('?') | KeyCode::F(1) => {
                app.status =
                    "q quit | arrows/n/p move | a raw-only toggle | :pc <addr> | :off <offset>"
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
            app.selection = next;
            app.status = format!("selected {next:?}");
            Control::Continue
        }
        Command::Help => {
            app.status = "commands: :pc <addr>, :off <offset>, :q".to_string();
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
        app.selection = Selection::Pc(pc);
        app.status = format!("selected pc {pc:#x}");
    } else {
        app.status = "no PC in that direction".to_string();
    }
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
            Constraint::Length(if app.command_mode { 3 } else { 2 }),
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
                "KJIT trace explorer",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!(
                "  entry={:#x} text_base={:#x} fragment_entry={:#x} view={}",
                app.trace.input.entry_pc,
                app.trace.input.text_base,
                app.trace.fragment.entry_offset,
                if app.show_raw_only { "all-raw" } else { "cfg" },
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
    let items = visible_pc_entries(app.trace, app.show_raw_only)
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
                "{:#010x} {:<8} {:<10} {}",
                entry.pc,
                pc_stage_label(entry),
                offsets_label(entry),
                pc_brief(app.trace, entry.pc)
            ))
            .style(style)
        })
        .collect::<Vec<_>>();

    frame.render_widget(
        List::new(items).block(
            Block::default()
                .title("CFG / original PC index")
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

fn offsets_label(entry: &userspace_harness::trace::PcIndexEntry) -> String {
    match entry.layout_offsets.as_slice() {
        [] => String::new(),
        [offset] => format!("off={offset:#x}"),
        offsets => {
            let mut out = String::from("off=");
            for (index, offset) in offsets.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                out.push_str(&format!("{offset:#x}"));
            }
            out
        }
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
            "cfg  block #{} [{:#x}, {:#x}) prev={:?} next={:?}",
            block.index, block.start_pc, block.end_pc, block.prev, block.next
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
                    .title("raw / A64Insn / CFG")
                    .borders(Borders::ALL),
            )
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn draw_rephrase(frame: &mut Frame<'_>, app: &App<'_>, pc: u64, area: Rect) {
    let mut lines = Vec::new();
    lines.push(Line::from("rephrased"));
    push_rephrased_lines(&mut lines, &app.trace.rephrased, pc);
    lines.push(Line::from(""));
    lines.push(Line::from("virtualized"));
    push_rephrased_lines(&mut lines, &app.trace.virtualized, pc);

    frame.render_widget(
        Paragraph::new(lines)
            .block(
                Block::default()
                    .title("translated / rephrased / virtualized")
                    .borders(Borders::ALL),
            )
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn push_rephrased_lines(
    lines: &mut Vec<Line<'_>>,
    blocks: &[userspace_harness::trace::TraceRephrasedBlock],
    pc: u64,
) {
    let len_before = lines.len();
    for block in blocks {
        for insn in block.insns.iter().filter(|insn| insn.original_pc == pc) {
            lines.push(Line::from(format!(
                "  b#{} i#{} {:?} {}",
                insn.block_index, insn.index_in_block, insn.kind, insn.pretty
            )));
        }
    }
    if lines.len() == len_before {
        lines.push(Line::from("  none"));
    }
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
            .block(Block::default().title("final layout").borders(Borders::ALL))
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn draw_offset(frame: &mut Frame<'_>, app: &App<'_>, offset: usize, area: Rect) {
    let lines = if let Some(entry) = app.trace.selected_offset(offset) {
        vec![Line::from(format!(
            "offset={:#x} runtime_pc={:#x} insn_index={} original_pc={:?} region={:?}",
            entry.offset, entry.runtime_pc, entry.insn_index, entry.original_pc, entry.region
        ))]
    } else {
        vec![Line::from(format!("offset {offset:#x} is not present"))]
    };
    frame.render_widget(
        Paragraph::new(lines).block(
            Block::default()
                .title("runtime offset")
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
                    .title("layout neighborhood")
                    .borders(Borders::ALL),
            )
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
            Line::from("enter submits, esc cancels"),
        ]
    } else {
        vec![Line::from(app.status.clone())]
    };
    frame.render_widget(
        Paragraph::new(lines).block(Block::default().borders(Borders::ALL)),
        area,
    );
}

fn layout_line(insn: &userspace_harness::trace::TraceLayoutInsn) -> Line<'static> {
    Line::from(format!(
        "off={:#06x} idx={:<3} {:?} original_pc={:?} {}",
        insn.offset, insn.index, insn.region, insn.original_pc, insn.pretty
    ))
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
