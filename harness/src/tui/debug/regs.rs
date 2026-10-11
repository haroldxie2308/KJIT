//! The registers at `t` with the registers the last tick wrote, and the memory it wrote.

use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

use super::fmt::{dim, flags, hex128, hex64, reg_name};
use crate::model::MachineState;
use crate::session::{RegId, RegWrite, StepAt, StepView};

fn written() -> Style {
    Style::default()
        .fg(Color::Yellow)
        .add_modifier(Modifier::BOLD)
}

fn write_lines(writes: &[RegWrite]) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    for write in writes {
        let name = format!("{:<5}", reg_name(write.reg));
        match write.reg {
            RegId::V(_) => {
                // 128 bits do not fit twice on a line.
                lines.push(Line::from(vec![
                    Span::styled(name, written()),
                    Span::styled(hex128(write.old), dim()),
                ]));
                lines.push(Line::from(vec![
                    Span::raw("     -> "),
                    Span::styled(hex128(write.new), written()),
                ]));
            }
            _ => lines.push(Line::from(vec![
                Span::styled(name, written()),
                Span::styled(hex64(write.old as u64), dim()),
                Span::raw(" -> "),
                Span::styled(hex64(write.new as u64), written()),
            ])),
        }
    }
    lines
}

fn grid_lines(state: &MachineState, writes: &[RegWrite], width: u16) -> Vec<Line<'static>> {
    let wrote = |reg: RegId| writes.iter().any(|write| write.reg == reg);
    let cell = |reg: RegId, value: u64| -> Vec<Span<'static>> {
        let style = if wrote(reg) { written() } else { Style::default() };
        vec![
            Span::styled(format!("{:<4}", reg_name(reg)), style),
            Span::styled(hex64(value), style),
        ]
    };
    // Two columns need 2 * 22 characters and a gap; a narrower pane gets one.
    let columns = if width >= 48 { 2 } else { 1 };
    let mut cells: Vec<Vec<Span<'static>>> = (0..31u8)
        .map(|index| cell(RegId::X(index), state.read_x(index)))
        .collect();
    cells.push(cell(RegId::Sp, state.sp()));
    cells
        .chunks(columns)
        .map(|row| {
            let mut spans = Vec::new();
            for (position, cell) in row.iter().enumerate() {
                if position > 0 {
                    spans.push(Span::raw("  "));
                }
                spans.extend(cell.iter().cloned());
            }
            Line::from(spans)
        })
        .collect()
}

pub fn draw_regs(
    frame: &mut Frame,
    area: Rect,
    t: u64,
    state: &MachineState,
    last: Option<&StepView<'_>>,
) {
    let writes: &[RegWrite] = last.map_or(&[], |step| step.reg_writes);
    let machine = match last.map(|step| step.at) {
        Some(StepAt::Fragment { .. }) => "fragment machine (virtualized regs)",
        Some(StepAt::User { .. }) => "user",
        None => "initial state",
    };
    let mut lines = Vec::new();
    match last {
        None => lines.push(Line::styled("no tick executed yet", dim())),
        Some(step) => {
            lines.push(Line::styled(
                format!("tick {t} wrote {} register(s):", writes.len()),
                dim(),
            ));
            let shown = write_lines(writes);
            // Leave room for the grid (16 rows) and its flags line.
            let room = (area.height as usize).saturating_sub(2 + 1 + 16 + 1 + 1);
            let hidden = shown.len().saturating_sub(room);
            lines.extend(shown.into_iter().take(room));
            if hidden > 0 {
                lines.push(Line::styled(format!("... {hidden} more line(s)"), dim()));
            }
            if step.flags_before != step.flags_after {
                lines.push(Line::from(vec![
                    Span::styled("nzcv ", written()),
                    Span::raw(flags(step.flags_before)),
                    Span::raw(" -> "),
                    Span::styled(flags(step.flags_after), written()),
                ]));
            }
        }
    }
    lines.extend(grid_lines(state, writes, area.width.saturating_sub(2)));
    lines.push(Line::from(vec![
        Span::styled("nzcv ", dim()),
        Span::raw(flags(state.flags)),
        Span::styled("  tpidr ", dim()),
        Span::raw(format!("{:#x}", state.tpidr_el0)),
    ]));
    frame.render_widget(
        Paragraph::new(lines).block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!(" registers @ t={t}: {machine} ")),
        ),
        area,
    );
}

pub fn draw_mem(frame: &mut Frame, area: Rect, t: u64, last: Option<&StepView<'_>>) {
    let mut lines = Vec::new();
    match last {
        None => lines.push(Line::styled("no tick executed yet", dim())),
        Some(step) if step.mem_writes.is_empty() => {
            lines.push(Line::styled(format!("tick {t} stored nothing"), dim()))
        }
        Some(step) => {
            for write in step.mem_writes {
                let width = usize::from(write.size) * 2;
                let mut spans = vec![
                    Span::styled(format!("{:#x} ", write.addr), written()),
                    Span::raw(format!(
                        "{}B {:#0w$x} -> {:#0w$x}",
                        write.size,
                        write.old,
                        write.new,
                        w = width + 2
                    )),
                ];
                if write.runtime_owned {
                    spans.push(Span::styled("  (runtime memory)", dim()));
                }
                lines.push(Line::from(spans));
            }
        }
    }
    frame.render_widget(
        Paragraph::new(lines).block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!(" memory writes of tick {t} ")),
        ),
        area,
    );
}
