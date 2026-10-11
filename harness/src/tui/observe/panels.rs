//! The panels of observe mode. Each takes what it shows and draws it into its area.

use std::collections::BTreeMap;

use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

use super::index::{Accum, Counts, Timeline};
use crate::session::{CacheView, LinkView, Session};
use crate::shared::abi::IBTC_TABLE_WORDS;

/// Width of the timeline's label column: name, then the row's maximum.
pub(super) const GUTTER: usize = 15;

const BARS: [char; 8] = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];

const DIM: Style = Style::new().fg(Color::DarkGray);

fn block(title: String) -> Block<'static> {
    Block::default().borders(Borders::ALL).title(title)
}

fn key(text: &str) -> Span<'static> {
    Span::styled(text.to_string(), DIM)
}

fn value(text: String) -> Span<'static> {
    Span::styled(text, Style::default().add_modifier(Modifier::BOLD))
}

/// `part / whole` as a percentage; `n/a` for an empty whole.
fn percent(part: u64, whole: u64) -> String {
    if whole == 0 {
        "n/a".to_string()
    } else {
        format!("{:.1}%", part as f64 * 100.0 / whole as f64)
    }
}

pub(super) struct Status<'a> {
    pub(super) playing: bool,
    pub(super) speed: u64,
    pub(super) t: u64,
    pub(super) ticks: u64,
    pub(super) filter: &'a str,
}

/// Terminals at least this wide get the long labels of the status and summary lines.
const WIDE: u16 = 100;

pub(super) fn status(frame: &mut Frame, area: Rect, status: &Status) {
    let (label, color) = if status.playing {
        (" PLAY ", Color::Green)
    } else {
        (" PAUSE ", Color::Yellow)
    };
    let line = Line::from(vec![
        Span::styled(label, Style::default().fg(Color::Black).bg(color)),
        key(" speed "),
        value(format!("{}x", status.speed)),
        key("  t "),
        value(format!("{}/{}", status.t, status.ticks)),
        key("  log filter "),
        value(status.filter.to_string()),
        key(if area.width >= WIDE {
            "   space play  +/- speed  f filter  ? keys"
        } else {
            "  ? keys"
        }),
    ]);
    frame.render_widget(Paragraph::new(line), area);
}

/// The summary up to `t`: two lines, with short labels below `WIDE` columns.
pub(super) fn summary_lines(
    width: u16,
    t: u64,
    fragment_ticks: u64,
    counts: &Counts,
) -> Vec<Line<'static>> {
    let wide = width >= WIDE;
    let label = |long: &'static str, short: &'static str| key(if wide { long } else { short });
    let entries_per_syscall = if counts.syscalls == 0 {
        "n/a".to_string()
    } else {
        format!("{:.2}", counts.exits as f64 / counts.syscalls as f64)
    };
    vec![
        Line::from(vec![
            label("in fragments ", "frag "),
            value(percent(fragment_ticks, t)),
            key(&format!(" ({fragment_ticks}/{t} ticks)")),
            label("  syscalls ", "  syscalls "),
            value(counts.syscalls.to_string()),
            label("  translations ", "  transl "),
            value(counts.translations.to_string()),
            key(&format!(" ({} rejected)", counts.rejected)),
        ]),
        Line::from(vec![
            label("fragment exits/syscall ", "exits/syscall "),
            value(entries_per_syscall),
            key(&format!(" ({} exits)", counts.exits)),
            label("  transfers: dispatch ", "  xfer: disp "),
            value(counts.dispatch.to_string()),
            key(" link "),
            value(counts.link.to_string()),
            label(" runtime ", " rt "),
            value(counts.runtime.to_string()),
        ]),
    ]
}

pub(super) fn summary(frame: &mut Frame, area: Rect, bordered: bool, lines: Vec<Line<'static>>) {
    let paragraph = Paragraph::new(lines);
    frame.render_widget(
        if bordered {
            paragraph.block(block(" summary up to t ".to_string()))
        } else {
            paragraph
        },
        area,
    );
}

/// How a column is drawn relative to the cursor: past columns normal, the cursor's
/// column reversed, the future dimmed.
fn column_style(color: Color, column: usize, cursor: usize) -> Style {
    use std::cmp::Ordering::*;
    match column.cmp(&cursor) {
        Less => Style::default().fg(color),
        Equal => Style::default()
            .fg(color)
            .add_modifier(Modifier::REVERSED | Modifier::BOLD),
        Greater => Style::default().fg(Color::DarkGray),
    }
}

fn bar(value: f64) -> char {
    // `value` in (0, 1]: at least the lowest bar, so any activity shows.
    BARS[((value * 8.0).ceil() as usize).clamp(1, 8) - 1]
}

fn row(
    name: &str,
    max: Option<u32>,
    cells: impl Iterator<Item = (char, Color)>,
    cursor: usize,
) -> Line<'static> {
    let max = max
        .map(|max| format!("{max:>3} "))
        .unwrap_or_else(|| "    ".to_string());
    debug_assert!(name.len() <= 11, "row labels fit the label column");
    let mut spans = vec![key(&format!("{name:<11}{max}"))];
    spans.extend(cells.enumerate().map(|(column, (symbol, color))| {
        Span::styled(symbol.to_string(), column_style(color, column, cursor))
    }));
    Line::from(spans)
}

fn counts_row(name: &str, values: &[u32], color: Color, cursor: usize) -> Line<'static> {
    let max = values.iter().copied().max().expect("a timeline has columns");
    row(
        name,
        Some(max),
        values.iter().map(|&count| {
            let symbol = if count == 0 {
                ' '
            } else {
                bar(f64::from(count) / f64::from(max))
            };
            (symbol, color)
        }),
        cursor,
    )
}

/// The timeline block. `compact`: only the fragment share and the markers; the cursor
/// is the reversed column.
pub(super) fn timeline(frame: &mut Frame, area: Rect, timeline: &Timeline, t: u64, compact: bool) {
    let cursor = timeline.column_of(t);
    let mut lines = vec![row(
        "in fragment",
        None,
        timeline.fragment_share.iter().map(|share| match share {
            None => (' ', Color::Green),
            Some(share) if *share == 0.0 => ('·', Color::Cyan),
            Some(share) => (bar(*share), Color::Green),
        }),
        cursor,
    )];
    if !compact {
        lines.push(counts_row(
            "round trips",
            &timeline.round_trips,
            Color::Red,
            cursor,
        ));
        lines.push(counts_row(
            "disp+link",
            &timeline.direct,
            Color::Yellow,
            cursor,
        ));
        lines.push(counts_row(
            "syscalls",
            &timeline.syscalls,
            Color::Cyan,
            cursor,
        ));
    }
    lines.push(row(
        "translation",
        None,
        (0..timeline.width).map(|column| {
            if timeline.rejected[column] {
                ('x', Color::Red)
            } else if timeline.installed[column] {
                ('T', Color::Yellow)
            } else {
                (' ', Color::Yellow)
            }
        }),
        cursor,
    ));
    if !compact {
        lines.push(row(
            "t",
            None,
            (0..timeline.width).map(|column| {
                if column == cursor {
                    ('▲', Color::Cyan)
                } else {
                    (' ', Color::Cyan)
                }
            }),
            usize::MAX,
        ));
    }
    frame.render_widget(
        Paragraph::new(lines).block(block(format!(
            " timeline  {} ticks/column  T translated  x rejected ",
            timeline.ticks_per_column()
        ))),
        area,
    );
}

/// "+k more" line for a list cut to fit.
fn more(hidden: usize, what: &str) -> Line<'static> {
    Line::styled(format!("  ... {hidden} {what}"), DIM)
}

fn links_by_fragment(links: &[LinkView]) -> BTreeMap<usize, Vec<&LinkView>> {
    let mut by_fragment: BTreeMap<usize, Vec<&LinkView>> = BTreeMap::new();
    for link in links {
        by_fragment.entry(link.fragment).or_default().push(link);
    }
    by_fragment
}

/// The fragments of the cache at `t`, newest last; the table occupancy is in the title.
pub(super) fn fragments(frame: &mut Frame, area: Rect, session: &Session, view: &CacheView) {
    let title = format!(
        " cache  all {}/{IBTC_TABLE_WORDS}  nofp {}/{IBTC_TABLE_WORDS} ",
        view.table_all.len(),
        view.table_nofp.len()
    );
    let capacity = (area.height as usize).saturating_sub(2);
    let mut lines = Vec::new();
    if capacity > 0 {
        lines.push(Line::styled(
            format!(
                "{:<5}{:<11}{:>6}{:>5}  links",
                "frag", "entry", "size", "tr"
            ),
            DIM,
        ));
    }
    let by_fragment = links_by_fragment(&view.links);
    let room = capacity.saturating_sub(1);
    let hidden = view.fragments.len().saturating_sub(room);
    // The newest fragments are the interesting ones while the cache warms up. Keep a
    // line for the "older" note when some are cut.
    let skip = if hidden > 0 { hidden + 1 } else { 0 };
    if hidden > 0 && room > 0 {
        lines.push(more(skip, "older fragments"));
    }
    for fragment in view.fragments.iter().skip(skip) {
        let size = session.translations()[fragment.translation].layout.len() * 4;
        let marks = by_fragment
            .get(&fragment.fragment)
            .map(|links| {
                links
                    .iter()
                    .map(|link| {
                        if link.linked_to.is_some() {
                            '●'
                        } else {
                            '○'
                        }
                    })
                    .collect::<String>()
            })
            .unwrap_or_default();
        let text = format!(
            "{:<5}{:<11}{:>5}B{:>5}  {}{}",
            format!("f{}", fragment.fragment),
            format!("{:#x}", fragment.entry_pc),
            size,
            format!("#{}", fragment.translation),
            marks,
            if fragment.retired { "  retired" } else { "" },
        );
        let style = if fragment.retired {
            Style::default().fg(Color::Red)
        } else {
            Style::default()
        };
        lines.push(Line::styled(text, style));
    }
    frame.render_widget(Paragraph::new(lines).block(block(title)), area);
}

/// The transfer edges between fragments up to `t`, with the linked slots marked.
pub(super) fn edges(frame: &mut Frame, area: Rect, accum: &Accum, view: &CacheView) {
    let capacity = (area.height as usize).saturating_sub(2);
    let mut sorted: Vec<_> = accum.edges.iter().collect();
    sorted.sort_by_key(|(edge, counts)| (std::cmp::Reverse(counts.iter().sum::<u64>()), **edge));
    let mut lines = Vec::new();
    if capacity > 0 {
        lines.push(Line::styled(
            format!("{:<12}{:>7}{:>7}{:>7}", "from -> to", "link", "disp", "rt"),
            DIM,
        ));
    }
    let room = capacity.saturating_sub(1);
    let shown = if sorted.len() > room {
        room.saturating_sub(1)
    } else {
        sorted.len()
    };
    for ((from, to), counts) in sorted.iter().take(shown) {
        let linked = view.links.iter().any(|link| {
            link.fragment == *from && link.linked_to.is_some_and(|target| target.fragment == *to)
        });
        lines.push(Line::from(vec![
            Span::raw(format!("{:<12}", format!("f{from} -> f{to}"))),
            Span::styled(
                format!("{:>7}", counts[1]),
                Style::default().fg(Color::Magenta),
            ),
            Span::styled(
                format!("{:>7}", counts[0]),
                Style::default().fg(Color::Yellow),
            ),
            Span::styled(format!("{:>7}", counts[2]), Style::default().fg(Color::Red)),
            Span::styled(
                if linked { " ●" } else { "" },
                Style::default().fg(Color::Magenta),
            ),
        ]));
    }
    if sorted.len() > shown {
        lines.push(more(sorted.len() - shown, "more edges"));
    }
    frame.render_widget(
        Paragraph::new(lines).block(block(" transfers up to t  (● slot linked) ".to_string())),
        area,
    );
}

/// The profiler's pcs up to `t`: hit counts against the threshold, then the pcs that
/// were requested.
pub(super) fn profiler(frame: &mut Frame, area: Rect, session: &Session, accum: &Accum) {
    let threshold = session.config().policy.hot_threshold;
    let inner = (area.width as usize).saturating_sub(2);
    let capacity = (area.height as usize).saturating_sub(2);
    let mut counting: Vec<_> = accum.pcs.iter().filter(|(_, pc)| pc.count > 0).collect();
    counting.sort_by_key(|(pc, state)| (std::cmp::Reverse(state.count), **pc));
    let mut done: Vec<_> = accum.pcs.iter().filter(|(_, pc)| pc.count == 0).collect();
    done.sort_by_key(|(pc, state)| (std::cmp::Reverse(state.hot_t), **pc));
    let hidden = (counting.len() + done.len()).saturating_sub(capacity);
    let take = if hidden > 0 {
        capacity.saturating_sub(1)
    } else {
        capacity
    };

    // `0x400020    svc ` then the bar then ` 41/64`.
    let bar_width = inner.saturating_sub(16 + 8).clamp(4, 24);
    let mut lines: Vec<Line> = counting
        .iter()
        .chain(done.iter())
        .take(take)
        .map(|(pc, state)| {
            let kind = match state.kind {
                crate::session::Trigger::SvcResume => "svc ",
                crate::session::Trigger::ExitTarget => "exit",
            };
            let head = Span::raw(format!("{:<11}{kind} ", format!("{pc:#x}")));
            if state.count > 0 {
                let filled = (state.count as usize * bar_width / threshold as usize).min(bar_width);
                Line::from(vec![
                    head,
                    Span::styled("█".repeat(filled), Style::default().fg(Color::Yellow)),
                    Span::styled("░".repeat(bar_width - filled), DIM),
                    Span::raw(format!(" {}/{threshold}", state.count)),
                ])
            } else {
                let translation = state
                    .translation
                    .expect("a pc whose count was reset has a translation request");
                let (text, color) = match session.translations()[translation].installed {
                    Some(fragment) => (format!("hot -> f{fragment}"), Color::Green),
                    None => ("hot, REJECTED".to_string(), Color::Red),
                };
                Line::from(vec![
                    head,
                    Span::styled(text, Style::default().fg(color)),
                    key(&format!(
                        " @{}",
                        state.hot_t.expect("a reset count follows Hot")
                    )),
                ])
            }
        })
        .collect();
    if hidden > 0 {
        lines.push(more(hidden, "more pcs"));
    }
    frame.render_widget(
        Paragraph::new(lines).block(block(format!(
            " profiler  hot at {threshold} hits  ({} pcs) ",
            accum.pcs.len()
        ))),
        area,
    );
}

pub(super) fn log(frame: &mut Frame, area: Rect, title: String, lines: Vec<Line<'static>>) {
    frame.render_widget(Paragraph::new(lines).block(block(title)), area);
}
