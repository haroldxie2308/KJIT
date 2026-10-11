//! What observe mode derives from a session once, in `ObserveMode::new`, so that a
//! frame at any tick costs a few binary searches and at most one bounded replay:
//!
//! - `Series`: the sorted ticks of one kind of event, so a count up to `t` or inside
//!   a timeline bucket is a binary search;
//! - a prefix sum of ticks spent in fragments;
//! - `Accum` snapshots (transfer-edge counts and profiler state) every
//!   `snapshot_every` events (`SNAPSHOT_EVERY`), so the state at any `t` is a clone plus a bounded replay;
//! - the event indices of each log filter.
//!
//! Nothing here is model logic: every figure is a count over `Session::events()` and
//! `Session::steps()`.

use std::collections::BTreeMap;

use crate::session::{Event, EventKind, Session, StepAt, TransferVia, Trigger};

/// Events between two `Accum` snapshots.
const SNAPSHOT_EVERY: usize = 8192;

/// The ticks of one kind of event, ascending (events are ordered by `t`).
#[derive(Default)]
pub(super) struct Series(Vec<u64>);

impl Series {
    fn push(&mut self, t: u64) {
        self.0.push(t);
    }

    /// Events with `Event::t <= t`.
    pub(super) fn upto(&self, t: u64) -> usize {
        self.0.partition_point(|&at| at <= t)
    }

    /// The tick of the last event at or before `t`.
    pub(super) fn last_upto(&self, t: u64) -> Option<u64> {
        self.upto(t).checked_sub(1).map(|index| self.0[index])
    }

    /// The tick of the first event after `t`.
    pub(super) fn next_after(&self, t: u64) -> Option<u64> {
        self.0.get(self.upto(t)).copied()
    }

    /// The tick of the last event before `t`.
    pub(super) fn prev_before(&self, t: u64) -> Option<u64> {
        self.0
            .partition_point(|&at| at < t)
            .checked_sub(1)
            .map(|index| self.0[index])
    }
}

/// The cumulative figures of the summary, up to some tick.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Counts {
    pub(super) syscalls: u64,
    /// Translation requests, rejected ones included.
    pub(super) translations: u64,
    pub(super) rejected: u64,
    pub(super) hot: u64,
    /// Returns of a fragment to the runtime (`Exit`).
    pub(super) exits: u64,
    pub(super) dispatch: u64,
    pub(super) link: u64,
    pub(super) runtime: u64,
}

/// What the profiler knows about one pc.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct PcState {
    /// Hits since the last request (the session resets it when the pc turns hot).
    pub(super) count: u32,
    /// The trigger of the latest hit.
    pub(super) kind: Trigger,
    /// The tick the pc last turned hot.
    pub(super) hot_t: Option<u64>,
    /// The latest translation request for the pc.
    pub(super) translation: Option<usize>,
}

/// Counts of the transfers `from -> to` by `TransferVia`: [dispatch, link, runtime].
pub(super) type EdgeCounts = [u64; 3];

pub(super) fn via_slot(via: TransferVia) -> usize {
    match via {
        TransferVia::Dispatch => 0,
        TransferVia::Link => 1,
        TransferVia::Runtime => 2,
    }
}

/// State that accumulates over the event log: replayed from a snapshot to read it at
/// a tick.
#[derive(Clone, Default)]
pub(super) struct Accum {
    pub(super) edges: BTreeMap<(usize, usize), EdgeCounts>,
    pub(super) pcs: BTreeMap<u64, PcState>,
}

impl Accum {
    fn apply(&mut self, session: &Session, event: &Event) {
        match event.kind {
            EventKind::Transfer { from, to, via } => {
                self.edges.entry((from.fragment, to.fragment)).or_default()[via_slot(via)] += 1;
            }
            EventKind::ProfileHit { pc, kind, count } => {
                let state = self.pcs.entry(pc).or_insert(PcState {
                    count,
                    kind,
                    hot_t: None,
                    translation: None,
                });
                state.count = count;
                state.kind = kind;
            }
            EventKind::Hot { pc } => {
                let state = self
                    .pcs
                    .get_mut(&pc)
                    .expect("a pc turns hot on a profiled hit");
                state.count = 0;
                state.hot_t = Some(event.t);
            }
            EventKind::Translated { translation } => {
                let pc = session.translations()[translation].entry_pc;
                self.pcs
                    .get_mut(&pc)
                    .expect("a request is made for a profiled pc")
                    .translation = Some(translation);
            }
            _ => {}
        }
    }
}

/// The event-log filters; `All` shows every event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Filter {
    All,
    User,
    Profiler,
    Cache,
    Runs,
    Transfers,
}

impl Filter {
    pub(super) fn label(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::User => "user (spans, syscalls)",
            Self::Profiler => "profiler",
            Self::Cache => "cache",
            Self::Runs => "runs (begin, exit, end)",
            Self::Transfers => "transfers",
        }
    }

    pub(super) fn next(self) -> Self {
        match self {
            Self::All => Self::User,
            Self::User => Self::Profiler,
            Self::Profiler => Self::Cache,
            Self::Cache => Self::Runs,
            Self::Runs => Self::Transfers,
            Self::Transfers => Self::All,
        }
    }

    /// Index into `Index::by_filter`; `All` has no list of its own.
    fn slot(self) -> Option<usize> {
        match self {
            Self::All => None,
            Self::User => Some(0),
            Self::Profiler => Some(1),
            Self::Cache => Some(2),
            Self::Runs => Some(3),
            Self::Transfers => Some(4),
        }
    }

    /// The filter (never `All`) an event belongs to.
    pub(super) fn of(kind: &EventKind) -> Self {
        match kind {
            EventKind::UserSpan { .. } | EventKind::Syscall { .. } => Self::User,
            EventKind::ProfileHit { .. } | EventKind::Hot { .. } | EventKind::Translated { .. } => {
                Self::Profiler
            }
            EventKind::Installed { .. }
            | EventKind::Published { .. }
            | EventKind::Linked { .. }
            | EventKind::Restored { .. }
            | EventKind::Retired { .. } => Self::Cache,
            EventKind::RunBegin { .. }
            | EventKind::Exit { .. }
            | EventKind::FaultRedirect { .. }
            | EventKind::RunEnd { .. }
            | EventKind::Divergence => Self::Runs,
            EventKind::Transfer { .. } => Self::Transfers,
        }
    }
}

pub(super) struct Index {
    /// `frag_prefix[t]`: ticks 1..=t that executed in a fragment.
    frag_prefix: Vec<u32>,
    pub(super) syscalls: Series,
    pub(super) translations: Series,
    pub(super) rejected: Series,
    pub(super) hot: Series,
    pub(super) exits: Series,
    pub(super) dispatch: Series,
    pub(super) link: Series,
    pub(super) runtime: Series,
    /// Events that change the cache (`cache_at` only moves at these).
    cache_events: Series,
    snapshot_every: usize,
    /// `snapshots[k]`: the `Accum` after the first `k * snapshot_every` events.
    snapshots: Vec<Accum>,
    /// Indices into `Session::events()` per filter, see `Filter::slot`.
    by_filter: [Vec<u32>; 5],
}

impl Index {
    pub(super) fn new(session: &Session) -> Self {
        Self::with_snapshot_every(session, SNAPSHOT_EVERY)
    }

    pub(super) fn with_snapshot_every(session: &Session, snapshot_every: usize) -> Self {
        let mut frag_prefix = Vec::with_capacity(session.ticks() as usize + 1);
        let mut in_fragment = 0u32;
        frag_prefix.push(in_fragment);
        for step in session.steps() {
            if matches!(step.at, StepAt::Fragment { .. }) {
                in_fragment += 1;
            }
            frag_prefix.push(in_fragment);
        }

        let mut index = Self {
            frag_prefix,
            syscalls: Series::default(),
            translations: Series::default(),
            rejected: Series::default(),
            hot: Series::default(),
            exits: Series::default(),
            dispatch: Series::default(),
            link: Series::default(),
            runtime: Series::default(),
            cache_events: Series::default(),
            snapshot_every,
            snapshots: Vec::new(),
            by_filter: Default::default(),
        };
        let mut accum = Accum::default();
        for (position, event) in session.events().iter().enumerate() {
            if position % snapshot_every == 0 {
                index.snapshots.push(accum.clone());
            }
            accum.apply(session, event);
            let t = event.t;
            match event.kind {
                EventKind::Syscall { .. } => index.syscalls.push(t),
                EventKind::Translated { translation } => {
                    index.translations.push(t);
                    if session.translations()[translation].installed.is_none() {
                        index.rejected.push(t);
                    }
                }
                EventKind::Hot { .. } => index.hot.push(t),
                EventKind::Exit { .. } => index.exits.push(t),
                EventKind::Transfer { via, .. } => match via {
                    TransferVia::Dispatch => index.dispatch.push(t),
                    TransferVia::Link => index.link.push(t),
                    TransferVia::Runtime => index.runtime.push(t),
                },
                EventKind::Installed { .. }
                | EventKind::Published { .. }
                | EventKind::Linked { .. }
                | EventKind::Restored { .. }
                | EventKind::Retired { .. } => index.cache_events.push(t),
                _ => {}
            }
            if let Some(slot) = Filter::of(&event.kind).slot() {
                index.by_filter[slot]
                    .push(u32::try_from(position).expect("fewer than 2^32 events"));
            }
        }
        if session.events().len() % snapshot_every == 0 {
            // `accum_after(events.len())` reads the snapshot of the last full block.
            index.snapshots.push(accum);
        }
        index
    }

    /// Ticks 1..=t spent in fragments.
    pub(super) fn fragment_ticks(&self, t: u64) -> u64 {
        u64::from(self.frag_prefix[t as usize])
    }

    pub(super) fn counts(&self, t: u64) -> Counts {
        Counts {
            syscalls: self.syscalls.upto(t) as u64,
            translations: self.translations.upto(t) as u64,
            rejected: self.rejected.upto(t) as u64,
            hot: self.hot.upto(t) as u64,
            exits: self.exits.upto(t) as u64,
            dispatch: self.dispatch.upto(t) as u64,
            link: self.link.upto(t) as u64,
            runtime: self.runtime.upto(t) as u64,
        }
    }

    /// The tick to ask `Session::cache_at` for to get the cache at `t`: the last tick
    /// at or before `t` where the cache changed, so frames between two cache events
    /// share one view.
    pub(super) fn cache_key(&self, t: u64) -> u64 {
        // No cache event yet: the cache is empty, which `cache_at(0)` also returns.
        self.cache_events.last_upto(t).unwrap_or(0)
    }

    /// The accumulated state after the first `n` events.
    pub(super) fn accum_after(&self, session: &Session, n: usize) -> Accum {
        let from = n / self.snapshot_every * self.snapshot_every;
        let mut accum = self.snapshots[n / self.snapshot_every].clone();
        for event in &session.events()[from..n] {
            accum.apply(session, event);
        }
        accum
    }

    /// The `rows` newest events of `filter` with `Event::t <= t`, oldest first,
    /// skipping the `back` newest (`back` is capped at `LogWindow::max_back`).
    pub(super) fn log_window<'a>(
        &self,
        session: &'a Session,
        filter: Filter,
        t: u64,
        back: usize,
        rows: usize,
    ) -> LogWindow<'a> {
        let events = session.events();
        let matching = match filter.slot() {
            None => {
                let end = events_upto(session, t);
                return window(end, back, rows, |i| &events[i]);
            }
            Some(slot) => &self.by_filter[slot],
        };
        let end = matching.partition_point(|&i| events[i as usize].t <= t);
        window(end, back, rows, |i| &events[matching[i] as usize])
    }
}

/// Events with `Event::t <= t`.
pub(super) fn events_upto(session: &Session, t: u64) -> usize {
    session.events().partition_point(|event| event.t <= t)
}

/// A slice of the event log for the log panel.
pub(super) struct LogWindow<'a> {
    pub(super) events: Vec<&'a Event>,
    /// The `back` that shows the oldest events: scrolling further does nothing.
    pub(super) max_back: usize,
}

fn window<'a>(
    end: usize,
    back: usize,
    rows: usize,
    at: impl Fn(usize) -> &'a Event,
) -> LogWindow<'a> {
    let max_back = end.saturating_sub(rows);
    let end = end - back.min(max_back);
    let start = end.saturating_sub(rows);
    LogWindow {
        events: (start..end).map(at).collect(),
        max_back,
    }
}

/// The timeline over `width` columns: column `b` covers ticks `(lo_b, hi_b]` with
/// `lo_b = ceil(b * ticks / width)`, so each tick is in exactly one column and
/// `column_of(t)` is the column of tick `t` (`t == 0` is in column 0, with the events
/// that precede the first tick).
pub(super) struct Timeline {
    pub(super) width: usize,
    ticks: u64,
    /// Share of the column's ticks spent in fragments; `None` for a column with no tick
    /// (more columns than ticks).
    pub(super) fragment_share: Vec<Option<f64>>,
    pub(super) round_trips: Vec<u32>,
    pub(super) direct: Vec<u32>,
    pub(super) syscalls: Vec<u32>,
    pub(super) installed: Vec<bool>,
    pub(super) rejected: Vec<bool>,
}

impl Timeline {
    pub(super) fn build(index: &Index, ticks: u64, width: usize) -> Self {
        assert!(width > 0, "a timeline has at least one column");
        let mut timeline = Self {
            width,
            ticks,
            fragment_share: Vec::with_capacity(width),
            round_trips: Vec::with_capacity(width),
            direct: Vec::with_capacity(width),
            syscalls: Vec::with_capacity(width),
            installed: Vec::with_capacity(width),
            rejected: Vec::with_capacity(width),
        };
        let columns = width as u64;
        for column in 0..columns {
            let lo = (column * ticks).div_ceil(columns);
            let hi = ((column + 1) * ticks).div_ceil(columns);
            let within = |series: &Series| -> u32 {
                let before = if column == 0 { 0 } else { series.upto(lo) };
                (series.upto(hi) - before) as u32
            };
            timeline.fragment_share.push((hi > lo).then(|| {
                (index.fragment_ticks(hi) - index.fragment_ticks(lo)) as f64 / (hi - lo) as f64
            }));
            timeline.round_trips.push(within(&index.runtime));
            timeline
                .direct
                .push(within(&index.dispatch) + within(&index.link));
            timeline.syscalls.push(within(&index.syscalls));
            let rejected = within(&index.rejected);
            timeline.rejected.push(rejected > 0);
            timeline
                .installed
                .push(within(&index.translations) > rejected);
        }
        timeline
    }

    pub(super) fn column_of(&self, t: u64) -> usize {
        if t == 0 {
            0
        } else {
            ((t - 1) * self.width as u64 / self.ticks) as usize
        }
    }

    /// Ticks per column, for the title.
    pub(super) fn ticks_per_column(&self) -> u64 {
        self.ticks.div_ceil(self.width as u64)
    }
}
