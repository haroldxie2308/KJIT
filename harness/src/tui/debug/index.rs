//! Indexes over a session, built once in `DebugMode::new` so navigation never scans:
//! the ticks of each event class, and the ticks at which each original pc is reached.

use std::collections::BTreeMap;

use crate::session::{EventKind, Session, StepAt};

/// A group of event kinds the user can navigate by.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum EventClass {
    Syscall,
    Exit,
    Transfer,
    Translation,
    Hot,
    RunBegin,
    RunEnd,
    Cache,
    Fault,
    Profile,
    UserSpan,
    Divergence,
}

impl EventClass {
    pub const ALL: [EventClass; 12] = [
        Self::Syscall,
        Self::Exit,
        Self::Transfer,
        Self::Translation,
        Self::Hot,
        Self::RunBegin,
        Self::RunEnd,
        Self::Cache,
        Self::Fault,
        Self::Profile,
        Self::UserSpan,
        Self::Divergence,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Self::Syscall => "syscall",
            Self::Exit => "exit",
            Self::Transfer => "transfer",
            Self::Translation => "translation",
            Self::Hot => "hot",
            Self::RunBegin => "run-begin",
            Self::RunEnd => "run-end",
            Self::Cache => "cache",
            Self::Fault => "fault-redirect",
            Self::Profile => "profile-hit",
            Self::UserSpan => "user-span",
            Self::Divergence => "divergence",
        }
    }

    pub fn of(kind: &EventKind) -> Self {
        match kind {
            EventKind::UserSpan { .. } => Self::UserSpan,
            EventKind::Syscall { .. } => Self::Syscall,
            EventKind::ProfileHit { .. } => Self::Profile,
            EventKind::Hot { .. } => Self::Hot,
            EventKind::Translated { .. } => Self::Translation,
            EventKind::Installed { .. }
            | EventKind::Published { .. }
            | EventKind::Linked { .. }
            | EventKind::Restored { .. }
            | EventKind::Retired { .. } => Self::Cache,
            EventKind::RunBegin { .. } => Self::RunBegin,
            EventKind::Transfer { .. } => Self::Transfer,
            EventKind::Exit { .. } => Self::Exit,
            EventKind::FaultRedirect { .. } => Self::Fault,
            EventKind::RunEnd { .. } => Self::RunEnd,
            EventKind::Divergence => Self::Divergence,
        }
    }

    /// The class after (`forward`) or before this one, wrapping around.
    pub fn cycled(self, forward: bool) -> Self {
        let count = Self::ALL.len();
        let at = Self::ALL
            .iter()
            .position(|&class| class == self)
            .expect("every class is in ALL");
        Self::ALL[if forward { (at + 1) % count } else { (at + count - 1) % count }]
    }
}

/// The original pc a tick executes: the pc of a user step, the `ori_pc` of the layout
/// word a fragment step is. `None` for a fragment's prologue and epilogue.
pub fn ori_pc_of(session: &Session, at: StepAt) -> Option<u64> {
    match at {
        StepAt::User { pc } => Some(pc),
        StepAt::Fragment { fragment, offset } => {
            let translation = session
                .translation_of(fragment)
                .expect("a fragment that executed was installed by a translation");
            session.translations()[translation]
                .word_at(offset)
                .expect("a fragment step is at a word of its layout")
                .ori_pc
        }
    }
}

pub struct Index {
    /// Per class (in `EventClass::ALL` order): the distinct `t` of its events,
    /// ascending.
    event_ticks: Vec<Vec<u64>>,
    /// Original pc -> the ticks `n` (step numbers, ascending) at which the pc is
    /// reached: step `n` executes it and is not the next word of the group the
    /// previous step was in (the words one instruction was translated into form one
    /// group, so a breakpoint stops once per group, not once per word).
    reached: BTreeMap<u64, Vec<u64>>,
}

impl Index {
    pub fn new(session: &Session) -> Self {
        let mut event_ticks = vec![Vec::new(); EventClass::ALL.len()];
        for event in session.events() {
            let class = EventClass::of(&event.kind);
            let ticks = &mut event_ticks[class_slot(class)];
            if ticks.last() != Some(&event.t) {
                ticks.push(event.t);
            }
        }

        let mut reached: BTreeMap<u64, Vec<u64>> = BTreeMap::new();
        let mut previous: Option<(StepAt, Option<u64>)> = None;
        for step in session.steps() {
            let pc = ori_pc_of(session, step.at);
            if let Some(pc) = pc {
                if !continues_group(previous, step.at, pc) {
                    reached.entry(pc).or_default().push(step.tick);
                }
            }
            previous = Some((step.at, pc));
        }
        Self {
            event_ticks,
            reached,
        }
    }

    /// The first `t` after `t` with an event of `class`.
    pub fn next_event(&self, class: EventClass, t: u64) -> Option<u64> {
        let ticks = &self.event_ticks[class_slot(class)];
        ticks.get(ticks.partition_point(|&tick| tick <= t)).copied()
    }

    /// The last `t` before `t` with an event of `class`.
    pub fn prev_event(&self, class: EventClass, t: u64) -> Option<u64> {
        let ticks = &self.event_ticks[class_slot(class)];
        ticks
            .partition_point(|&tick| tick < t)
            .checked_sub(1)
            .map(|at| ticks[at])
    }

    /// The first cursor position after `t` at which the next instruction to execute
    /// is one of `pcs`: `t' > t` such that step `t' + 1` reaches a pc of `pcs`.
    pub fn next_reached(&self, pcs: impl Iterator<Item = u64>, t: u64) -> Option<u64> {
        pcs.filter_map(|pc| {
            let steps = self.reached.get(&pc)?;
            // Step n = t' + 1 > t + 1.
            steps
                .get(steps.partition_point(|&n| n <= t + 1))
                .map(|n| n - 1)
        })
        .min()
    }

    /// The last cursor position before `t` at which the next instruction is one of
    /// `pcs`.
    pub fn prev_reached(&self, pcs: impl Iterator<Item = u64>, t: u64) -> Option<u64> {
        pcs.filter_map(|pc| {
            let steps = self.reached.get(&pc)?;
            // Step n = t' + 1 <= t.
            steps
                .partition_point(|&n| n <= t)
                .checked_sub(1)
                .map(|at| steps[at] - 1)
        })
        .max()
    }

    /// Whether the pc is ever reached; a breakpoint on any other can never stop.
    pub fn is_reached(&self, pc: u64) -> bool {
        self.reached.contains_key(&pc)
    }
}

fn class_slot(class: EventClass) -> usize {
    EventClass::ALL
        .iter()
        .position(|&candidate| candidate == class)
        .expect("every class is in ALL")
}

/// Whether the step at `at` with pc `pc` is the next word of the fragment group the
/// previous step was in.
fn continues_group(previous: Option<(StepAt, Option<u64>)>, at: StepAt, pc: u64) -> bool {
    match (previous, at) {
        (
            Some((
                StepAt::Fragment {
                    fragment: before,
                    offset: before_offset,
                },
                Some(before_pc),
            )),
            StepAt::Fragment { fragment, offset },
        ) => before == fragment && before_offset + 4 == offset && before_pc == pc,
        _ => false,
    }
}
