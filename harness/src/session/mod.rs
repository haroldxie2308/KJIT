//! The session recorder: the data layer of the TUI (docs/pipeline.md, section 7,
//! "Session recorder (TUI data layer)").
//!
//! One deterministic whole-program run under the harness model of the kernel
//! (translation, code cache, profiler, chaining, links), recorded once by
//! `Session::record` and read through the query methods of `Session`. Nothing here
//! executes anything: the recorder drives `OriginalStepper`, `URuntime` and
//! `CodeCache`, and records what they did.
//!
//! Conventions
//!
//! - Time `t` counts ticks: one per instruction executed in the KJIT world, user code
//!   and fragment code alike. `state_at(t)` is the machine after `t` ticks; `step(n)`
//!   is the `n`-th tick (1-based), the one that takes `state_at(n - 1)` to
//!   `state_at(n)`.
//! - An `Event` has the `t` of the tick count when it happened: it is part of what
//!   follows `state_at(t)`. Events with the same `t` are in the order they happened.
//!   A `UserSpan` is the exception: its `t` is the tick before its first step, and its
//!   `steps` and `to_pc` are final.
//! - `state_at` is the state a reader of the KJIT world sees: the machine's registers
//!   (inside a fragment those are the fragment's own, virtualized ones; at a runtime
//!   boundary, the user's from `pt_regs`) and user memory. The runtime's own memory is
//!   left out.

use std::collections::BTreeMap;
use std::fmt;

use crate::code_cache::CodeCache;
use crate::model::{Flags, HaltReason, MachineState};
use crate::runtime::URuntimeHalt;
use crate::shared::abi::RetStatus;

pub mod cli;
mod query;
mod record;
mod steps;
pub mod translation;

#[cfg(test)]
pub(crate) mod tests;

pub use query::{CacheView, FragmentView, Lineage, LinkTarget, LinkView, Origin, QueryError};
pub use steps::{RegId, RegWrite, StepAt, StepMemWrite, StepView};
pub use translation::{
    CfgBlockRecord, InsnPos, LayoutRegion, LayoutWord, Pass, PassBlock, Rejection,
    TranslationRecord, Trigger, Verdict,
};

pub use crate::code_cache::{Occupant, TableId};

/// The pc userspace returns to when the program ends: x30 at the entry. Not readable
/// text, so a branch to it is a dispatch miss and the session ends when the user pc
/// reaches it.
pub const SESSION_EXIT_PC: u64 = 0xfeed_0000;

/// The kernel's profiler and chaining parameters (docs/pipeline.md, section 9). The
/// `hot_window_ms` window is not modeled: the harness has no clock, hits are only
/// counted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionPolicy {
    /// Hits of one pc that make it hot (the kernel's `hot_threshold`).
    pub hot_threshold: u32,
    /// Fragment entries per hook call, the first included (the kernel's
    /// `chain_budget`).
    pub chain_budget: usize,
    /// Whether the cache patches direct `BL` links (A16).
    pub links: bool,
}

impl Default for SessionPolicy {
    fn default() -> Self {
        Self {
            hot_threshold: 64,
            chain_budget: crate::cached_run::CACHED_CHAIN_BUDGET,
            links: true,
        }
    }
}

/// Bounds of a recording. Memory is O(`max_steps`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionLimits {
    /// Ticks after which the recording stops with `Outcome::StepLimit`.
    pub max_steps: u64,
    /// A full state is kept every this many ticks; `state_at` replays at most this
    /// many steps.
    pub checkpoint_every: u64,
}

impl Default for SessionLimits {
    fn default() -> Self {
        Self {
            max_steps: 1_000_000,
            checkpoint_every: 4096,
        }
    }
}

/// What to record. `initial_state` maps the text (`fixture_state` does) and holds the
/// program's data; the session overwrites its x30 with `SESSION_EXIT_PC`.
#[derive(Clone, Debug)]
pub struct SessionConfig {
    pub text_base: u64,
    pub text: Vec<u8>,
    pub entry_pc: u64,
    pub initial_state: MachineState,
    pub policy: SessionPolicy,
    pub limits: SessionLimits,
}

impl SessionConfig {
    /// A fixture program: the default fixture state with the text mapped, the default
    /// policy and limits.
    pub fn fixture(text_base: u64, text: Vec<u8>, entry_pc: u64) -> Result<Self, SessionError> {
        let initial_state =
            crate::fixture_state(text_base, &text).map_err(SessionError::InvalidConfig)?;
        Ok(Self {
            text_base,
            text,
            entry_pc,
            initial_state,
            policy: SessionPolicy::default(),
            limits: SessionLimits::default(),
        })
    }
}

/// Why a session could not be recorded. A mismatch between the worlds is not an error:
/// it is the `Outcome::Divergence` of a recorded session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SessionError {
    InvalidConfig(String),
    /// The entry pc is not readable text.
    EntryUnreadable { entry_pc: u64 },
    /// The original-code interpreter failed (an unsupported form, not a halt).
    Interpreter(String),
    /// The runtime or the code cache failed outside a fragment run.
    Runtime(String),
    /// A translation record differs from the fragment the cache installed, or the
    /// cache installed what the record rejected: the passes drifted.
    TranslationDrift { translation: usize, message: String },
}

impl fmt::Display for SessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig(message) => write!(f, "invalid session config: {message}"),
            Self::EntryUnreadable { entry_pc } => {
                write!(f, "entry pc {entry_pc:#x} is not readable text")
            }
            Self::Interpreter(message) => write!(f, "interpreter: {message}"),
            Self::Runtime(message) => write!(f, "runtime: {message}"),
            Self::TranslationDrift {
                translation,
                message,
            } => write!(f, "translation {translation} drifted from the cache: {message}"),
        }
    }
}

impl std::error::Error for SessionError {}

/// A place in fragment code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Loc {
    pub fragment: usize,
    pub offset: usize,
}

/// How control passed from one fragment location to another.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransferVia {
    /// The dispatch template's `br` (a table hit).
    Dispatch,
    /// A link slot's `b` (A16).
    Link,
    /// A runtime round trip: the fragment exited and the chain continued.
    Runtime,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventKind {
    /// A coalesced run of `steps` ticks of original code, from `from_pc` to the pc
    /// after the last of them.
    UserSpan { from_pc: u64, to_pc: u64, steps: u64 },
    /// The `k`-th syscall (1-based) of the run, the `SVC` at `pc`; both worlds were
    /// compared here.
    Syscall { k: u64, pc: u64 },
    /// The profiler counted one more hit of `pc`, where userspace resumes with no
    /// fragment for it.
    ProfileHit { pc: u64, kind: Trigger, count: u32 },
    /// `pc` reached `hot_threshold`: its translation is requested.
    Hot { pc: u64 },
    /// A translation request ran: `translations()[translation]`.
    Translated { translation: usize },
    Installed { fragment: usize, translation: usize },
    Published {
        table: TableId,
        slot: usize,
        pc: u64,
        fragment: usize,
        replaced: Option<Occupant>,
    },
    Linked {
        fragment: usize,
        slot_offset: usize,
        target: LinkTarget,
    },
    Restored {
        fragment: usize,
        slot_offset: usize,
        target: LinkTarget,
    },
    Retired { fragment: usize },
    /// A chain starts: the hook found `fragment`, translated for `entry_pc`.
    RunBegin { fragment: usize, entry_pc: u64 },
    Transfer { from: Loc, to: Loc, via: TransferVia },
    /// A fragment returned to the runtime through the exit group that ends at `offset`
    /// of `fragment` (`origin` says which original instruction it belongs to), with
    /// this status and these parameters (x0, x10, x11).
    Exit {
        fragment: usize,
        offset: usize,
        status: RetStatus,
        param0: u64,
        param1: u64,
    },
    /// A user access at `access_offset` faulted; the fragment resumes at its `Mem`
    /// stub.
    FaultRedirect {
        fragment: usize,
        access_offset: usize,
        stub_offset: usize,
    },
    /// The chain ended: userspace resumes at `user_pc` (after the syscall of an `SVC`
    /// exit). `entries`: fragment entries made, the first included. `chain_capped`:
    /// the chain budget stopped it.
    RunEnd {
        user_pc: u64,
        entries: u32,
        chain_capped: bool,
    },
    /// The worlds disagreed: `Outcome::Divergence` has the details.
    Divergence,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Event {
    pub t: u64,
    pub kind: EventKind,
}

/// A syscall of the run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SyscallRecord {
    /// 1-based.
    pub k: u64,
    /// The `SVC` instruction.
    pub pc: u64,
    /// Ticks executed once the `SVC` had.
    pub t: u64,
}

/// Where a world stopped for the comparison.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SyncPoint {
    /// At the `SVC` at `pc`.
    Svc { pc: u64 },
    /// The user pc reached `SESSION_EXIT_PC`.
    Exit,
    /// Original code halted: a fault, or a word userspace executes natively that the
    /// model does not (`Unsupported`).
    Halt(HaltReason),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DivergenceKind {
    /// The worlds stopped at different places.
    SyncPoint {
        reference: SyncPoint,
        kjit: SyncPoint,
    },
    /// Same place, different states (`Divergence::diff`).
    State,
    /// A chain stopped in a way no kernel run does (a fell-off fragment, an execution
    /// error, an unknown status).
    RuntimeHalt(URuntimeHalt),
    /// The reference ran `steps` instructions without reaching a sync point the KJIT
    /// world reached.
    ReferenceRunaway { steps: u64 },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegDiff {
    pub reg: RegId,
    pub reference: u128,
    pub kjit: u128,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemDiff {
    pub addr: u64,
    pub reference: u8,
    pub kjit: u8,
}

/// What differs between two states.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StateDiff {
    pub regs: Vec<RegDiff>,
    /// (reference, kjit)
    pub flags: Option<(Flags, Flags)>,
    pub mem: Vec<MemDiff>,
    /// TPIDR_EL0, the counter registers or the page map.
    pub other: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Divergence {
    /// Ticks executed when the worlds were compared.
    pub t: u64,
    /// The syscall (1-based) they were compared at; `None`: at the end.
    pub syscall: Option<u64>,
    pub kind: DivergenceKind,
    pub reference: MachineState,
    pub kjit: MachineState,
    pub diff: StateDiff,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Both worlds reached `SESSION_EXIT_PC` in equal states.
    Exited,
    /// Both worlds halted the same way, in equal states (up to the footprint of a
    /// faulting store, as in the differential oracle).
    Halted(HaltReason),
    /// `max_steps` ticks were executed. The worlds agreed at every syscall until then.
    StepLimit,
    Divergence(Box<Divergence>),
}

/// One recorded session. Read it through the methods; nothing mutates it.
pub struct Session {
    pub(crate) config: SessionConfig,
    pub(crate) translations: Vec<TranslationRecord>,
    pub(crate) events: Vec<Event>,
    pub(crate) steps: steps::StepLog,
    /// `checkpoints[i]` is the state after tick `i * checkpoint_every`.
    pub(crate) checkpoints: Vec<MachineState>,
    pub(crate) syscalls: Vec<SyscallRecord>,
    pub(crate) outcome: Outcome,
    pub(crate) cache: CodeCache,
    /// Translation of each fragment of `cache`.
    pub(crate) fragment_translation: BTreeMap<usize, usize>,
    /// The KJIT world's state when the recording ended, taken directly from the
    /// machine, not replayed.
    pub(crate) final_state: MachineState,
}

impl Session {
    /// Records the program of `config`. See the module doc and docs/pipeline.md.
    pub fn record(config: SessionConfig) -> Result<Session, SessionError> {
        record::record(config)
    }

    pub fn config(&self) -> &SessionConfig {
        &self.config
    }

    pub fn outcome(&self) -> &Outcome {
        &self.outcome
    }

    /// Ticks executed.
    pub fn ticks(&self) -> u64 {
        self.steps.len()
    }

    /// One record per translation request, in order.
    pub fn translations(&self) -> &[TranslationRecord] {
        &self.translations
    }

    /// Every event, ordered by `t`.
    pub fn events(&self) -> &[Event] {
        &self.events
    }

    /// The syscalls of the run, in order (`k` is index + 1).
    pub fn syscalls(&self) -> &[SyscallRecord] {
        &self.syscalls
    }

    /// Tick `tick` (1-based).
    pub fn step(&self, tick: u64) -> Option<StepView<'_>> {
        self.steps.get(tick)
    }

    pub fn steps(&self) -> impl Iterator<Item = StepView<'_>> + '_ {
        (1..=self.ticks()).map(|tick| self.steps.get(tick).expect("tick in range"))
    }

    /// The KJIT world's state at the end of the recording.
    pub fn final_state(&self) -> &MachineState {
        &self.final_state
    }

    /// The code cache as the recording left it. Its fragments keep their final code,
    /// link patches included; `cache_at` has the state at any tick.
    pub fn final_cache(&self) -> &CodeCache {
        &self.cache
    }

    /// The translation that installed `fragment`.
    pub fn translation_of(&self, fragment: usize) -> Option<usize> {
        self.fragment_translation.get(&fragment).copied()
    }
}
