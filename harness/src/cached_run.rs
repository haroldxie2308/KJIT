//! Differential runs over a code cache (A11, docs/pipeline.md "Code cache and cached
//! runs (A11a)").
//!
//! A case runs against a `CodeCache` that starts empty (cold: every branch exit
//! misses and goes through the runtime, which translates and publishes, as the
//! kernel's chaining does) and again against the cache the cold run left (warm:
//! transfers hit in the dispatch tables and stay inside fragment code). Both
//! runs are compared with the original code, which here *follows* its branches
//! (`OriginalStepper::follow_branches`): the fragments call and return across one
//! another, so the run ends where a fragment run ends -- a fault, an `Unsupported`
//! pc (a branch to unreadable text included), or a `Budget` exit or the chain
//! budget's `SVC` stop, which the original is stopped at (`InstanceCap`).

use crate::arm64::LoggedAccess;
use crate::code_cache::{synthetic_loader, CodeCache};
use crate::model::{ExecutionResult, HaltReason, MachineState};
use crate::shared::abi::RetStatus;
use crate::runtime::{
    URuntime, URuntimeConfig, URuntimeHalt, URuntimeReport, DEFAULT_BASE_PC, DEFAULT_CACHE_LAYOUT,
};
use crate::{
    faulting_footprint, run_counting, run_original_following_branches, runtime_halt_matches_original,
    undo_footprint, DifferentialError, Footprint, InstanceCap, Mismatch, MismatchKind,
    MockCodeProvider, OriginalRunError,
};

/// An empty cache over the fixture text, in the interpreter's synthetic address
/// space.
pub fn new_interpreter_cache(text_base: u64, text: &[u8]) -> CodeCache {
    CodeCache::new(
        DEFAULT_CACHE_LAYOUT,
        Some(MockCodeProvider::new(text_base, text.to_vec())),
        synthetic_loader(DEFAULT_BASE_PC),
    )
    .with_chain_budget(CACHED_CHAIN_BUDGET)
}

/// The kernel's default `chain_budget` (docs/pipeline.md, "Chain budget (A10)").
pub const CACHED_CHAIN_BUDGET: usize = 1024;

/// Both sides of one cached run, not yet compared.
#[derive(Debug)]
pub struct CachedRun {
    pub original: ExecutionResult,
    /// Where the original was stopped to match a `Budget` exit or the chain budget's
    /// `SVC` stop.
    pub original_cap: Option<InstanceCap>,
    pub original_footprint: Footprint,
    pub original_accesses: Vec<LoggedAccess>,
    pub report: URuntimeReport,
    /// Runtime round trips of the fragment run (entries after the first).
    pub runtime_entries: usize,
}

/// The fragment for `entry_pc` (translated if the cache has none), then the
/// fragment run over `cache` and the original run stopped to match it. The cache
/// is handed back with whatever the run published and translated.
pub fn run_cached_differential(
    mut cache: CodeCache,
    text_base: u64,
    text: &[u8],
    entry_pc: u64,
    initial_state: &MachineState,
) -> Result<(CachedRun, CodeCache), DifferentialError> {
    let entry = match cache.fragment_for_entry(entry_pc) {
        Some(entry) => entry,
        None => cache
            .translate(entry_pc, entry_pc.wrapping_sub(4))
            .map_err(DifferentialError::Translate)?
            .ok_or_else(|| {
                DifferentialError::Translate(format!("entry {entry_pc:#x} is not readable text"))
            })?,
    };
    let mut runtime = URuntime::with_cache(
        cache,
        entry,
        initial_state.clone(),
        URuntimeConfig::default(),
    );
    let counted = run_counting(&mut runtime, None, true).map_err(DifferentialError::Fragment)?;
    runtime
        .cache()
        .check_invariants()
        .map_err(DifferentialError::Fragment)?;

    let mut original_accesses = Vec::new();
    let original = run_original_following_branches(
        text,
        text_base,
        entry_pc,
        initial_state,
        counted.cap,
        None,
        &mut |stepper| {
            let log = stepper.access_log().expect("original runs record accesses");
            original_accesses.extend_from_slice(&log[original_accesses.len()..]);
        },
    )
    .map_err(DifferentialError::Original)?;
    if let HaltReason::Fault(fault) = original.halt_reason {
        original_accesses.push(LoggedAccess {
            pc: fault.pc,
            access: fault.access,
            privilege: crate::model::Privilege::User,
        });
    }
    let original_footprint = faulting_footprint(text, text_base, &original)
        .map_err(|message| DifferentialError::Original(OriginalRunError::Harness(message)))?;
    Ok((
        CachedRun {
            original,
            original_cap: counted.cap,
            original_footprint,
            original_accesses,
            report: counted.report,
            runtime_entries: counted.runtime_entries,
        },
        runtime.into_cache(),
    ))
}

/// The cached differential oracle: the fragment run must end in the original's user
/// state, up to the faulting store footprint, with a corresponding halt.
pub fn compare_cached(name: &str, run: &CachedRun) -> Result<(), Mismatch> {
    let (original, report) = (&run.original, &run.report);
    let fragment_state = undo_footprint(&original.state, &run.original_footprint, &report.state);
    if original.state != fragment_state {
        return Err(Mismatch {
            kind: MismatchKind::State,
            message: format!(
                "original vs cached fragment state mismatch for `{name}`\noriginal: {:#?}\nfragment: {:#?}",
                original.state, report.state,
            ),
        });
    }
    if !cached_halt_matches(original, &report.halt) {
        return Err(Mismatch {
            kind: MismatchKind::Halt,
            message: format!(
                "original vs cached fragment halt mismatch for `{name}`\noriginal: {:#?}\nfragment: {:#?}",
                original.halt_reason, report.halt,
            ),
        });
    }
    Ok(())
}

/// `runtime_halt_matches_original` plus the chain budget's stop: the fragment run
/// returned to userspace after the SVC at `pc`, where the original was capped before
/// executing it.
pub(crate) fn cached_halt_matches(original: &ExecutionResult, halt: &URuntimeHalt) -> bool {
    match (original.halt_reason, halt) {
        (
            HaltReason::InstanceCap { pc, .. },
            URuntimeHalt::ReturnedToUserspace {
                status: RetStatus::Svc,
                target_pc,
            },
        ) => pc.wrapping_add(4) == *target_pc,
        _ => runtime_halt_matches_original(original, halt),
    }
}
