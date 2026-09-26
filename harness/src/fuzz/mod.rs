//! Spec-driven differential fuzzer (roadmap V2).
//!
//! Generates random programs over the generated A64 subset (`forms`, `gen`),
//! runs the original through the interpreter and the translated fragment
//! through `URuntime` with `run_differential`, and holds them to the same
//! oracle as the fixture suite (`compare_differential`). Optionally (Linux
//! arm64) every agreeing program also runs natively: interpreter original ==
//! native original == native fragment. Failures are minimized and written as
//! `.s` regression fixtures (`minimize`).
//!
//! Outcomes that are not a verdict are counted, never dropped:
//! - `NonTerminating`: neither side halted within `LIMITS`.
//! - `Chained`: the original halted at a BL/BLR/BR/RET whose target is a PC
//!   the fragment translated. The runtime continues inside the fragment there
//!   (`decide_runtime_return`); the original interpreter stops, so the oracle
//!   cannot compare the two. Generated register values reach text addresses
//!   only through arithmetic (e.g. `movz`/`movk` building a PC).

pub mod forms;
pub mod gen;
pub mod minimize;
pub mod program;
pub mod rng;

use std::collections::BTreeMap;
use std::fmt;
use std::panic::{self, AssertUnwindSafe};

use crate::arm64::OriginalStepper;
use crate::asm_fixture::panic_message;
use crate::model::{HaltReason, MachineState};
use crate::runtime::URuntimeHalt;
use crate::shared::trans::cfg::RuntimeExitReason;
use crate::{
    compare_differential, run_differential, DifferentialError, DifferentialRun, MismatchKind,
    OriginalRunError, StepLimits,
};
use forms::{Catalog, Form};
use gen::{generate, GenConfig};
use program::{Program, ENTRY_PC, TEXT_BASE};
use rng::Rng;

/// A generated loop either terminates (counter loops, a few hundred original
/// instructions) or runs into the fragment's back-edge budget, where the
/// original is capped at the same instance: at most `KJIT_BACKEDGE_BUDGET`
/// iterations of a body of at most 64 instructions. Only an SVC inside an
/// endless loop (the budget restarts on every re-entry) runs past both limits;
/// that program is discarded (`NoHalt`).
pub const LIMITS: StepLimits = StepLimits {
    original: 600_000,
    fragment: 12_000_000,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum FailureKind {
    /// The interpreter errored on the original (harness bug or gap).
    OriginalError,
    /// `compile_request` rejected a program over the supported subset.
    Translate,
    /// The independent verifier rejected the fragment: a translator bug it
    /// caught, or a verifier false positive. Either way a bug.
    Verify,
    /// The fragment halted; the original did not within `LIMITS.original`.
    OriginalStepLimit,
    /// Something panicked (translator or harness).
    Panic,
    /// The fragment did not halt although the original did.
    FragmentStepLimit,
    /// The fragment run ended in a harness error (PAN violation, a fault the
    /// original did not take, invalid status, ...).
    FragmentError,
    StateMismatch,
    HaltMismatch,
    /// Interpreter and fragment agree, the host CPU does not.
    Native,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Failure {
    pub kind: FailureKind,
    pub message: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    Pass,
    NonTerminating,
    Chained,
    Fail(Failure),
}

/// Runs one program both ways (and natively, if enabled) and classifies it.
pub struct Checker<'a> {
    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    native: Option<&'a crate::native::NativeSession>,
    #[cfg(not(all(target_os = "linux", target_arch = "aarch64")))]
    _native: std::marker::PhantomData<&'a ()>,
}

impl<'a> Checker<'a> {
    pub fn interpreter_only() -> Self {
        Self {
            #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
            native: None,
            #[cfg(not(all(target_os = "linux", target_arch = "aarch64")))]
            _native: std::marker::PhantomData,
        }
    }

    /// Every program the interpreter check passes is also run on the CPU.
    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    pub fn with_native(session: &'a crate::native::NativeSession) -> Self {
        Self {
            native: Some(session),
        }
    }

    pub fn native_enabled(&self) -> bool {
        #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
        return self.native.is_some();
        #[cfg(not(all(target_os = "linux", target_arch = "aarch64")))]
        return false;
    }

    pub fn check(
        &self,
        program: &Program,
        state: &MachineState,
        before_original_step: &mut dyn FnMut(&OriginalStepper),
    ) -> (Outcome, Option<HaltReason>) {
        let text = program
            .text_bytes()
            .unwrap_or_else(|err| panic!("checked program does not encode: {err}"));
        // Registers before the most recent original step: the halting step's
        // own inputs, which a BLR x30 exit overwrites.
        let mut pre_halt_regs = [0u64; 32];
        let run = panic::catch_unwind(AssertUnwindSafe(|| {
            run_differential(
                TEXT_BASE,
                text.clone(),
                ENTRY_PC,
                state,
                Some(LIMITS),
                &mut |stepper| {
                    for reg in 0..32u8 {
                        pre_halt_regs[reg as usize] = stepper.state().read_x(reg);
                    }
                    before_original_step(stepper)
                },
            )
        }));
        let run = match run {
            Err(payload) => {
                return (
                    fail(FailureKind::Panic, panic_message(payload.as_ref())),
                    None,
                )
            }
            Ok(Err(DifferentialError::NoHalt)) => return (Outcome::NonTerminating, None),
            Ok(Err(DifferentialError::Original(OriginalRunError::StepLimit { limit }))) => {
                return (
                    fail(
                        FailureKind::OriginalStepLimit,
                        format!("the fragment halted, the original ran past {limit} steps"),
                    ),
                    None,
                )
            }
            Ok(Err(DifferentialError::Original(OriginalRunError::Harness(message)))) => {
                return (fail(FailureKind::OriginalError, message), None)
            }
            Ok(Err(DifferentialError::Translate(message))) => {
                return (fail(FailureKind::Translate, message), None)
            }
            Ok(Err(DifferentialError::Verify(message))) => {
                return (fail(FailureKind::Verify, message), None)
            }
            Ok(Err(DifferentialError::Fragment(message))) => {
                return (fail(FailureKind::FragmentError, message), None)
            }
            Ok(Ok(run)) => run,
        };
        let halt = Some(run.original.halt_reason);
        if exit_target(&run.original.halt_reason, &pre_halt_regs)
            .is_some_and(|target| run.fragment.offset_for_pc(target).is_some())
        {
            return (Outcome::Chained, halt);
        }
        let outcome = classify(&run);
        if outcome != Outcome::Pass {
            return (outcome, halt);
        }
        #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
        if let Some(session) = self.native {
            if let Err(message) = self.check_native(session, &text, state, &run) {
                return (fail(FailureKind::Native, message), halt);
            }
        }
        (Outcome::Pass, halt)
    }

    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    fn check_native(
        &self,
        session: &crate::native::NativeSession,
        text: &[u8],
        state: &MachineState,
        run: &DifferentialRun,
    ) -> Result<(), String> {
        crate::native::check_against_interpreter(
            session,
            TEXT_BASE,
            text,
            ENTRY_PC,
            state,
            &run.original,
            run.original_cap,
            &run.fragment,
            &run.encoded_fragment,
        )
        .map(|_| ())
    }
}

/// Where a branch exit goes, from the registers before the exit executed.
fn exit_target(halt: &HaltReason, pre_regs: &[u64; 32]) -> Option<u64> {
    match *halt {
        HaltReason::RuntimeExit { reason } => match reason {
            RuntimeExitReason::Ret { lr_reg: reg }
            | RuntimeExitReason::Br { target_reg: reg }
            | RuntimeExitReason::Blr {
                target_reg: reg, ..
            } => Some(pre_regs[reg as usize]),
            RuntimeExitReason::Bl { target_pc, .. } => Some(target_pc),
            RuntimeExitReason::Svc { .. } | RuntimeExitReason::Unsupported { .. } => None,
        },
        HaltReason::Fault(_) | HaltReason::InstanceCap { .. } => None,
    }
}

fn fail(kind: FailureKind, message: String) -> Outcome {
    Outcome::Fail(Failure { kind, message })
}

fn classify(run: &DifferentialRun) -> Outcome {
    match (&run.original.halt_reason, &run.report.halt) {
        (_, URuntimeHalt::StepLimit { pc, steps }) => fail(
            FailureKind::FragmentStepLimit,
            format!(
                "fragment did not halt within {steps} steps (at {pc:#x}); original halted with {}",
                run.original.halt_reason
            ),
        ),
        (_, URuntimeHalt::ExecutionError { pc, message }) => fail(
            FailureKind::FragmentError,
            format!(
                "fragment error at {pc:#x}: {message}; original halted with {}",
                run.original.halt_reason
            ),
        ),
        _ => match compare_differential("fuzz", run) {
            Ok(()) => Outcome::Pass,
            Err(mismatch) => fail(
                match mismatch.kind {
                    MismatchKind::State => FailureKind::StateMismatch,
                    MismatchKind::Halt => FailureKind::HaltMismatch,
                },
                mismatch.message,
            ),
        },
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FuzzConfig {
    pub seed: u64,
    /// Index of the first program; program i is `Rng::for_program(seed, i)`.
    pub start: u64,
    pub iters: u64,
    pub gen: GenConfig,
}

#[derive(Clone, Debug)]
pub struct FailureReport {
    pub index: u64,
    pub failure: Failure,
    /// How the original halted, when it ran to a halt.
    pub original_halt: Option<HaltReason>,
    pub program: Program,
    pub state: MachineState,
}

#[derive(Clone, Debug, Default)]
pub struct Stats {
    pub generated: u64,
    /// Programs the original halted in (`generated - discarded_nonterminating`):
    /// passed + failed + chained.
    pub run: u64,
    pub discarded_nonterminating: u64,
    /// Original exits into a translated PC; see `Outcome::Chained`.
    pub chained: u64,
    pub passed: u64,
    pub failed: u64,
    /// Passed programs that also agreed natively.
    pub native_passed: u64,
    pub failures_by_kind: BTreeMap<FailureKind, u64>,
    /// How the original halted, over programs that ran.
    pub original_halts: BTreeMap<&'static str, u64>,
    /// Form instances in programs that ran.
    pub generated_by_form: BTreeMap<&'static str, u64>,
    /// Original instructions executed (or halted at), per form, in programs that ran.
    pub executed_by_form: BTreeMap<&'static str, u64>,
}

pub fn fuzz(
    catalog: &Catalog,
    config: &FuzzConfig,
    checker: &Checker<'_>,
    on_failure: &mut dyn FnMut(FailureReport),
    on_progress: &mut dyn FnMut(u64, &Stats),
) -> Stats {
    let mut stats = Stats::default();
    for form in &catalog.forms {
        stats.generated_by_form.insert(form.key(), 0);
        stats.executed_by_form.insert(form.key(), 0);
    }

    for index in config.start..config.start + config.iters {
        let mut rng = Rng::for_program(config.seed, index);
        let generated = generate(catalog, &mut rng, config.gen);
        let program = generated.program;
        stats.generated += 1;

        let words = program
            .words()
            .unwrap_or_else(|err| panic!("generated program does not encode: {err}"));
        let keys = words
            .iter()
            .map(|&word| catalog.form_for_word(word).map(Form::key))
            .collect::<Vec<_>>();
        let mut executed = vec![0u64; words.len()];
        let (outcome, halt) = checker.check(&program, &generated.state, &mut |stepper| {
            // The step that falls off the end starts at the first PC past the text.
            let slot = ((stepper.pc() - ENTRY_PC) / 4) as usize;
            if let Some(count) = executed.get_mut(slot) {
                *count += 1;
            }
        });

        if outcome == Outcome::NonTerminating {
            stats.discarded_nonterminating += 1;
            continue;
        }
        stats.run += 1;
        for (slot, key) in keys.iter().enumerate() {
            if let Some(key) = key {
                *stats.generated_by_form.entry(key).or_default() += 1;
                *stats.executed_by_form.entry(key).or_default() += executed[slot];
            }
        }
        if let Some(halt) = halt {
            *stats.original_halts.entry(halt_label(&halt)).or_default() += 1;
        }
        match outcome {
            Outcome::Pass => {
                stats.passed += 1;
                if checker.native_enabled() {
                    stats.native_passed += 1;
                }
            }
            Outcome::Chained => stats.chained += 1,
            Outcome::Fail(failure) => {
                stats.failed += 1;
                *stats.failures_by_kind.entry(failure.kind).or_default() += 1;
                on_failure(FailureReport {
                    index,
                    failure,
                    original_halt: halt,
                    program,
                    state: generated.state,
                });
            }
            Outcome::NonTerminating => unreachable!("handled above"),
        }
        on_progress(index, &stats);
    }
    stats
}

pub fn halt_label(halt: &HaltReason) -> &'static str {
    match halt {
        HaltReason::Fault(_) => "fault",
        HaltReason::InstanceCap { .. } => "budget",
        HaltReason::RuntimeExit { reason } => match reason {
            RuntimeExitReason::Bl { .. } => "bl",
            RuntimeExitReason::Blr { .. } => "blr",
            RuntimeExitReason::Br { .. } => "br",
            RuntimeExitReason::Ret { .. } => "ret",
            RuntimeExitReason::Svc { .. } => "svc",
            RuntimeExitReason::Unsupported { word: None, .. } => "unreadable",
            RuntimeExitReason::Unsupported { .. } => "unsupported",
        },
    }
}

impl fmt::Display for Stats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "generated:                {}", self.generated)?;
        writeln!(f, "run:                      {}", self.run)?;
        writeln!(
            f,
            "discarded-nonterminating: {}",
            self.discarded_nonterminating
        )?;
        writeln!(f, "chained (no verdict):     {}", self.chained)?;
        writeln!(f, "passed:                   {}", self.passed)?;
        writeln!(f, "native-passed:            {}", self.native_passed)?;
        writeln!(f, "failed:                   {}", self.failed)?;
        for (kind, count) in &self.failures_by_kind {
            writeln!(f, "  {kind:?}: {count}")?;
        }
        writeln!(f, "original halts:")?;
        for (halt, count) in &self.original_halts {
            writeln!(f, "  {halt:<14} {count}")?;
        }
        writeln!(
            f,
            "per-form coverage (instances generated / original steps executed):"
        )?;
        for (key, generated) in &self.generated_by_form {
            let executed = self.executed_by_form.get(key).copied().unwrap_or(0);
            writeln!(f, "  {key:<40} {generated:>9} {executed:>10}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Failures the smoke seed produces on the current translator. Every one is
    /// an instance of the two open translator bugs parked in
    /// `tests/arm64/fuzz-pending/`:
    /// - `fuzz_regress_3d74ff35501da143.s`: layout emits blocks in CFG discovery
    ///   order, so a conditional branch's fallthrough block is not always next;
    /// - `fuzz_regress_4d8286952cad317f.s`: a block that ends at the end of the
    ///   readable text gets no exit, so the fragment runs off its end.
    /// (Checked by laying blocks out in address order in a scratch copy: only
    /// the fall-off-the-end failures remain, and none without fall-off.)
    ///
    /// Any change to generation, the catalog or the translator moves this
    /// number. Update it only after checking the new failures are these bugs
    /// (`make fuzz SEED=0x5eed0ff022 ITERS=2000`); set it to 0 once both are fixed.
    const OPEN_BUG_FAILURES: u64 = 423;

    /// Deterministic slice of the fuzzer inside `make harness-test`.
    #[test]
    fn fixed_seed_programs_agree() {
        let catalog = Catalog::from_generated();
        let config = FuzzConfig {
            seed: 0x5eed_0f_f022,
            start: 0,
            iters: 2_000,
            gen: GenConfig::default(),
        };
        let mut failures = Vec::new();
        let stats = fuzz(
            &catalog,
            &config,
            &Checker::interpreter_only(),
            &mut |report| failures.push(report),
            &mut |_, _| {},
        );
        println!("fuzz smoke (seed {:#x}):\n{stats}", config.seed);

        let listed = failures
            .iter()
            .map(|report| {
                format!(
                    "  program {}: {:?}: {}",
                    report.index,
                    report.failure.kind,
                    report.failure.message.lines().next().unwrap_or("")
                )
            })
            .collect::<Vec<_>>()
            .join("\n");
        // The open bugs only ever show up as the fragment diverging; an
        // interpreter error, a translation error or a panic is something new.
        let harness_side = failures.iter().filter(|report| {
            matches!(
                report.failure.kind,
                FailureKind::OriginalError | FailureKind::Translate | FailureKind::Panic
            )
        });
        assert_eq!(
            harness_side.count(),
            0,
            "unexpected failure kinds:\n{listed}"
        );
        assert_eq!(
            stats.failed, OPEN_BUG_FAILURES,
            "fuzz failures changed (see OPEN_BUG_FAILURES):\n{listed}"
        );
        // The generator must reach every generated form and produce verdicts.
        for (key, count) in &stats.generated_by_form {
            assert!(*count > 0, "form {key} was never generated");
        }
        assert!(
            stats.passed * 2 > stats.generated,
            "fewer than half the programs passed:\n{stats}"
        );
    }
}
