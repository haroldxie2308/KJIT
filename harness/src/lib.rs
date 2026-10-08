extern crate alloc;

pub mod a64_forms;
pub mod a64_pretty;
pub mod active_step;
pub(crate) mod asm_fixture;
pub mod explorer;
pub mod golden;
pub mod arm64;
pub mod cached_run;
pub mod code_cache;
pub mod fuzz;
pub mod model;
// Platform gate, not a skip: the native oracle executes AArch64 code on the host
// CPU and needs Linux signal/ucontext semantics (macOS reserves x18). Run it with
// `make harness-test-native`, which fails unless it reaches Linux arm64.
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
pub mod native;
pub mod report_util;
pub mod runtime;
pub mod shared;
pub(crate) mod simd;
pub mod trace;

#[cfg(test)]
mod asm_fixture_tests;
#[cfg(test)]
mod dispatch_tests;
#[cfg(test)]
mod encoding_tests;
#[cfg(test)]
mod verify_mutation_tests;

use std::fmt;

use crate::shared::arm64::A64OperandRole;
use crate::shared::emit::layout::ExecutionFragment;
use crate::shared::trans::cfg::{admit_at, RuntimeExitReason};
use crate::shared::trans::input::{
    CodeProvider, CodeReadError, RegisterSnapshot, TranslationRequest, TranslationTrigger,
};
use crate::shared::trans::translate::{compile_request, translate_request, TranslatedProgram};
use crate::shared::verify::{verify_fragment, FaultSiteEntry, VerifyError, VerifyInput, VerifyOk};
use arm64::OriginalStepper;
use model::{ExecutionResult, HaltReason, MachineState, PagePerm, PAGE_SIZE};
use runtime::{URuntime, URuntimeHalt, URuntimeReport, URuntimeStepper};

/// Continuation bound for mocked-SVC original runs and interpreter fragment runs.
const MAX_RUNTIME_EXITS: usize = 10_000;

#[derive(Debug)]
pub struct CaseReport {
    pub name: &'static str,
    pub fragment: ExecutionFragment,
    pub encoded_fragment: Vec<u8>,
    pub original: ExecutionResult,
    /// Where the original run was stopped to match a `Budget` exit of the fragment.
    pub original_cap: Option<InstanceCap>,
    /// See `DifferentialRun::original_footprint`.
    pub original_footprint: Footprint,
    /// See `DifferentialRun::original_accesses`.
    pub original_accesses: Vec<arm64::LoggedAccess>,
    pub fragment_state: MachineState,
    pub fragment_halt: URuntimeHalt,
    pub fragment_steps: usize,
}

/// Stop an original run right before the `instance`-th (1-based) execution of the
/// instruction at `pc`, counted over the whole run (SVC continuations included).
/// This is the dynamic point where a fragment's `Budget` exit returns to userspace
/// (docs/pipeline.md, "Execution budget (A6)"); `fragment_instance_cap` derives it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InstanceCap {
    pub pc: u64,
    pub instance: u64,
}

/// Text at `base_pc`, owned (`Vec<u8>`) or borrowed (`&[u8]`, as the original
/// interpreter holds it).
pub struct MockCodeProvider<B = Vec<u8>> {
    base_pc: u64,
    bytes: B,
}

impl<B: AsRef<[u8]>> MockCodeProvider<B> {
    pub fn new(base_pc: u64, bytes: B) -> Self {
        Self { base_pc, bytes }
    }

    pub fn slice_from(&self, pc: u64) -> Result<&[u8], String> {
        let offset = self.offset(pc, 0).map_err(|err| err.to_string())?;
        Ok(&self.bytes.as_ref()[offset..])
    }

    fn offset(&self, pc: u64, len: usize) -> Result<usize, CodeReadError> {
        let Some(relative) = pc.checked_sub(self.base_pc) else {
            return Err(CodeReadError::Unmapped { pc, len });
        };
        let Ok(offset) = usize::try_from(relative) else {
            return Err(CodeReadError::Unmapped { pc, len });
        };
        let Some(end) = offset.checked_add(len) else {
            return Err(CodeReadError::Unmapped { pc, len });
        };
        if relative % 4 != 0 || end > self.bytes.as_ref().len() {
            return Err(CodeReadError::Unmapped { pc, len });
        }
        Ok(offset)
    }
}

impl<B: AsRef<[u8]>> CodeProvider for MockCodeProvider<B> {
    fn entry_addr(&self) -> u64 {
        self.base_pc
    }

    fn read_exact(&self, pc: u64, dst: &mut [u8]) -> Result<(), CodeReadError> {
        let offset = self.offset(pc, dst.len())?;
        dst.copy_from_slice(&self.bytes.as_ref()[offset..offset + dst.len()]);
        Ok(())
    }
}

/// Fixture data window. x12 points at its base, and fixtures derive every data
/// address from x12. The window and the text base (`TEXT_BASE` in
/// `scripts/compile-asm-fixture.sh`) stay at or above Linux's `vm.mmap_min_addr`
/// (64 KiB) so the native runner maps them at the addresses the interpreter uses.
pub const FIXTURE_DATA_BASE: u64 = 0x20000;
/// Must equal the `TEXT_BASE` default in `scripts/compile-asm-fixture.sh`.
pub const FIXTURE_TEXT_BASE: u64 = 0x10000;
pub const FIXTURE_DATA_LEN: u64 = 0x4000;
/// TPIDR_EL0 of fixture cases: a TLS block in the last page of the data window.
pub const FIXTURE_TLS_BASE: u64 = FIXTURE_DATA_BASE + 0x3000;
/// CNTVCT_EL0 of fixture cases: a plausible uptime (~2 h at 24 MHz) whose bytes
/// all differ, so a misrouted or truncated read shows.
pub const FIXTURE_CNTVCT: u64 = 0x0000_00a1_b2c3_d4e5;
/// CNTFRQ_EL0 of fixture cases (the generic timer's common 24 MHz).
pub const FIXTURE_CNTFRQ: u64 = 24_000_000;
/// One read-only page right after the data window (x12 + 0x4000), so fixtures
/// can fault on a store to it. The page after it (x12 + 0x5000) is unmapped.
pub const FIXTURE_RO_BASE: u64 = FIXTURE_DATA_BASE + FIXTURE_DATA_LEN;

/// Initial machine state for `.s` fixture cases, before the text is mapped
/// (`fixture_state` adds it): x12 points at the fixture data window, which is
/// read-write, followed by one read-only page (`FIXTURE_RO_BASE`); TPIDR_EL0 is
/// `FIXTURE_TLS_BASE` inside the window; the counter reads `FIXTURE_CNTVCT` and
/// `FIXTURE_CNTFRQ`. Everything else is unmapped. The
/// fuzzer builds on it and its minimizer lifts states relative to it.
pub fn default_fixture_state() -> MachineState {
    let mut state = MachineState::new();
    state.write_x(12, FIXTURE_DATA_BASE);
    state.tpidr_el0 = FIXTURE_TLS_BASE;
    state.cntvct_el0 = FIXTURE_CNTVCT;
    state.cntfrq_el0 = FIXTURE_CNTFRQ;
    state
        .map_user_range(
            FIXTURE_DATA_BASE,
            FIXTURE_DATA_BASE + FIXTURE_DATA_LEN,
            PagePerm::ReadWrite,
        )
        .expect("fixture data window is page-aligned");
    state
        .map_user_range(
            FIXTURE_RO_BASE,
            FIXTURE_RO_BASE + PAGE_SIZE,
            PagePerm::ReadOnly,
        )
        .expect("fixture read-only page is page-aligned");
    state
}

/// The initial state of a fixture case: `default_fixture_state()` with the text
/// mapped (`with_text_mapped`). Shared by the fixture suites and `trace-tui`.
pub fn fixture_state(text_base: u64, text: &[u8]) -> Result<MachineState, String> {
    with_text_mapped(&default_fixture_state(), text_base, text)
}

/// `state` with the text a user page, as a process maps it: read-only (and
/// executable; the interpreter does not model execute permission), holding the
/// text bytes, so literal pools in the text load as data and a store to the text
/// faults. Every page the text touches is mapped; bytes past its end read zero.
/// The pages must not be mapped yet.
pub fn with_text_mapped(
    state: &MachineState,
    text_base: u64,
    text: &[u8],
) -> Result<MachineState, String> {
    let text_end = text_base
        .checked_add(text.len() as u64)
        .ok_or("text wraps the address space")?;
    let first_page = text_base & !(PAGE_SIZE - 1);
    let end_page = text_end
        .checked_add(PAGE_SIZE - 1)
        .ok_or("text wraps the address space")?
        & !(PAGE_SIZE - 1);
    let mut state = state.clone();
    for page in (first_page..end_page).step_by(PAGE_SIZE as usize) {
        if state.user_page_perm(page).is_some() {
            return Err(format!("text page {page:#x} is already a mapped user page"));
        }
    }
    state.map_user_range(first_page, end_page, PagePerm::ReadOnly)?;
    for (offset, &byte) in text.iter().enumerate() {
        state.write_le(text_base + offset as u64, 1, u64::from(byte));
    }
    Ok(state)
}

pub fn run_entry_fixture(
    name: &'static str,
    text_base: u64,
    text_bytes: Vec<u8>,
    entry_pc: u64,
    initial_state: &MachineState,
) -> Result<CaseReport, String> {
    let run = run_differential(
        text_base,
        text_bytes,
        entry_pc,
        initial_state,
        None,
        &mut |_| {},
    )
    .map_err(|err| match err {
        DifferentialError::Verify(message) => format!("verifier rejected `{name}`: {message}"),
        other => other.to_string(),
    })?;
    compare_differential(name, &run).map_err(|mismatch| mismatch.message)?;

    Ok(CaseReport {
        name,
        fragment: run.fragment,
        encoded_fragment: run.encoded_fragment,
        original: run.original,
        original_cap: run.original_cap,
        original_footprint: run.original_footprint,
        original_accesses: run.original_accesses,
        fragment_state: run.report.state,
        fragment_halt: run.report.halt,
        fragment_steps: run.report.steps,
    })
}

/// Bounds for `run_differential`. Hand-written fixtures run unbounded; generated
/// programs need bounds because either side may run forever (an SVC inside an
/// endless loop resets the back-edge budget on every re-entry).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StepLimits {
    /// Original instructions.
    pub original: usize,
    /// Fragment instructions, over all runtime entries.
    pub fragment: usize,
}

/// Both sides of one differential run, not yet compared.
#[derive(Debug)]
pub struct DifferentialRun {
    pub fragment: ExecutionFragment,
    pub encoded_fragment: Vec<u8>,
    pub original: ExecutionResult,
    /// Where the original was stopped to match a `Budget` exit of the fragment.
    pub original_cap: Option<InstanceCap>,
    /// When the original faulted: what it may already have done
    /// (`faulting_footprint`). Empty otherwise.
    pub original_footprint: Footprint,
    /// Every user access the original attempted, in order (a faulting one last).
    pub original_accesses: Vec<arm64::LoggedAccess>,
    pub report: URuntimeReport,
}

/// `state` with every footprint unit, and every byte of a footprint register,
/// that holds its new value reset to its value in `original` (the state before
/// the faulting instruction).
pub(crate) fn undo_footprint(
    original: &MachineState,
    footprint: &Footprint,
    state: &MachineState,
) -> MachineState {
    let mut state = state.clone();
    for unit in &footprint.stores {
        let got = state.read_le(unit.addr, unit.size);
        let old = original.read_le(unit.addr, unit.size);
        if got != old && got == unit.value {
            state.write_le(unit.addr, unit.size, old);
        }
    }
    for &(reg, new) in &footprint.vregs {
        let old = original.v[reg as usize];
        let mut got = state.v[reg as usize];
        for byte in 0..16 {
            let mask = 0xff_u128 << (8 * byte);
            if got & mask != old & mask && got & mask == new & mask {
                got = (got & !mask) | (old & mask);
            }
        }
        state.v[reg as usize] = got;
    }
    state
}

/// One store unit (one access) of an instruction, with the value it writes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StoreUnit {
    pub addr: u64,
    pub size: u8,
    pub value: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DifferentialError {
    /// `compile_request` rejected the code, or its fragment does not encode.
    Translate(String),
    /// The independent verifier rejected the encoded fragment.
    Verify(String),
    /// The fragment run failed outside the fragment (runtime setup, a `Budget`
    /// exit without a body label).
    Fragment(String),
    /// The original-code interpreter did not reach a halt.
    Original(OriginalRunError),
    /// Neither side halted within its `StepLimits`: the program does not
    /// terminate (e.g. an SVC in an endless loop, which resets the budget).
    NoHalt,
}

impl fmt::Display for DifferentialError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Translate(message) | Self::Fragment(message) => write!(f, "{message}"),
            Self::Verify(message) => write!(f, "verifier rejected the fragment: {message}"),
            Self::Original(err) => write!(f, "{err}"),
            Self::NoHalt => write!(f, "neither side halted within the step limits"),
        }
    }
}

/// Translates, encodes and verifies the code, runs the fragment through
/// `URuntime`, then runs the original through the interpreter from the same
/// initial state. The fragment runs first: a `Budget` exit decides where the
/// original stops (`InstanceCap`). `before_original_step` sees the interpreter
/// before each original step.
pub fn run_differential(
    text_base: u64,
    text_bytes: Vec<u8>,
    entry_pc: u64,
    initial_state: &MachineState,
    limits: Option<StepLimits>,
    before_original_step: &mut dyn FnMut(&OriginalStepper),
) -> Result<DifferentialRun, DifferentialError> {
    let fragment =
        compile_fixture_fragment(text_base, text_bytes.clone(), entry_pc, initial_state)
            .map_err(DifferentialError::Translate)?;
    let encoded_fragment = encode_fragment(&fragment).map_err(DifferentialError::Translate)?;
    // The kernel runs only verified fragments; so does every differential run.
    let verified = verify_encoded_fragment(&fragment, &encoded_fragment)
        .map_err(|err| DifferentialError::Verify(format!("{err:?}")))?;
    // A9a: the verifier's `uses_fpsimd`, derived from the bytes alone, agrees with
    // the translator's own view (some instruction names a V register).
    let names_v_register = fragment.insns.iter().any(|insn| {
        insn.operand_roles().iter().any(|role| {
            matches!(
                role,
                A64OperandRole::VecRead { .. } | A64OperandRole::VecWrite { .. }
            )
        })
    });
    if verified.uses_fpsimd != names_v_register {
        return Err(DifferentialError::Verify(format!(
            "uses_fpsimd = {} but the fragment {} a V register",
            verified.uses_fpsimd,
            if names_v_register {
                "names"
            } else {
                "never names"
            }
        )));
    }
    let mut runtime = URuntime::new(fragment, initial_state.clone());
    let (report, original_cap) =
        run_fragment_counting_instances(&mut runtime, limits.map(|limits| limits.fragment))
            .map_err(DifferentialError::Fragment)?;
    let mut original_accesses = Vec::new();
    let original = run_original_with_mocked_svc(
        &text_bytes,
        text_base,
        entry_pc,
        initial_state,
        None,
        original_cap,
        limits.map(|limits| limits.original),
        &mut |stepper| {
            // Before each step: every access of the steps so far. The halting
            // step accesses memory only when it faults (added below).
            let log = stepper.access_log().expect("original runs record accesses");
            original_accesses.extend_from_slice(&log[original_accesses.len()..]);
            before_original_step(stepper)
        },
    )
    .map_err(|err| match (&err, &report.halt) {
        (OriginalRunError::StepLimit { .. }, URuntimeHalt::StepLimit { .. }) => {
            DifferentialError::NoHalt
        }
        _ => DifferentialError::Original(err),
    })?;
    if let HaltReason::Fault(fault) = original.halt_reason {
        original_accesses.push(arm64::LoggedAccess {
            pc: fault.pc,
            access: fault.access,
            privilege: model::Privilege::User,
        });
    }
    let original_footprint = faulting_footprint(&text_bytes, text_base, &original)
        .map_err(|message| DifferentialError::Original(OriginalRunError::Harness(message)))?;
    let mut cache = runtime.into_cache();
    Ok(DifferentialRun {
        fragment: cache.fragments.swap_remove(0).fragment,
        encoded_fragment,
        original,
        original_cap,
        original_footprint,
        original_accesses,
        report,
    })
}

/// What a faulting original instruction may already have done when it aborted,
/// and what userspace then redoes when it re-executes it:
/// - docs/pipeline.md "Fault sites (A5)", fault footprint: a store split into several
///   user accesses (STP) that faults on a later one has already written the
///   earlier units;
/// - A9a: a SIMD&FP access is performed in smaller single-copy-atomic parts, so
///   the bytes of the faulting access itself that lie on permitted pages may
///   already be written (hardware writes the part of an `stp q` before a
///   read-only page), and a load's SIMD&FP destination registers are UNKNOWN
///   after the abort (hardware loads `q0` of an `ldp q0, q1` and the first
///   registers of an `ld1` before the faulting page).
///
/// Each unit or register byte may hold its old or its new value, the new one
/// being what a complete execution writes. Empty unless the original halted on a
/// permission fault (an alignment fault performs no access).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Footprint {
    pub stores: Vec<StoreUnit>,
    /// SIMD&FP registers (number, value after a complete execution).
    pub vregs: Vec<(u8, u128)>,
}

pub(crate) fn faulting_footprint(
    text: &[u8],
    text_base: u64,
    original: &ExecutionResult,
) -> Result<Footprint, String> {
    let HaltReason::Fault(fault) = original.halt_reason else {
        return Ok(Footprint::default());
    };
    if fault.cause != model::FaultCause::Permission {
        return Ok(Footprint::default());
    }
    let insn = match admit_at(&MockCodeProvider::new(text_base, text), fault.pc)
        .map_err(|err| err.to_string())?
    {
        Ok(insn) => insn.inner,
        Err(exit) => return Err(format!("faulting pc {:#x} is an exit: {exit:?}", fault.pc)),
    };
    let execute = |state: &mut MachineState| {
        let mut log = Vec::new();
        let result = arm64::execute_insn(
            insn,
            fault.pc,
            state,
            &mut arm64::AccessContext::Original {
                counter: None,
                log: Some(&mut log),
            },
        );
        (result, log)
    };

    // The accesses before the faulting one passed their checks.
    let (_, log) = execute(&mut original.state.clone());
    let mut units = log
        .iter()
        .take(log.len().saturating_sub(1))
        .filter(|logged| logged.access.kind == model::AccessKind::Write)
        .map(|logged| (logged.access.addr, logged.access.size))
        .collect::<Vec<_>>();
    // An access that starts outside the 48-bit user VA (the kernel half, or past
    // 2^48) performs nothing of itself: EL0 translation faults on its first byte
    // and a window's range check leaves before it.
    let user_address = fault.access.addr >> crate::shared::abi::USER_VA_BITS == 0;
    // The faulting store's own bytes on writable pages (A9a).
    if user_address && fault.access.kind == model::AccessKind::Write {
        for addr in fault.access.addr
            ..fault
                .access
                .addr
                .saturating_add(u64::from(fault.access.size))
        {
            if original.state.user_access_allowed(model::MemAccess {
                addr,
                size: 1,
                kind: model::AccessKind::Write,
            }) {
                units.push((addr, 1));
            }
        }
    }
    let simd_load =
        user_address && insn.fpsimd_mem().is_some() && fault.access.kind == model::AccessKind::Read;
    if units.is_empty() && !simd_load {
        return Ok(Footprint::default());
    }

    // New values: rerun with every page the instruction faults on made writable
    // (a later access of an LD1/ST1 may fault on a further page).
    let mut state = original.state.clone();
    let mut faulting = fault.access;
    for _ in 0..8 {
        let end = faulting
            .addr
            .checked_add(u64::from(faulting.size))
            .ok_or_else(|| format!("faulting access at {:#x} wraps", faulting.addr))?;
        let first_page = faulting.addr & !(PAGE_SIZE - 1);
        let end_page = end.checked_add(PAGE_SIZE - 1).ok_or_else(|| {
            format!(
                "faulting access at {:#x} ends at the top page",
                faulting.addr
            )
        })? & !(PAGE_SIZE - 1);
        state.map_user_range(first_page, end_page, PagePerm::ReadWrite)?;
        let mut attempt = state.clone();
        match execute(&mut attempt) {
            (Ok(_), _) => {
                let stores = units
                    .iter()
                    .map(|&(addr, size)| StoreUnit {
                        addr,
                        size,
                        value: attempt.read_le(addr, size),
                    })
                    .collect();
                let vregs = (0..32u8)
                    .filter(|&reg| attempt.v[reg as usize] != original.state.v[reg as usize])
                    .map(|reg| (reg, attempt.v[reg as usize]))
                    .collect();
                return Ok(Footprint { stores, vregs });
            }
            (Err(arm64::InsnError::Fault(next)), _) => faulting = next.access,
            (Err(err), _) => {
                return Err(format!(
                    "instruction at {:#x} fails with its faulting pages writable: {err:?}",
                    fault.pc
                ))
            }
        }
    }
    Err(format!(
        "instruction at {:#x} still faults with its faulting pages writable",
        fault.pc
    ))
}


/// Runs a fragment to its halt like `URuntime::run`, and, when it ends in a `Budget`
/// exit at back-edge `pc`, returns where the original run must stop to match it.
///
/// The fragment starts original instruction `pc` exactly when it executes `pc`'s
/// body label: every runtime entry, branch and fall-through into `pc` lands there,
/// and for a back-edge that label is the first instruction of its budget check. So
/// the exit happened on dynamic instance `executions(label(pc))` of `pc`.
///
/// `max_steps = Some(n)` halts with `StepLimit` after n fragment instructions.
/// Unbounded, more than `MAX_RUNTIME_EXITS` runtime continuations are an error;
/// bounded, they are a `StepLimit` halt too (the run did not end).
pub(crate) fn run_fragment_counting_instances(
    runtime: &mut URuntime,
    max_steps: Option<usize>,
) -> Result<(URuntimeReport, Option<InstanceCap>), String> {
    let counted = run_counting(runtime, max_steps, false)?;
    Ok((counted.report, counted.cap))
}

/// A fragment run with its dynamic instance counts resolved (`run_counting`).
pub(crate) struct CountedRun {
    pub(crate) report: URuntimeReport,
    pub(crate) cap: Option<InstanceCap>,
    /// Runtime round trips: fragment entries after the first.
    pub(crate) runtime_entries: usize,
}

/// `run_fragment_counting_instances` over every fragment the run executes. Original
/// pc P's dynamic instances are the executions of P's body label, summed over the
/// fragments that hold one (a dispatch hit enters another fragment at its label).
///
/// `cap_svc_exits`: a cached run's chain budget can return to userspace at an `SVC`
/// (`CodeCache::with_chain_budget`); the original, which does not stop at an SVC,
/// is capped before that SVC like before a `Budget` exit's branch.
pub(crate) fn run_counting(
    runtime: &mut URuntime,
    max_steps: Option<usize>,
    cap_svc_exits: bool,
) -> Result<CountedRun, String> {
    // executions[fragment][insn index]
    let mut executions: Vec<Vec<u64>> = Vec::new();
    let mut continuations = 0usize;
    let report = {
        let mut stepper = URuntimeStepper::new(runtime)
            .map_err(|message| format!("fragment runtime setup failed: {message}"))?;
        loop {
            if max_steps.is_some_and(|max| stepper.steps() >= max) {
                break stepper.report_for_halt(URuntimeHalt::StepLimit {
                    pc: stepper.pc(),
                    steps: stepper.steps(),
                });
            }
            let step = match stepper.advance() {
                Ok(Some(step)) => step,
                Ok(None) => {
                    break stepper.report_for_halt(URuntimeHalt::ExecutionError {
                        pc: stepper.pc(),
                        message: "runtime stepper stopped without a halt reason".to_string(),
                    })
                }
                Err(message) => {
                    break stepper.report_for_halt(URuntimeHalt::ExecutionError {
                        pc: stepper.pc(),
                        message,
                    })
                }
            };
            if let (true, Some(offset)) = (step.executed, step.offset) {
                if executions.len() <= step.fragment {
                    executions.resize_with(step.fragment + 1, Vec::new);
                }
                let counts = &mut executions[step.fragment];
                if counts.len() <= offset / 4 {
                    counts.resize(offset / 4 + 1, 0);
                }
                counts[offset / 4] += 1;
            }
            if step.runtime_transition.is_some_and(|transition| {
                matches!(transition, runtime::URuntimeTransition::Continued { .. })
            }) {
                continuations += 1;
                if continuations >= MAX_RUNTIME_EXITS {
                    if max_steps.is_some() {
                        break stepper.report_for_halt(URuntimeHalt::StepLimit {
                            pc: stepper.pc(),
                            steps: stepper.steps(),
                        });
                    }
                    return Err(
                        "fragment run exceeded the runtime-exit continuation limit".to_string()
                    );
                }
            }
            if let Some(halt) = step.halt {
                break stepper.report_for_halt(halt);
            }
        }
    };

    let pc = match report.halt {
        URuntimeHalt::ReturnedToUserspace {
            status: crate::shared::abi::RetStatus::Budget,
            target_pc,
        } => target_pc,
        URuntimeHalt::ReturnedToUserspace {
            status: crate::shared::abi::RetStatus::Svc,
            target_pc,
        } if cap_svc_exits => target_pc.wrapping_sub(4),
        _ => {
            return Ok(CountedRun {
                report,
                cap: None,
                runtime_entries: continuations,
            })
        }
    };
    let mut instance = 0;
    let mut labelled = false;
    for (index, frag) in runtime.cache().fragments.iter().enumerate() {
        if let Some(label) = frag.label_for_pc(pc) {
            labelled = true;
            instance += executions
                .get(index)
                .and_then(|counts| counts.get(label.offset / 4))
                .copied()
                .unwrap_or(0);
        }
    }
    if !labelled {
        return Err(format!("exit at {pc:#x}, which has no body label"));
    }
    if instance == 0 {
        return Err(format!(
            "exit at {pc:#x}, but its body label never executed"
        ));
    }
    Ok(CountedRun {
        report,
        cap: Some(InstanceCap { pc, instance }),
        runtime_entries: continuations,
    })
}

/// `InstanceCap` of a fixture case: compiles and runs its fragment
/// (`run_fragment_counting_instances`). `None` unless the fragment ends in `Budget`.
#[cfg(test)]
pub(crate) fn fragment_instance_cap(
    text_base: u64,
    text_bytes: &[u8],
    entry_pc: u64,
    initial_state: &MachineState,
) -> Result<Option<InstanceCap>, String> {
    let fragment =
        compile_fixture_fragment(text_base, text_bytes.to_vec(), entry_pc, initial_state)?;
    let mut runtime = URuntime::new(fragment, initial_state.clone());
    Ok(run_fragment_counting_instances(&mut runtime, None)?.1)
}

/// Translates a fixture case exactly as `run_entry_fixture` does.
pub(crate) fn compile_fixture_fragment(
    text_base: u64,
    text_bytes: Vec<u8>,
    entry_pc: u64,
    initial_state: &MachineState,
) -> Result<ExecutionFragment, String> {
    let code = MockCodeProvider::new(text_base, text_bytes);
    let request = TranslationRequest {
        entry_pc,
        trigger: TranslationTrigger::HotSvc,
        regs: Some(register_snapshot(initial_state, entry_pc)),
    };
    compile_request(&request, &code).map_err(|err| err.to_string())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MismatchKind {
    /// Final user state (registers, SP, NZCV, memory, page map) differs.
    State,
    /// Both states agree but the halts do not correspond.
    Halt,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mismatch {
    pub kind: MismatchKind,
    pub message: String,
}

/// The differential oracle: the fragment must end in the original's user
/// state with a corresponding halt, except that each unit of a faulting store's
/// footprint may hold its new value. The only copy of this check; the fixture
/// suite, `trace-tui --check` and the fuzzer all use it.
pub fn compare_differential(name: &str, run: &DifferentialRun) -> Result<(), Mismatch> {
    let (original, report) = (&run.original, &run.report);
    let fragment_state = undo_footprint(&original.state, &run.original_footprint, &report.state);
    if original.state != fragment_state {
        return Err(Mismatch {
            kind: MismatchKind::State,
            message: format!(
                "original vs fragment state mismatch for `{name}`\noriginal: {:#?}\nfragment: {:#?}",
                original.state, report.state,
            ),
        });
    }
    if !runtime_halt_matches_original(original, &report.halt) {
        return Err(Mismatch {
            kind: MismatchKind::Halt,
            message: format!(
                "original vs fragment halt mismatch for `{name}`\noriginal: {:#?}\nfragment: {:#?}",
                original.halt_reason, report.halt,
            ),
        });
    }
    Ok(())
}

pub fn run_legacy_flattened_fixture(
    text_base: u64,
    text_bytes: Vec<u8>,
    entry_pc: u64,
    initial_state: &MachineState,
) -> Result<TranslatedProgram, String> {
    let code = MockCodeProvider::new(text_base, text_bytes);
    let request = TranslationRequest {
        entry_pc,
        trigger: TranslationTrigger::HotSvc,
        regs: Some(register_snapshot(initial_state, entry_pc)),
    };
    translate_request(&request, &code).map_err(|err| err.to_string())
}

/// Why the original-code interpreter stopped without a halt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OriginalRunError {
    /// `limit` instructions executed without a halt.
    StepLimit { limit: usize },
    /// Interpreter error: unsupported form, SVC continuation limit, ...
    Harness(String),
}

impl fmt::Display for OriginalRunError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StepLimit { limit } => {
                write!(f, "original code did not halt within {limit} steps")
            }
            Self::Harness(message) => write!(f, "{message}"),
        }
    }
}

impl From<String> for OriginalRunError {
    fn from(message: String) -> Self {
        Self::Harness(message)
    }
}

impl From<OriginalRunError> for String {
    fn from(err: OriginalRunError) -> Self {
        err.to_string()
    }
}

/// Runs original code to a halt, resuming after every SVC as if the syscall
/// returned without side effects. `fail_user_access = Some(k)` faults the k-th
/// dynamic user access of the whole run (1-based, SVC continuations included)
/// regardless of permissions. `cap` halts with `HaltReason::InstanceCap` before the
/// instruction it names executes. `step_limit = Some(n)` fails with `StepLimit`
/// once n instructions have executed without a halt. `before_step` sees the
/// stepper before each step, the capped one included; the stepper records its accesses
/// (`OriginalStepper::access_log`).
pub(crate) fn run_original_with_mocked_svc(
    program: &[u8],
    text_base: u64,
    entry_pc: u64,
    initial_state: &MachineState,
    fail_user_access: Option<u64>,
    cap: Option<InstanceCap>,
    step_limit: Option<usize>,
    before_step: &mut dyn FnMut(&OriginalStepper),
) -> Result<ExecutionResult, OriginalRunError> {
    run_original(
        program,
        text_base,
        entry_pc,
        initial_state,
        fail_user_access,
        cap,
        step_limit,
        false,
        before_step,
    )
}

/// `run_original_with_mocked_svc` for a run over a code cache: BL/BLR/BR/RET are
/// executed (`OriginalStepper::follow_branches`), so the run ends only at an SVC-free
/// halt: a fault, an `Unsupported` pc (an unreadable branch target included), or the
/// `cap` (a `Budget` exit, or a `Ret` return to userspace, of the fragment run).
pub(crate) fn run_original_following_branches(
    program: &[u8],
    text_base: u64,
    entry_pc: u64,
    initial_state: &MachineState,
    cap: Option<InstanceCap>,
    step_limit: Option<usize>,
    before_step: &mut dyn FnMut(&OriginalStepper),
) -> Result<ExecutionResult, OriginalRunError> {
    run_original(
        program,
        text_base,
        entry_pc,
        initial_state,
        None,
        cap,
        step_limit,
        true,
        before_step,
    )
}

fn run_original(
    program: &[u8],
    text_base: u64,
    entry_pc: u64,
    initial_state: &MachineState,
    fail_user_access: Option<u64>,
    cap: Option<InstanceCap>,
    step_limit: Option<usize>,
    follow_branches: bool,
    before_step: &mut dyn FnMut(&OriginalStepper),
) -> Result<ExecutionResult, OriginalRunError> {
    let mut stepper =
        OriginalStepper::new(program, text_base, entry_pc, initial_state)?.record_accesses();
    if follow_branches {
        stepper = stepper.follow_branches();
    }
    if let Some(k) = fail_user_access {
        stepper = stepper.fail_user_access(k);
    }
    let mut steps = 0usize;
    let mut runtime_exits = 0usize;
    let mut cap_arrivals = 0u64;

    loop {
        if let Some(limit) = step_limit.filter(|&limit| steps >= limit) {
            return Err(OriginalRunError::StepLimit { limit });
        }
        before_step(&stepper);
        if let Some(cap) = cap.filter(|cap| cap.pc == stepper.pc()) {
            cap_arrivals += 1;
            if cap_arrivals == cap.instance {
                return Ok(ExecutionResult {
                    state: stepper.state().clone(),
                    halt_reason: HaltReason::InstanceCap {
                        pc: cap.pc,
                        instance: cap.instance,
                    },
                    steps,
                });
            }
        }
        let Some(step) = stepper.advance()? else {
            return Err("original stepper stopped without a halt reason"
                .to_string()
                .into());
        };
        if step.executed {
            steps += 1;
        }
        match step.halt_reason {
            None => {}
            Some(HaltReason::RuntimeExit {
                reason: RuntimeExitReason::Svc { resume_pc, .. },
            }) => {
                runtime_exits += 1;
                // Bounded, endless SVC continuations are one more way not to halt.
                if let Some(limit) = step_limit.filter(|_| runtime_exits >= MAX_RUNTIME_EXITS) {
                    return Err(OriginalRunError::StepLimit { limit });
                }
                if runtime_exits >= MAX_RUNTIME_EXITS {
                    return Err("original fixture exceeded runtime-exit continuation limit"
                        .to_string()
                        .into());
                }
                stepper.resume_at(resume_pc);
            }
            Some(halt_reason) => {
                return Ok(ExecutionResult {
                    state: stepper.state().clone(),
                    halt_reason,
                    steps,
                });
            }
        }
    }
}

pub(crate) fn runtime_halt_matches_original(original: &ExecutionResult, halt: &URuntimeHalt) -> bool {
    match (original.halt_reason, halt) {
        (
            HaltReason::RuntimeExit {
                reason: RuntimeExitReason::Ret { lr_reg },
            },
            URuntimeHalt::ReturnedToUserspace {
                status: crate::shared::abi::RetStatus::Ret,
                target_pc,
            },
        ) => original.state.read_x(lr_reg) == *target_pc,
        (
            HaltReason::RuntimeExit {
                reason: RuntimeExitReason::Br { target_reg },
            },
            URuntimeHalt::NeedsTranslation {
                status: crate::shared::abi::RetStatus::Br,
                target_pc,
                ..
            },
        ) => original.state.read_x(target_reg) == *target_pc,
        (
            HaltReason::RuntimeExit {
                reason: RuntimeExitReason::Bl { target_pc, .. },
            },
            URuntimeHalt::NeedsTranslation {
                status: crate::shared::abi::RetStatus::Bl,
                target_pc: runtime_target_pc,
                ..
            },
        ) => target_pc == *runtime_target_pc,
        (
            HaltReason::RuntimeExit {
                reason: RuntimeExitReason::Blr { target_reg, .. },
            },
            URuntimeHalt::NeedsTranslation {
                status: crate::shared::abi::RetStatus::Blr,
                target_pc,
                ..
            },
        ) => {
            target_reg == crate::shared::abi::ABI_LINK_REG
                || original.state.read_x(target_reg) == *target_pc
        }
        (
            HaltReason::RuntimeExit {
                reason: RuntimeExitReason::Unsupported { pc, .. },
            },
            URuntimeHalt::ReturnedToUserspace {
                status: crate::shared::abi::RetStatus::Unsupported,
                target_pc,
            },
        ) => pc == *target_pc,
        // The original faulted; the fragment must leave through that instruction's
        // Mem stub so userspace re-executes it and takes the fault itself.
        (
            HaltReason::Fault(fault),
            URuntimeHalt::ReturnedToUserspace {
                status: crate::shared::abi::RetStatus::Mem,
                target_pc,
            },
        ) => fault.pc == *target_pc,
        // The original was capped at the dynamic instance the fragment's Budget exit
        // counted; userspace resumes natively at that back-edge branch.
        (
            HaltReason::InstanceCap { pc, .. },
            URuntimeHalt::ReturnedToUserspace {
                status: crate::shared::abi::RetStatus::Budget,
                target_pc,
            },
        ) => pc == *target_pc,
        _ => false,
    }
}

pub fn encode_legacy_translated_program(program: &TranslatedProgram) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::with_capacity(program.len() * 4);
    for insn in program {
        let word = insn
            .inner
            .encode()
            .map_err(|err| format!("failed to encode {}: {err:?}", insn.inner.key()))?;
        bytes.extend_from_slice(&word.to_le_bytes());
    }
    Ok(bytes)
}

pub fn encode_fragment(fragment: &ExecutionFragment) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::with_capacity(fragment.insns.len() * 4);
    for insn in &fragment.insns {
        let word = insn
            .encode()
            .map_err(|err| format!("failed to encode {}: {err:?}", insn.key()))?;
        bytes.extend_from_slice(&word.to_le_bytes());
    }
    Ok(bytes)
}

/// The side tables the kernel holds next to a fragment's code, in the verifier's
/// input shape. Built from translator types here; the verifier never sees them.
pub struct FragmentTables {
    pub fault_sites: Vec<FaultSiteEntry>,
    /// `entry_offset` and every `vlabels` offset: any of them can be the runtime's
    /// entry address (`offset_for_pc` after a runtime exit).
    pub entry_offsets: Vec<usize>,
}

impl FragmentTables {
    pub fn of(fragment: &ExecutionFragment) -> Self {
        let fault_sites = fragment
            .fault_sites
            .iter()
            .map(|site| FaultSiteEntry {
                access_offset: site.access_offset,
                stub_offset: site.stub_offset,
            })
            .collect();
        let entry_offsets = core::iter::once(fragment.entry_offset)
            .chain(fragment.vlabels.iter().map(|&(_, offset)| offset))
            .collect();
        Self {
            fault_sites,
            entry_offsets,
        }
    }

    pub fn input<'a>(&'a self, code: &'a [u8]) -> VerifyInput<'a> {
        VerifyInput {
            code,
            fault_sites: &self.fault_sites,
            entry_offsets: &self.entry_offsets,
        }
    }
}

/// Runs the independent verifier over `code`, the encoding of `fragment`.
pub fn verify_encoded_fragment(
    fragment: &ExecutionFragment,
    code: &[u8],
) -> Result<VerifyOk, VerifyError> {
    verify_fragment(&FragmentTables::of(fragment).input(code))
}

fn register_snapshot(state: &MachineState, pc: u64) -> RegisterSnapshot {
    let mut x = [0_u64; 31];
    for reg in 0..31 {
        x[reg] = state.read_x(reg as u8);
    }
    RegisterSnapshot {
        x,
        sp: state.sp(),
        pc,
        pstate: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::arm64::{
        A64Condition, A64Imm, A64Insn, A64Mem, A64Reg, A64Reg31Mode, A64RegWidth,
    };

    #[test]
    fn generated_arm64_subset_matches_sample_opcodes() {
        let samples = [
            ("ADR.ADR_only_pcreladdr", 0x1000_0000_u32),
            ("ADD_addsub_imm.ADD_64_addsub_imm", 0x9100_1441_u32),
            ("B_uncond.B_only_branch_imm", 0x1400_0000_u32),
            ("B_cond.B_only_condbranch", 0x5400_0000_u32),
            ("CBZ.CBZ_64_compbranch", 0xB400_0003_u32),
            ("CBNZ.CBNZ_64_compbranch", 0xB500_0004_u32),
            ("MOVZ.MOVZ_64_movewide", 0xD2A2_4685_u32),
            ("MOVK.MOVK_64_movewide", 0xF2D5_79A5_u32),
            ("TBZ.TBZ_only_testbranch", 0x3638_0006_u32),
            ("TBNZ.TBNZ_only_testbranch", 0xB708_0007_u32),
            ("LDR_imm_gen.LDR_64_ldst_pos", 0xF940_0928_u32),
            ("STR_imm_gen.STR_64_ldst_pos", 0xF900_0D6A_u32),
        ];

        for (expected_key, opcode) in samples {
            let insn = A64Insn::decode(opcode).unwrap_or_else(|| {
                panic!("no generated instruction matched opcode {opcode:#010x}")
            });
            assert_eq!(
                insn.key(),
                expected_key,
                "unexpected match for opcode {opcode:#010x}"
            );
        }
    }

    #[test]
    fn generated_arm64_subset_extracts_expected_fields() {
        assert_eq!(
            A64Insn::decode(0x9100_1441),
            Some(A64Insn::AddAddsubImmAdd64AddsubImm {
                sh: 0,
                imm12: A64Imm::unsigned(5, 12),
                rn: A64Reg::x_sp(2),
                rd: A64Reg::x_sp(1),
            })
        );
        assert_eq!(
            A64Insn::decode(0xD2A2_4685),
            Some(A64Insn::MovzMovz64Movewide {
                hw: 1,
                imm16: A64Imm::unsigned(0x1234, 16),
                rd: A64Reg::x(5),
            })
        );
        assert_eq!(
            A64Insn::decode(0xF2D5_79A5),
            Some(A64Insn::MovkMovk64Movewide {
                hw: 2,
                imm16: A64Imm::unsigned(0xABCD, 16),
                rd: A64Reg::x(5),
            })
        );
        assert_eq!(
            A64Insn::decode(0x3638_0006),
            Some(A64Insn::TbzTbzOnlyTestbranch {
                b5: 0,
                b40: 7,
                imm14: A64Imm::scaled_signed(0, 14, 2),
                rt: A64Reg::new(6, A64RegWidth::Unknown, A64Reg31Mode::Xzr),
            })
        );
        assert_eq!(
            A64Insn::decode(0xB708_0007),
            Some(A64Insn::TbnzTbnzOnlyTestbranch {
                b5: 1,
                b40: 1,
                imm14: A64Imm::scaled_signed(0, 14, 2),
                rt: A64Reg::new(7, A64RegWidth::Unknown, A64Reg31Mode::Xzr),
            })
        );
        assert_eq!(
            A64Insn::decode(0xF940_0928),
            Some(A64Insn::LdrImmGenLdr64LdstPos {
                rt: A64Reg::x(8),
                mem: A64Mem::offset(A64Reg::x_sp(9), A64Imm::scaled_unsigned(2, 12, 3)),
            })
        );
        assert_eq!(
            A64Insn::decode(0xF900_0D6A),
            Some(A64Insn::StrImmGenStr64LdstPos {
                rt: A64Reg::x(10),
                mem: A64Mem::offset(A64Reg::x_sp(11), A64Imm::scaled_unsigned(3, 12, 3)),
            })
        );
    }

    #[test]
    fn shared_cfg_splits_conditional_branch_into_basic_blocks() {
        use crate::shared::trans::cfg::build_cfg;

        let base_pc = 0x6000;
        let mut program = Vec::new();
        program.extend_from_slice(
            &encode(A64Insn::MovzMovz64Movewide {
                hw: 0,
                imm16: A64Imm::unsigned(5, 16),
                rd: A64Reg::x(0),
            })
            .to_le_bytes(),
        );
        program.extend_from_slice(
            &encode(A64Insn::SubsAddsubImmSubs64sAddsubImm {
                sh: 0,
                imm12: A64Imm::unsigned(5, 12),
                rn: A64Reg::x_sp(0),
                rd: A64Reg::x(31),
            })
            .to_le_bytes(),
        );
        program.extend_from_slice(
            &encode(A64Insn::BCondBOnlyCondbranch {
                imm19: A64Imm::scaled_signed(branch_imm(8, 19), 19, 2),
                cond: A64Condition::Eq.bits(),
            })
            .to_le_bytes(),
        );
        program.extend_from_slice(
            &encode(A64Insn::MovzMovz64Movewide {
                hw: 0,
                imm16: A64Imm::unsigned(0x1111, 16),
                rd: A64Reg::x(1),
            })
            .to_le_bytes(),
        );
        program.extend_from_slice(
            &encode(A64Insn::MovzMovz64Movewide {
                hw: 0,
                imm16: A64Imm::unsigned(0x2222, 16),
                rd: A64Reg::x(1),
            })
            .to_le_bytes(),
        );

        let code = MockCodeProvider::new(base_pc, program);
        let request = TranslationRequest {
            entry_pc: base_pc,
            trigger: TranslationTrigger::Manual,
            regs: None,
        };
        let cfg = build_cfg(&request, &code).unwrap();

        assert_eq!(cfg.blocks.len(), 3);

        assert_eq!(cfg.blocks[0].start_addr, base_pc);
        assert_eq!(cfg.blocks[0].end_addr, base_pc + 12);
        assert_eq!(cfg.blocks[0].insns.len(), 3);
        assert_eq!(&*cfg.blocks[0].prev, &[]);
        assert_eq!(
            &*cfg.blocks[0].next,
            &[cfg.blocks[2].start_addr, cfg.blocks[1].start_addr]
        );

        assert_eq!(cfg.blocks[1].start_addr, base_pc + 12);
        assert_eq!(cfg.blocks[1].end_addr, base_pc + 16);
        assert_eq!(cfg.blocks[1].insns.len(), 1);
        assert_eq!(&*cfg.blocks[1].prev, &[cfg.blocks[0].start_addr]);
        assert_eq!(&*cfg.blocks[1].next, &[cfg.blocks[2].start_addr]);

        assert_eq!(cfg.blocks[2].start_addr, base_pc + 16);
        assert_eq!(cfg.blocks[2].end_addr, base_pc + 20);
        assert_eq!(cfg.blocks[2].insns.len(), 1);
        assert_eq!(
            &*cfg.blocks[2].prev,
            &[cfg.blocks[0].start_addr, cfg.blocks[1].start_addr]
        );
        assert_eq!(&*cfg.blocks[2].next, &[]);
    }

    #[test]
    fn shared_cfg_splits_existing_block_when_branch_targets_middle() {
        use crate::shared::trans::cfg::build_cfg;

        let base_pc = 0x9000;
        let mut program = Vec::new();
        program.extend_from_slice(
            &encode(A64Insn::BCondBOnlyCondbranch {
                imm19: A64Imm::scaled_signed(branch_imm(12, 19), 19, 2),
                cond: A64Condition::Eq.bits(),
            })
            .to_le_bytes(),
        );
        program.extend_from_slice(&encode(A64Insn::NopNopHiHints {}).to_le_bytes());
        program.extend_from_slice(&encode(A64Insn::NopNopHiHints {}).to_le_bytes());
        program.extend_from_slice(
            &encode(A64Insn::BUncondBOnlyBranchImm {
                imm26: A64Imm::scaled_signed(branch_imm(-4, 26), 26, 2),
            })
            .to_le_bytes(),
        );

        let code = MockCodeProvider::new(base_pc, program);
        let request = TranslationRequest {
            entry_pc: base_pc,
            trigger: TranslationTrigger::Manual,
            regs: None,
        };
        let cfg = build_cfg(&request, &code).unwrap();

        assert_eq!(cfg.blocks.len(), 4);
        assert_eq!(cfg.blocks[0].start_addr, base_pc);
        assert_eq!(cfg.blocks[1].start_addr, base_pc + 4);
        assert_eq!(cfg.blocks[2].start_addr, base_pc + 8);
        assert_eq!(cfg.blocks[3].start_addr, base_pc + 12);

        assert_eq!(cfg.blocks[1].end_addr, base_pc + 8);
        assert_eq!(cfg.blocks[1].insns.len(), 1);
        assert_eq!(&*cfg.blocks[1].prev, &[cfg.blocks[0].start_addr]);
        assert_eq!(&*cfg.blocks[1].next, &[base_pc + 8]);

        assert_eq!(cfg.blocks[2].end_addr, base_pc + 12);
        assert_eq!(cfg.blocks[2].insns.len(), 1);
        assert_eq!(
            &*cfg.blocks[2].prev,
            &[base_pc + 4, cfg.blocks[3].start_addr]
        );
        assert_eq!(&*cfg.blocks[2].next, &[base_pc + 12]);

        assert_eq!(
            &*cfg.blocks[3].prev,
            &[cfg.blocks[0].start_addr, base_pc + 8]
        );
        assert_eq!(&*cfg.blocks[3].next, &[base_pc + 8]);
    }

    /// A pair store whose second unit faults (read-only page): the fragment has
    /// already stored the first unit, which the oracle accepts as the store
    /// footprint (docs/pipeline.md "Fault sites (A5)").
    #[test]
    fn faulting_pair_store_may_leave_its_first_unit_written() {
        let text_base = FIXTURE_TEXT_BASE;
        let svc = encode(A64Insn::SvcSvcExException {
            imm16: A64Imm::unsigned(0, 16),
        });
        let stp = encode(A64Insn::StpGenStp64LdstpairOff {
            rt2: A64Reg::x(1),
            rt: A64Reg::x(0),
            mem: A64Mem::offset(A64Reg::x_sp(2), A64Imm::scaled_signed(0, 7, 3)),
        });
        let text = [svc, stp]
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .collect::<Vec<u8>>();
        let mut state = default_fixture_state();
        state.write_x(0, 0x1111);
        state.write_x(1, 0x2222);
        state.write_x(2, FIXTURE_RO_BASE - 8);

        let run = run_differential(text_base, text, text_base + 4, &state, None, &mut |_| {})
            .unwrap();
        assert_eq!(
            run.original_footprint.stores,
            [StoreUnit {
                addr: FIXTURE_RO_BASE - 8,
                size: 8,
                value: 0x1111,
            }]
        );
        assert_eq!(run.report.state.read_u64(FIXTURE_RO_BASE - 8), 0x1111);
        assert_eq!(run.original.state.read_u64(FIXTURE_RO_BASE - 8), 0);
        compare_differential("pair-store-footprint", &run).unwrap();
    }

    fn encode(insn: A64Insn) -> u32 {
        insn.encode()
            .unwrap_or_else(|err| panic!("failed to encode {}: {err:?}", insn.key()))
    }

    fn branch_imm(offset_bytes: i64, bits: u8) -> u32 {
        assert_eq!(offset_bytes % 4, 0);
        let value = offset_bytes >> 2;
        let min = -(1_i64 << (bits - 1));
        let max = (1_i64 << (bits - 1)) - 1;
        assert!((min..=max).contains(&value));
        (value as i128 & ((1_i128 << bits) - 1)) as u32
    }
}
