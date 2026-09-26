extern crate alloc;

pub mod a64_pretty;
pub mod active_step;
pub mod explorer;
pub mod golden;
pub mod arm64;
pub mod model;
// Platform gate, not a skip: the native oracle executes AArch64 code on the host
// CPU and needs Linux signal/ucontext semantics (macOS reserves x18). Run it with
// `make harness-test-native`, which fails unless it reaches Linux arm64.
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
pub mod native;
pub mod runtime;
pub mod shared;
pub mod trace;

#[cfg(test)]
mod asm_fixture_tests;
#[cfg(test)]
mod encoding_tests;

use crate::shared::emit::layout::ExecutionFragment;
use crate::shared::trans::cfg::RuntimeExitReason;
use crate::shared::trans::input::{
    CodeProvider, CodeReadError, RegisterSnapshot, TranslationRequest, TranslationTrigger,
};
use crate::shared::trans::translate::{compile_request, translate_request, TranslatedProgram};
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
    pub fragment_state: MachineState,
    pub fragment_halt: URuntimeHalt,
    pub fragment_steps: usize,
}

/// Stop an original run right before the `instance`-th (1-based) execution of the
/// instruction at `pc`, counted over the whole run (SVC continuations included).
/// This is the dynamic point where a fragment's `Budget` exit returns to userspace
/// (tmp/pipeline.md, "Execution budget (A6)"); `fragment_instance_cap` derives it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InstanceCap {
    pub pc: u64,
    pub instance: u64,
}

pub struct MockCodeProvider {
    base_pc: u64,
    bytes: Vec<u8>,
}

impl MockCodeProvider {
    pub fn new(base_pc: u64, bytes: Vec<u8>) -> Self {
        Self { base_pc, bytes }
    }

    pub fn slice_from(&self, pc: u64) -> Result<&[u8], String> {
        let offset = self.offset(pc, 0).map_err(|err| err.to_string())?;
        Ok(&self.bytes[offset..])
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
        if relative % 4 != 0 || end > self.bytes.len() {
            return Err(CodeReadError::Unmapped { pc, len });
        }
        Ok(offset)
    }
}

impl CodeProvider for MockCodeProvider {
    fn entry_addr(&self) -> u64 {
        self.base_pc
    }

    fn read_exact(&self, pc: u64, dst: &mut [u8]) -> Result<(), CodeReadError> {
        let offset = self.offset(pc, dst.len())?;
        dst.copy_from_slice(&self.bytes[offset..offset + dst.len()]);
        Ok(())
    }
}

/// Fixture data window. x12 points at its base, and fixtures derive every data
/// address from x12. The window and the text base (`TEXT_BASE` in
/// `scripts/compile-asm-fixture.sh`) stay at or above Linux's `vm.mmap_min_addr`
/// (64 KiB) so the native runner maps them at the addresses the interpreter uses.
pub const FIXTURE_DATA_BASE: u64 = 0x20000;
pub const FIXTURE_DATA_LEN: u64 = 0x4000;
/// TPIDR_EL0 of fixture cases: a TLS block in the last page of the data window.
pub const FIXTURE_TLS_BASE: u64 = FIXTURE_DATA_BASE + 0x3000;
/// One read-only page right after the data window (x12 + 0x4000), so fixtures
/// can fault on a store to it. The page after it (x12 + 0x5000) is unmapped.
pub const FIXTURE_RO_BASE: u64 = FIXTURE_DATA_BASE + FIXTURE_DATA_LEN;

/// Initial machine state for `.s` fixture cases. Shared by `trace-tui --check`
/// and the fixture suite so both check the same starting point: x12 points at
/// the fixture data window, which is read-write, followed by one read-only page
/// (`FIXTURE_RO_BASE`); TPIDR_EL0 is `FIXTURE_TLS_BASE` inside the window.
/// Everything else is unmapped.
pub fn default_fixture_state() -> MachineState {
    let mut state = MachineState::new();
    state.write_x(12, FIXTURE_DATA_BASE);
    state.tpidr_el0 = FIXTURE_TLS_BASE;
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

pub fn run_entry_fixture(
    name: &'static str,
    text_base: u64,
    text_bytes: Vec<u8>,
    entry_pc: u64,
    initial_state: &MachineState,
) -> Result<CaseReport, String> {
    // The fragment runs first: a Budget exit decides where the original stops.
    let fragment =
        compile_fixture_fragment(text_base, text_bytes.clone(), entry_pc, initial_state)?;
    let mut runtime = URuntime::new(fragment, initial_state.clone());
    let (report, original_cap) = run_fragment_counting_instances(&mut runtime)?;
    let encoded_fragment = encode_fragment(&runtime.fragment)?;
    let original = execute_original_with_mocked_svc(
        &text_bytes,
        text_base,
        entry_pc,
        initial_state,
        original_cap,
    )?;

    if original.state != report.state {
        return Err(format!(
            "original vs fragment state mismatch for `{name}`\noriginal: {:#?}\nfragment: {:#?}",
            original.state, report.state,
        ));
    }
    if !runtime_halt_matches_original(&original, &report.halt) {
        return Err(format!(
            "original vs fragment halt mismatch for `{name}`\noriginal: {:#?}\nfragment: {:#?}",
            original.halt_reason, report.halt,
        ));
    }

    Ok(CaseReport {
        name,
        fragment: runtime.fragment,
        encoded_fragment,
        original,
        original_cap,
        fragment_state: report.state,
        fragment_halt: report.halt,
        fragment_steps: report.steps,
    })
}

/// Runs a fragment to its halt like `URuntime::run`, and, when it ends in a `Budget`
/// exit at back-edge `pc`, returns where the original run must stop to match it.
///
/// The fragment starts original instruction `pc` exactly when it executes `pc`'s
/// body label: every runtime entry, branch and fall-through into `pc` lands there,
/// and for a back-edge that label is the first instruction of its budget check. So
/// the exit happened on dynamic instance `executions(label(pc))` of `pc`.
pub(crate) fn run_fragment_counting_instances(
    runtime: &mut URuntime,
) -> Result<(URuntimeReport, Option<InstanceCap>), String> {
    let mut executions = vec![0_u64; runtime.fragment.insns.len()];
    let report = {
        let mut stepper = URuntimeStepper::new(runtime)
            .map_err(|message| format!("fragment runtime setup failed: {message}"))?;
        let mut continuations = 0usize;
        loop {
            let step = match stepper.step() {
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
                executions[offset / 4] += 1;
            }
            if step.runtime_transition.is_some_and(|transition| {
                matches!(transition, runtime::URuntimeTransition::Continued { .. })
            }) {
                continuations += 1;
                if continuations >= MAX_RUNTIME_EXITS {
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

    let URuntimeHalt::ReturnedToUserspace {
        status: crate::shared::abi::RetStatus::Budget,
        target_pc: pc,
    } = report.halt
    else {
        return Ok((report, None));
    };
    let label = runtime
        .fragment
        .offset_for_pc(pc)
        .ok_or_else(|| format!("Budget exit at {pc:#x}, which has no body label"))?;
    let instance = executions[label / 4];
    if instance == 0 {
        return Err(format!(
            "Budget exit at {pc:#x}, but its body label {label:#x} never executed"
        ));
    }
    Ok((report, Some(InstanceCap { pc, instance })))
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
    Ok(run_fragment_counting_instances(&mut runtime)?.1)
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

fn execute_original_with_mocked_svc(
    program: &[u8],
    text_base: u64,
    entry_pc: u64,
    initial_state: &MachineState,
    cap: Option<InstanceCap>,
) -> Result<ExecutionResult, String> {
    run_original_with_mocked_svc(
        program,
        text_base,
        entry_pc,
        initial_state,
        None,
        cap,
        &mut |_| {},
    )
}

/// Runs original code to a halt, resuming after every SVC as if the syscall
/// returned without side effects. `fail_user_access = Some(k)` faults the k-th
/// dynamic user access of the whole run (1-based, SVC continuations included)
/// regardless of permissions. `cap` halts with `HaltReason::InstanceCap` before the
/// instruction it names executes. `before_step` sees the stepper before each step,
/// the capped one included; the stepper records its accesses
/// (`OriginalStepper::access_log`).
pub(crate) fn run_original_with_mocked_svc(
    program: &[u8],
    text_base: u64,
    entry_pc: u64,
    initial_state: &MachineState,
    fail_user_access: Option<u64>,
    cap: Option<InstanceCap>,
    before_step: &mut dyn FnMut(&OriginalStepper),
) -> Result<ExecutionResult, String> {
    let mut stepper =
        OriginalStepper::new(program, text_base, entry_pc, initial_state)?.record_accesses();
    if let Some(k) = fail_user_access {
        stepper = stepper.fail_user_access(k);
    }
    let mut steps = 0usize;
    let mut runtime_exits = 0usize;
    let mut cap_arrivals = 0u64;

    loop {
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
        let Some(step) = stepper.step()? else {
            return Err("original stepper stopped without a halt reason".to_string());
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
                if runtime_exits >= MAX_RUNTIME_EXITS {
                    return Err(
                        "original fixture exceeded runtime-exit continuation limit".to_string()
                    );
                }
                stepper.resume_at(resume_pc);
            }
            Some(halt_reason) => {
                return Ok(ExecutionResult {
                    state: step.state,
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
        (HaltReason::FellOffEnd, URuntimeHalt::FellOffFragment { .. }) => true,
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
