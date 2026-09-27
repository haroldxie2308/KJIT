use crate::model::{
    AccessKind, FaultCause, Flags, HaltReason, MachineState, MemAccess, MemFault, Privilege,
};
use crate::shared::abi::USER_VA_BITS;
use crate::shared::arm64::{
    A64Atomic, A64AtomicOp, A64Condition, A64Imm, A64Insn, A64Mem, A64Reg, A64Reg31Mode,
};
use crate::shared::trans::cfg::{admit_at, RuntimeExitReason};
use crate::MockCodeProvider;

/// Why an instruction did not retire.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum InsnError {
    /// A user access faulted. Nothing was mutated.
    Fault(MemFault),
    /// Harness error: unsupported form, PAN violation, missing metadata.
    Error(String),
}

impl From<String> for InsnError {
    fn from(message: String) -> Self {
        InsnError::Error(message)
    }
}

/// Numbers the dynamic user accesses of an original-code run and optionally
/// fails one of them regardless of permissions.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct UserAccessCounter {
    seen: u64,
    fail_at: Option<u64>,
}

impl UserAccessCounter {
    /// Fails the `k`-th user access (1-based).
    pub fn failing_at(k: u64) -> Self {
        assert!(k >= 1, "injected user access index is 1-based");
        Self {
            seen: 0,
            fail_at: Some(k),
        }
    }

    pub fn seen(&self) -> u64 {
        self.seen
    }

    /// Counts one user access; true when it is the injected one.
    fn record(&mut self) -> bool {
        self.seen += 1;
        self.fail_at == Some(self.seen)
    }
}

/// One attempted memory access, in execution order. A faulting access is
/// recorded too (it is the last one of its run).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LoggedAccess {
    pub pc: u64,
    pub access: MemAccess,
    pub privilege: Privilege,
}

/// Who executes the instruction, which decides each access's privilege.
pub(crate) enum AccessContext<'a> {
    /// Original code runs at EL0: every access is a user access. `counter`
    /// numbers them for fault injection.
    Original {
        counter: Option<&'a mut UserAccessCounter>,
        log: Option<&'a mut Vec<LoggedAccess>>,
    },
    /// Translated fragment at EL1. Privilege is decided by the instruction, never
    /// the address: `LDTR`/`STTR` are user accesses (EL0 permissions, numbered by
    /// `counter`); an LSE atomic (A8) or SIMD&FP load/store (A9a) is a privileged
    /// access to user memory, legal only while `pan` (PSTATE.PAN, written by `msr
    /// pan`) is clear; every other load/store is a runtime access and must stay
    /// inside `runtime_ranges` (else a PAN violation).
    Fragment {
        runtime_ranges: &'a [(u64, u64)],
        counter: &'a mut UserAccessCounter,
        log: Option<&'a mut Vec<LoggedAccess>>,
        pan: &'a mut bool,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OriginalStep {
    pub pc: u64,
    pub next_pc: Option<u64>,
    pub executed: bool,
    pub runtime_exit: Option<RuntimeExitReason>,
    pub halt_reason: Option<HaltReason>,
    pub state: MachineState,
}

/// An `OriginalStep` without its state snapshot; see `OriginalStepper::advance`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OriginalAdvance {
    pub pc: u64,
    pub next_pc: Option<u64>,
    pub executed: bool,
    pub runtime_exit: Option<RuntimeExitReason>,
    pub halt_reason: Option<HaltReason>,
}

#[derive(Debug)]
pub struct OriginalStepper<'a> {
    program: &'a [u8],
    base_pc: u64,
    pc: u64,
    state: MachineState,
    stopped: bool,
    user_accesses: UserAccessCounter,
    access_log: Option<Vec<LoggedAccess>>,
}

impl<'a> OriginalStepper<'a> {
    pub fn new(
        program: &'a [u8],
        base_pc: u64,
        entry_pc: u64,
        initial_state: &MachineState,
    ) -> Result<Self, String> {
        if program.len() % 4 != 0 {
            return Err("program length must be a multiple of 4 bytes".to_string());
        }
        Ok(Self {
            program,
            base_pc,
            pc: entry_pc,
            state: initial_state.clone(),
            stopped: false,
            user_accesses: UserAccessCounter::default(),
            access_log: None,
        })
    }

    /// Records every attempted access of this stepper's run.
    pub fn record_accesses(mut self) -> Self {
        self.access_log = Some(Vec::new());
        self
    }

    /// The recorded accesses; `None` unless `record_accesses` was called.
    pub fn access_log(&self) -> Option<&[LoggedAccess]> {
        self.access_log.as_deref()
    }

    /// Fails the `k`-th dynamic user access of this stepper's run (1-based,
    /// counted across `resume_at` continuations) regardless of permissions.
    pub fn fail_user_access(mut self, k: u64) -> Self {
        self.user_accesses = UserAccessCounter::failing_at(k);
        self
    }

    pub fn pc(&self) -> u64 {
        self.pc
    }

    pub fn state(&self) -> &MachineState {
        &self.state
    }

    /// User accesses performed (or attempted, for a faulting one) so far.
    pub fn user_accesses(&self) -> u64 {
        self.user_accesses.seen()
    }

    pub fn resume_at(&mut self, pc: u64) {
        self.pc = pc;
        self.stopped = false;
    }

    pub fn step(&mut self) -> Result<Option<OriginalStep>, String> {
        Ok(self.advance()?.map(|advanced| OriginalStep {
            pc: advanced.pc,
            next_pc: advanced.next_pc,
            executed: advanced.executed,
            runtime_exit: advanced.runtime_exit,
            halt_reason: advanced.halt_reason,
            state: self.state.clone(),
        }))
    }

    /// `step` without the state snapshot (a full memory copy); read
    /// `state()` when it is needed.
    pub fn advance(&mut self) -> Result<Option<OriginalAdvance>, String> {
        if self.stopped {
            return Ok(None);
        }

        // The translator's own decision at this PC, running off the text included.
        let text = MockCodeProvider::new(self.base_pc, self.program);
        let decoded = match admit_at(&text, self.pc).map_err(|err| err.to_string())? {
            Ok(decoded) => decoded,
            Err(exit) => {
                let reason = RuntimeExitReason::Unsupported {
                    pc: exit.pc(),
                    word: exit.word(),
                };
                self.stopped = true;
                return Ok(Some(OriginalAdvance {
                    pc: exit.pc(),
                    next_pc: None,
                    executed: false,
                    runtime_exit: Some(reason),
                    halt_reason: Some(HaltReason::RuntimeExit { reason }),
                }));
            }
        };

        if let Some(reason) = decoded.inner.runtime_exit_reason(self.pc) {
            apply_runtime_exit_side_effect(decoded.inner, self.pc, &mut self.state);
            self.stopped = true;
            return Ok(Some(OriginalAdvance {
                pc: self.pc,
                next_pc: None,
                executed: true,
                runtime_exit: Some(reason),
                halt_reason: Some(HaltReason::RuntimeExit { reason }),
            }));
        }

        let pc = self.pc;
        let mut ctx = AccessContext::Original {
            counter: Some(&mut self.user_accesses),
            log: self.access_log.as_mut(),
        };
        let next_pc = match execute_insn(decoded.inner, pc, &mut self.state, &mut ctx) {
            Ok(next_pc) => next_pc,
            Err(InsnError::Fault(fault)) => {
                self.stopped = true;
                return Ok(Some(OriginalAdvance {
                    pc,
                    next_pc: None,
                    executed: false,
                    runtime_exit: None,
                    halt_reason: Some(HaltReason::Fault(fault)),
                }));
            }
            Err(InsnError::Error(message)) => return Err(message),
        };
        self.pc = next_pc;
        Ok(Some(OriginalAdvance {
            pc,
            next_pc: Some(next_pc),
            executed: true,
            runtime_exit: None,
            halt_reason: None,
        }))
    }
}

/// Executes one non-exit instruction. Every memory access is validated before
/// any register or byte is written, so an `Err` leaves `state` untouched.
pub(crate) fn execute_insn(
    insn: A64Insn,
    pc: u64,
    state: &mut MachineState,
    ctx: &mut AccessContext<'_>,
) -> Result<u64, InsnError> {
    match insn {
        A64Insn::NopNopHiHints {} => Ok(pc + 4),
        // Executed in sequence, BTI is a NOP. The landing-pad check it takes part in
        // (PSTATE.BTYPE after an indirect branch into a guarded page) is not modelled.
        A64Insn::BtiBtiHbHints { .. } => Ok(pc + 4),

        A64Insn::AdrAdrOnlyPcreladdr { rd, .. } | A64Insn::AdrpAdrpOnlyPcreladdr { rd, .. } => {
            let value = insn
                .pc_relative_address(pc)
                .ok_or_else(|| format!("missing PC-relative value for {}", insn.key()))?;
            state.write_reg(rd, value);
            Ok(pc + 4)
        }

        A64Insn::MovzMovz32Movewide { hw, imm16, rd } => {
            write_movz(state, 32, rd, imm16, hw)?;
            Ok(pc + 4)
        }
        A64Insn::MovzMovz64Movewide { hw, imm16, rd } => {
            write_movz(state, 64, rd, imm16, hw)?;
            Ok(pc + 4)
        }
        A64Insn::MovkMovk32Movewide { hw, imm16, rd } => {
            write_movk(state, 32, rd, imm16, hw)?;
            Ok(pc + 4)
        }
        A64Insn::MovkMovk64Movewide { hw, imm16, rd } => {
            write_movk(state, 64, rd, imm16, hw)?;
            Ok(pc + 4)
        }

        A64Insn::AddAddsubImmAdd32AddsubImm { sh, imm12, rn, rd } => {
            let result = read_reg_sized(state, rn, 32).wrapping_add(add_sub_imm(sh, imm12, insn)?);
            write_reg_sized(state, rd, result, 32);
            Ok(pc + 4)
        }
        A64Insn::AddAddsubImmAdd64AddsubImm { sh, imm12, rn, rd } => {
            let result = state
                .read_reg(rn)
                .wrapping_add(add_sub_imm(sh, imm12, insn)?);
            state.write_reg(rd, result);
            Ok(pc + 4)
        }
        A64Insn::SubAddsubImmSub32AddsubImm { sh, imm12, rn, rd } => {
            let result = read_reg_sized(state, rn, 32).wrapping_sub(add_sub_imm(sh, imm12, insn)?);
            write_reg_sized(state, rd, result, 32);
            Ok(pc + 4)
        }
        A64Insn::SubAddsubImmSub64AddsubImm { sh, imm12, rn, rd } => {
            let result = state
                .read_reg(rn)
                .wrapping_sub(add_sub_imm(sh, imm12, insn)?);
            state.write_reg(rd, result);
            Ok(pc + 4)
        }
        A64Insn::SubsAddsubImmSubs32sAddsubImm { sh, imm12, rn, rd } => {
            let imm = add_sub_imm(sh, imm12, insn)?;
            add_sub(
                state,
                rd,
                read_reg_sized(state, rn, 32),
                imm,
                AddSub::Sub,
                true,
                32,
            );
            Ok(pc + 4)
        }
        A64Insn::SubsAddsubImmSubs64sAddsubImm { sh, imm12, rn, rd } => {
            let imm = add_sub_imm(sh, imm12, insn)?;
            add_sub(state, rd, state.read_reg(rn), imm, AddSub::Sub, true, 64);
            Ok(pc + 4)
        }
        A64Insn::AddsAddsubImmAdds32sAddsubImm { sh, imm12, rn, rd } => {
            let imm = add_sub_imm(sh, imm12, insn)?;
            add_sub(
                state,
                rd,
                read_reg_sized(state, rn, 32),
                imm,
                AddSub::Add,
                true,
                32,
            );
            Ok(pc + 4)
        }
        A64Insn::AddsAddsubImmAdds64sAddsubImm { sh, imm12, rn, rd } => {
            let imm = add_sub_imm(sh, imm12, insn)?;
            add_sub(state, rd, state.read_reg(rn), imm, AddSub::Add, true, 64);
            Ok(pc + 4)
        }

        A64Insn::AddAddsubShiftAdd32AddsubShift {
            shift,
            rm,
            imm6,
            rn,
            rd,
        } => {
            add_sub_shifted(state, AddSub::Add, false, 32, shift, rm, imm6, rn, rd)?;
            Ok(pc + 4)
        }
        A64Insn::AddAddsubShiftAdd64AddsubShift {
            shift,
            rm,
            imm6,
            rn,
            rd,
        } => {
            add_sub_shifted(state, AddSub::Add, false, 64, shift, rm, imm6, rn, rd)?;
            Ok(pc + 4)
        }
        A64Insn::AddsAddsubShiftAdds32AddsubShift {
            shift,
            rm,
            imm6,
            rn,
            rd,
        } => {
            add_sub_shifted(state, AddSub::Add, true, 32, shift, rm, imm6, rn, rd)?;
            Ok(pc + 4)
        }
        A64Insn::AddsAddsubShiftAdds64AddsubShift {
            shift,
            rm,
            imm6,
            rn,
            rd,
        } => {
            add_sub_shifted(state, AddSub::Add, true, 64, shift, rm, imm6, rn, rd)?;
            Ok(pc + 4)
        }
        A64Insn::SubAddsubShiftSub32AddsubShift {
            shift,
            rm,
            imm6,
            rn,
            rd,
        } => {
            add_sub_shifted(state, AddSub::Sub, false, 32, shift, rm, imm6, rn, rd)?;
            Ok(pc + 4)
        }
        A64Insn::SubAddsubShiftSub64AddsubShift {
            shift,
            rm,
            imm6,
            rn,
            rd,
        } => {
            add_sub_shifted(state, AddSub::Sub, false, 64, shift, rm, imm6, rn, rd)?;
            Ok(pc + 4)
        }
        A64Insn::SubsAddsubShiftSubs32AddsubShift {
            shift,
            rm,
            imm6,
            rn,
            rd,
        } => {
            add_sub_shifted(state, AddSub::Sub, true, 32, shift, rm, imm6, rn, rd)?;
            Ok(pc + 4)
        }
        A64Insn::SubsAddsubShiftSubs64AddsubShift {
            shift,
            rm,
            imm6,
            rn,
            rd,
        } => {
            add_sub_shifted(state, AddSub::Sub, true, 64, shift, rm, imm6, rn, rd)?;
            Ok(pc + 4)
        }

        A64Insn::AddAddsubExtAdd32AddsubExt {
            rm,
            option,
            imm3,
            rn,
            rd,
        } => {
            add_sub_extended(state, AddSub::Add, false, 32, rm, option, imm3, rn, rd)?;
            Ok(pc + 4)
        }
        A64Insn::AddAddsubExtAdd64AddsubExt {
            rm,
            option,
            imm3,
            rn,
            rd,
        } => {
            add_sub_extended(state, AddSub::Add, false, 64, rm, option, imm3, rn, rd)?;
            Ok(pc + 4)
        }
        A64Insn::AddsAddsubExtAdds32sAddsubExt {
            rm,
            option,
            imm3,
            rn,
            rd,
        } => {
            add_sub_extended(state, AddSub::Add, true, 32, rm, option, imm3, rn, rd)?;
            Ok(pc + 4)
        }
        A64Insn::AddsAddsubExtAdds64sAddsubExt {
            rm,
            option,
            imm3,
            rn,
            rd,
        } => {
            add_sub_extended(state, AddSub::Add, true, 64, rm, option, imm3, rn, rd)?;
            Ok(pc + 4)
        }
        A64Insn::SubAddsubExtSub32AddsubExt {
            rm,
            option,
            imm3,
            rn,
            rd,
        } => {
            add_sub_extended(state, AddSub::Sub, false, 32, rm, option, imm3, rn, rd)?;
            Ok(pc + 4)
        }
        A64Insn::SubAddsubExtSub64AddsubExt {
            rm,
            option,
            imm3,
            rn,
            rd,
        } => {
            add_sub_extended(state, AddSub::Sub, false, 64, rm, option, imm3, rn, rd)?;
            Ok(pc + 4)
        }
        A64Insn::SubsAddsubExtSubs32sAddsubExt {
            rm,
            option,
            imm3,
            rn,
            rd,
        } => {
            add_sub_extended(state, AddSub::Sub, true, 32, rm, option, imm3, rn, rd)?;
            Ok(pc + 4)
        }
        A64Insn::SubsAddsubExtSubs64sAddsubExt {
            rm,
            option,
            imm3,
            rn,
            rd,
        } => {
            add_sub_extended(state, AddSub::Sub, true, 64, rm, option, imm3, rn, rd)?;
            Ok(pc + 4)
        }

        A64Insn::MovnMovn32Movewide { hw, imm16, rd } => {
            write_movn(state, 32, rd, imm16, hw)?;
            Ok(pc + 4)
        }
        A64Insn::MovnMovn64Movewide { hw, imm16, rd } => {
            write_movn(state, 64, rd, imm16, hw)?;
            Ok(pc + 4)
        }

        A64Insn::AndLogShiftAnd32LogShift {
            shift,
            rm,
            imm6,
            rn,
            rd,
        } => {
            logical_shifted(state, Logic::And, false, false, 32, shift, rm, imm6, rn, rd)?;
            Ok(pc + 4)
        }
        A64Insn::AndLogShiftAnd64LogShift {
            shift,
            rm,
            imm6,
            rn,
            rd,
        } => {
            logical_shifted(state, Logic::And, false, false, 64, shift, rm, imm6, rn, rd)?;
            Ok(pc + 4)
        }
        A64Insn::AndsLogShiftAnds32LogShift {
            shift,
            rm,
            imm6,
            rn,
            rd,
        } => {
            logical_shifted(state, Logic::And, false, true, 32, shift, rm, imm6, rn, rd)?;
            Ok(pc + 4)
        }
        A64Insn::AndsLogShiftAnds64LogShift {
            shift,
            rm,
            imm6,
            rn,
            rd,
        } => {
            logical_shifted(state, Logic::And, false, true, 64, shift, rm, imm6, rn, rd)?;
            Ok(pc + 4)
        }
        A64Insn::OrrLogShiftOrr32LogShift {
            shift,
            rm,
            imm6,
            rn,
            rd,
        } => {
            logical_shifted(state, Logic::Orr, false, false, 32, shift, rm, imm6, rn, rd)?;
            Ok(pc + 4)
        }
        A64Insn::OrrLogShiftOrr64LogShift {
            shift,
            rm,
            imm6,
            rn,
            rd,
        } => {
            logical_shifted(state, Logic::Orr, false, false, 64, shift, rm, imm6, rn, rd)?;
            Ok(pc + 4)
        }
        A64Insn::EorLogShiftEor32LogShift {
            shift,
            rm,
            imm6,
            rn,
            rd,
        } => {
            logical_shifted(state, Logic::Eor, false, false, 32, shift, rm, imm6, rn, rd)?;
            Ok(pc + 4)
        }
        A64Insn::EorLogShiftEor64LogShift {
            shift,
            rm,
            imm6,
            rn,
            rd,
        } => {
            logical_shifted(state, Logic::Eor, false, false, 64, shift, rm, imm6, rn, rd)?;
            Ok(pc + 4)
        }
        A64Insn::EonEon32LogShift {
            shift,
            rm,
            imm6,
            rn,
            rd,
        } => {
            logical_shifted(state, Logic::Eor, true, false, 32, shift, rm, imm6, rn, rd)?;
            Ok(pc + 4)
        }
        A64Insn::EonEon64LogShift {
            shift,
            rm,
            imm6,
            rn,
            rd,
        } => {
            logical_shifted(state, Logic::Eor, true, false, 64, shift, rm, imm6, rn, rd)?;
            Ok(pc + 4)
        }
        A64Insn::BicLogShiftBic32LogShift {
            shift,
            rm,
            imm6,
            rn,
            rd,
        } => {
            logical_shifted(state, Logic::And, true, false, 32, shift, rm, imm6, rn, rd)?;
            Ok(pc + 4)
        }
        A64Insn::BicLogShiftBic64LogShift {
            shift,
            rm,
            imm6,
            rn,
            rd,
        } => {
            logical_shifted(state, Logic::And, true, false, 64, shift, rm, imm6, rn, rd)?;
            Ok(pc + 4)
        }
        A64Insn::BicsBics32LogShift {
            shift,
            rm,
            imm6,
            rn,
            rd,
        } => {
            logical_shifted(state, Logic::And, true, true, 32, shift, rm, imm6, rn, rd)?;
            Ok(pc + 4)
        }
        A64Insn::BicsBics64LogShift {
            shift,
            rm,
            imm6,
            rn,
            rd,
        } => {
            logical_shifted(state, Logic::And, true, true, 64, shift, rm, imm6, rn, rd)?;
            Ok(pc + 4)
        }
        A64Insn::OrnLogShiftOrn32LogShift {
            shift,
            rm,
            imm6,
            rn,
            rd,
        } => {
            logical_shifted(state, Logic::Orr, true, false, 32, shift, rm, imm6, rn, rd)?;
            Ok(pc + 4)
        }
        A64Insn::OrnLogShiftOrn64LogShift {
            shift,
            rm,
            imm6,
            rn,
            rd,
        } => {
            logical_shifted(state, Logic::Orr, true, false, 64, shift, rm, imm6, rn, rd)?;
            Ok(pc + 4)
        }

        A64Insn::AndLogImmAnd32LogImm { immr, imms, rn, rd } => {
            logical_imm(state, Logic::And, false, 32, 0, immr, imms, rn, rd)?;
            Ok(pc + 4)
        }
        A64Insn::AndLogImmAnd64LogImm {
            n,
            immr,
            imms,
            rn,
            rd,
        } => {
            logical_imm(state, Logic::And, false, 64, n, immr, imms, rn, rd)?;
            Ok(pc + 4)
        }
        A64Insn::AndsLogImmAnds32sLogImm { immr, imms, rn, rd } => {
            logical_imm(state, Logic::And, true, 32, 0, immr, imms, rn, rd)?;
            Ok(pc + 4)
        }
        A64Insn::AndsLogImmAnds64sLogImm {
            n,
            immr,
            imms,
            rn,
            rd,
        } => {
            logical_imm(state, Logic::And, true, 64, n, immr, imms, rn, rd)?;
            Ok(pc + 4)
        }
        A64Insn::OrrLogImmOrr32LogImm { immr, imms, rn, rd } => {
            logical_imm(state, Logic::Orr, false, 32, 0, immr, imms, rn, rd)?;
            Ok(pc + 4)
        }
        A64Insn::OrrLogImmOrr64LogImm {
            n,
            immr,
            imms,
            rn,
            rd,
        } => {
            logical_imm(state, Logic::Orr, false, 64, n, immr, imms, rn, rd)?;
            Ok(pc + 4)
        }
        A64Insn::EorLogImmEor32LogImm { immr, imms, rn, rd } => {
            logical_imm(state, Logic::Eor, false, 32, 0, immr, imms, rn, rd)?;
            Ok(pc + 4)
        }
        A64Insn::EorLogImmEor64LogImm {
            n,
            immr,
            imms,
            rn,
            rd,
        } => {
            logical_imm(state, Logic::Eor, false, 64, n, immr, imms, rn, rd)?;
            Ok(pc + 4)
        }

        A64Insn::SbfmSbfm32mBitfield { immr, imms, rn, rd } => {
            bitfield_move(state, Bitfield::Signed, 32, 0, immr, imms, rn, rd)?;
            Ok(pc + 4)
        }
        A64Insn::SbfmSbfm64mBitfield { immr, imms, rn, rd } => {
            bitfield_move(state, Bitfield::Signed, 64, 1, immr, imms, rn, rd)?;
            Ok(pc + 4)
        }
        A64Insn::UbfmUbfm32mBitfield { immr, imms, rn, rd } => {
            bitfield_move(state, Bitfield::Unsigned, 32, 0, immr, imms, rn, rd)?;
            Ok(pc + 4)
        }
        A64Insn::UbfmUbfm64mBitfield { immr, imms, rn, rd } => {
            bitfield_move(state, Bitfield::Unsigned, 64, 1, immr, imms, rn, rd)?;
            Ok(pc + 4)
        }
        A64Insn::BfmBfm32mBitfield { immr, imms, rn, rd } => {
            bitfield_move(state, Bitfield::Insert, 32, 0, immr, imms, rn, rd)?;
            Ok(pc + 4)
        }
        A64Insn::BfmBfm64mBitfield { immr, imms, rn, rd } => {
            bitfield_move(state, Bitfield::Insert, 64, 1, immr, imms, rn, rd)?;
            Ok(pc + 4)
        }

        A64Insn::ExtrExtr32Extract { rm, imms, rn, rd } => {
            extract(state, 32, rm, imms, rn, rd)?;
            Ok(pc + 4)
        }
        A64Insn::ExtrExtr64Extract { rm, imms, rn, rd } => {
            extract(state, 64, rm, imms, rn, rd)?;
            Ok(pc + 4)
        }

        A64Insn::CselCsel32Condsel { rm, cond, rn, rd } => {
            cond_select(state, CondSelect::Sel, 32, rm, cond, rn, rd)?;
            Ok(pc + 4)
        }
        A64Insn::CselCsel64Condsel { rm, cond, rn, rd } => {
            cond_select(state, CondSelect::Sel, 64, rm, cond, rn, rd)?;
            Ok(pc + 4)
        }
        A64Insn::CsincCsinc32Condsel { rm, cond, rn, rd } => {
            cond_select(state, CondSelect::Inc, 32, rm, cond, rn, rd)?;
            Ok(pc + 4)
        }
        A64Insn::CsincCsinc64Condsel { rm, cond, rn, rd } => {
            cond_select(state, CondSelect::Inc, 64, rm, cond, rn, rd)?;
            Ok(pc + 4)
        }
        A64Insn::CsinvCsinv32Condsel { rm, cond, rn, rd } => {
            cond_select(state, CondSelect::Inv, 32, rm, cond, rn, rd)?;
            Ok(pc + 4)
        }
        A64Insn::CsinvCsinv64Condsel { rm, cond, rn, rd } => {
            cond_select(state, CondSelect::Inv, 64, rm, cond, rn, rd)?;
            Ok(pc + 4)
        }
        A64Insn::CsnegCsneg32Condsel { rm, cond, rn, rd } => {
            cond_select(state, CondSelect::Neg, 32, rm, cond, rn, rd)?;
            Ok(pc + 4)
        }
        A64Insn::CsnegCsneg64Condsel { rm, cond, rn, rd } => {
            cond_select(state, CondSelect::Neg, 64, rm, cond, rn, rd)?;
            Ok(pc + 4)
        }

        A64Insn::CcmpImmCcmp32CondcmpImm {
            imm5,
            cond,
            rn,
            nzcv,
        } => {
            cond_compare(state, AddSub::Sub, 32, imm5.raw() as u64, cond, rn, nzcv)?;
            Ok(pc + 4)
        }
        A64Insn::CcmpImmCcmp64CondcmpImm {
            imm5,
            cond,
            rn,
            nzcv,
        } => {
            cond_compare(state, AddSub::Sub, 64, imm5.raw() as u64, cond, rn, nzcv)?;
            Ok(pc + 4)
        }
        A64Insn::CcmpRegCcmp32CondcmpReg { rm, cond, rn, nzcv } => {
            let operand2 = read_reg_sized(state, rm, 32);
            cond_compare(state, AddSub::Sub, 32, operand2, cond, rn, nzcv)?;
            Ok(pc + 4)
        }
        A64Insn::CcmpRegCcmp64CondcmpReg { rm, cond, rn, nzcv } => {
            let operand2 = state.read_reg(rm);
            cond_compare(state, AddSub::Sub, 64, operand2, cond, rn, nzcv)?;
            Ok(pc + 4)
        }
        A64Insn::CcmnImmCcmn32CondcmpImm {
            imm5,
            cond,
            rn,
            nzcv,
        } => {
            cond_compare(state, AddSub::Add, 32, imm5.raw() as u64, cond, rn, nzcv)?;
            Ok(pc + 4)
        }
        A64Insn::CcmnImmCcmn64CondcmpImm {
            imm5,
            cond,
            rn,
            nzcv,
        } => {
            cond_compare(state, AddSub::Add, 64, imm5.raw() as u64, cond, rn, nzcv)?;
            Ok(pc + 4)
        }
        A64Insn::CcmnRegCcmn32CondcmpReg { rm, cond, rn, nzcv } => {
            let operand2 = read_reg_sized(state, rm, 32);
            cond_compare(state, AddSub::Add, 32, operand2, cond, rn, nzcv)?;
            Ok(pc + 4)
        }
        A64Insn::CcmnRegCcmn64CondcmpReg { rm, cond, rn, nzcv } => {
            let operand2 = state.read_reg(rm);
            cond_compare(state, AddSub::Add, 64, operand2, cond, rn, nzcv)?;
            Ok(pc + 4)
        }

        A64Insn::LslvLslv32Dp2src { rm, rn, rd } => {
            shift_variable(state, 0b00, 32, rm, rn, rd)?;
            Ok(pc + 4)
        }
        A64Insn::LslvLslv64Dp2src { rm, rn, rd } => {
            shift_variable(state, 0b00, 64, rm, rn, rd)?;
            Ok(pc + 4)
        }
        A64Insn::LsrvLsrv32Dp2src { rm, rn, rd } => {
            shift_variable(state, 0b01, 32, rm, rn, rd)?;
            Ok(pc + 4)
        }
        A64Insn::LsrvLsrv64Dp2src { rm, rn, rd } => {
            shift_variable(state, 0b01, 64, rm, rn, rd)?;
            Ok(pc + 4)
        }
        A64Insn::AsrvAsrv32Dp2src { rm, rn, rd } => {
            shift_variable(state, 0b10, 32, rm, rn, rd)?;
            Ok(pc + 4)
        }
        A64Insn::AsrvAsrv64Dp2src { rm, rn, rd } => {
            shift_variable(state, 0b10, 64, rm, rn, rd)?;
            Ok(pc + 4)
        }
        A64Insn::RorvRorv32Dp2src { rm, rn, rd } => {
            shift_variable(state, 0b11, 32, rm, rn, rd)?;
            Ok(pc + 4)
        }
        A64Insn::RorvRorv64Dp2src { rm, rn, rd } => {
            shift_variable(state, 0b11, 64, rm, rn, rd)?;
            Ok(pc + 4)
        }

        A64Insn::UdivUdiv32Dp2src { rm, rn, rd } => {
            divide(state, false, 32, rm, rn, rd);
            Ok(pc + 4)
        }
        A64Insn::UdivUdiv64Dp2src { rm, rn, rd } => {
            divide(state, false, 64, rm, rn, rd);
            Ok(pc + 4)
        }
        A64Insn::SdivSdiv32Dp2src { rm, rn, rd } => {
            divide(state, true, 32, rm, rn, rd);
            Ok(pc + 4)
        }
        A64Insn::SdivSdiv64Dp2src { rm, rn, rd } => {
            divide(state, true, 64, rm, rn, rd);
            Ok(pc + 4)
        }

        A64Insn::MaddMadd32aDp3src { rm, ra, rn, rd } => {
            multiply_add(state, AddSub::Add, 32, rm, ra, rn, rd);
            Ok(pc + 4)
        }
        A64Insn::MaddMadd64aDp3src { rm, ra, rn, rd } => {
            multiply_add(state, AddSub::Add, 64, rm, ra, rn, rd);
            Ok(pc + 4)
        }
        A64Insn::MsubMsub32aDp3src { rm, ra, rn, rd } => {
            multiply_add(state, AddSub::Sub, 32, rm, ra, rn, rd);
            Ok(pc + 4)
        }
        A64Insn::MsubMsub64aDp3src { rm, ra, rn, rd } => {
            multiply_add(state, AddSub::Sub, 64, rm, ra, rn, rd);
            Ok(pc + 4)
        }
        A64Insn::SmaddlSmaddl64waDp3src { rm, ra, rn, rd } => {
            let product = sign_extend_width(state.read_reg(rn), 32)
                .wrapping_mul(sign_extend_width(state.read_reg(rm), 32));
            state.write_reg(rd, state.read_reg(ra).wrapping_add(product as u64));
            Ok(pc + 4)
        }
        A64Insn::UmaddlUmaddl64waDp3src { rm, ra, rn, rd } => {
            let product = read_reg_sized(state, rn, 32) * read_reg_sized(state, rm, 32);
            state.write_reg(rd, state.read_reg(ra).wrapping_add(product));
            Ok(pc + 4)
        }
        A64Insn::SmsublSmsubl64waDp3src { rm, ra, rn, rd } => {
            let product = sign_extend_width(state.read_reg(rn), 32)
                .wrapping_mul(sign_extend_width(state.read_reg(rm), 32));
            state.write_reg(rd, state.read_reg(ra).wrapping_sub(product as u64));
            Ok(pc + 4)
        }
        A64Insn::UmsublUmsubl64waDp3src { rm, ra, rn, rd } => {
            let product = read_reg_sized(state, rn, 32) * read_reg_sized(state, rm, 32);
            state.write_reg(rd, state.read_reg(ra).wrapping_sub(product));
            Ok(pc + 4)
        }
        A64Insn::SmulhSmulh64Dp3src { rm, rn, rd } => {
            let product =
                i128::from(state.read_reg(rn) as i64) * i128::from(state.read_reg(rm) as i64);
            state.write_reg(rd, (product >> 64) as u64);
            Ok(pc + 4)
        }
        A64Insn::UmulhUmulh64Dp3src { rm, rn, rd } => {
            let product = u128::from(state.read_reg(rn)) * u128::from(state.read_reg(rm));
            state.write_reg(rd, (product >> 64) as u64);
            Ok(pc + 4)
        }

        A64Insn::AdcAdc32AddsubCarry { rm, rn, rd } => {
            add_sub_carry(state, AddSub::Add, false, 32, rm, rn, rd);
            Ok(pc + 4)
        }
        A64Insn::AdcAdc64AddsubCarry { rm, rn, rd } => {
            add_sub_carry(state, AddSub::Add, false, 64, rm, rn, rd);
            Ok(pc + 4)
        }
        A64Insn::AdcsAdcs32AddsubCarry { rm, rn, rd } => {
            add_sub_carry(state, AddSub::Add, true, 32, rm, rn, rd);
            Ok(pc + 4)
        }
        A64Insn::AdcsAdcs64AddsubCarry { rm, rn, rd } => {
            add_sub_carry(state, AddSub::Add, true, 64, rm, rn, rd);
            Ok(pc + 4)
        }
        A64Insn::SbcSbc32AddsubCarry { rm, rn, rd } => {
            add_sub_carry(state, AddSub::Sub, false, 32, rm, rn, rd);
            Ok(pc + 4)
        }
        A64Insn::SbcSbc64AddsubCarry { rm, rn, rd } => {
            add_sub_carry(state, AddSub::Sub, false, 64, rm, rn, rd);
            Ok(pc + 4)
        }
        A64Insn::SbcsSbcs32AddsubCarry { rm, rn, rd } => {
            add_sub_carry(state, AddSub::Sub, true, 32, rm, rn, rd);
            Ok(pc + 4)
        }
        A64Insn::SbcsSbcs64AddsubCarry { rm, rn, rd } => {
            add_sub_carry(state, AddSub::Sub, true, 64, rm, rn, rd);
            Ok(pc + 4)
        }

        A64Insn::Crc32Crc32b32cDp2src { rm, rn, rd } => {
            crc32(state, CRC32_POLY_REFLECTED, 8, rm, rn, rd);
            Ok(pc + 4)
        }
        A64Insn::Crc32Crc32h32cDp2src { rm, rn, rd } => {
            crc32(state, CRC32_POLY_REFLECTED, 16, rm, rn, rd);
            Ok(pc + 4)
        }
        A64Insn::Crc32Crc32w32cDp2src { rm, rn, rd } => {
            crc32(state, CRC32_POLY_REFLECTED, 32, rm, rn, rd);
            Ok(pc + 4)
        }
        A64Insn::Crc32Crc32x64cDp2src { rm, rn, rd } => {
            crc32(state, CRC32_POLY_REFLECTED, 64, rm, rn, rd);
            Ok(pc + 4)
        }
        A64Insn::Crc32cCrc32cb32cDp2src { rm, rn, rd } => {
            crc32(state, CRC32C_POLY_REFLECTED, 8, rm, rn, rd);
            Ok(pc + 4)
        }
        A64Insn::Crc32cCrc32ch32cDp2src { rm, rn, rd } => {
            crc32(state, CRC32C_POLY_REFLECTED, 16, rm, rn, rd);
            Ok(pc + 4)
        }
        A64Insn::Crc32cCrc32cw32cDp2src { rm, rn, rd } => {
            crc32(state, CRC32C_POLY_REFLECTED, 32, rm, rn, rd);
            Ok(pc + 4)
        }
        A64Insn::Crc32cCrc32cx64cDp2src { rm, rn, rd } => {
            crc32(state, CRC32C_POLY_REFLECTED, 64, rm, rn, rd);
            Ok(pc + 4)
        }

        A64Insn::ClzIntClz32Dp1src { rn, rd } => {
            let value = read_reg_sized(state, rn, 32) as u32;
            write_reg_sized(state, rd, u64::from(value.leading_zeros()), 32);
            Ok(pc + 4)
        }
        A64Insn::ClzIntClz64Dp1src { rn, rd } => {
            state.write_reg(rd, u64::from(state.read_reg(rn).leading_zeros()));
            Ok(pc + 4)
        }
        A64Insn::RbitIntRbit32Dp1src { rn, rd } => {
            let value = read_reg_sized(state, rn, 32) as u32;
            write_reg_sized(state, rd, u64::from(value.reverse_bits()), 32);
            Ok(pc + 4)
        }
        A64Insn::RbitIntRbit64Dp1src { rn, rd } => {
            state.write_reg(rd, state.read_reg(rn).reverse_bits());
            Ok(pc + 4)
        }
        A64Insn::RevRev32Dp1src { rn, rd } => {
            reverse_bytes(state, 32, 32, rn, rd);
            Ok(pc + 4)
        }
        A64Insn::RevRev64Dp1src { rn, rd } => {
            reverse_bytes(state, 64, 64, rn, rd);
            Ok(pc + 4)
        }
        A64Insn::Rev16IntRev1632Dp1src { rn, rd } => {
            reverse_bytes(state, 32, 16, rn, rd);
            Ok(pc + 4)
        }
        A64Insn::Rev16IntRev1664Dp1src { rn, rd } => {
            reverse_bytes(state, 64, 16, rn, rd);
            Ok(pc + 4)
        }
        A64Insn::Rev32IntRev3264Dp1src { rn, rd } => {
            reverse_bytes(state, 64, 32, rn, rd);
            Ok(pc + 4)
        }

        // The decoder admits MRS only for these registers (subset.toml field
        // instances); all three are read-only user state.
        A64Insn::MrsMrsRsSystemmoveTpidrEl0 { rt } => {
            state.write_reg(rt, state.tpidr_el0);
            Ok(pc + 4)
        }
        A64Insn::MrsMrsRsSystemmoveCntvctEl0 { rt } => {
            state.write_reg(rt, state.cntvct_el0);
            Ok(pc + 4)
        }
        A64Insn::MrsMrsRsSystemmoveCntfrqEl0 { rt } => {
            state.write_reg(rt, state.cntfrq_el0);
            Ok(pc + 4)
        }

        A64Insn::BUncondBOnlyBranchImm { .. } => insn
            .direct_branch_target(pc)
            .ok_or_else(|| format!("missing branch target for {}", insn.key()).into()),
        A64Insn::BCondBOnlyCondbranch { .. } => {
            let (taken, fallthrough) = insn
                .conditional_targets(pc)
                .ok_or_else(|| format!("missing conditional target for {}", insn.key()))?;
            let condition = insn
                .condition()
                .ok_or_else(|| format!("unsupported condition in {}", insn.key()))?;
            Ok(if eval_condition(condition, state) {
                taken
            } else {
                fallthrough
            })
        }
        A64Insn::CbzCbz32Compbranch { rt, .. } => branch_on_zero(insn, pc, state, rt, 32, true),
        A64Insn::CbzCbz64Compbranch { rt, .. } => branch_on_zero(insn, pc, state, rt, 64, true),
        A64Insn::CbnzCbnz32Compbranch { rt, .. } => branch_on_zero(insn, pc, state, rt, 32, false),
        A64Insn::CbnzCbnz64Compbranch { rt, .. } => branch_on_zero(insn, pc, state, rt, 64, false),
        A64Insn::TbzTbzOnlyTestbranch { b5, b40, rt, .. } => {
            branch_on_bit(insn, pc, state, rt, bit_index(b5, b40), false)
        }
        A64Insn::TbnzTbnzOnlyTestbranch { b5, b40, rt, .. } => {
            branch_on_bit(insn, pc, state, rt, bit_index(b5, b40), true)
        }

        // Loads and stores: `Elem` gives the element size and how a loaded element
        // becomes the register value (Mem, then ZeroExtend/SignExtend to the
        // destination width); `Addr` gives the addressing mode.
        A64Insn::LdrImmGenLdr32LdstPos { rt, mem }
        | A64Insn::LdrImmGenLdr32LdstImmpre { rt, mem }
        | A64Insn::LdrImmGenLdr32LdstImmpost { rt, mem }
        | A64Insn::LdurGenLdur32LdstUnscaled { rt, mem }
        | A64Insn::LdtrLdtr32LdstUnpriv { rt, mem } => {
            execute_mem(ctx, state, pc, insn, zx(4, 32), rt, None, Addr::Imm(mem))
        }
        A64Insn::LdrImmGenLdr64LdstPos { rt, mem }
        | A64Insn::LdrImmGenLdr64LdstImmpre { rt, mem }
        | A64Insn::LdrImmGenLdr64LdstImmpost { rt, mem }
        | A64Insn::LdurGenLdur64LdstUnscaled { rt, mem }
        | A64Insn::LdtrLdtr64LdstUnpriv { rt, mem } => {
            execute_mem(ctx, state, pc, insn, zx(8, 64), rt, None, Addr::Imm(mem))
        }
        A64Insn::LdrbImmLdrb32LdstPos { rt, mem }
        | A64Insn::LdrbImmLdrb32LdstImmpre { rt, mem }
        | A64Insn::LdrbImmLdrb32LdstImmpost { rt, mem }
        | A64Insn::LdurbLdurb32LdstUnscaled { rt, mem }
        | A64Insn::LdtrbLdtrb32LdstUnpriv { rt, mem } => {
            execute_mem(ctx, state, pc, insn, zx(1, 32), rt, None, Addr::Imm(mem))
        }
        A64Insn::LdrhImmLdrh32LdstPos { rt, mem }
        | A64Insn::LdrhImmLdrh32LdstImmpre { rt, mem }
        | A64Insn::LdrhImmLdrh32LdstImmpost { rt, mem }
        | A64Insn::LdurhLdurh32LdstUnscaled { rt, mem }
        | A64Insn::LdtrhLdtrh32LdstUnpriv { rt, mem } => {
            execute_mem(ctx, state, pc, insn, zx(2, 32), rt, None, Addr::Imm(mem))
        }
        A64Insn::LdrsbImmLdrsb32LdstPos { rt, mem }
        | A64Insn::LdrsbImmLdrsb32LdstImmpre { rt, mem }
        | A64Insn::LdrsbImmLdrsb32LdstImmpost { rt, mem }
        | A64Insn::LdursbLdursb32LdstUnscaled { rt, mem }
        | A64Insn::LdtrsbLdtrsb32LdstUnpriv { rt, mem } => {
            execute_mem(ctx, state, pc, insn, sx(1, 32), rt, None, Addr::Imm(mem))
        }
        A64Insn::LdrsbImmLdrsb64LdstPos { rt, mem }
        | A64Insn::LdrsbImmLdrsb64LdstImmpre { rt, mem }
        | A64Insn::LdrsbImmLdrsb64LdstImmpost { rt, mem }
        | A64Insn::LdursbLdursb64LdstUnscaled { rt, mem }
        | A64Insn::LdtrsbLdtrsb64LdstUnpriv { rt, mem } => {
            execute_mem(ctx, state, pc, insn, sx(1, 64), rt, None, Addr::Imm(mem))
        }
        A64Insn::LdrshImmLdrsh32LdstPos { rt, mem }
        | A64Insn::LdrshImmLdrsh32LdstImmpre { rt, mem }
        | A64Insn::LdrshImmLdrsh32LdstImmpost { rt, mem }
        | A64Insn::LdurshLdursh32LdstUnscaled { rt, mem }
        | A64Insn::LdtrshLdtrsh32LdstUnpriv { rt, mem } => {
            execute_mem(ctx, state, pc, insn, sx(2, 32), rt, None, Addr::Imm(mem))
        }
        A64Insn::LdrshImmLdrsh64LdstPos { rt, mem }
        | A64Insn::LdrshImmLdrsh64LdstImmpre { rt, mem }
        | A64Insn::LdrshImmLdrsh64LdstImmpost { rt, mem }
        | A64Insn::LdurshLdursh64LdstUnscaled { rt, mem }
        | A64Insn::LdtrshLdtrsh64LdstUnpriv { rt, mem } => {
            execute_mem(ctx, state, pc, insn, sx(2, 64), rt, None, Addr::Imm(mem))
        }
        A64Insn::LdrswImmLdrsw64LdstPos { rt, mem }
        | A64Insn::LdrswImmLdrsw64LdstImmpre { rt, mem }
        | A64Insn::LdrswImmLdrsw64LdstImmpost { rt, mem }
        | A64Insn::LdurswLdursw64LdstUnscaled { rt, mem }
        | A64Insn::LdtrswLdtrsw64LdstUnpriv { rt, mem } => {
            execute_mem(ctx, state, pc, insn, sx(4, 64), rt, None, Addr::Imm(mem))
        }
        A64Insn::StrImmGenStr32LdstPos { rt, mem }
        | A64Insn::StrImmGenStr32LdstImmpre { rt, mem }
        | A64Insn::StrImmGenStr32LdstImmpost { rt, mem }
        | A64Insn::SturGenStur32LdstUnscaled { rt, mem }
        | A64Insn::SttrSttr32LdstUnpriv { rt, mem } => {
            execute_mem(ctx, state, pc, insn, st(4), rt, None, Addr::Imm(mem))
        }
        A64Insn::StrImmGenStr64LdstPos { rt, mem }
        | A64Insn::StrImmGenStr64LdstImmpre { rt, mem }
        | A64Insn::StrImmGenStr64LdstImmpost { rt, mem }
        | A64Insn::SturGenStur64LdstUnscaled { rt, mem }
        | A64Insn::SttrSttr64LdstUnpriv { rt, mem } => {
            execute_mem(ctx, state, pc, insn, st(8), rt, None, Addr::Imm(mem))
        }
        A64Insn::StrbImmStrb32LdstPos { rt, mem }
        | A64Insn::StrbImmStrb32LdstImmpre { rt, mem }
        | A64Insn::StrbImmStrb32LdstImmpost { rt, mem }
        | A64Insn::SturbSturb32LdstUnscaled { rt, mem }
        | A64Insn::SttrbSttrb32LdstUnpriv { rt, mem } => {
            execute_mem(ctx, state, pc, insn, st(1), rt, None, Addr::Imm(mem))
        }
        A64Insn::StrhImmStrh32LdstPos { rt, mem }
        | A64Insn::StrhImmStrh32LdstImmpre { rt, mem }
        | A64Insn::StrhImmStrh32LdstImmpost { rt, mem }
        | A64Insn::SturhSturh32LdstUnscaled { rt, mem }
        | A64Insn::SttrhSttrh32LdstUnpriv { rt, mem } => {
            execute_mem(ctx, state, pc, insn, st(2), rt, None, Addr::Imm(mem))
        }

        A64Insn::LdpGenLdp32LdstpairPost { rt2, rt, mem }
        | A64Insn::LdpGenLdp32LdstpairPre { rt2, rt, mem }
        | A64Insn::LdpGenLdp32LdstpairOff { rt2, rt, mem } => execute_mem(
            ctx,
            state,
            pc,
            insn,
            zx(4, 32),
            rt,
            Some(rt2),
            Addr::Imm(mem),
        ),
        A64Insn::LdpGenLdp64LdstpairPost { rt2, rt, mem }
        | A64Insn::LdpGenLdp64LdstpairPre { rt2, rt, mem }
        | A64Insn::LdpGenLdp64LdstpairOff { rt2, rt, mem } => execute_mem(
            ctx,
            state,
            pc,
            insn,
            zx(8, 64),
            rt,
            Some(rt2),
            Addr::Imm(mem),
        ),
        A64Insn::LdpswLdpsw64LdstpairPost { rt2, rt, mem }
        | A64Insn::LdpswLdpsw64LdstpairPre { rt2, rt, mem }
        | A64Insn::LdpswLdpsw64LdstpairOff { rt2, rt, mem } => execute_mem(
            ctx,
            state,
            pc,
            insn,
            sx(4, 64),
            rt,
            Some(rt2),
            Addr::Imm(mem),
        ),
        A64Insn::StpGenStp32LdstpairPost { rt2, rt, mem }
        | A64Insn::StpGenStp32LdstpairPre { rt2, rt, mem }
        | A64Insn::StpGenStp32LdstpairOff { rt2, rt, mem } => {
            execute_mem(ctx, state, pc, insn, st(4), rt, Some(rt2), Addr::Imm(mem))
        }
        A64Insn::StpGenStp64LdstpairPost { rt2, rt, mem }
        | A64Insn::StpGenStp64LdstpairPre { rt2, rt, mem }
        | A64Insn::StpGenStp64LdstpairOff { rt2, rt, mem } => {
            execute_mem(ctx, state, pc, insn, st(8), rt, Some(rt2), Addr::Imm(mem))
        }

        A64Insn::LdrRegGenLdr32LdstRegoff {
            rm,
            option,
            s,
            rn,
            rt,
        } => execute_mem(
            ctx,
            state,
            pc,
            insn,
            zx(4, 32),
            rt,
            None,
            Addr::reg(rn, rm, option, s),
        ),
        A64Insn::LdrRegGenLdr64LdstRegoff {
            rm,
            option,
            s,
            rn,
            rt,
        } => execute_mem(
            ctx,
            state,
            pc,
            insn,
            zx(8, 64),
            rt,
            None,
            Addr::reg(rn, rm, option, s),
        ),
        A64Insn::StrRegGenStr32LdstRegoff {
            rm,
            option,
            s,
            rn,
            rt,
        } => execute_mem(
            ctx,
            state,
            pc,
            insn,
            st(4),
            rt,
            None,
            Addr::reg(rn, rm, option, s),
        ),
        A64Insn::StrRegGenStr64LdstRegoff {
            rm,
            option,
            s,
            rn,
            rt,
        } => execute_mem(
            ctx,
            state,
            pc,
            insn,
            st(8),
            rt,
            None,
            Addr::reg(rn, rm, option, s),
        ),
        A64Insn::LdrbRegLdrb32bLdstRegoff {
            rm,
            option,
            s,
            rn,
            rt,
        } => execute_mem(
            ctx,
            state,
            pc,
            insn,
            zx(1, 32),
            rt,
            None,
            Addr::reg(rn, rm, option, s),
        ),
        A64Insn::LdrbRegLdrb32blLdstRegoff { rm, s, rn, rt } => execute_mem(
            ctx,
            state,
            pc,
            insn,
            zx(1, 32),
            rt,
            None,
            Addr::reg(rn, rm, LSL, s),
        ),
        A64Insn::StrbRegStrb32bLdstRegoff {
            rm,
            option,
            s,
            rn,
            rt,
        } => execute_mem(
            ctx,
            state,
            pc,
            insn,
            st(1),
            rt,
            None,
            Addr::reg(rn, rm, option, s),
        ),
        A64Insn::StrbRegStrb32blLdstRegoff { rm, s, rn, rt } => execute_mem(
            ctx,
            state,
            pc,
            insn,
            st(1),
            rt,
            None,
            Addr::reg(rn, rm, LSL, s),
        ),
        A64Insn::LdrhRegLdrh32LdstRegoff {
            rm,
            option,
            s,
            rn,
            rt,
        } => execute_mem(
            ctx,
            state,
            pc,
            insn,
            zx(2, 32),
            rt,
            None,
            Addr::reg(rn, rm, option, s),
        ),
        A64Insn::StrhRegStrh32LdstRegoff {
            rm,
            option,
            s,
            rn,
            rt,
        } => execute_mem(
            ctx,
            state,
            pc,
            insn,
            st(2),
            rt,
            None,
            Addr::reg(rn, rm, option, s),
        ),
        A64Insn::LdrsbRegLdrsb32bLdstRegoff {
            rm,
            option,
            s,
            rn,
            rt,
        } => execute_mem(
            ctx,
            state,
            pc,
            insn,
            sx(1, 32),
            rt,
            None,
            Addr::reg(rn, rm, option, s),
        ),
        A64Insn::LdrsbRegLdrsb32blLdstRegoff { rm, s, rn, rt } => execute_mem(
            ctx,
            state,
            pc,
            insn,
            sx(1, 32),
            rt,
            None,
            Addr::reg(rn, rm, LSL, s),
        ),
        A64Insn::LdrsbRegLdrsb64bLdstRegoff {
            rm,
            option,
            s,
            rn,
            rt,
        } => execute_mem(
            ctx,
            state,
            pc,
            insn,
            sx(1, 64),
            rt,
            None,
            Addr::reg(rn, rm, option, s),
        ),
        A64Insn::LdrsbRegLdrsb64blLdstRegoff { rm, s, rn, rt } => execute_mem(
            ctx,
            state,
            pc,
            insn,
            sx(1, 64),
            rt,
            None,
            Addr::reg(rn, rm, LSL, s),
        ),
        A64Insn::LdrshRegLdrsh32LdstRegoff {
            rm,
            option,
            s,
            rn,
            rt,
        } => execute_mem(
            ctx,
            state,
            pc,
            insn,
            sx(2, 32),
            rt,
            None,
            Addr::reg(rn, rm, option, s),
        ),
        A64Insn::LdrshRegLdrsh64LdstRegoff {
            rm,
            option,
            s,
            rn,
            rt,
        } => execute_mem(
            ctx,
            state,
            pc,
            insn,
            sx(2, 64),
            rt,
            None,
            Addr::reg(rn, rm, option, s),
        ),
        A64Insn::LdrswRegLdrsw64LdstRegoff {
            rm,
            option,
            s,
            rn,
            rt,
        } => execute_mem(
            ctx,
            state,
            pc,
            insn,
            sx(4, 64),
            rt,
            None,
            Addr::reg(rn, rm, option, s),
        ),

        A64Insn::LdrLitGenLdr32Loadlit { imm19, rt } => execute_mem(
            ctx,
            state,
            pc,
            insn,
            zx(4, 32),
            rt,
            None,
            Addr::literal(pc, imm19),
        ),
        A64Insn::LdrLitGenLdr64Loadlit { imm19, rt } => execute_mem(
            ctx,
            state,
            pc,
            insn,
            zx(8, 64),
            rt,
            None,
            Addr::literal(pc, imm19),
        ),
        A64Insn::LdrswLitLdrsw64Loadlit { imm19, rt } => execute_mem(
            ctx,
            state,
            pc,
            insn,
            sx(4, 64),
            rt,
            None,
            Addr::literal(pc, imm19),
        ),

        // Prefetch hints: no architectural effect, never a data abort.
        A64Insn::PrfmImmPrfmPLdstPos { .. }
        | A64Insn::PrfmLitPrfmPLoadlit { .. }
        | A64Insn::PrfmRegPrfmPLdstRegoff { .. } => Ok(pc + 4),

        // Barriers only order memory effects between observers. The model has one
        // observer (a single thread, no caches or speculation), where every access
        // is already in program order, so they are no-ops here.
        A64Insn::DmbDmbBoBarriers { .. }
        | A64Insn::DsbDsbBoBarriers { .. }
        | A64Insn::IsbIsbBiBarriers { .. } => Ok(pc + 4),

        // Acquire/release: the plain access plus the ordered-access alignment rule
        // (`Addr::Ordered`); the ordering itself is invisible to one thread.
        A64Insn::LdarLdarLr32Ldstord { rn, rt } | A64Insn::LdaprLdapr32lMemop { rn, rt } => {
            execute_mem(ctx, state, pc, insn, zx(4, 32), rt, None, Addr::Ordered(rn))
        }
        A64Insn::LdarLdarLr64Ldstord { rn, rt } | A64Insn::LdaprLdapr64lMemop { rn, rt } => {
            execute_mem(ctx, state, pc, insn, zx(8, 64), rt, None, Addr::Ordered(rn))
        }
        A64Insn::LdarbLdarbLr32Ldstord { rn, rt } | A64Insn::LdaprbLdaprb32lMemop { rn, rt } => {
            execute_mem(ctx, state, pc, insn, zx(1, 32), rt, None, Addr::Ordered(rn))
        }
        A64Insn::LdarhLdarhLr32Ldstord { rn, rt } | A64Insn::LdaprhLdaprh32lMemop { rn, rt } => {
            execute_mem(ctx, state, pc, insn, zx(2, 32), rt, None, Addr::Ordered(rn))
        }
        A64Insn::StlrStlrSl32Ldstord { rn, rt } => {
            execute_mem(ctx, state, pc, insn, st(4), rt, None, Addr::Ordered(rn))
        }
        A64Insn::StlrStlrSl64Ldstord { rn, rt } => {
            execute_mem(ctx, state, pc, insn, st(8), rt, None, Addr::Ordered(rn))
        }
        A64Insn::StlrbStlrbSl32Ldstord { rn, rt } => {
            execute_mem(ctx, state, pc, insn, st(1), rt, None, Addr::Ordered(rn))
        }
        A64Insn::StlrhStlrhSl32Ldstord { rn, rt } => {
            execute_mem(ctx, state, pc, insn, st(2), rt, None, Addr::Ordered(rn))
        }

        // LSE single-register atomics (A8): EL0 user accesses in original code; in a
        // fragment a privileged access that requires PSTATE.PAN == 0.
        A64Insn::LdaddLdadd32Memop { .. }
        | A64Insn::LdaddLdadda32Memop { .. }
        | A64Insn::LdaddLdaddal32Memop { .. }
        | A64Insn::LdaddLdaddl32Memop { .. }
        | A64Insn::LdaddLdadd64Memop { .. }
        | A64Insn::LdaddLdadda64Memop { .. }
        | A64Insn::LdaddLdaddal64Memop { .. }
        | A64Insn::LdaddLdaddl64Memop { .. }
        | A64Insn::LdaddbLdaddb32Memop { .. }
        | A64Insn::LdaddbLdaddab32Memop { .. }
        | A64Insn::LdaddbLdaddalb32Memop { .. }
        | A64Insn::LdaddbLdaddlb32Memop { .. }
        | A64Insn::LdaddhLdaddh32Memop { .. }
        | A64Insn::LdaddhLdaddah32Memop { .. }
        | A64Insn::LdaddhLdaddalh32Memop { .. }
        | A64Insn::LdaddhLdaddlh32Memop { .. }
        | A64Insn::LdclrLdclr32Memop { .. }
        | A64Insn::LdclrLdclra32Memop { .. }
        | A64Insn::LdclrLdclral32Memop { .. }
        | A64Insn::LdclrLdclrl32Memop { .. }
        | A64Insn::LdclrLdclr64Memop { .. }
        | A64Insn::LdclrLdclra64Memop { .. }
        | A64Insn::LdclrLdclral64Memop { .. }
        | A64Insn::LdclrLdclrl64Memop { .. }
        | A64Insn::LdclrbLdclrb32Memop { .. }
        | A64Insn::LdclrbLdclrab32Memop { .. }
        | A64Insn::LdclrbLdclralb32Memop { .. }
        | A64Insn::LdclrbLdclrlb32Memop { .. }
        | A64Insn::LdclrhLdclrh32Memop { .. }
        | A64Insn::LdclrhLdclrah32Memop { .. }
        | A64Insn::LdclrhLdclralh32Memop { .. }
        | A64Insn::LdclrhLdclrlh32Memop { .. }
        | A64Insn::LdeorLdeor32Memop { .. }
        | A64Insn::LdeorLdeora32Memop { .. }
        | A64Insn::LdeorLdeoral32Memop { .. }
        | A64Insn::LdeorLdeorl32Memop { .. }
        | A64Insn::LdeorLdeor64Memop { .. }
        | A64Insn::LdeorLdeora64Memop { .. }
        | A64Insn::LdeorLdeoral64Memop { .. }
        | A64Insn::LdeorLdeorl64Memop { .. }
        | A64Insn::LdeorbLdeorb32Memop { .. }
        | A64Insn::LdeorbLdeorab32Memop { .. }
        | A64Insn::LdeorbLdeoralb32Memop { .. }
        | A64Insn::LdeorbLdeorlb32Memop { .. }
        | A64Insn::LdeorhLdeorh32Memop { .. }
        | A64Insn::LdeorhLdeorah32Memop { .. }
        | A64Insn::LdeorhLdeoralh32Memop { .. }
        | A64Insn::LdeorhLdeorlh32Memop { .. }
        | A64Insn::LdsetLdset32Memop { .. }
        | A64Insn::LdsetLdseta32Memop { .. }
        | A64Insn::LdsetLdsetal32Memop { .. }
        | A64Insn::LdsetLdsetl32Memop { .. }
        | A64Insn::LdsetLdset64Memop { .. }
        | A64Insn::LdsetLdseta64Memop { .. }
        | A64Insn::LdsetLdsetal64Memop { .. }
        | A64Insn::LdsetLdsetl64Memop { .. }
        | A64Insn::LdsetbLdsetb32Memop { .. }
        | A64Insn::LdsetbLdsetab32Memop { .. }
        | A64Insn::LdsetbLdsetalb32Memop { .. }
        | A64Insn::LdsetbLdsetlb32Memop { .. }
        | A64Insn::LdsethLdseth32Memop { .. }
        | A64Insn::LdsethLdsetah32Memop { .. }
        | A64Insn::LdsethLdsetalh32Memop { .. }
        | A64Insn::LdsethLdsetlh32Memop { .. }
        | A64Insn::LdsmaxLdsmax32Memop { .. }
        | A64Insn::LdsmaxLdsmaxa32Memop { .. }
        | A64Insn::LdsmaxLdsmaxal32Memop { .. }
        | A64Insn::LdsmaxLdsmaxl32Memop { .. }
        | A64Insn::LdsmaxLdsmax64Memop { .. }
        | A64Insn::LdsmaxLdsmaxa64Memop { .. }
        | A64Insn::LdsmaxLdsmaxal64Memop { .. }
        | A64Insn::LdsmaxLdsmaxl64Memop { .. }
        | A64Insn::LdsmaxbLdsmaxb32Memop { .. }
        | A64Insn::LdsmaxbLdsmaxab32Memop { .. }
        | A64Insn::LdsmaxbLdsmaxalb32Memop { .. }
        | A64Insn::LdsmaxbLdsmaxlb32Memop { .. }
        | A64Insn::LdsmaxhLdsmaxh32Memop { .. }
        | A64Insn::LdsmaxhLdsmaxah32Memop { .. }
        | A64Insn::LdsmaxhLdsmaxalh32Memop { .. }
        | A64Insn::LdsmaxhLdsmaxlh32Memop { .. }
        | A64Insn::LdsminLdsmin32Memop { .. }
        | A64Insn::LdsminLdsmina32Memop { .. }
        | A64Insn::LdsminLdsminal32Memop { .. }
        | A64Insn::LdsminLdsminl32Memop { .. }
        | A64Insn::LdsminLdsmin64Memop { .. }
        | A64Insn::LdsminLdsmina64Memop { .. }
        | A64Insn::LdsminLdsminal64Memop { .. }
        | A64Insn::LdsminLdsminl64Memop { .. }
        | A64Insn::LdsminbLdsminb32Memop { .. }
        | A64Insn::LdsminbLdsminab32Memop { .. }
        | A64Insn::LdsminbLdsminalb32Memop { .. }
        | A64Insn::LdsminbLdsminlb32Memop { .. }
        | A64Insn::LdsminhLdsminh32Memop { .. }
        | A64Insn::LdsminhLdsminah32Memop { .. }
        | A64Insn::LdsminhLdsminalh32Memop { .. }
        | A64Insn::LdsminhLdsminlh32Memop { .. }
        | A64Insn::LdumaxLdumax32Memop { .. }
        | A64Insn::LdumaxLdumaxa32Memop { .. }
        | A64Insn::LdumaxLdumaxal32Memop { .. }
        | A64Insn::LdumaxLdumaxl32Memop { .. }
        | A64Insn::LdumaxLdumax64Memop { .. }
        | A64Insn::LdumaxLdumaxa64Memop { .. }
        | A64Insn::LdumaxLdumaxal64Memop { .. }
        | A64Insn::LdumaxLdumaxl64Memop { .. }
        | A64Insn::LdumaxbLdumaxb32Memop { .. }
        | A64Insn::LdumaxbLdumaxab32Memop { .. }
        | A64Insn::LdumaxbLdumaxalb32Memop { .. }
        | A64Insn::LdumaxbLdumaxlb32Memop { .. }
        | A64Insn::LdumaxhLdumaxh32Memop { .. }
        | A64Insn::LdumaxhLdumaxah32Memop { .. }
        | A64Insn::LdumaxhLdumaxalh32Memop { .. }
        | A64Insn::LdumaxhLdumaxlh32Memop { .. }
        | A64Insn::LduminLdumin32Memop { .. }
        | A64Insn::LduminLdumina32Memop { .. }
        | A64Insn::LduminLduminal32Memop { .. }
        | A64Insn::LduminLduminl32Memop { .. }
        | A64Insn::LduminLdumin64Memop { .. }
        | A64Insn::LduminLdumina64Memop { .. }
        | A64Insn::LduminLduminal64Memop { .. }
        | A64Insn::LduminLduminl64Memop { .. }
        | A64Insn::LduminbLduminb32Memop { .. }
        | A64Insn::LduminbLduminab32Memop { .. }
        | A64Insn::LduminbLduminalb32Memop { .. }
        | A64Insn::LduminbLduminlb32Memop { .. }
        | A64Insn::LduminhLduminh32Memop { .. }
        | A64Insn::LduminhLduminah32Memop { .. }
        | A64Insn::LduminhLduminalh32Memop { .. }
        | A64Insn::LduminhLduminlh32Memop { .. }
        | A64Insn::SwpSwp32Memop { .. }
        | A64Insn::SwpSwpa32Memop { .. }
        | A64Insn::SwpSwpal32Memop { .. }
        | A64Insn::SwpSwpl32Memop { .. }
        | A64Insn::SwpSwp64Memop { .. }
        | A64Insn::SwpSwpa64Memop { .. }
        | A64Insn::SwpSwpal64Memop { .. }
        | A64Insn::SwpSwpl64Memop { .. }
        | A64Insn::SwpbSwpb32Memop { .. }
        | A64Insn::SwpbSwpab32Memop { .. }
        | A64Insn::SwpbSwpalb32Memop { .. }
        | A64Insn::SwpbSwplb32Memop { .. }
        | A64Insn::SwphSwph32Memop { .. }
        | A64Insn::SwphSwpah32Memop { .. }
        | A64Insn::SwphSwpalh32Memop { .. }
        | A64Insn::SwphSwplh32Memop { .. }
        | A64Insn::CasCasC32Comswap { .. }
        | A64Insn::CasCasaC32Comswap { .. }
        | A64Insn::CasCasalC32Comswap { .. }
        | A64Insn::CasCaslC32Comswap { .. }
        | A64Insn::CasCasC64Comswap { .. }
        | A64Insn::CasCasaC64Comswap { .. }
        | A64Insn::CasCasalC64Comswap { .. }
        | A64Insn::CasCaslC64Comswap { .. }
        | A64Insn::CasbCasbC32Comswap { .. }
        | A64Insn::CasbCasabC32Comswap { .. }
        | A64Insn::CasbCasalbC32Comswap { .. }
        | A64Insn::CasbCaslbC32Comswap { .. }
        | A64Insn::CashCashC32Comswap { .. }
        | A64Insn::CashCasahC32Comswap { .. }
        | A64Insn::CashCasalhC32Comswap { .. }
        | A64Insn::CashCaslhC32Comswap { .. } => {
            let atomic = insn
                .lse_atomic()
                .ok_or_else(|| format!("{} is not an LSE atomic", insn.key()))?;
            execute_atomic(ctx, state, pc, atomic)
        }
        // A9a SIMD&FP (tmp/pipeline.md, "A9 contract").
        A64Insn::LdrImmFpsimdLdrBLdstImmpost { .. }
        | A64Insn::LdrImmFpsimdLdrHLdstImmpost { .. }
        | A64Insn::LdrImmFpsimdLdrSLdstImmpost { .. }
        | A64Insn::LdrImmFpsimdLdrDLdstImmpost { .. }
        | A64Insn::LdrImmFpsimdLdrQLdstImmpost { .. }
        | A64Insn::LdrImmFpsimdLdrBLdstImmpre { .. }
        | A64Insn::LdrImmFpsimdLdrHLdstImmpre { .. }
        | A64Insn::LdrImmFpsimdLdrSLdstImmpre { .. }
        | A64Insn::LdrImmFpsimdLdrDLdstImmpre { .. }
        | A64Insn::LdrImmFpsimdLdrQLdstImmpre { .. }
        | A64Insn::LdrImmFpsimdLdrBLdstPos { .. }
        | A64Insn::LdrImmFpsimdLdrHLdstPos { .. }
        | A64Insn::LdrImmFpsimdLdrSLdstPos { .. }
        | A64Insn::LdrImmFpsimdLdrDLdstPos { .. }
        | A64Insn::LdrImmFpsimdLdrQLdstPos { .. }
        | A64Insn::StrImmFpsimdStrBLdstImmpost { .. }
        | A64Insn::StrImmFpsimdStrHLdstImmpost { .. }
        | A64Insn::StrImmFpsimdStrSLdstImmpost { .. }
        | A64Insn::StrImmFpsimdStrDLdstImmpost { .. }
        | A64Insn::StrImmFpsimdStrQLdstImmpost { .. }
        | A64Insn::StrImmFpsimdStrBLdstImmpre { .. }
        | A64Insn::StrImmFpsimdStrHLdstImmpre { .. }
        | A64Insn::StrImmFpsimdStrSLdstImmpre { .. }
        | A64Insn::StrImmFpsimdStrDLdstImmpre { .. }
        | A64Insn::StrImmFpsimdStrQLdstImmpre { .. }
        | A64Insn::StrImmFpsimdStrBLdstPos { .. }
        | A64Insn::StrImmFpsimdStrHLdstPos { .. }
        | A64Insn::StrImmFpsimdStrSLdstPos { .. }
        | A64Insn::StrImmFpsimdStrDLdstPos { .. }
        | A64Insn::StrImmFpsimdStrQLdstPos { .. }
        | A64Insn::LdurFpsimdLdurBLdstUnscaled { .. }
        | A64Insn::LdurFpsimdLdurHLdstUnscaled { .. }
        | A64Insn::LdurFpsimdLdurSLdstUnscaled { .. }
        | A64Insn::LdurFpsimdLdurDLdstUnscaled { .. }
        | A64Insn::LdurFpsimdLdurQLdstUnscaled { .. }
        | A64Insn::SturFpsimdSturBLdstUnscaled { .. }
        | A64Insn::SturFpsimdSturHLdstUnscaled { .. }
        | A64Insn::SturFpsimdSturSLdstUnscaled { .. }
        | A64Insn::SturFpsimdSturDLdstUnscaled { .. }
        | A64Insn::SturFpsimdSturQLdstUnscaled { .. }
        | A64Insn::LdpFpsimdLdpSLdstpairPost { .. }
        | A64Insn::LdpFpsimdLdpDLdstpairPost { .. }
        | A64Insn::LdpFpsimdLdpQLdstpairPost { .. }
        | A64Insn::LdpFpsimdLdpSLdstpairPre { .. }
        | A64Insn::LdpFpsimdLdpDLdstpairPre { .. }
        | A64Insn::LdpFpsimdLdpQLdstpairPre { .. }
        | A64Insn::LdpFpsimdLdpSLdstpairOff { .. }
        | A64Insn::LdpFpsimdLdpDLdstpairOff { .. }
        | A64Insn::LdpFpsimdLdpQLdstpairOff { .. }
        | A64Insn::StpFpsimdStpSLdstpairPost { .. }
        | A64Insn::StpFpsimdStpDLdstpairPost { .. }
        | A64Insn::StpFpsimdStpQLdstpairPost { .. }
        | A64Insn::StpFpsimdStpSLdstpairPre { .. }
        | A64Insn::StpFpsimdStpDLdstpairPre { .. }
        | A64Insn::StpFpsimdStpQLdstpairPre { .. }
        | A64Insn::StpFpsimdStpSLdstpairOff { .. }
        | A64Insn::StpFpsimdStpDLdstpairOff { .. }
        | A64Insn::StpFpsimdStpQLdstpairOff { .. }
        | A64Insn::Ld1AdvsimdMultLd1AsisdlseR11v { .. }
        | A64Insn::Ld1AdvsimdMultLd1AsisdlseR22v { .. }
        | A64Insn::Ld1AdvsimdMultLd1AsisdlseR33v { .. }
        | A64Insn::Ld1AdvsimdMultLd1AsisdlseR44v { .. }
        | A64Insn::Ld1AdvsimdMultLd1AsisdlsepI1I1 { .. }
        | A64Insn::Ld1AdvsimdMultLd1AsisdlsepR1R1 { .. }
        | A64Insn::Ld1AdvsimdMultLd1AsisdlsepI2I2 { .. }
        | A64Insn::Ld1AdvsimdMultLd1AsisdlsepR2R2 { .. }
        | A64Insn::Ld1AdvsimdMultLd1AsisdlsepI3I3 { .. }
        | A64Insn::Ld1AdvsimdMultLd1AsisdlsepR3R3 { .. }
        | A64Insn::Ld1AdvsimdMultLd1AsisdlsepI4I4 { .. }
        | A64Insn::Ld1AdvsimdMultLd1AsisdlsepR4R4 { .. }
        | A64Insn::St1AdvsimdMultSt1AsisdlseR11v { .. }
        | A64Insn::St1AdvsimdMultSt1AsisdlseR22v { .. }
        | A64Insn::St1AdvsimdMultSt1AsisdlseR33v { .. }
        | A64Insn::St1AdvsimdMultSt1AsisdlseR44v { .. }
        | A64Insn::St1AdvsimdMultSt1AsisdlsepI1I1 { .. }
        | A64Insn::St1AdvsimdMultSt1AsisdlsepR1R1 { .. }
        | A64Insn::St1AdvsimdMultSt1AsisdlsepI2I2 { .. }
        | A64Insn::St1AdvsimdMultSt1AsisdlsepR2R2 { .. }
        | A64Insn::St1AdvsimdMultSt1AsisdlsepI3I3 { .. }
        | A64Insn::St1AdvsimdMultSt1AsisdlsepR3R3 { .. }
        | A64Insn::St1AdvsimdMultSt1AsisdlsepI4I4 { .. }
        | A64Insn::St1AdvsimdMultSt1AsisdlsepR4R4 { .. }
        | A64Insn::DupAdvsimdEltDupAsisdoneOnly { .. }
        | A64Insn::DupAdvsimdEltDupAsimdinsDvV { .. }
        | A64Insn::DupAdvsimdGenDupAsimdinsDrR { .. }
        | A64Insn::InsAdvsimdEltInsAsimdinsIvV { .. }
        | A64Insn::InsAdvsimdGenInsAsimdinsIrR { .. }
        | A64Insn::UmovAdvsimdUmovAsimdinsWW { .. }
        | A64Insn::UmovAdvsimdUmovAsimdinsXX { .. }
        | A64Insn::MoviAdvsimdMoviAsimdimmNB { .. }
        | A64Insn::MoviAdvsimdMoviAsimdimmLHl { .. }
        | A64Insn::MoviAdvsimdMoviAsimdimmLSl { .. }
        | A64Insn::MoviAdvsimdMoviAsimdimmMSm { .. }
        | A64Insn::MoviAdvsimdMoviAsimdimmDDs { .. }
        | A64Insn::MoviAdvsimdMoviAsimdimmD2D { .. }
        | A64Insn::MvniAdvsimdMvniAsimdimmLHl { .. }
        | A64Insn::MvniAdvsimdMvniAsimdimmLSl { .. }
        | A64Insn::MvniAdvsimdMvniAsimdimmMSm { .. }
        | A64Insn::FmovFloatGenFmovS32Float2int { .. }
        | A64Insn::FmovFloatGenFmov32sFloat2int { .. }
        | A64Insn::FmovFloatGenFmovD64Float2int { .. }
        | A64Insn::FmovFloatGenFmovV64iFloat2int { .. }
        | A64Insn::FmovFloatGenFmov64dFloat2int { .. }
        | A64Insn::FmovFloatGenFmov64vxFloat2int { .. }
        | A64Insn::FmovFloatFmovSFloatdp1 { .. }
        | A64Insn::FmovFloatFmovDFloatdp1 { .. }
        | A64Insn::CmeqAdvsimdRegCmeqAsisdsameOnly { .. }
        | A64Insn::CmeqAdvsimdRegCmeqAsimdsameOnly { .. }
        | A64Insn::CmeqAdvsimdZeroCmeqAsisdmiscZ { .. }
        | A64Insn::CmeqAdvsimdZeroCmeqAsimdmiscZ { .. }
        | A64Insn::CmhiAdvsimdCmhiAsisdsameOnly { .. }
        | A64Insn::CmhiAdvsimdCmhiAsimdsameOnly { .. }
        | A64Insn::CmhsAdvsimdCmhsAsisdsameOnly { .. }
        | A64Insn::CmhsAdvsimdCmhsAsimdsameOnly { .. }
        | A64Insn::CmgtAdvsimdRegCmgtAsisdsameOnly { .. }
        | A64Insn::CmgtAdvsimdRegCmgtAsimdsameOnly { .. }
        | A64Insn::CmgtAdvsimdZeroCmgtAsisdmiscZ { .. }
        | A64Insn::CmgtAdvsimdZeroCmgtAsimdmiscZ { .. }
        | A64Insn::CmgeAdvsimdRegCmgeAsisdsameOnly { .. }
        | A64Insn::CmgeAdvsimdRegCmgeAsimdsameOnly { .. }
        | A64Insn::CmgeAdvsimdZeroCmgeAsisdmiscZ { .. }
        | A64Insn::CmgeAdvsimdZeroCmgeAsimdmiscZ { .. }
        | A64Insn::CmtstAdvsimdCmtstAsisdsameOnly { .. }
        | A64Insn::CmtstAdvsimdCmtstAsimdsameOnly { .. }
        | A64Insn::AndAdvsimdAndAsimdsameOnly { .. }
        | A64Insn::OrrAdvsimdRegOrrAsimdsameOnly { .. }
        | A64Insn::EorAdvsimdEorAsimdsameOnly { .. }
        | A64Insn::BicAdvsimdRegBicAsimdsameOnly { .. }
        | A64Insn::OrnAdvsimdOrnAsimdsameOnly { .. }
        | A64Insn::BitAdvsimdBitAsimdsameOnly { .. }
        | A64Insn::BifAdvsimdBifAsimdsameOnly { .. }
        | A64Insn::BslAdvsimdBslAsimdsameOnly { .. }
        | A64Insn::NotAdvsimdNotAsimdmiscR { .. }
        | A64Insn::AddAdvsimdAddAsisdsameOnly { .. }
        | A64Insn::AddAdvsimdAddAsimdsameOnly { .. }
        | A64Insn::SubAdvsimdSubAsisdsameOnly { .. }
        | A64Insn::SubAdvsimdSubAsimdsameOnly { .. }
        | A64Insn::AddpAdvsimdVecAddpAsimdsameOnly { .. }
        | A64Insn::AddpAdvsimdPairAddpAsisdpairOnly { .. }
        | A64Insn::UmaxpAdvsimdUmaxpAsimdsameOnly { .. }
        | A64Insn::UminpAdvsimdUminpAsimdsameOnly { .. }
        | A64Insn::AddvAdvsimdAddvAsimdallOnly { .. }
        | A64Insn::UmaxvAdvsimdUmaxvAsimdallOnly { .. }
        | A64Insn::UminvAdvsimdUminvAsimdallOnly { .. }
        | A64Insn::ShrnAdvsimdShrnAsimdshfN { .. }
        | A64Insn::UshrAdvsimdUshrAsisdshfR { .. }
        | A64Insn::UshrAdvsimdUshrAsimdshfR { .. }
        | A64Insn::ShlAdvsimdShlAsisdshfR { .. }
        | A64Insn::ShlAdvsimdShlAsimdshfR { .. }
        | A64Insn::UshllAdvsimdUshllAsimdshfL { .. }
        | A64Insn::XtnAdvsimdXtnAsimdmiscN { .. }
        | A64Insn::ExtAdvsimdExtAsimdextOnly { .. }
        | A64Insn::Rev16AdvsimdRev16AsimdmiscR { .. }
        | A64Insn::Rev32AdvsimdRev32AsimdmiscR { .. }
        | A64Insn::Rev64AdvsimdRev64AsimdmiscR { .. }
        | A64Insn::CntAdvsimdCntAsimdmiscR { .. }
        | A64Insn::TblAdvsimdTblAsimdtblL11 { .. } => crate::simd::execute(insn, pc, state, ctx),
        // `msr pan, #imm` (A8): only a fragment's PAN window and PAN stubs contain it
        // (admission rejects it in user code, so an original run never gets here).
        A64Insn::MsrImmMsrSiPstate { crm } => match ctx {
            AccessContext::Fragment { pan, .. } => {
                **pan = crm & 1 == 1;
                Ok(pc + 4)
            }
            AccessContext::Original { .. } => Err(InsnError::Error(format!(
                "msr pan at pc={pc:#x} in original code (UNDEFINED at EL0)"
            ))),
        },

        A64Insn::BlBlOnlyBranchImm { imm26 } => {
            let target = pc_relative_target(pc, imm26.raw(), 26);
            state.write_x(30, pc.wrapping_add(4));
            Ok(target)
        }
        A64Insn::BlrBlr64BranchReg { rn } => {
            let target = state.read_reg(rn);
            state.write_x(30, pc.wrapping_add(4));
            Ok(target)
        }
        A64Insn::BrBr64BranchReg { rn } => Ok(state.read_reg(rn)),
        A64Insn::RetRet64rBranchReg { rn } => Ok(state.read_reg(rn)),
        A64Insn::SvcSvcExException { .. } => Err(InsnError::Error(
            "raw SVC is not executable inside the userspace runtime fragment".to_string(),
        )),
    }
}

fn apply_runtime_exit_side_effect(insn: A64Insn, pc: u64, state: &mut MachineState) {
    match insn {
        A64Insn::BlBlOnlyBranchImm { .. } | A64Insn::BlrBlr64BranchReg { .. } => {
            state.write_x(30, pc.wrapping_add(4));
        }
        _ => {}
    }
}

fn add_sub_imm(sh: u8, imm12: A64Imm, insn: A64Insn) -> Result<u64, String> {
    A64Insn::add_sub_imm(sh, imm12)
        .ok_or_else(|| format!("unsupported add/sub immediate shift in {}", insn.key()))
}

fn write_movz(
    state: &mut MachineState,
    bits: u8,
    rd: A64Reg,
    imm16: A64Imm,
    hw: u8,
) -> Result<(), String> {
    let shift = A64Insn::move_wide_shift(hw)
        .ok_or_else(|| format!("unsupported MOVZ shift field: {hw}"))?;
    write_reg_sized(state, rd, (imm16.raw() as u64) << shift, bits);
    Ok(())
}

fn write_movk(
    state: &mut MachineState,
    bits: u8,
    rd: A64Reg,
    imm16: A64Imm,
    hw: u8,
) -> Result<(), String> {
    let shift = A64Insn::move_wide_shift(hw)
        .ok_or_else(|| format!("unsupported MOVK shift field: {hw}"))?;
    let old = read_reg_sized(state, rd, bits);
    let mask = !(0xFFFF_u64 << shift);
    write_reg_sized(
        state,
        rd,
        (old & mask) | ((imm16.raw() as u64) << shift),
        bits,
    );
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AddSub {
    Add,
    Sub,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Logic {
    And,
    Orr,
    Eor,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Bitfield {
    Signed,
    Unsigned,
    Insert,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CondSelect {
    Sel,
    Inc,
    Inv,
    Neg,
}

fn width_mask(bits: u8) -> u64 {
    match bits {
        64 => u64::MAX,
        1..=63 => (1_u64 << bits) - 1,
        _ => unreachable!("unsupported operand width {bits}"),
    }
}

/// `SInt(value[bits-1:0])`.
fn sign_extend_width(value: u64, bits: u8) -> i64 {
    let shift = 64 - u32::from(bits);
    ((value << shift) as i64) >> shift
}

/// `AddWithCarry` from the Arm pseudocode, on the low `bits` of both operands.
pub(crate) fn add_with_carry(x: u64, y: u64, carry_in: bool, bits: u8) -> (u64, Flags) {
    let mask = width_mask(bits);
    let (x, y) = (x & mask, y & mask);
    let unsigned_sum = u128::from(x) + u128::from(y) + u128::from(carry_in);
    let signed_sum = i128::from(sign_extend_width(x, bits))
        + i128::from(sign_extend_width(y, bits))
        + i128::from(carry_in);
    let result = (unsigned_sum as u64) & mask;
    let flags = Flags {
        n: (result >> (bits - 1)) & 1 != 0,
        z: result == 0,
        c: u128::from(result) != unsigned_sum,
        v: i128::from(sign_extend_width(result, bits)) != signed_sum,
    };
    (result, flags)
}

/// ADD/SUB core: `operand1 + operand2` or `operand1 + NOT(operand2) + 1`; writes the
/// result through `rd`'s own register-31 mode and, if `set_flags`, NZCV.
fn add_sub(
    state: &mut MachineState,
    rd: A64Reg,
    operand1: u64,
    operand2: u64,
    op: AddSub,
    set_flags: bool,
    bits: u8,
) {
    let (result, flags) = match op {
        AddSub::Add => add_with_carry(operand1, operand2, false, bits),
        AddSub::Sub => add_with_carry(operand1, !operand2, true, bits),
    };
    if set_flags {
        state.flags = flags;
    }
    write_reg_sized(state, rd, result, bits);
}

/// ADC/ADCS/SBC/SBCS: `Rn + Rm + C` or `Rn + NOT(Rm) + C` with the current carry
/// flag; ADCS/SBCS also write NZCV. Rn/Rm/Rd are never SP (ZR mode).
fn add_sub_carry(
    state: &mut MachineState,
    op: AddSub,
    set_flags: bool,
    bits: u8,
    rm: A64Reg,
    rn: A64Reg,
    rd: A64Reg,
) {
    let operand1 = read_reg_sized(state, rn, bits);
    let operand2 = match op {
        AddSub::Add => read_reg_sized(state, rm, bits),
        AddSub::Sub => !read_reg_sized(state, rm, bits),
    };
    let (result, flags) = add_with_carry(operand1, operand2, state.flags.c, bits);
    if set_flags {
        state.flags = flags;
    }
    write_reg_sized(state, rd, result, bits);
}

/// Bit-reversed `0x04C11DB7` (CRC32*) and `0x1EDC6F41` (CRC32C*).
const CRC32_POLY_REFLECTED: u32 = 0xEDB8_8320;
const CRC32C_POLY_REFLECTED: u32 = 0x82F6_3B78;

/// CRC32*/CRC32C*: `Wd = CRC(Wn, Rm[size-1:0])`. The pseudocode's
/// `BitReverse(Poly32Mod2(BitReverse(acc):0^size XOR BitReverse(val):0^32, poly))`
/// is the bit-reflected CRC update, least-significant bit first, with no
/// pre/post inversion.
fn crc32(state: &mut MachineState, poly: u32, size: u8, rm: A64Reg, rn: A64Reg, rd: A64Reg) {
    let mut crc = read_reg_sized(state, rn, 32) as u32;
    let value = state.read_reg(rm) & width_mask(size);
    for bit in 0..u32::from(size) {
        let feedback = (crc ^ (value >> bit) as u32) & 1;
        crc = (crc >> 1) ^ if feedback != 0 { poly } else { 0 };
    }
    write_reg_sized(state, rd, u64::from(crc), 32);
}

/// `ShiftReg`: shift type 0..=3 is LSL, LSR, ASR, ROR over `bits`.
fn shift_value(value: u64, shift: u8, amount: u32, bits: u8) -> Result<u64, String> {
    if amount >= u32::from(bits) {
        return Err(format!(
            "shift amount {amount} out of range for {bits}-bit operand"
        ));
    }
    let mask = width_mask(bits);
    let value = value & mask;
    let shifted = match shift {
        0b00 => value << amount,
        0b01 => value >> amount,
        0b10 => (sign_extend_width(value, bits) >> amount) as u64,
        0b11 if amount == 0 => value,
        0b11 => (value >> amount) | (value << (u32::from(bits) - amount)),
        _ => return Err(format!("unsupported shift type field: {shift}")),
    };
    Ok(shifted & mask)
}

/// `ExtendReg`: `option` selects UXTB..UXTX, SXTB..SXTX; the result is shifted left
/// by `shift` (0..=4).
fn extend_value(value: u64, option: u8, shift: u32, bits: u8) -> Result<u64, String> {
    if shift > 4 {
        return Err(format!("extended-register shift {shift} is reserved"));
    }
    let (len, signed) = match option {
        0b000 => (8, false),
        0b001 => (16, false),
        0b010 => (32, false),
        0b011 => (64, false),
        0b100 => (8, true),
        0b101 => (16, true),
        0b110 => (32, true),
        0b111 => (64, true),
        _ => return Err(format!("unsupported extend option field: {option}")),
    };
    let len = len.min(bits);
    let extended = if signed {
        sign_extend_width(value, len) as u64
    } else {
        value & width_mask(len)
    };
    Ok((extended << shift) & width_mask(bits))
}

fn add_sub_shifted(
    state: &mut MachineState,
    op: AddSub,
    set_flags: bool,
    bits: u8,
    shift: u8,
    rm: A64Reg,
    imm6: A64Imm,
    rn: A64Reg,
    rd: A64Reg,
) -> Result<(), String> {
    if shift == 0b11 {
        return Err("add/sub shifted register with ROR shift is reserved".to_string());
    }
    let operand2 = shift_value(state.read_reg(rm), shift, imm6.raw(), bits)?;
    add_sub(state, rd, state.read_reg(rn), operand2, op, set_flags, bits);
    Ok(())
}

fn add_sub_extended(
    state: &mut MachineState,
    op: AddSub,
    set_flags: bool,
    bits: u8,
    rm: A64Reg,
    option: u8,
    imm3: A64Imm,
    rn: A64Reg,
    rd: A64Reg,
) -> Result<(), String> {
    let operand2 = extend_value(state.read_reg(rm), option, imm3.raw(), bits)?;
    add_sub(state, rd, state.read_reg(rn), operand2, op, set_flags, bits);
    Ok(())
}

/// Logical result; `set_flags` gives N and Z from the result with C = V = 0.
fn logical(
    state: &mut MachineState,
    op: Logic,
    set_flags: bool,
    bits: u8,
    operand1: u64,
    operand2: u64,
    rd: A64Reg,
) {
    let result = match op {
        Logic::And => operand1 & operand2,
        Logic::Orr => operand1 | operand2,
        Logic::Eor => operand1 ^ operand2,
    } & width_mask(bits);
    if set_flags {
        state.flags = Flags {
            n: (result >> (bits - 1)) & 1 != 0,
            z: result == 0,
            c: false,
            v: false,
        };
    }
    write_reg_sized(state, rd, result, bits);
}

fn logical_shifted(
    state: &mut MachineState,
    op: Logic,
    invert: bool,
    set_flags: bool,
    bits: u8,
    shift: u8,
    rm: A64Reg,
    imm6: A64Imm,
    rn: A64Reg,
    rd: A64Reg,
) -> Result<(), String> {
    let shifted = shift_value(state.read_reg(rm), shift, imm6.raw(), bits)?;
    let operand2 = if invert { !shifted } else { shifted };
    logical(state, op, set_flags, bits, state.read_reg(rn), operand2, rd);
    Ok(())
}

fn logical_imm(
    state: &mut MachineState,
    op: Logic,
    set_flags: bool,
    bits: u8,
    n: u8,
    immr: A64Imm,
    imms: A64Imm,
    rn: A64Reg,
    rd: A64Reg,
) -> Result<(), String> {
    let (imm, _) = decode_bit_masks(n, imms.raw(), immr.raw(), true, bits)?;
    logical(state, op, set_flags, bits, state.read_reg(rn), imm, rd);
    Ok(())
}

/// `DecodeBitMasks` from the Arm pseudocode: `(wmask, tmask)` over `bits`.
pub(crate) fn decode_bit_masks(
    n: u8,
    imms: u32,
    immr: u32,
    immediate: bool,
    bits: u8,
) -> Result<(u64, u64), String> {
    let n_not_imms = (u32::from(n & 1) << 6) | (!imms & 0x3f);
    if n_not_imms >> 1 == 0 {
        return Err(format!("reserved bitmask immediate N={n} imms={imms:#x}"));
    }
    let len = 31 - n_not_imms.leading_zeros();
    let esize = 1_u32 << len;
    if esize > u32::from(bits) {
        return Err(format!(
            "bitmask element size {esize} exceeds {bits}-bit operand"
        ));
    }
    let levels = esize - 1;
    if immediate && imms & levels == levels {
        return Err(format!(
            "reserved all-ones logical immediate imms={imms:#x}"
        ));
    }
    let s = imms & levels;
    let r = immr & levels;
    let d = s.wrapping_sub(r) & levels;
    let esize_bits = esize as u8;
    let welem = width_mask(s as u8 + 1);
    let telem = width_mask(d as u8 + 1);
    let wmask = replicate(rotate_right(welem, r, esize_bits), esize_bits, bits);
    let tmask = replicate(telem, esize_bits, bits);
    Ok((wmask, tmask))
}

fn rotate_right(value: u64, amount: u32, bits: u8) -> u64 {
    let mask = width_mask(bits);
    let value = value & mask;
    if amount == 0 {
        value
    } else {
        ((value >> amount) | (value << (u32::from(bits) - amount))) & mask
    }
}

fn replicate(element: u64, esize: u8, bits: u8) -> u64 {
    let mut result = 0;
    let mut pos = 0;
    while pos < bits {
        result |= element << pos;
        pos += esize;
    }
    result & width_mask(bits)
}

fn bitfield_move(
    state: &mut MachineState,
    kind: Bitfield,
    bits: u8,
    n: u8,
    immr: A64Imm,
    imms: A64Imm,
    rn: A64Reg,
    rd: A64Reg,
) -> Result<(), String> {
    let (r, s) = (immr.raw(), imms.raw());
    if r >= u32::from(bits) || s >= u32::from(bits) {
        return Err(format!(
            "bitfield immr={r} imms={s} out of range for {bits}-bit operand"
        ));
    }
    let (wmask, tmask) = decode_bit_masks(n, s, r, false, bits)?;
    let src = read_reg_sized(state, rn, bits);
    let rotated = rotate_right(src, r, bits);
    let result = match kind {
        Bitfield::Signed => {
            let top = if (src >> s) & 1 != 0 {
                width_mask(bits)
            } else {
                0
            };
            (top & !tmask) | (rotated & wmask & tmask)
        }
        Bitfield::Unsigned => rotated & wmask & tmask,
        Bitfield::Insert => {
            let dst = read_reg_sized(state, rd, bits);
            let bot = (dst & !wmask) | (rotated & wmask);
            (dst & !tmask) | (bot & tmask)
        }
    };
    write_reg_sized(state, rd, result, bits);
    Ok(())
}

fn extract(
    state: &mut MachineState,
    bits: u8,
    rm: A64Reg,
    imms: A64Imm,
    rn: A64Reg,
    rd: A64Reg,
) -> Result<(), String> {
    let lsb = imms.raw();
    if lsb >= u32::from(bits) {
        return Err(format!(
            "EXTR lsb {lsb} out of range for {bits}-bit operand"
        ));
    }
    let concat = (u128::from(read_reg_sized(state, rn, bits)) << bits)
        | u128::from(read_reg_sized(state, rm, bits));
    write_reg_sized(state, rd, (concat >> lsb) as u64 & width_mask(bits), bits);
    Ok(())
}

fn condition_holds(cond: u8, state: &MachineState) -> Result<bool, String> {
    let condition = A64Condition::from_bits(cond)
        .ok_or_else(|| format!("invalid condition field: {cond:#x}"))?;
    Ok(eval_condition(condition, state))
}

fn cond_select(
    state: &mut MachineState,
    kind: CondSelect,
    bits: u8,
    rm: A64Reg,
    cond: u8,
    rn: A64Reg,
    rd: A64Reg,
) -> Result<(), String> {
    let result = if condition_holds(cond, state)? {
        state.read_reg(rn)
    } else {
        let operand2 = state.read_reg(rm);
        match kind {
            CondSelect::Sel => operand2,
            CondSelect::Inc => operand2.wrapping_add(1),
            CondSelect::Inv => !operand2,
            CondSelect::Neg => operand2.wrapping_neg(),
        }
    };
    write_reg_sized(state, rd, result & width_mask(bits), bits);
    Ok(())
}

/// CCMP/CCMN: flags of `Rn - operand2` / `Rn + operand2` if `cond` holds, else `nzcv`.
fn cond_compare(
    state: &mut MachineState,
    op: AddSub,
    bits: u8,
    operand2: u64,
    cond: u8,
    rn: A64Reg,
    nzcv: u8,
) -> Result<(), String> {
    state.flags = if condition_holds(cond, state)? {
        let operand1 = state.read_reg(rn);
        match op {
            AddSub::Add => add_with_carry(operand1, operand2, false, bits).1,
            AddSub::Sub => add_with_carry(operand1, !operand2, true, bits).1,
        }
    } else {
        Flags {
            n: nzcv & 0b1000 != 0,
            z: nzcv & 0b0100 != 0,
            c: nzcv & 0b0010 != 0,
            v: nzcv & 0b0001 != 0,
        }
    };
    Ok(())
}

fn shift_variable(
    state: &mut MachineState,
    shift: u8,
    bits: u8,
    rm: A64Reg,
    rn: A64Reg,
    rd: A64Reg,
) -> Result<(), String> {
    let amount = (state.read_reg(rm) % u64::from(bits)) as u32;
    let result = shift_value(state.read_reg(rn), shift, amount, bits)?;
    write_reg_sized(state, rd, result, bits);
    Ok(())
}

/// UDIV/SDIV: division by zero gives 0; SDIV rounds toward zero, and INT_MIN / -1
/// wraps to INT_MIN (`result[datasize-1:0]`).
fn divide(state: &mut MachineState, signed: bool, bits: u8, rm: A64Reg, rn: A64Reg, rd: A64Reg) {
    let (dividend, divisor) = (state.read_reg(rn), state.read_reg(rm));
    let result = if divisor & width_mask(bits) == 0 {
        0
    } else if signed {
        let quotient = i128::from(sign_extend_width(dividend, bits))
            / i128::from(sign_extend_width(divisor, bits));
        quotient as u64
    } else {
        (dividend & width_mask(bits)) / (divisor & width_mask(bits))
    };
    write_reg_sized(state, rd, result & width_mask(bits), bits);
}

/// MADD/MSUB: `Ra +/- Rn * Rm` over `bits`.
fn multiply_add(
    state: &mut MachineState,
    op: AddSub,
    bits: u8,
    rm: A64Reg,
    ra: A64Reg,
    rn: A64Reg,
    rd: A64Reg,
) {
    let product = state.read_reg(rn).wrapping_mul(state.read_reg(rm));
    let accumulator = state.read_reg(ra);
    let result = match op {
        AddSub::Add => accumulator.wrapping_add(product),
        AddSub::Sub => accumulator.wrapping_sub(product),
    };
    write_reg_sized(state, rd, result & width_mask(bits), bits);
}

/// REV/REV16/REV32: reverse the bytes inside each `container`-bit lane.
fn reverse_bytes(state: &mut MachineState, bits: u8, container: u8, rn: A64Reg, rd: A64Reg) {
    let operand = read_reg_sized(state, rn, bits);
    let mut result = 0_u64;
    let mut lane = 0;
    while lane < bits {
        let value = (operand >> lane) & width_mask(container);
        let reversed = value.swap_bytes() >> (64 - u32::from(container));
        result |= reversed << lane;
        lane += container;
    }
    write_reg_sized(state, rd, result, bits);
}

fn write_movn(
    state: &mut MachineState,
    bits: u8,
    rd: A64Reg,
    imm16: A64Imm,
    hw: u8,
) -> Result<(), String> {
    let shift = A64Insn::move_wide_shift(hw)
        .ok_or_else(|| format!("unsupported MOVN shift field: {hw}"))?;
    write_reg_sized(state, rd, !((imm16.raw() as u64) << shift), bits);
    Ok(())
}

/// One element of a load/store: its size in bytes and, for a load, how it becomes
/// the register value (`ZeroExtend`/`SignExtend` to `dest_bits`).
#[derive(Clone, Copy, Debug)]
enum Elem {
    Load {
        size: u8,
        signed: bool,
        dest_bits: u8,
    },
    Store {
        size: u8,
    },
}

impl Elem {
    const fn size(self) -> u8 {
        match self {
            Elem::Load { size, .. } | Elem::Store { size } => size,
        }
    }
}

const fn zx(size: u8, dest_bits: u8) -> Elem {
    Elem::Load {
        size,
        signed: false,
        dest_bits,
    }
}

const fn sx(size: u8, dest_bits: u8) -> Elem {
    Elem::Load {
        size,
        signed: true,
        dest_bits,
    }
}

const fn st(size: u8) -> Elem {
    Elem::Store { size }
}

/// `option` of the register-offset `*BL` byte forms, which encode `LSL` (UXTX).
const LSL: u8 = 0b011;

/// Addressing mode of a load/store.
#[derive(Clone, Copy, Debug)]
enum Addr {
    /// Base plus immediate; pre/post-index forms write the base back.
    Imm(A64Mem),
    /// `base + ExtendReg(index, option, S ? log2(size) : 0)`.
    Reg {
        base: A64Reg,
        index: A64Reg,
        option: u8,
        s: u8,
    },
    /// `pc + imm19 * 4`.
    Literal(u64),
    /// `[base]` of an acquire/release form (LDAR, STLR, LDAPR). Such an access
    /// that crosses a 16-byte boundary is an Alignment fault: the XML's
    /// `AArch64_UnalignedAccessFaults` for `acqsc`/`acqpc`/`relsc` with
    /// SCTLR_EL1.nAA == 0 (Linux leaves it clear), which is what FEAT_LSE2
    /// hardware (the native oracle's) does.
    Ordered(A64Reg),
}

impl Addr {
    const fn reg(base: A64Reg, index: A64Reg, option: u8, s: u8) -> Self {
        Addr::Reg {
            base,
            index,
            option,
            s,
        }
    }

    fn literal(pc: u64, imm19: A64Imm) -> Self {
        Addr::Literal(pc.wrapping_add_signed(sign_extend(imm19.raw(), 19) << 2))
    }
}

/// Every load/store (single or pair, user or `LDTR*`/`STTR*`). A pair is two
/// element accesses at consecutive addresses. All accesses are checked before
/// anything is written; then memory or the destination registers, then the
/// writeback. A store reads its registers before the writeback, so a writeback
/// STR whose `rt` is its base stores the old base (CONSTRAINED UNPREDICTABLE; one
/// of the permitted behaviours; reg-virt rejects the encoding anyway).
#[allow(clippy::too_many_arguments)]
fn execute_mem(
    ctx: &mut AccessContext<'_>,
    state: &mut MachineState,
    pc: u64,
    insn: A64Insn,
    elem: Elem,
    rt: A64Reg,
    rt2: Option<A64Reg>,
    addr: Addr,
) -> Result<u64, InsnError> {
    let size = elem.size();
    let (address, writeback) = match addr {
        Addr::Imm(mem) => mem_addressing(state, mem),
        Addr::Reg {
            base,
            index,
            option,
            s,
        } => {
            let shift = if s == 1 { size.trailing_zeros() } else { 0 };
            let offset = extend_value(state.read_reg(index), option, shift, 64)?;
            (state.read_reg(base).wrapping_add(offset), None)
        }
        Addr::Literal(address) => (address, None),
        Addr::Ordered(base) => (state.read_reg(base), None),
    };
    let address = untagged(address);
    if let (Addr::Imm(mem), Some(_), Elem::Load { .. }, Some(rt2)) = (addr, writeback, elem, rt2) {
        let base = mem.base();
        if base.enc() != 31 && (base.enc() == rt.enc() || base.enc() == rt2.enc()) {
            return Err(InsnError::Error(
                "writeback pair load with base/target overlap is unsupported".to_string(),
            ));
        }
    }

    let transfers: &[A64Reg] = match &rt2 {
        Some(rt2) => &[rt, *rt2],
        None => &[rt],
    };
    let accesses = transfers
        .iter()
        .enumerate()
        .map(|(index, _)| {
            let at = address.wrapping_add(index as u64 * u64::from(size));
            match elem {
                Elem::Load { .. } => read_access(at, size),
                Elem::Store { .. } => write_access(at, size),
            }
        })
        .collect::<Vec<_>>();
    let store_values = transfers
        .iter()
        .map(|reg| state.read_reg(*reg) & width_mask(size * 8))
        .collect::<Vec<_>>();
    // EL0 SP alignment check (SCTLR_EL1.SA0, set by Linux): an SP-based access
    // with SP not 16-byte aligned faults before any access. Original code only;
    // a fragment's SP accesses are to the runtime frame, at EL1.
    let is_sp = |reg: A64Reg| reg.enc() == 31 && reg.reg31 == A64Reg31Mode::Sp;
    let sp_based = match addr {
        Addr::Imm(mem) => is_sp(mem.base()),
        Addr::Reg { base, .. } | Addr::Ordered(base) => is_sp(base),
        Addr::Literal(_) => false,
    };
    if matches!(ctx, AccessContext::Original { .. }) && sp_based && state.sp() % 16 != 0 {
        return Err(InsnError::Fault(MemFault {
            pc,
            access: accesses[0],
            cause: FaultCause::SpAlignment,
        }));
    }
    // Ordered-access alignment (`Addr::Ordered`): checked after the SP check and
    // before translation, as in the `Mem` accessor. Fragments never contain
    // ordered forms (the verifier rejects them).
    if matches!(addr, Addr::Ordered(_)) && (address % 16) + u64::from(size) > 16 {
        return Err(InsnError::Fault(MemFault {
            pc,
            access: accesses[0],
            cause: FaultCause::Alignment,
        }));
    }
    check_accesses(ctx, state, pc, &accesses, insn.is_unprivileged_access())?;

    match elem {
        Elem::Load {
            signed, dest_bits, ..
        } => {
            let values = accesses
                .iter()
                .map(|access| {
                    let raw = state.read_le(access.addr, size);
                    let extended = if signed {
                        sign_extend_width(raw, size * 8) as u64
                    } else {
                        raw
                    };
                    extended & width_mask(dest_bits)
                })
                .collect::<Vec<_>>();
            if let (Addr::Imm(mem), Some(new_base)) = (addr, writeback) {
                state.write_reg(mem.base(), new_base);
            }
            for (reg, value) in transfers.iter().zip(values) {
                state.write_reg(*reg, value);
            }
        }
        Elem::Store { .. } => {
            for (access, value) in accesses.iter().zip(store_values) {
                state.write_le(access.addr, size, value);
            }
            if let (Addr::Imm(mem), Some(new_base)) = (addr, writeback) {
                state.write_reg(mem.base(), new_base);
            }
        }
    }
    Ok(pc + 4)
}

/// An LSE single-register atomic (A8): one read-modify-write access of `size`
/// bytes at `[Rn]`, which needs write permission (the access descriptor has both
/// read and write, whether or not a CAS compares equal). Checks run before
/// anything is written: the EL0 SP alignment check (original code), then the
/// atomic alignment rule (FEAT_LSE2: an access crossing a 16-byte boundary is an
/// Alignment fault; `MemSingleGranule()` is at least 16), then permissions.
/// `LD<op>`/`SWP` return the old value in `Rt`, `CAS` in `Rs`; a failed CAS writes
/// no memory. Ordering (A/L) is invisible to the single-threaded model.
fn execute_atomic(
    ctx: &mut AccessContext<'_>,
    state: &mut MachineState,
    pc: u64,
    atomic: A64Atomic,
) -> Result<u64, InsnError> {
    let size = atomic.size;
    let address = untagged(state.read_reg(atomic.rn));
    let access = write_access(address, size);
    let sp_based = atomic.rn.enc() == 31 && atomic.rn.reg31 == A64Reg31Mode::Sp;
    if matches!(ctx, AccessContext::Original { .. }) && sp_based && state.sp() % 16 != 0 {
        return Err(InsnError::Fault(MemFault {
            pc,
            access,
            cause: FaultCause::SpAlignment,
        }));
    }
    if (address % 16) + u64::from(size) > 16 {
        return Err(InsnError::Fault(MemFault {
            pc,
            access,
            cause: FaultCause::Alignment,
        }));
    }
    check_window_accesses(ctx, state, pc, &[access])?;

    let bits = size * 8;
    let mask = width_mask(bits);
    let old = state.read_le(address, size);
    let operand = state.read_reg(atomic.rs) & mask;
    let signed = |value: u64| sign_extend_width(value, bits);
    let new = match atomic.op {
        A64AtomicOp::Add => Some(old.wrapping_add(operand) & mask),
        A64AtomicOp::Clr => Some(old & !operand),
        A64AtomicOp::Eor => Some(old ^ operand),
        A64AtomicOp::Set => Some(old | operand),
        A64AtomicOp::Smax => Some(if signed(old) >= signed(operand) {
            old
        } else {
            operand
        }),
        A64AtomicOp::Smin => Some(if signed(old) <= signed(operand) {
            old
        } else {
            operand
        }),
        A64AtomicOp::Umax => Some(old.max(operand)),
        A64AtomicOp::Umin => Some(old.min(operand)),
        A64AtomicOp::Swp => Some(operand),
        A64AtomicOp::Cas => (old == operand).then(|| state.read_reg(atomic.rt) & mask),
    };
    if let Some(new) = new {
        state.write_le(address, size, new);
    }
    // The destination is the zero-extended old value, 32-bit for every form but
    // the 64-bit ones (`regsize`).
    let regsize = if size == 8 { 64 } else { 32 };
    let dest = match atomic.op {
        A64AtomicOp::Cas => atomic.rs,
        _ => atomic.rt,
    };
    write_reg_sized(state, dest, old, regsize);
    Ok(pc + 4)
}

/// The permission check of a PAN-window instruction's accesses (an LSE atomic,
/// A8, or an A9a SIMD&FP load/store), in order. Original code: EL0 user accesses.
/// Fragment: privileged accesses, legal only while PSTATE.PAN is clear (a PAN
/// violation otherwise, a hard error: an oops in the kernel) and only to user
/// memory: the window's range check proves the first access starts below 2^48
/// (else a hard error), and none may touch runtime memory (the kernel's here).
/// A later access of a multi-byte or multi-element instruction may run past 2^48,
/// which in the kernel is an ordinary translation fault on a TTBR0 address: here
/// an unmapped page. Each access is numbered with the user accesses for fault
/// injection and faults on the same EL0 page permissions (Linux user pages give
/// EL1 the same read/write permission; execute-only pages are not modelled).
pub(crate) fn check_window_accesses(
    ctx: &mut AccessContext<'_>,
    state: &MachineState,
    pc: u64,
    accesses: &[MemAccess],
) -> Result<(), InsnError> {
    for (index, &access) in accesses.iter().enumerate() {
        let (privilege, counter, log) = match ctx {
            AccessContext::Original { counter, log } => {
                (Privilege::User, counter.as_deref_mut(), log.as_deref_mut())
            }
            AccessContext::Fragment {
                runtime_ranges,
                counter,
                log,
                pan,
            } => {
                if **pan {
                    return Err(InsnError::Error(format!(
                        "PAN violation: privileged access at pc={pc:#x} to {:#x} with PSTATE.PAN set",
                        access.addr
                    )));
                }
                let overlaps_runtime = runtime_ranges.iter().any(|&(start, end)| {
                    access.addr < end && access.addr.saturating_add(u64::from(access.size)) > start
                });
                if overlaps_runtime || (index == 0 && access.addr >> USER_VA_BITS != 0) {
                    return Err(InsnError::Error(format!(
                        "privileged access at pc={pc:#x} to {:#x}: not a user address",
                        access.addr
                    )));
                }
                (Privilege::Window, Some(&mut **counter), log.as_deref_mut())
            }
        };
        if let Some(log) = log {
            log.push(LoggedAccess {
                pc,
                access,
                privilege,
            });
        }
        let injected = counter.is_some_and(|counter| counter.record());
        if injected || !state.user_access_allowed(access) {
            return Err(InsnError::Fault(MemFault {
                pc,
                access,
                cause: FaultCause::Permission,
            }));
        }
    }
    Ok(())
}

fn read_access(addr: u64, size: u8) -> MemAccess {
    MemAccess {
        addr,
        size,
        kind: AccessKind::Read,
    }
}

fn write_access(addr: u64, size: u8) -> MemAccess {
    MemAccess {
        addr,
        size,
        kind: AccessKind::Write,
    }
}

/// Validates every access of one instruction, in order, before it mutates
/// anything. A user access that is not permitted (or is the injected one)
/// faults; a runtime access outside runtime-owned memory is a PAN violation,
/// which is a hard error because in the kernel it is an oops. `unprivileged`:
/// the instruction is `LDTR`/`STTR`.
pub(crate) fn check_accesses(
    ctx: &mut AccessContext<'_>,
    state: &MachineState,
    pc: u64,
    accesses: &[MemAccess],
    unprivileged: bool,
) -> Result<(), InsnError> {
    for &access in accesses {
        let (privilege, counter, log) = match ctx {
            AccessContext::Original { counter, log } => {
                (Privilege::User, counter.as_deref_mut(), log.as_deref_mut())
            }
            AccessContext::Fragment {
                runtime_ranges,
                counter,
                log,
                ..
            } => {
                if !unprivileged && !access_in_ranges(runtime_ranges, access) {
                    return Err(InsnError::Error(format!(
                        "PAN violation: runtime access at pc={pc:#x} to {:#x} (size {}) \
                         is outside runtime-owned memory",
                        access.addr, access.size
                    )));
                }
                let privilege = if unprivileged {
                    Privilege::User
                } else {
                    Privilege::Runtime
                };
                (privilege, Some(&mut **counter), log.as_deref_mut())
            }
        };
        if let Some(log) = log {
            log.push(LoggedAccess {
                pc,
                access,
                privilege,
            });
        }
        if privilege == Privilege::Runtime {
            continue;
        }
        let injected = counter.is_some_and(|counter| counter.record());
        if injected || !state.user_access_allowed(access) {
            return Err(InsnError::Fault(MemFault {
                pc,
                access,
                cause: FaultCause::Permission,
            }));
        }
    }
    Ok(())
}

/// Whether `access` lies entirely inside one of `ranges` (`[start, end)`).
pub(crate) fn access_in_ranges(ranges: &[(u64, u64)], access: MemAccess) -> bool {
    let Some(end) = access.addr.checked_add(access.size as u64) else {
        return false;
    };
    ranges
        .iter()
        .any(|&(start, range_end)| start <= access.addr && end <= range_end)
}

/// The access address and, for pre/post-index forms, the base register's new
/// value. Pure: writeback is applied by the caller after the access checks.
/// Top-byte-ignore for data (Linux sets TCR_EL1.TBI0): bits 63:56 of a user data
/// address take no part in translation when bit 55 is clear. With bit 55 set the
/// address is in the kernel half and faults at EL0 whatever its top byte. This is
/// Linux's `untagged_addr` (`addr & sign_extend64(addr, 55)`), which is also the
/// fault address it reports. The same holds for a fragment's LDTR/STTR, which
/// translate through the EL0 regime. A base writeback keeps the tag: only the
/// access address is untagged.
pub(crate) fn untagged(address: u64) -> u64 {
    address & ((((address << 8) as i64) >> 8) as u64)
}

fn mem_addressing(state: &MachineState, mem: A64Mem) -> (u64, Option<u64>) {
    let base = state.read_reg(mem.base());
    let offset = mem.offset_imm().value();

    match mem {
        A64Mem::Offset { .. } => (add_signed(base, offset), None),
        A64Mem::PreIndex { .. } => {
            let addr = add_signed(base, offset);
            (addr, Some(addr))
        }
        A64Mem::PostIndex { .. } => (base, Some(add_signed(base, offset))),
    }
}

fn branch_on_zero(
    insn: A64Insn,
    pc: u64,
    state: &MachineState,
    rt: A64Reg,
    bits: u8,
    branch_if_zero: bool,
) -> Result<u64, InsnError> {
    let (taken, fallthrough) = insn
        .conditional_targets(pc)
        .ok_or_else(|| format!("missing conditional target for {}", insn.key()))?;
    let is_zero = read_reg_sized(state, rt, bits) == 0;
    Ok(if is_zero == branch_if_zero {
        taken
    } else {
        fallthrough
    })
}

fn branch_on_bit(
    insn: A64Insn,
    pc: u64,
    state: &MachineState,
    rt: A64Reg,
    bit: u8,
    branch_if_set: bool,
) -> Result<u64, InsnError> {
    let (taken, fallthrough) = insn
        .conditional_targets(pc)
        .ok_or_else(|| format!("missing conditional target for {}", insn.key()))?;
    let is_set = ((state.read_reg(rt) >> bit) & 1) != 0;
    Ok(if is_set == branch_if_set {
        taken
    } else {
        fallthrough
    })
}

fn bit_index(b5: u8, b40: u8) -> u8 {
    (b5 << 5) | b40
}

/// `ConditionHolds` from the Arm pseudocode.
fn eval_condition(condition: A64Condition, state: &MachineState) -> bool {
    let Flags { n, z, c, v } = state.flags;
    match condition {
        A64Condition::Eq => z,
        A64Condition::Ne => !z,
        A64Condition::Hs => c,
        A64Condition::Lo => !c,
        A64Condition::Mi => n,
        A64Condition::Pl => !n,
        A64Condition::Vs => v,
        A64Condition::Vc => !v,
        A64Condition::Hi => c && !z,
        A64Condition::Ls => !(c && !z),
        A64Condition::Ge => n == v,
        A64Condition::Lt => n != v,
        A64Condition::Gt => n == v && !z,
        A64Condition::Le => !(n == v && !z),
        A64Condition::Al | A64Condition::Nv => true,
    }
}

fn read_reg_sized(state: &MachineState, reg: A64Reg, bits: u8) -> u64 {
    match bits {
        32 => state.read_reg(reg) & 0xFFFF_FFFF,
        64 => state.read_reg(reg),
        _ => unreachable!("unsupported register width"),
    }
}

fn write_reg_sized(state: &mut MachineState, reg: A64Reg, value: u64, bits: u8) {
    match bits {
        32 => state.write_reg(reg, value & 0xFFFF_FFFF),
        64 => state.write_reg(reg, value),
        _ => unreachable!("unsupported register width"),
    }
}

fn add_signed(value: u64, offset: i64) -> u64 {
    value.wrapping_add_signed(offset)
}

fn pc_relative_target(pc: u64, encoded: u32, bits: u8) -> u64 {
    pc.wrapping_add_signed(sign_extend(encoded, bits) << 2)
}

fn sign_extend(value: u32, bits: u8) -> i64 {
    let shift = 64 - bits as u32;
    ((value as i64) << shift) >> shift
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::PagePerm;
    use crate::shared::arm64::ergo::{scaled_simm, uimm, x};

    fn exec_user(insn: A64Insn, pc: u64, state: &mut MachineState) -> Result<u64, InsnError> {
        execute_insn(
            insn,
            pc,
            state,
            &mut AccessContext::Original {
                counter: None,
                log: None,
            },
        )
    }

    /// Runs `insn` alone at 0x4000 from `state` and returns its fault.
    /// Asserts the faulting instruction left the state bit-identical.
    fn expect_fault(insn: A64Insn, state: &MachineState, stepper_fail_at: Option<u64>) -> MemFault {
        let program = encode_insns(&[insn]);
        let mut stepper = OriginalStepper::new(&program, 0x4000, 0x4000, state).unwrap();
        if let Some(k) = stepper_fail_at {
            stepper = stepper.fail_user_access(k);
        }
        let step = stepper.step().unwrap().unwrap();
        assert!(!step.executed);
        assert_eq!(step.next_pc, None);
        assert_eq!(&step.state, state, "faulting instruction mutated state");
        match step.halt_reason {
            Some(HaltReason::Fault(fault)) => {
                assert_eq!(fault.pc, 0x4000);
                fault
            }
            other => panic!("expected a fault halt, got {other:?}"),
        }
    }

    fn rw_page_at_0x9000() -> MachineState {
        let mut state = MachineState::new();
        state
            .map_user_range(0x9000, 0xa000, PagePerm::ReadWrite)
            .unwrap();
        state
    }

    fn pair_imm(value: i64) -> A64Imm {
        A64Imm::scaled_signed(signed_field(value, 7) as u32, 7, 3)
    }

    #[test]
    fn map_user_range_rejects_misaligned_or_empty_ranges() {
        let mut state = MachineState::new();
        assert!(state
            .map_user_range(0x9001, 0xa000, PagePerm::ReadWrite)
            .is_err());
        assert!(state
            .map_user_range(0x9000, 0x9fff, PagePerm::ReadWrite)
            .is_err());
        assert!(state
            .map_user_range(0x9000, 0x9000, PagePerm::ReadWrite)
            .is_err());
        assert_eq!(state, MachineState::new());
    }

    #[test]
    fn load_from_unmapped_page_faults() {
        let mut state = rw_page_at_0x9000();
        state.write_x(1, 0xa000);
        state.write_x(0, 0x55);

        let fault = expect_fault(
            A64Insn::LdrImmGenLdr64LdstPos {
                rt: x(0),
                mem: A64Mem::offset(A64Reg::x_sp(1), A64Imm::scaled_unsigned(0, 12, 3)),
            },
            &state,
            None,
        );
        assert_eq!(
            fault.access,
            MemAccess {
                addr: 0xa000,
                size: 8,
                kind: AccessKind::Read
            }
        );
    }

    #[test]
    fn store_to_read_only_page_faults_and_leaves_memory() {
        let mut state = MachineState::new();
        state
            .map_user_range(0x9000, 0xa000, PagePerm::ReadOnly)
            .unwrap();
        state.seed_memory_u64(0x9000, 0x1122);
        state.write_x(0, 0x3344);
        state.write_x(1, 0x9000);

        // Post-index: neither the byte store nor the base writeback may land.
        let fault = expect_fault(
            A64Insn::StrImmGenStr64LdstImmpost {
                rt: x(0),
                mem: A64Mem::post_index(A64Reg::x_sp(1), A64Imm::signed(8, 9)),
            },
            &state,
            None,
        );
        assert_eq!(fault.access.kind, AccessKind::Write);
        assert_eq!(fault.access.addr, 0x9000);

        // Reads of a read-only page are fine.
        let mut loaded = state.clone();
        exec_user(
            A64Insn::LdrImmGenLdr64LdstPos {
                rt: x(2),
                mem: A64Mem::offset(A64Reg::x_sp(1), A64Imm::scaled_unsigned(0, 12, 3)),
            },
            0x4000,
            &mut loaded,
        )
        .unwrap();
        assert_eq!(loaded.read_x(2), 0x1122);
    }

    #[test]
    fn page_straddling_store_faults_on_unmapped_second_page_and_writes_nothing() {
        let mut state = rw_page_at_0x9000();
        state.write_x(0, u64::MAX);
        state.write_x(1, 0x9ffc);

        let fault = expect_fault(
            A64Insn::StrImmGenStr64LdstPos {
                rt: x(0),
                mem: A64Mem::offset(A64Reg::x_sp(1), A64Imm::scaled_unsigned(0, 12, 3)),
            },
            &state,
            None,
        );
        assert_eq!(fault.access.addr, 0x9ffc);
        assert_eq!(fault.access.size, 8);
    }

    #[test]
    fn faulting_ldp_stp_and_writeback_leave_base_and_destinations_unchanged() {
        let mut state = rw_page_at_0x9000();
        state.write_x(0, 0xaaaa);
        state.write_x(1, 0xbbbb);
        state.write_x(3, 0xcccc);
        state.seed_memory_u64(0x9ff8, 0x1234);

        // LDP post-index: first access is mapped, second (0xa000) is not.
        state.write_x(2, 0x9ff8);
        let fault = expect_fault(
            A64Insn::LdpGenLdp64LdstpairPost {
                rt2: x(1),
                rt: x(0),
                mem: A64Mem::post_index(A64Reg::x_sp(2), pair_imm(2)),
            },
            &state,
            None,
        );
        assert_eq!(fault.access.addr, 0xa000);

        // STP pre-index: 0x9ff8 would be writable, 0xa000 is not; nothing lands.
        state.write_x(2, 0xa008);
        let fault = expect_fault(
            A64Insn::StpGenStp64LdstpairPre {
                rt2: x(1),
                rt: x(0),
                mem: A64Mem::pre_index(A64Reg::x_sp(2), pair_imm(-2)),
            },
            &state,
            None,
        );
        assert_eq!(fault.access.addr, 0xa000);
        assert_eq!(fault.access.kind, AccessKind::Write);

        // LDR pre-index into an unmapped page.
        state.write_x(2, 0x9ff8);
        expect_fault(
            A64Insn::LdrImmGenLdr64LdstImmpre {
                rt: x(3),
                mem: A64Mem::pre_index(A64Reg::x_sp(2), A64Imm::signed(8, 9)),
            },
            &state,
            None,
        );
    }

    #[test]
    fn injected_fault_on_second_ldp_access_faults_whole_instruction() {
        let mut state = rw_page_at_0x9000();
        state.write_x(2, 0x9000);
        state.seed_memory_u64(0x9000, 0x11);
        state.seed_memory_u64(0x9008, 0x22);
        let ldp = A64Insn::LdpGenLdp64LdstpairPre {
            rt2: x(1),
            rt: x(0),
            mem: A64Mem::pre_index(A64Reg::x_sp(2), pair_imm(0)),
        };

        let fault = expect_fault(ldp, &state, Some(2));
        assert_eq!(
            fault.access,
            MemAccess {
                addr: 0x9008,
                size: 8,
                kind: AccessKind::Read
            }
        );
        assert_eq!(expect_fault(ldp, &state, Some(1)).access.addr, 0x9000);

        // Uninjected, the same instruction retires and counts two accesses.
        let program = encode_insns(&[ldp]);
        let mut stepper = OriginalStepper::new(&program, 0x4000, 0x4000, &state).unwrap();
        let step = stepper.step().unwrap().unwrap();
        assert_eq!(step.halt_reason, None);
        assert_eq!(step.state.read_x(0), 0x11);
        assert_eq!(step.state.read_x(1), 0x22);
        assert_eq!(stepper.user_accesses(), 2);
    }

    fn exec_fragment(
        insn: A64Insn,
        state: &mut MachineState,
        counter: &mut UserAccessCounter,
    ) -> Result<u64, InsnError> {
        execute_insn(
            insn,
            0x4000,
            state,
            &mut AccessContext::Fragment {
                runtime_ranges: &[(0x7000, 0x8000)],
                counter,
                log: None,
                pan: &mut true,
            },
        )
    }

    fn simm9(value: i32) -> A64Imm {
        A64Imm::signed(value as u32 & 0x1FF, 9)
    }

    #[test]
    fn ldtr_sttr_use_unscaled_simm9_and_zero_extend_32_bit_loads() {
        let mut state = rw_page_at_0x9000();
        state.write_x(1, 0x9010);
        state.write_x(2, 0xffff_ffff_8765_4321);
        let mut counter = UserAccessCounter::default();

        // STTR w2, [x1, #-3]: 4 bytes at 0x900d.
        exec_fragment(
            A64Insn::SttrSttr32LdstUnpriv {
                rt: A64Reg::w(2),
                mem: A64Mem::offset(A64Reg::x_sp(1), simm9(-3)),
            },
            &mut state,
            &mut counter,
        )
        .unwrap();
        assert_eq!(state.read_le(0x900d, 4), 0x8765_4321);
        assert_eq!(state.read_le(0x9011, 1), 0);

        // LDTR w3 zero-extends; LDTR x4 reads 8 bytes; STTR x keeps writeback-free base.
        state.write_x(3, u64::MAX);
        exec_fragment(
            A64Insn::LdtrLdtr32LdstUnpriv {
                rt: A64Reg::w(3),
                mem: A64Mem::offset(A64Reg::x_sp(1), simm9(-3)),
            },
            &mut state,
            &mut counter,
        )
        .unwrap();
        assert_eq!(state.read_x(3), 0x8765_4321);
        exec_fragment(
            A64Insn::SttrSttr64LdstUnpriv {
                rt: x(2),
                mem: A64Mem::offset(A64Reg::x_sp(1), simm9(255)),
            },
            &mut state,
            &mut counter,
        )
        .unwrap();
        exec_fragment(
            A64Insn::LdtrLdtr64LdstUnpriv {
                rt: x(4),
                mem: A64Mem::offset(A64Reg::x_sp(1), simm9(255)),
            },
            &mut state,
            &mut counter,
        )
        .unwrap();
        assert_eq!(state.read_x(4), 0xffff_ffff_8765_4321);
        assert_eq!(state.read_x(1), 0x9010);
        assert_eq!(counter.seen(), 4);
    }

    #[test]
    fn fragment_ldtr_is_a_user_access_and_plain_ldr_a_runtime_access() {
        let mut state = rw_page_at_0x9000();
        state.write_x(1, 0xa000); // unmapped user page
        let ldtr = A64Insn::LdtrLdtr64LdstUnpriv {
            rt: x(0),
            mem: A64Mem::offset(A64Reg::x_sp(1), A64Imm::signed(0, 9)),
        };
        let mut counter = UserAccessCounter::default();
        let before = state.clone();
        match exec_fragment(ldtr, &mut state, &mut counter) {
            Err(InsnError::Fault(fault)) => assert_eq!(fault.access.addr, 0xa000),
            other => panic!("expected a user fault, got {other:?}"),
        }
        assert_eq!(state, before);

        // Injection counts only LDTR/STTR.
        state.write_x(1, 0x9000);
        let mut counter = UserAccessCounter::failing_at(1);
        assert!(matches!(
            exec_fragment(ldtr, &mut state, &mut counter),
            Err(InsnError::Fault(_))
        ));

        // A plain LDR of the same, readable, user page is a PAN violation.
        let ldr = A64Insn::LdrImmGenLdr64LdstPos {
            rt: x(0),
            mem: A64Mem::offset(A64Reg::x_sp(1), A64Imm::scaled_unsigned(0, 12, 3)),
        };
        match exec_fragment(ldr, &mut state, &mut UserAccessCounter::default()) {
            Err(InsnError::Error(message)) => assert!(message.contains("PAN violation")),
            other => panic!("expected a PAN violation, got {other:?}"),
        }
        // ...and inside runtime memory it is fine and not a user access.
        state.write_x(1, 0x7000);
        let mut counter = UserAccessCounter::failing_at(1);
        exec_fragment(ldr, &mut state, &mut counter).unwrap();
        assert_eq!(counter.seen(), 0);
    }

    #[test]
    fn user_ldtr_in_original_code_is_an_unsupported_exit() {
        let ldtr = A64Insn::LdtrLdtr64LdstUnpriv {
            rt: x(0),
            mem: A64Mem::offset(A64Reg::x_sp(1), A64Imm::signed(0, 9)),
        };
        let program = encode_insns(&[ldtr]);
        let state = rw_page_at_0x9000();
        let mut stepper = OriginalStepper::new(&program, 0x4000, 0x4000, &state).unwrap();
        let step = stepper.step().unwrap().unwrap();
        assert_eq!(
            step.halt_reason,
            Some(HaltReason::RuntimeExit {
                reason: RuntimeExitReason::Unsupported {
                    pc: 0x4000,
                    word: Some(ldtr.encode().unwrap()),
                }
            })
        );
    }

    fn encode_insns(insns: &[A64Insn]) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(insns.len() * 4);
        for insn in insns {
            bytes.extend_from_slice(&insn.encode().unwrap().to_le_bytes());
        }
        bytes
    }

    #[test]
    fn original_stepper_advances_one_arithmetic_instruction() {
        let program = encode_insns(&[A64Insn::MovzMovz64Movewide {
            hw: 0,
            imm16: uimm(7, 16),
            rd: x(0),
        }]);
        let state = MachineState::new();
        let mut stepper = OriginalStepper::new(&program, 0x4000, 0x4000, &state).unwrap();

        let step = stepper.step().unwrap().unwrap();

        assert_eq!(step.pc, 0x4000);
        assert_eq!(step.next_pc, Some(0x4004));
        assert_eq!(step.runtime_exit, None);
        assert_eq!(step.halt_reason, None);
        assert_eq!(step.state.read_x(0), 7);
        assert_eq!(stepper.pc(), 0x4004);
    }

    #[test]
    fn original_stepper_direct_branch_updates_pc() {
        let program = encode_insns(&[
            A64Insn::BUncondBOnlyBranchImm {
                imm26: scaled_simm(2, 26, 2),
            },
            A64Insn::MovzMovz64Movewide {
                hw: 0,
                imm16: uimm(1, 16),
                rd: x(0),
            },
            A64Insn::MovzMovz64Movewide {
                hw: 0,
                imm16: uimm(2, 16),
                rd: x(0),
            },
        ]);
        let state = MachineState::new();
        let mut stepper = OriginalStepper::new(&program, 0x4000, 0x4000, &state).unwrap();

        let branch = stepper.step().unwrap().unwrap();
        let target = stepper.step().unwrap().unwrap();

        assert_eq!(branch.next_pc, Some(0x4008));
        assert_eq!(target.pc, 0x4008);
        assert_eq!(target.state.read_x(0), 2);
    }

    #[test]
    fn original_stepper_svc_can_resume_at_resume_pc() {
        let program = encode_insns(&[
            A64Insn::SvcSvcExException {
                imm16: A64Imm::unsigned(0, 16),
            },
            A64Insn::MovzMovz64Movewide {
                hw: 0,
                imm16: uimm(7, 16),
                rd: x(0),
            },
        ]);
        let state = MachineState::new();
        let mut stepper = OriginalStepper::new(&program, 0x4000, 0x4000, &state).unwrap();

        let svc = stepper.step().unwrap().unwrap();
        assert_eq!(
            svc.runtime_exit,
            Some(RuntimeExitReason::Svc {
                imm16: 0,
                resume_pc: 0x4004
            })
        );

        stepper.resume_at(0x4004);
        let resumed = stepper.step().unwrap().unwrap();
        assert_eq!(resumed.pc, 0x4004);
        assert_eq!(resumed.state.read_x(0), 7);
    }

    #[test]
    fn original_stepper_ret_and_br_halt_with_runtime_exit_reasons() {
        let ret_program = encode_insns(&[A64Insn::RetRet64rBranchReg { rn: x(30) }]);
        let mut ret_state = MachineState::new();
        ret_state.write_x(30, 0x9000);
        let mut ret_stepper =
            OriginalStepper::new(&ret_program, 0x4000, 0x4000, &ret_state).unwrap();
        let ret = ret_stepper.step().unwrap().unwrap();
        assert_eq!(
            ret.halt_reason,
            Some(HaltReason::RuntimeExit {
                reason: RuntimeExitReason::Ret { lr_reg: 30 }
            })
        );

        let br_program = encode_insns(&[A64Insn::BrBr64BranchReg { rn: x(5) }]);
        let mut br_state = MachineState::new();
        br_state.write_x(5, 0x8000);
        let mut br_stepper = OriginalStepper::new(&br_program, 0x5000, 0x5000, &br_state).unwrap();
        let br = br_stepper.step().unwrap().unwrap();
        assert_eq!(
            br.halt_reason,
            Some(HaltReason::RuntimeExit {
                reason: RuntimeExitReason::Br { target_reg: 5 }
            })
        );
    }

    #[test]
    fn original_stepper_blr_updates_lr_before_runtime_exit() {
        let program = encode_insns(&[A64Insn::BlrBlr64BranchReg { rn: x(10) }]);
        let mut state = MachineState::new();
        state.write_x(10, 0x9000);
        state.write_x(30, 0x7777);
        let mut stepper = OriginalStepper::new(&program, 0x4000, 0x4000, &state).unwrap();

        let blr = stepper.step().unwrap().unwrap();

        assert_eq!(
            blr.halt_reason,
            Some(HaltReason::RuntimeExit {
                reason: RuntimeExitReason::Blr {
                    target_reg: 10,
                    resume_pc: 0x4004,
                }
            })
        );
        assert_eq!(blr.state.read_x(10), 0x9000);
        assert_eq!(blr.state.read_x(30), 0x4004);
    }

    #[test]
    fn execute_blr_x30_branches_to_old_lr_and_then_updates_lr() {
        let mut state = MachineState::new();
        state.write_x(30, 0x9000);

        let next_pc =
            exec_user(A64Insn::BlrBlr64BranchReg { rn: x(30) }, 0x4000, &mut state).unwrap();

        assert_eq!(next_pc, 0x9000);
        assert_eq!(state.read_x(30), 0x4004);
    }

    #[test]
    fn add_sub_immediate_distinguishes_sp_from_xzr() {
        let mut state = MachineState::new();
        state.set_sp(0x1000);

        exec_user(
            A64Insn::AddAddsubImmAdd64AddsubImm {
                sh: 0,
                imm12: A64Imm::unsigned(0x20, 12),
                rn: A64Reg::x_sp(31),
                rd: A64Reg::x_sp(0),
            },
            0x4000,
            &mut state,
        )
        .unwrap();
        assert_eq!(state.read_x(0), 0x1020);
        assert_eq!(state.read_x(31), 0);
        assert_eq!(state.read_reg(A64Reg::x_sp(31)), 0x1000);

        exec_user(
            A64Insn::SubAddsubImmSub64AddsubImm {
                sh: 0,
                imm12: A64Imm::unsigned(0x10, 12),
                rn: A64Reg::x_sp(31),
                rd: A64Reg::x_sp(31),
            },
            0x4004,
            &mut state,
        )
        .unwrap();
        assert_eq!(state.sp(), 0x0ff0);
        assert_eq!(state.read_x(31), 0);
    }

    /// Top-byte-ignore: a tagged pointer into a mapped page accesses that page,
    /// the base keeps its tag on writeback, and a fault reports the untagged
    /// address.
    #[test]
    fn data_accesses_ignore_the_top_byte() {
        let mut state = rw_page_at_0x9000();
        state.seed_memory_u64(0x9008, 0x55);
        state.write_x(1, 0xab00_0000_0000_9000);
        exec_user(
            A64Insn::LdrImmGenLdr64LdstImmpre {
                rt: x(0),
                mem: A64Mem::pre_index(A64Reg::x_sp(1), A64Imm::signed(8, 9)),
            },
            0x4000,
            &mut state,
        )
        .unwrap();
        assert_eq!(state.read_x(0), 0x55);
        assert_eq!(state.read_x(1), 0xab00_0000_0000_9008);

        state.write_x(1, 0xab00_0000_0000_a000);
        let fault = expect_fault(
            A64Insn::LdrImmGenLdr64LdstPos {
                rt: x(0),
                mem: A64Mem::offset(A64Reg::x_sp(1), A64Imm::scaled_unsigned(0, 12, 3)),
            },
            &state,
            None,
        );
        assert_eq!(fault.access.addr, 0xa000);
    }

    /// EL0 SP alignment checking: an SP-based access faults when SP is not
    /// 16-byte aligned, even though the page is mapped; a non-SP base does not.
    #[test]
    fn sp_based_access_with_misaligned_sp_faults() {
        let mut state = rw_page_at_0x9000();
        state.set_sp(0x9008);
        state.write_x(1, 0x9008);
        let ldr = |base: A64Reg| A64Insn::LdrImmGenLdr64LdstPos {
            rt: x(0),
            mem: A64Mem::offset(base, A64Imm::scaled_unsigned(1, 12, 3)),
        };

        let fault = expect_fault(ldr(A64Reg::x_sp(31)), &state, None);
        assert_eq!(fault.cause, FaultCause::SpAlignment);
        assert_eq!(fault.access.addr, 0x9010);

        exec_user(ldr(A64Reg::x_sp(1)), 0x4000, &mut state).unwrap();
        state.set_sp(0x9010);
        exec_user(ldr(A64Reg::x_sp(31)), 0x4000, &mut state).unwrap();
    }

    /// A7c: an acquire/release access faults (Alignment) iff it crosses a 16-byte
    /// boundary; misaligned inside one block it runs (as on the FEAT_LSE2 host,
    /// probed natively: `ldar x` at +8 runs, at +9 faults). SP alignment first.
    /// A8: every LSE operation on its size, the destination (Rt, or Rs for CAS)
    /// receiving the zero-extended old value.
    #[test]
    fn lse_atomics_compute_every_operation() {
        use A64Insn as I;
        let (xs, w) = (A64Reg::x_sp, A64Reg::w);
        // (insn, memory before, Rs, Rt, memory after, destination after)
        let cases: [(A64Insn, u64, u64, u64, u64, u64); 14] = [
            (
                I::LdaddLdadd64Memop {
                    rs: x(1),
                    rn: xs(3),
                    rt: x(2),
                },
                5,
                7,
                0,
                12,
                5,
            ),
            (
                I::LdclrLdclral64Memop {
                    rs: x(1),
                    rn: xs(3),
                    rt: x(2),
                },
                0xff,
                0x0f,
                0,
                0xf0,
                0xff,
            ),
            (
                I::LdeorLdeor32Memop {
                    rs: w(1),
                    rn: xs(3),
                    rt: w(2),
                },
                0xff,
                0x0f,
                0,
                0xf0,
                0xff,
            ),
            (
                I::LdsetLdsetl64Memop {
                    rs: x(1),
                    rn: xs(3),
                    rt: x(2),
                },
                0xf0,
                0x0f,
                0,
                0xff,
                0xf0,
            ),
            // Signed byte: 0x80 = -128 < 1.
            (
                I::LdsmaxbLdsmaxb32Memop {
                    rs: w(1),
                    rn: xs(3),
                    rt: w(2),
                },
                0x80,
                1,
                0,
                1,
                0x80,
            ),
            (
                I::LdsminhLdsminh32Memop {
                    rs: w(1),
                    rn: xs(3),
                    rt: w(2),
                },
                1,
                0x8000,
                0,
                0x8000,
                1,
            ),
            (
                I::LdumaxLdumax32Memop {
                    rs: w(1),
                    rn: xs(3),
                    rt: w(2),
                },
                0x8000_0000,
                1,
                0,
                0x8000_0000,
                0x8000_0000,
            ),
            (
                I::LduminLdumina64Memop {
                    rs: x(1),
                    rn: xs(3),
                    rt: x(2),
                },
                u64::MAX,
                3,
                0,
                3,
                u64::MAX,
            ),
            // 32-bit add wraps inside the word; the upper memory word is untouched.
            (
                I::LdaddLdadd32Memop {
                    rs: w(1),
                    rn: xs(3),
                    rt: w(2),
                },
                0x1_ffff_ffff,
                1,
                0,
                0x1_0000_0000,
                0xffff_ffff,
            ),
            (
                I::SwpSwpal64Memop {
                    rs: x(1),
                    rn: xs(3),
                    rt: x(2),
                },
                9,
                4,
                0,
                4,
                9,
            ),
            // CAS success: memory == Rs, store Rt; Rs = old.
            (
                I::CasCasalC64Comswap {
                    rs: x(1),
                    rn: xs(3),
                    rt: x(2),
                },
                6,
                6,
                8,
                8,
                6,
            ),
            // CAS failure: no store; Rs = old.
            (
                I::CasCasalC64Comswap {
                    rs: x(1),
                    rn: xs(3),
                    rt: x(2),
                },
                6,
                5,
                8,
                6,
                6,
            ),
            (
                I::CasbCasabC32Comswap {
                    rs: w(1),
                    rn: xs(3),
                    rt: w(2),
                },
                0x1ab,
                0xab,
                0xcd,
                0x1cd,
                0xab,
            ),
            // ST<op>: Rt = XZR discards the old value.
            (
                I::LdaddLdadd64Memop {
                    rs: x(1),
                    rn: xs(3),
                    rt: x(31),
                },
                5,
                7,
                0,
                12,
                0,
            ),
        ];
        for (insn, before, rs, rt, after, dest) in cases {
            let mut state = rw_page_at_0x9000();
            state.write_x(3, 0x9008);
            state.write_u64(0x9008, before);
            state.write_x(1, rs);
            state.write_x(2, rt);
            assert_eq!(exec_user(insn, 0x4000, &mut state), Ok(0x4004), "{insn:?}");
            assert_eq!(state.read_u64(0x9008), after, "{insn:?} memory");
            let dest_reg = if insn.lse_atomic().unwrap().op == A64AtomicOp::Cas {
                1
            } else {
                2
            };
            assert_eq!(state.read_x(dest_reg), dest, "{insn:?} destination");
        }
    }

    /// A8: an atomic needs write permission (a failing CAS too), crosses no
    /// 16-byte boundary, and with an SP base needs SP 16-byte aligned; every fault
    /// leaves the state untouched.
    #[test]
    fn lse_atomic_faults_are_precise() {
        let mut state = rw_page_at_0x9000();
        state
            .map_user_range(0xa000, 0xb000, PagePerm::ReadOnly)
            .unwrap();
        state.write_x(1, 0x5);
        state.write_x(2, 0x7);
        let cas = |rn| A64Insn::CasCasalC64Comswap {
            rs: x(1),
            rn: A64Reg::x_sp(rn),
            rt: x(2),
        };
        state.write_x(3, 0xa000);
        assert_eq!(
            expect_fault(cas(3), &state, None).cause,
            FaultCause::Permission
        );
        state.write_x(3, 0xb000);
        assert_eq!(
            expect_fault(cas(3), &state, None).cause,
            FaultCause::Permission
        );
        state.write_x(3, 0x900c);
        assert_eq!(
            expect_fault(cas(3), &state, None).cause,
            FaultCause::Alignment
        );
        state.write_x(3, 0x9004);
        assert!(exec_user(cas(3), 0x4000, &mut state.clone()).is_ok());
        state.set_sp(0x9008);
        assert_eq!(
            expect_fault(cas(31), &state, None).cause,
            FaultCause::SpAlignment
        );
        state.set_sp(0x9010);
        assert_eq!(
            expect_fault(cas(31), &state, Some(1)).cause,
            FaultCause::Permission
        );
    }

    /// A8: in a fragment an atomic is a privileged access: a PAN violation (hard
    /// error) while PSTATE.PAN is set, and never on runtime memory or beyond the
    /// user VA range; with PAN clear it is logged as a window access and faults on
    /// the user page permissions. `msr pan` sets the modelled PSTATE.PAN.
    #[test]
    fn window_atomic_requires_pan_clear_and_user_memory() {
        let run = |insn: A64Insn, state: &mut MachineState, pan: &mut bool| {
            let mut counter = UserAccessCounter::default();
            let mut log = Vec::new();
            let result = execute_insn(
                insn,
                0x4000,
                state,
                &mut AccessContext::Fragment {
                    runtime_ranges: &[(0x7000, 0x8000)],
                    counter: &mut counter,
                    log: Some(&mut log),
                    pan,
                },
            );
            (result, log)
        };
        let ldadd = A64Insn::LdaddLdadd64Memop {
            rs: x(1),
            rn: A64Reg::x_sp(3),
            rt: x(2),
        };
        let mut state = rw_page_at_0x9000();
        state.write_x(1, 1);
        state.write_x(3, 0x9000);

        let mut pan = true;
        let (result, _) = run(ldadd, &mut state, &mut pan);
        assert!(
            matches!(&result, Err(InsnError::Error(message)) if message.contains("PAN violation")),
            "{result:?}"
        );
        let (result, _) = run(A64Insn::MsrImmMsrSiPstate { crm: 0 }, &mut state, &mut pan);
        assert_eq!((result, pan), (Ok(0x4004), false));
        let (result, log) = run(ldadd, &mut state, &mut pan);
        assert_eq!(result, Ok(0x4004));
        assert_eq!(log[0].privilege, Privilege::Window);
        assert_eq!(state.read_u64(0x9000), 1);
        for address in [0x7008, 0x1_0000_0000_9000, 0xffff_8000_0000_9000] {
            state.write_x(3, address);
            let (result, _) = run(ldadd, &mut state, &mut pan);
            assert!(
                matches!(result, Err(InsnError::Error(_))),
                "{address:#x}: {result:?}"
            );
        }
        state.write_x(3, 0xa000);
        let (result, _) = run(ldadd, &mut state, &mut pan);
        assert!(matches!(result, Err(InsnError::Fault(_))), "{result:?}");
        let (result, _) = run(A64Insn::MsrImmMsrSiPstate { crm: 1 }, &mut state, &mut pan);
        assert_eq!((result, pan), (Ok(0x4004), true));
        // Original code never executes `msr pan` (admission rejects it).
        assert!(exec_user(A64Insn::MsrImmMsrSiPstate { crm: 1 }, 0x4000, &mut state).is_err());
    }

    #[test]
    fn acquire_release_alignment_faults_only_across_16_byte_blocks() {
        let mut state = rw_page_at_0x9000();
        let ldar_x = A64Insn::LdarLdarLr64Ldstord {
            rn: A64Reg::x_sp(1),
            rt: x(0),
        };
        let stlr_w = A64Insn::StlrStlrSl32Ldstord {
            rn: A64Reg::x_sp(1),
            rt: A64Reg::w(2),
        };
        let ldaprh = A64Insn::LdaprhLdaprh32lMemop {
            rn: A64Reg::x_sp(1),
            rt: A64Reg::w(0),
        };
        let ldarb = A64Insn::LdarbLdarbLr32Ldstord {
            rn: A64Reg::x_sp(1),
            rt: A64Reg::w(0),
        };
        for (insn, size) in [(ldar_x, 8u64), (stlr_w, 4), (ldaprh, 2), (ldarb, 1)] {
            for offset in 0..16u64 {
                state.write_x(1, 0x9020 + offset);
                if offset + size > 16 {
                    let fault = expect_fault(insn, &state, None);
                    assert_eq!(fault.cause, FaultCause::Alignment, "{insn:?} +{offset}");
                    assert_eq!(fault.access.addr, 0x9020 + offset);
                } else {
                    exec_user(insn, 0x4000, &mut state)
                        .unwrap_or_else(|err| panic!("{insn:?} +{offset}: {err:?}"));
                }
            }
        }
        // A tagged base is aligned on its untagged address.
        state.write_x(1, 0x5a00_0000_0000_9028);
        exec_user(ldar_x, 0x4000, &mut state).unwrap();

        // SP base: the SP alignment check comes first.
        state.set_sp(0x9008);
        let ldar_sp = A64Insn::LdarLdarLr64Ldstord {
            rn: A64Reg::x_sp(31),
            rt: x(0),
        };
        assert_eq!(
            expect_fault(ldar_sp, &state, None).cause,
            FaultCause::SpAlignment
        );
    }

    #[test]
    fn barriers_are_no_ops_and_acquire_release_move_data() {
        let mut state = rw_page_at_0x9000();
        state.write_x(1, 0x9040);
        state.write_x(2, 0x1122_3344_5566_7788);
        let before = state.clone();
        for crm in 0..16 {
            for barrier in [
                A64Insn::DmbDmbBoBarriers { crm },
                A64Insn::DsbDsbBoBarriers { crm },
                A64Insn::IsbIsbBiBarriers { crm },
            ] {
                assert_eq!(exec_user(barrier, 0x4000, &mut state).unwrap(), 0x4004);
            }
        }
        assert_eq!(state, before);

        let rn = A64Reg::x_sp(1);
        exec_user(A64Insn::StlrStlrSl64Ldstord { rn, rt: x(2) }, 0x4000, &mut state).unwrap();
        exec_user(
            A64Insn::LdarhLdarhLr32Ldstord {
                rn,
                rt: A64Reg::w(3),
            },
            0x4000,
            &mut state,
        )
        .unwrap();
        assert_eq!(state.read_x(3), 0x7788);
        exec_user(
            A64Insn::StlrbStlrbSl32Ldstord {
                rn,
                rt: A64Reg::w(31),
            },
            0x4000,
            &mut state,
        )
        .unwrap();
        exec_user(
            A64Insn::LdaprLdapr64lMemop { rn, rt: x(4) },
            0x4000,
            &mut state,
        )
        .unwrap();
        assert_eq!(state.read_x(4), 0x1122_3344_5566_7700);
        exec_user(
            A64Insn::LdarLdarLr32Ldstord {
                rn,
                rt: A64Reg::w(5),
            },
            0x4000,
            &mut state,
        )
        .unwrap();
        assert_eq!(state.read_x(5), 0x5566_7700);
    }

    #[test]
    fn ldr_str_use_sp_as_memory_base() {
        let mut state = MachineState::new();
        state
            .map_user_range(0x8000, 0x9000, PagePerm::ReadWrite)
            .unwrap();
        state.set_sp(0x8000);
        state.write_x(0, 0x1122_3344_5566_7788);

        exec_user(
            A64Insn::StrImmGenStr64LdstPos {
                rt: A64Reg::x(0),
                mem: A64Mem::offset(A64Reg::x_sp(31), A64Imm::scaled_unsigned(1, 12, 3)),
            },
            0x4000,
            &mut state,
        )
        .unwrap();
        assert_eq!(state.read_u64(0x8008), 0x1122_3344_5566_7788);

        exec_user(
            A64Insn::LdrImmGenLdr64LdstPos {
                rt: A64Reg::x(1),
                mem: A64Mem::offset(A64Reg::x_sp(31), A64Imm::scaled_unsigned(1, 12, 3)),
            },
            0x4004,
            &mut state,
        )
        .unwrap();
        assert_eq!(state.read_x(1), 0x1122_3344_5566_7788);
    }

    #[test]
    fn ldp_stp_pair_support_sp_pre_and_post_index() {
        let mut state = MachineState::new();
        state
            .map_user_range(0x8000, 0x9000, PagePerm::ReadWrite)
            .unwrap();
        state.set_sp(0x9000);
        state.write_x(29, 0x1111_2222_3333_4444);
        state.write_x(30, 0xAAAA_BBBB_CCCC_DDDD);

        exec_user(
            A64Insn::StpGenStp64LdstpairPre {
                rt2: A64Reg::x(30),
                rt: A64Reg::x(29),
                mem: A64Mem::pre_index(
                    A64Reg::x_sp(31),
                    A64Imm::scaled_signed(signed_field(-2, 7) as u32, 7, 3),
                ),
            },
            0x4000,
            &mut state,
        )
        .unwrap();
        assert_eq!(state.sp(), 0x8ff0);
        assert_eq!(state.read_u64(0x8ff0), 0x1111_2222_3333_4444);
        assert_eq!(state.read_u64(0x8ff8), 0xAAAA_BBBB_CCCC_DDDD);

        state.write_x(29, 0);
        state.write_x(30, 0);
        exec_user(
            A64Insn::LdpGenLdp64LdstpairPost {
                rt2: A64Reg::x(30),
                rt: A64Reg::x(29),
                mem: A64Mem::post_index(
                    A64Reg::x_sp(31),
                    A64Imm::scaled_signed(signed_field(2, 7) as u32, 7, 3),
                ),
            },
            0x4004,
            &mut state,
        )
        .unwrap();
        assert_eq!(state.read_x(29), 0x1111_2222_3333_4444);
        assert_eq!(state.read_x(30), 0xAAAA_BBBB_CCCC_DDDD);
        assert_eq!(state.sp(), 0x9000);
    }

    fn signed_field(value: i64, bits: u8) -> u8 {
        let min = -(1_i64 << (bits - 1));
        let max = (1_i64 << (bits - 1)) - 1;
        assert!((min..=max).contains(&value));
        (value as i128 & ((1_i128 << bits) - 1)) as u8
    }
}

#[cfg(test)]
mod alu_tests {
    use super::*;
    use crate::shared::arm64::ergo::{uimm, w, x};

    fn xsp(enc: u8) -> A64Reg {
        A64Reg::x_sp(enc)
    }

    fn run(state: &mut MachineState, insn: A64Insn) {
        assert!(!insn.is_decode_undefined(), "{} is UNDEFINED", insn.key());
        let mut ctx = AccessContext::Original {
            counter: None,
            log: None,
        };
        assert_eq!(execute_insn(insn, 0x4000, state, &mut ctx).unwrap(), 0x4004);
    }

    fn flags(n: bool, z: bool, c: bool, v: bool) -> Flags {
        Flags { n, z, c, v }
    }

    fn adds64(rn: u64, imm: u32) -> (u64, Flags) {
        let mut state = MachineState::new();
        state.write_x(1, rn);
        run(
            &mut state,
            A64Insn::AddsAddsubImmAdds64sAddsubImm {
                sh: 0,
                imm12: uimm(imm, 12),
                rn: xsp(1),
                rd: x(0),
            },
        );
        (state.read_x(0), state.flags)
    }

    fn subs_reg(bits: u8, rn: u64, rm: u64) -> (u64, Flags) {
        let mut state = MachineState::new();
        state.write_x(0, 0xdead_beef_dead_beef);
        state.write_x(1, rn);
        state.write_x(2, rm);
        let insn = match bits {
            32 => A64Insn::SubsAddsubShiftSubs32AddsubShift {
                shift: 0,
                rm: w(2),
                imm6: uimm(0, 6),
                rn: w(1),
                rd: w(0),
            },
            _ => A64Insn::SubsAddsubShiftSubs64AddsubShift {
                shift: 0,
                rm: x(2),
                imm6: uimm(0, 6),
                rn: x(1),
                rd: x(0),
            },
        };
        run(&mut state, insn);
        (state.read_x(0), state.flags)
    }

    #[test]
    fn adds_subs_carry_and_overflow_at_boundaries() {
        assert_eq!(adds64(u64::MAX, 1), (0, flags(false, true, true, false)));
        assert_eq!(
            adds64(i64::MAX as u64, 1),
            (1 << 63, flags(true, false, false, true))
        );
        assert_eq!(adds64(0, 0), (0, flags(false, true, false, false)));

        assert_eq!(
            subs_reg(64, 0, 1),
            (u64::MAX, flags(true, false, false, false))
        );
        assert_eq!(
            subs_reg(64, 1 << 63, 1),
            (i64::MAX as u64, flags(false, false, true, true))
        );
        assert_eq!(subs_reg(64, 5, 5), (0, flags(false, true, true, false)));
        assert_eq!(
            subs_reg(64, u64::MAX, u64::MAX),
            (0, flags(false, true, true, false))
        );

        // 32-bit: upper source bits are ignored, the result zero-extends.
        assert_eq!(
            subs_reg(32, 0xffff_ffff_0000_0000, 1),
            (0xffff_ffff, flags(true, false, false, false))
        );
        assert_eq!(
            subs_reg(32, 0x8000_0000, 1),
            (0x7fff_ffff, flags(false, false, true, true))
        );
        assert_eq!(
            subs_reg(32, 0x1_0000_0007, 7),
            (0, flags(false, true, true, false))
        );
    }

    #[test]
    fn cmn_detects_glibc_syscall_error_range() {
        // glibc: `cmn x0, #1, lsl #12; b.hi error` <=> x0 in [-4095, -1].
        for (x0, hi) in [
            (0_u64, false),
            ((-4096_i64) as u64, false),
            ((-4095_i64) as u64, true),
            (u64::MAX, true),
        ] {
            let mut state = MachineState::new();
            state.write_x(0, x0);
            run(
                &mut state,
                A64Insn::AddsAddsubImmAdds64sAddsubImm {
                    sh: 1,
                    imm12: uimm(1, 12),
                    rn: xsp(0),
                    rd: x(31),
                },
            );
            assert_eq!(eval_condition(A64Condition::Hi, &state), hi, "x0 = {x0:#x}");
            assert_eq!(state.read_x(0), x0, "cmn must not write x0");
        }
    }

    #[test]
    fn thirty_two_bit_results_zero_extend() {
        let mut state = MachineState::new();
        state.write_x(1, 0xffff_ffff_0000_0005);
        state.write_x(2, 0x1234_5678_0000_0003);

        run(
            &mut state,
            A64Insn::AddAddsubShiftAdd32AddsubShift {
                shift: 0,
                rm: w(2),
                imm6: uimm(0, 6),
                rn: w(1),
                rd: w(0),
            },
        );
        assert_eq!(state.read_x(0), 8);

        run(
            &mut state,
            A64Insn::SubAddsubShiftSub32AddsubShift {
                shift: 0,
                rm: w(1),
                imm6: uimm(0, 6),
                rn: w(31),
                rd: w(3),
            },
        );
        assert_eq!(state.read_x(3), 0xffff_fffb, "neg w3, w1");

        run(
            &mut state,
            A64Insn::OrrLogShiftOrr32LogShift {
                shift: 0,
                rm: w(1),
                imm6: uimm(0, 6),
                rn: w(31),
                rd: w(4),
            },
        );
        assert_eq!(state.read_x(4), 5, "mov w4, w1");

        run(
            &mut state,
            A64Insn::MovnMovn32Movewide {
                hw: 0,
                imm16: uimm(0, 16),
                rd: w(5),
            },
        );
        assert_eq!(state.read_x(5), 0xffff_ffff);

        state.flags = flags(false, true, false, false);
        run(
            &mut state,
            A64Insn::CsnegCsneg32Condsel {
                rm: w(2),
                cond: A64Condition::Ne.bits(),
                rn: w(1),
                rd: w(6),
            },
        );
        assert_eq!(
            state.read_x(6),
            0xffff_fffd,
            "csneg picks -w2 when ne fails"
        );
    }

    #[test]
    fn extended_register_add_uses_sp_and_sign_extends_index() {
        let mut state = MachineState::new();
        state.set_sp(0x8000);
        state.write_x(1, 0x0000_0000_ffff_fffe); // w1 = -2
        run(
            &mut state,
            A64Insn::AddAddsubExtAdd64AddsubExt {
                rm: x(1),
                option: 6,
                imm3: uimm(2, 3),
                rn: xsp(31),
                rd: xsp(0),
            },
        );
        assert_eq!(state.read_x(0), 0x8000 - 8, "add x0, sp, w1, sxtw #2");

        run(
            &mut state,
            A64Insn::AddAddsubExtAdd64AddsubExt {
                rm: x(1),
                option: 2,
                imm3: uimm(0, 3),
                rn: xsp(31),
                rd: xsp(31),
            },
        );
        assert_eq!(state.sp(), 0x8000 + 0xffff_fffe, "add sp, sp, w1, uxtw");
        assert_eq!(state.read_x(31), 0);
    }

    #[test]
    fn logical_forms_set_nz_and_clear_cv() {
        let mut state = MachineState::new();
        state.flags = flags(false, false, true, true);
        state.write_x(1, 0x8000_0000_0000_00f0);
        run(
            &mut state,
            A64Insn::AndsLogImmAnds64sLogImm {
                n: 1,
                immr: uimm(1, 6),
                imms: uimm(0, 6),
                rn: x(1),
                rd: x(0),
            },
        );
        assert_eq!(state.read_x(0), 1 << 63);
        assert_eq!(state.flags, flags(true, false, false, false));

        run(
            &mut state,
            A64Insn::BicsBics32LogShift {
                shift: 0,
                rm: w(1),
                imm6: uimm(0, 6),
                rn: w(1),
                rd: w(2),
            },
        );
        assert_eq!(state.read_x(2), 0);
        assert_eq!(state.flags, flags(false, true, false, false));

        // orr wsp, w1, #0x3: logical-immediate Rd is SP-capable.
        run(
            &mut state,
            A64Insn::OrrLogImmOrr32LogImm {
                immr: uimm(0, 6),
                imms: uimm(1, 6),
                rn: w(1),
                rd: A64Reg::w_sp(31),
            },
        );
        assert_eq!(state.sp(), 0xf3);
    }

    #[test]
    fn decode_bit_masks_matches_known_immediates() {
        let imm = |n, immr, imms, bits| decode_bit_masks(n, imms, immr, true, bits).unwrap().0;
        assert_eq!(imm(0, 0, 7, 32), 0xff);
        assert_eq!(imm(1, 60, 59, 64), 0xffff_ffff_ffff_fff0);
        assert_eq!(imm(0, 0, 0b111100, 64), 0x5555_5555_5555_5555);
        assert_eq!(imm(0, 0, 0b100111, 64), 0x00ff_00ff_00ff_00ff);
        assert_eq!(imm(0, 31, 30, 32), 0xffff_fffe);
        assert!(decode_bit_masks(1, 0x3f, 0, true, 64).is_err());
        assert!(decode_bit_masks(0, 0x3d, 0, true, 64).is_err());
    }

    fn bitfield(insn: A64Insn, rd: u64, rn: u64) -> u64 {
        let mut state = MachineState::new();
        state.write_x(0, rd);
        state.write_x(1, rn);
        run(&mut state, insn);
        state.read_x(0)
    }

    #[test]
    fn bitfield_aliases() {
        let sbfm64 = |immr, imms| A64Insn::SbfmSbfm64mBitfield {
            immr: uimm(immr, 6),
            imms: uimm(imms, 6),
            rn: x(1),
            rd: x(0),
        };
        let ubfm64 = |immr, imms| A64Insn::UbfmUbfm64mBitfield {
            immr: uimm(immr, 6),
            imms: uimm(imms, 6),
            rn: x(1),
            rd: x(0),
        };
        let sbfm32 = |immr, imms| A64Insn::SbfmSbfm32mBitfield {
            immr: uimm(immr, 6),
            imms: uimm(imms, 6),
            rn: w(1),
            rd: w(0),
        };
        let ubfm32 = |immr, imms| A64Insn::UbfmUbfm32mBitfield {
            immr: uimm(immr, 6),
            imms: uimm(imms, 6),
            rn: w(1),
            rd: w(0),
        };

        assert_eq!(
            bitfield(sbfm64(0, 31), 0, 0x1234_5678_8000_0000),
            0xffff_ffff_8000_0000,
            "sxtw"
        );
        assert_eq!(bitfield(sbfm64(63, 63), 0, 1 << 63), u64::MAX, "asr #63");
        assert_eq!(
            bitfield(sbfm64(4, 11), 0, 0xf80),
            (-8_i64) as u64,
            "sbfx #4, #8"
        );
        assert_eq!(bitfield(ubfm64(1, 0), 0, 3), 1 << 63, "lsl #63");
        assert_eq!(bitfield(ubfm64(63, 63), 0, 1 << 63), 1, "lsr #63");
        assert_eq!(bitfield(ubfm64(4, 11), 0, 0xabc), 0xab, "ubfx #4, #8");
        assert_eq!(bitfield(ubfm64(60, 3), 0, 0xff), 0xf0, "ubfiz #4, #4");
        assert_eq!(
            bitfield(sbfm32(31, 31), 0, 0x8000_0000),
            0xffff_ffff,
            "asr w #31"
        );
        assert_eq!(bitfield(sbfm32(0, 7), 0, 0x80), 0xffff_ff80, "sxtb w");
        assert_eq!(
            bitfield(ubfm32(31, 30), 0, 0xffff_ffff),
            0xffff_fffe,
            "lsl w #1"
        );
        assert_eq!(bitfield(ubfm32(0, 7), 0, 0x1ff), 0xff, "uxtb w");

        let bfi = A64Insn::BfmBfm32mBitfield {
            immr: uimm(29, 6),
            imms: uimm(3, 6),
            rn: w(1),
            rd: w(0),
        };
        assert_eq!(
            bitfield(bfi, 0xffff_ffff_ffff_ffff, 0x5),
            0xffff_ffaf,
            "bfi w0, w1, #3, #4"
        );
        let bfxil = A64Insn::BfmBfm64mBitfield {
            immr: uimm(8, 6),
            imms: uimm(63, 6),
            rn: x(1),
            rd: x(0),
        };
        assert_eq!(
            bitfield(bfxil, 0xaaaa_aaaa_aaaa_aaaa, 0x1122_3344_5566_7788),
            0xaa11_2233_4455_6677
        );
        let bfm_edge = A64Insn::BfmBfm64mBitfield {
            immr: uimm(63, 6),
            imms: uimm(0, 6),
            rn: x(1),
            rd: x(0),
        };
        assert_eq!(bitfield(bfm_edge, 0, 1), 2, "bfi x0, x1, #1, #1");
    }

    #[test]
    fn extr_and_variable_shifts() {
        let mut state = MachineState::new();
        state.write_x(1, 0x0123_4567_89ab_cdef);
        state.write_x(2, 65);
        run(
            &mut state,
            A64Insn::ExtrExtr64Extract {
                rm: x(1),
                imms: uimm(8, 6),
                rn: x(1),
                rd: x(0),
            },
        );
        assert_eq!(state.read_x(0), 0xef01_2345_6789_abcd, "ror #8");

        run(
            &mut state,
            A64Insn::LslvLslv64Dp2src {
                rm: x(2),
                rn: x(1),
                rd: x(3),
            },
        );
        assert_eq!(
            state.read_x(3),
            0x0246_8acf_1357_9bde,
            "shift amount is mod 64"
        );

        state.write_x(2, 33);
        run(
            &mut state,
            A64Insn::AsrvAsrv32Dp2src {
                rm: w(2),
                rn: w(1),
                rd: w(4),
            },
        );
        assert_eq!(state.read_x(4), 0xc4d5_e6f7, "asr w by 33 mod 32");

        run(
            &mut state,
            A64Insn::RorvRorv32Dp2src {
                rm: w(2),
                rn: w(1),
                rd: w(5),
            },
        );
        assert_eq!(state.read_x(5), 0xc4d5_e6f7, "ror w by 1");
    }

    fn ccmp(z_before: bool, rn: u64) -> Flags {
        let mut state = MachineState::new();
        state.flags = flags(false, z_before, false, false);
        state.write_x(1, rn);
        run(
            &mut state,
            A64Insn::CcmpImmCcmp64CondcmpImm {
                imm5: uimm(5, 5),
                cond: A64Condition::Eq.bits(),
                rn: x(1),
                nzcv: 0b0010,
            },
        );
        state.flags
    }

    #[test]
    fn ccmp_takes_compare_or_immediate_flags() {
        assert_eq!(
            ccmp(true, 5),
            flags(false, true, true, false),
            "eq holds: 5 - 5"
        );
        assert_eq!(
            ccmp(true, 4),
            flags(true, false, false, false),
            "eq holds: 4 - 5"
        );
        assert_eq!(
            ccmp(false, 5),
            flags(false, false, true, false),
            "eq fails: nzcv"
        );

        let mut state = MachineState::new();
        state.write_x(1, u64::MAX);
        state.write_x(2, 1);
        run(
            &mut state,
            A64Insn::CcmnRegCcmn64CondcmpReg {
                rm: x(2),
                cond: A64Condition::Al.bits(),
                rn: x(1),
                nzcv: 0,
            },
        );
        assert_eq!(state.flags, flags(false, true, true, false), "ccmn -1 + 1");
    }

    fn div(insn: fn(A64Reg, A64Reg, A64Reg) -> A64Insn, rn: u64, rm: u64) -> u64 {
        let mut state = MachineState::new();
        state.write_x(1, rn);
        state.write_x(2, rm);
        run(&mut state, insn(x(2), x(1), x(0)));
        state.read_x(0)
    }

    #[test]
    fn division_edge_cases() {
        let udiv64 = |rm, rn, rd| A64Insn::UdivUdiv64Dp2src { rm, rn, rd };
        let sdiv64 = |rm, rn, rd| A64Insn::SdivSdiv64Dp2src { rm, rn, rd };
        let udiv32 = |rm: A64Reg, rn: A64Reg, rd: A64Reg| A64Insn::UdivUdiv32Dp2src { rm, rn, rd };
        let sdiv32 = |rm: A64Reg, rn: A64Reg, rd: A64Reg| A64Insn::SdivSdiv32Dp2src { rm, rn, rd };

        assert_eq!(div(udiv64, 7, 0), 0);
        assert_eq!(div(sdiv64, 7, 0), 0);
        assert_eq!(div(udiv32, 7, 0x1_0000_0000), 0, "w divisor is 0");
        assert_eq!(div(sdiv64, 1 << 63, u64::MAX), 1 << 63, "INT64_MIN / -1");
        assert_eq!(
            div(sdiv32, 0x8000_0000, 0xffff_ffff),
            0x8000_0000,
            "INT32_MIN / -1"
        );
        assert_eq!(
            div(sdiv64, (-7_i64) as u64, 2),
            (-3_i64) as u64,
            "rounds toward zero"
        );
        assert_eq!(div(sdiv32, 7, (-2_i32) as u32 as u64), 0xffff_fffd);
        assert_eq!(div(udiv64, u64::MAX, 2), u64::MAX / 2);
    }

    #[test]
    fn multiply_high_and_long() {
        let mut state = MachineState::new();
        state.write_x(1, u64::MAX);
        state.write_x(2, u64::MAX);
        run(
            &mut state,
            A64Insn::UmulhUmulh64Dp3src {
                rm: x(2),
                rn: x(1),
                rd: x(0),
            },
        );
        assert_eq!(state.read_x(0), u64::MAX - 1);
        run(
            &mut state,
            A64Insn::SmulhSmulh64Dp3src {
                rm: x(2),
                rn: x(1),
                rd: x(0),
            },
        );
        assert_eq!(state.read_x(0), 0, "-1 * -1");
        state.write_x(1, 1 << 63);
        state.write_x(2, 2);
        run(
            &mut state,
            A64Insn::SmulhSmulh64Dp3src {
                rm: x(2),
                rn: x(1),
                rd: x(0),
            },
        );
        assert_eq!(state.read_x(0), u64::MAX, "INT64_MIN * 2 high half");

        state.write_x(1, 0xdead_0000_ffff_fffe); // w1 = -2
        state.write_x(2, 0xbeef_0000_0000_0003); // w2 = 3
        state.write_x(3, 10);
        run(
            &mut state,
            A64Insn::SmaddlSmaddl64waDp3src {
                rm: w(2),
                ra: x(3),
                rn: w(1),
                rd: x(0),
            },
        );
        assert_eq!(state.read_x(0), 4, "10 + (-2 * 3)");
        run(
            &mut state,
            A64Insn::UmaddlUmaddl64waDp3src {
                rm: w(2),
                ra: x(31),
                rn: w(1),
                rd: x(0),
            },
        );
        assert_eq!(state.read_x(0), 0xffff_fffe * 3);
        run(
            &mut state,
            A64Insn::MsubMsub32aDp3src {
                rm: w(2),
                ra: w(3),
                rn: w(1),
                rd: w(0),
            },
        );
        assert_eq!(state.read_x(0), 16, "10 - (-2 * 3)");
    }

    /// `op` = ADC/ADCS/SBC/SBCS with `rd = x0, rn = x1, rm = x2`, from the given
    /// operands and carry-in. Every other flag is set before, so a non-flag-setting
    /// form must leave all four unchanged.
    fn carry_op(
        insn: fn(A64Reg, A64Reg, A64Reg) -> A64Insn,
        bits: u8,
        rn: u64,
        rm: u64,
        carry: bool,
    ) -> (u64, Flags) {
        let mut state = MachineState::new();
        state.write_x(0, 0x5555_5555_5555_5555);
        state.write_x(1, rn);
        state.write_x(2, rm);
        state.flags = flags(true, true, carry, true);
        let reg = if bits == 32 { w } else { x };
        run(&mut state, insn(reg(2), reg(1), reg(0)));
        (state.read_x(0), state.flags)
    }

    #[test]
    fn add_sub_with_carry_at_boundaries() {
        let adc64 = |rm, rn, rd| A64Insn::AdcAdc64AddsubCarry { rm, rn, rd };
        let adcs64 = |rm, rn, rd| A64Insn::AdcsAdcs64AddsubCarry { rm, rn, rd };
        let adcs32 = |rm, rn, rd| A64Insn::AdcsAdcs32AddsubCarry { rm, rn, rd };
        let sbc32 = |rm, rn, rd| A64Insn::SbcSbc32AddsubCarry { rm, rn, rd };
        let sbcs64 = |rm, rn, rd| A64Insn::SbcsSbcs64AddsubCarry { rm, rn, rd };
        let sbcs32 = |rm, rn, rd| A64Insn::SbcsSbcs32AddsubCarry { rm, rn, rd };

        // ADC reads C and writes no flag.
        assert_eq!(
            carry_op(adc64, 64, 1, 2, true),
            (4, flags(true, true, true, true))
        );
        assert_eq!(carry_op(adc64, 64, 1, 2, false).0, 3);
        // ADCS: the carry-in alone carries out, and alone overflows.
        assert_eq!(
            carry_op(adcs64, 64, u64::MAX, 0, true),
            (0, flags(false, true, true, false))
        );
        assert_eq!(
            carry_op(adcs64, 64, i64::MAX as u64, 0, true),
            (1 << 63, flags(true, false, false, true))
        );
        assert_eq!(
            carry_op(adcs64, 64, u64::MAX, u64::MAX, true),
            (u64::MAX, flags(true, false, true, false))
        );
        // 32-bit: operands are the low words, the result zero-extends.
        assert_eq!(
            carry_op(
                adcs32,
                32,
                0xdead_beef_ffff_ffff,
                0xffff_0000_0000_0000,
                true
            ),
            (0, flags(false, true, true, false))
        );
        assert_eq!(
            carry_op(adcs32, 32, 0x7fff_ffff, 0, true),
            (0x8000_0000, flags(true, false, false, true))
        );
        // SBC(S): Rn - Rm - NOT(C). C clear is a borrow.
        assert_eq!(
            carry_op(sbcs64, 64, 0, 0, false),
            (u64::MAX, flags(true, false, false, false))
        );
        assert_eq!(
            carry_op(sbcs64, 64, 0, 0, true),
            (0, flags(false, true, true, false))
        );
        assert_eq!(
            carry_op(sbcs64, 64, 1 << 63, 0, false),
            (i64::MAX as u64, flags(false, false, true, true))
        );
        assert_eq!(
            carry_op(sbcs32, 32, 0x1_0000_0000, 1, true),
            (0xffff_ffff, flags(true, false, false, false))
        );
        assert_eq!(
            carry_op(sbc32, 32, 5, 7, false),
            (0xffff_fffd, flags(true, true, false, true))
        );
        // NGC x0, x2 = SBC x0, xzr, x2.
        let mut state = MachineState::new();
        state.write_x(2, 5);
        state.flags = flags(false, false, false, false);
        run(
            &mut state,
            A64Insn::SbcSbc64AddsubCarry {
                rm: x(2),
                rn: x(31),
                rd: x(0),
            },
        );
        assert_eq!(state.read_x(0), (-6_i64) as u64);
    }

    /// 128-bit add and subtract through ADDS/ADCS and SUBS/SBCS.
    #[test]
    fn multi_word_carry_chain() {
        let mut state = MachineState::new();
        let (a, b) = (
            0x0000_0001_ffff_ffff_ffff_ffff_u128,
            0x0000_0002_0000_0000_0000_0001_u128,
        );
        state.write_x(1, a as u64);
        state.write_x(2, (a >> 64) as u64);
        state.write_x(3, b as u64);
        state.write_x(4, (b >> 64) as u64);
        run(
            &mut state,
            A64Insn::AddsAddsubShiftAdds64AddsubShift {
                shift: 0,
                rm: x(3),
                imm6: uimm(0, 6),
                rn: x(1),
                rd: x(5),
            },
        );
        run(
            &mut state,
            A64Insn::AdcAdc64AddsubCarry {
                rm: x(4),
                rn: x(2),
                rd: x(6),
            },
        );
        let sum = a + b;
        assert_eq!(state.read_x(5), sum as u64);
        assert_eq!(state.read_x(6), (sum >> 64) as u64);
        run(
            &mut state,
            A64Insn::SubsAddsubShiftSubs64AddsubShift {
                shift: 0,
                rm: x(3),
                imm6: uimm(0, 6),
                rn: x(1),
                rd: x(5),
            },
        );
        run(
            &mut state,
            A64Insn::SbcsSbcs64AddsubCarry {
                rm: x(4),
                rn: x(2),
                rd: x(6),
            },
        );
        let diff = a.wrapping_sub(b);
        assert_eq!(state.read_x(5), diff as u64);
        assert_eq!(state.read_x(6), (diff >> 64) as u64);
        assert!(state.flags.n && !state.flags.c, "a < b borrows out");
    }

    #[test]
    fn multiply_subtract_long() {
        let mut state = MachineState::new();
        state.write_x(1, 0xdead_0000_ffff_fffe); // w1 = -2 (signed), 0xfffffffe
        state.write_x(2, 0xbeef_0000_0000_0003); // w2 = 3
        state.write_x(3, 10);
        run(
            &mut state,
            A64Insn::SmsublSmsubl64waDp3src {
                rm: w(2),
                ra: x(3),
                rn: w(1),
                rd: x(0),
            },
        );
        assert_eq!(state.read_x(0), 16, "10 - (-2 * 3)");
        run(
            &mut state,
            A64Insn::UmsublUmsubl64waDp3src {
                rm: w(2),
                ra: x(3),
                rn: w(1),
                rd: x(0),
            },
        );
        assert_eq!(state.read_x(0), 10_u64.wrapping_sub(0xffff_fffe * 3));
        // SMNEGL: Ra = xzr.
        run(
            &mut state,
            A64Insn::SmsublSmsubl64waDp3src {
                rm: w(2),
                ra: x(31),
                rn: w(1),
                rd: x(0),
            },
        );
        assert_eq!(state.read_x(0), 6);
    }

    /// CRC-32 and CRC-32C check values of "123456789" (initial value and final
    /// XOR 0xffffffff, applied by software around the instructions), fed as
    /// bytes, as halfwords + words, and as a doubleword + byte.
    #[test]
    fn crc32_check_values() {
        let data = b"123456789";
        type Crc = fn(A64Reg, A64Reg, A64Reg) -> A64Insn;
        let sizes = |crc32c: bool| -> [(usize, Crc); 4] {
            if crc32c {
                [
                    (1, |rm, rn, rd| A64Insn::Crc32cCrc32cb32cDp2src {
                        rm,
                        rn,
                        rd,
                    }),
                    (2, |rm, rn, rd| A64Insn::Crc32cCrc32ch32cDp2src {
                        rm,
                        rn,
                        rd,
                    }),
                    (4, |rm, rn, rd| A64Insn::Crc32cCrc32cw32cDp2src {
                        rm,
                        rn,
                        rd,
                    }),
                    (8, |rm, rn, rd| A64Insn::Crc32cCrc32cx64cDp2src {
                        rm,
                        rn,
                        rd,
                    }),
                ]
            } else {
                [
                    (1, |rm, rn, rd| A64Insn::Crc32Crc32b32cDp2src { rm, rn, rd }),
                    (2, |rm, rn, rd| A64Insn::Crc32Crc32h32cDp2src { rm, rn, rd }),
                    (4, |rm, rn, rd| A64Insn::Crc32Crc32w32cDp2src { rm, rn, rd }),
                    (8, |rm, rn, rd| A64Insn::Crc32Crc32x64cDp2src { rm, rn, rd }),
                ]
            }
        };
        for (crc32c, check) in [(false, 0xcbf4_3926_u64), (true, 0xe306_9283)] {
            let forms = sizes(crc32c);
            for chunks in [&[1; 9][..], &[2, 2, 4, 1], &[8, 1]] {
                let mut state = MachineState::new();
                // Initial CRC 0xffffffff; the upper word must be ignored.
                state.write_x(0, u64::MAX);
                let mut at = 0;
                for &size in chunks {
                    let (_, form) = forms.iter().find(|(bytes, _)| *bytes == size).unwrap();
                    let mut chunk = [0_u8; 8];
                    chunk[..size].copy_from_slice(&data[at..at + size]);
                    // Bytes above the operand size must be ignored.
                    let garbage = if size < 8 { u64::MAX << (size * 8) } else { 0 };
                    state.write_x(1, u64::from_le_bytes(chunk) | garbage);
                    let reg = if size == 8 { x } else { w };
                    run(&mut state, form(reg(1), w(0), w(0)));
                    at += size;
                }
                assert_eq!(
                    state.read_x(0) ^ 0xffff_ffff,
                    check,
                    "crc32c={crc32c} {chunks:?}"
                );
            }
        }
    }

    #[test]
    fn bti_is_a_nop() {
        let mut state = MachineState::new();
        state.write_x(0, 7);
        state.flags = flags(true, false, true, false);
        let before = state.clone();
        for op2 in [0b000, 0b010, 0b100, 0b110] {
            run(&mut state, A64Insn::BtiBtiHbHints { op2 });
            assert_eq!(state, before);
        }
    }

    #[test]
    fn byte_and_bit_reversal() {
        let mut state = MachineState::new();
        state.write_x(1, 0x0102_0304_0506_0708);
        run(&mut state, A64Insn::RevRev64Dp1src { rn: x(1), rd: x(0) });
        assert_eq!(state.read_x(0), 0x0807_0605_0403_0201);
        run(&mut state, A64Insn::RevRev32Dp1src { rn: w(1), rd: w(0) });
        assert_eq!(state.read_x(0), 0x0807_0605);
        run(
            &mut state,
            A64Insn::Rev32IntRev3264Dp1src { rn: x(1), rd: x(0) },
        );
        assert_eq!(state.read_x(0), 0x0403_0201_0807_0605);
        run(
            &mut state,
            A64Insn::Rev16IntRev1664Dp1src { rn: x(1), rd: x(0) },
        );
        assert_eq!(state.read_x(0), 0x0201_0403_0605_0807);
        run(
            &mut state,
            A64Insn::Rev16IntRev1632Dp1src { rn: w(1), rd: w(0) },
        );
        assert_eq!(state.read_x(0), 0x0605_0807);
        run(
            &mut state,
            A64Insn::RbitIntRbit32Dp1src { rn: w(1), rd: w(0) },
        );
        assert_eq!(state.read_x(0), 0x10e0_60a0);
        run(
            &mut state,
            A64Insn::ClzIntClz32Dp1src {
                rn: w(31),
                rd: w(0),
            },
        );
        assert_eq!(state.read_x(0), 32);
        run(
            &mut state,
            A64Insn::ClzIntClz64Dp1src { rn: x(1), rd: x(0) },
        );
        assert_eq!(state.read_x(0), 7);
    }

    #[test]
    fn mrs_reads_its_register() {
        let mut state = MachineState::new();
        state.tpidr_el0 = 0x9800;
        state.cntvct_el0 = 0x1234_5678;
        state.cntfrq_el0 = 24_000_000;
        run(&mut state, A64Insn::MrsMrsRsSystemmoveTpidrEl0 { rt: x(1) });
        run(&mut state, A64Insn::MrsMrsRsSystemmoveCntvctEl0 { rt: x(2) });
        run(&mut state, A64Insn::MrsMrsRsSystemmoveCntfrqEl0 { rt: x(3) });
        // The model's counter does not advance.
        run(&mut state, A64Insn::MrsMrsRsSystemmoveCntvctEl0 { rt: x(4) });
        assert_eq!(state.read_x(1), 0x9800);
        assert_eq!(state.read_x(2), 0x1234_5678);
        assert_eq!(state.read_x(3), 24_000_000);
        assert_eq!(state.read_x(4), 0x1234_5678);
    }

    /// Every condition against every NZCV value, checked against the bit-level
    /// `ConditionHolds` definition (base test on cond[3:1], inverted by cond[0]
    /// except for 0b1111).
    #[test]
    fn condition_codes_follow_condition_holds() {
        for nzcv in 0..16_u8 {
            let mut state = MachineState::new();
            state.flags = flags(nzcv & 8 != 0, nzcv & 4 != 0, nzcv & 2 != 0, nzcv & 1 != 0);
            let Flags { n, z, c, v } = state.flags;
            for cond in 0..16_u8 {
                let base = match cond >> 1 {
                    0b000 => z,
                    0b001 => c,
                    0b010 => n,
                    0b011 => v,
                    0b100 => c && !z,
                    0b101 => n == v,
                    0b110 => n == v && !z,
                    _ => true,
                };
                let expected = if cond & 1 == 1 && cond != 0b1111 {
                    !base
                } else {
                    base
                };
                let condition = A64Condition::from_bits(cond).unwrap();
                assert_eq!(condition.bits(), cond);
                assert_eq!(
                    eval_condition(condition, &state),
                    expected,
                    "cond {cond:#x} nzcv {nzcv:#06b}"
                );
            }
        }
    }
}

/// Semantics of the A7b load/store forms: extension, access sizes, register-offset
/// addressing, alignment and page crossing. The native oracle checks the same
/// forms on hardware through the fixtures; these pin the edge values.
#[cfg(test)]
mod mem_form_tests {
    use super::*;
    use crate::model::PagePerm;

    const PAGE: u64 = 0x9000;

    fn run(state: &mut MachineState, insn: A64Insn) -> Result<u64, InsnError> {
        execute_insn(
            insn,
            0x4000,
            state,
            &mut AccessContext::Original {
                counter: None,
                log: None,
            },
        )
    }

    /// Two RW pages at 0x9000..0xb000 with x1 = 0x9000; x0 holds garbage.
    fn two_pages() -> MachineState {
        let mut state = MachineState::new();
        state
            .map_user_range(PAGE, PAGE + 0x2000, PagePerm::ReadWrite)
            .unwrap();
        state.write_x(1, PAGE);
        state.write_x(0, 0xdead_beef_dead_beef);
        state
    }

    fn off(base: u8) -> A64Mem {
        A64Mem::offset(A64Reg::x_sp(base), A64Imm::signed(0, 9))
    }

    /// Loads `bytes` at 0x9000 with `insn` (addressing [x1]) and returns x0.
    fn load(insn: fn(A64Reg, A64Mem) -> A64Insn, rt: A64Reg, bytes: &[u8]) -> u64 {
        let mut state = two_pages();
        for (i, byte) in bytes.iter().enumerate() {
            state.write_le(PAGE + i as u64, 1, u64::from(*byte));
        }
        run(&mut state, insn(rt, off(1))).unwrap();
        state.read_x(0)
    }

    #[test]
    fn signed_loads_extend_at_every_boundary_and_32_bit_targets_clear_the_top() {
        type Make = fn(A64Reg, A64Mem) -> A64Insn;
        let ldursb32: Make = |rt, mem| A64Insn::LdursbLdursb32LdstUnscaled { rt, mem };
        let ldursb64: Make = |rt, mem| A64Insn::LdursbLdursb64LdstUnscaled { rt, mem };
        let ldursh32: Make = |rt, mem| A64Insn::LdurshLdursh32LdstUnscaled { rt, mem };
        let ldursh64: Make = |rt, mem| A64Insn::LdurshLdursh64LdstUnscaled { rt, mem };
        let ldursw: Make = |rt, mem| A64Insn::LdurswLdursw64LdstUnscaled { rt, mem };
        let ldurb: Make = |rt, mem| A64Insn::LdurbLdurb32LdstUnscaled { rt, mem };
        let ldurh: Make = |rt, mem| A64Insn::LdurhLdurh32LdstUnscaled { rt, mem };
        let ldur32: Make = |rt, mem| A64Insn::LdurGenLdur32LdstUnscaled { rt, mem };
        let (w0, x0) = (A64Reg::w(0), A64Reg::x(0));
        let cases: [(Make, A64Reg, &[u8], u64); 20] = [
            (ldursb32, w0, &[0x7f], 0x7f),
            (ldursb32, w0, &[0x80], 0xffff_ff80),
            (ldursb64, x0, &[0x7f], 0x7f),
            (ldursb64, x0, &[0x80], 0xffff_ffff_ffff_ff80),
            (ldursh32, w0, &[0xff, 0x7f], 0x7fff),
            (ldursh32, w0, &[0x00, 0x80], 0xffff_8000),
            (ldursh64, x0, &[0xff, 0x7f], 0x7fff),
            (ldursh64, x0, &[0x00, 0x80], 0xffff_ffff_ffff_8000),
            (ldursw, x0, &[0xff, 0xff, 0xff, 0x7f], 0x7fff_ffff),
            (ldursw, x0, &[0x00, 0x00, 0x00, 0x80], 0xffff_ffff_8000_0000),
            // Zero-extending forms at the same values, and only `size` bytes read.
            (ldurb, w0, &[0x80, 0xaa], 0x80),
            (ldurh, w0, &[0x00, 0x80, 0xaa], 0x8000),
            (ldur32, w0, &[0x00, 0x00, 0x00, 0x80, 0xaa], 0x8000_0000),
            (ldurb, w0, &[0xff], 0xff),
            (ldursb32, w0, &[0xff], 0xffff_ffff),
            (ldursb64, x0, &[0x00], 0),
            (ldursh32, w0, &[0xff, 0xff], 0xffff_ffff),
            (ldursh64, x0, &[0x01, 0x00], 1),
            (ldursw, x0, &[0xff, 0xff, 0xff, 0xff], u64::MAX),
            (ldursw, x0, &[0x01, 0x00, 0x00, 0x00, 0xff], 1),
        ];
        for (index, (make, rt, bytes, expected)) in cases.into_iter().enumerate() {
            assert_eq!(load(make, rt, bytes), expected, "case {index}: {bytes:x?}");
        }
    }

    #[test]
    fn narrow_stores_write_only_their_bytes() {
        let mut state = two_pages();
        state.write_le(PAGE, 8, u64::MAX);
        state.write_x(2, 0x1122_3344_5566_7788);
        run(
            &mut state,
            A64Insn::SturbSturb32LdstUnscaled {
                rt: A64Reg::w(2),
                mem: off(1),
            },
        )
        .unwrap();
        assert_eq!(state.read_le(PAGE, 8), 0xffff_ffff_ffff_ff88);
        run(
            &mut state,
            A64Insn::StrhImmStrh32LdstPos {
                rt: A64Reg::w(2),
                mem: A64Mem::offset(A64Reg::x_sp(1), A64Imm::scaled_unsigned(1, 12, 1)),
            },
        )
        .unwrap();
        assert_eq!(state.read_le(PAGE, 8), 0xffff_ffff_7788_ff88);
        run(
            &mut state,
            A64Insn::StpGenStp32LdstpairOff {
                rt2: A64Reg::w(31),
                rt: A64Reg::w(2),
                mem: A64Mem::offset(A64Reg::x_sp(1), A64Imm::scaled_signed(1, 7, 2)),
            },
        )
        .unwrap();
        assert_eq!(state.read_le(PAGE, 8), 0x5566_7788_7788_ff88);
        assert_eq!(state.read_le(PAGE + 8, 4), 0);
    }

    fn ldr_reg(option: u8, s: u8, rt: A64Reg) -> A64Insn {
        A64Insn::LdrRegGenLdr64LdstRegoff {
            rm: A64Reg::x(2),
            option,
            s,
            rn: A64Reg::x_sp(1),
            rt,
        }
    }

    #[test]
    fn register_offset_applies_every_extend_and_the_size_shift() {
        let mut state = two_pages();
        // x1 points into the middle of the two pages.
        state.write_x(1, PAGE + 0x1000);
        for slot in -4i64..4 {
            let addr = (PAGE + 0x1000).wrapping_add_signed(slot * 8);
            state.write_le(addr, 8, 0x1000_u64.wrapping_add_signed(slot));
        }
        let cases: [(u8, u8, u64, i64); 9] = [
            // (option, S, x2, expected slot)
            (0b011, 1, 3, 3),                      // lsl #3
            (0b011, 0, 16, 2),                     // lsl #0
            (0b010, 1, 0xffff_ffff_0000_0002, 2),  // uxtw #3 drops the top half
            (0b110, 1, 0x0000_0001_ffff_fffe, -2), // sxtw #3: w2 = -2
            (0b110, 0, 0xffff_ffff_ffff_fff8, -1), // sxtw: w2 = -8 bytes
            (0b111, 1, (-3i64) as u64, -3),        // sxtx #3
            (0b111, 0, (-32i64) as u64, -4),       // sxtx
            (0b010, 0, 0x8000_0000_0000_0008, 1),  // uxtw ignores bit 63
            (0b011, 1, 0, 0),
        ];
        for (option, s, index, slot) in cases {
            state.write_x(2, index);
            run(&mut state, ldr_reg(option, s, A64Reg::x(0))).unwrap();
            assert_eq!(
                state.read_x(0),
                0x1000_u64.wrapping_add_signed(slot),
                "option {option:#05b} S {s} index {index:#x}"
            );
        }
        // Byte and halfword forms: S = 1 shifts by log2(size); XZR index is zero.
        state.write_x(2, 3);
        run(
            &mut state,
            A64Insn::LdrhRegLdrh32LdstRegoff {
                rm: A64Reg::x(2),
                option: 0b011,
                s: 1,
                rn: A64Reg::x_sp(1),
                rt: A64Reg::w(0),
            },
        )
        .unwrap();
        assert_eq!(state.read_x(0), state.read_le(PAGE + 0x1006, 2));
        run(
            &mut state,
            A64Insn::LdrsbRegLdrsb64blLdstRegoff {
                rm: A64Reg::x(31),
                s: 1,
                rn: A64Reg::x_sp(1),
                rt: A64Reg::x(0),
            },
        )
        .unwrap();
        assert_eq!(state.read_x(0), 0);
    }

    #[test]
    fn unaligned_and_page_crossing_accesses_are_allowed_on_mapped_pages() {
        let mut state = two_pages();
        for i in 0..16u64 {
            state.write_le(PAGE + 0xff8 + i, 1, 0x10 + i);
        }
        // Unaligned 8-byte load inside a page.
        state.write_x(1, PAGE + 0xff9);
        run(
            &mut state,
            A64Insn::LdurGenLdur64LdstUnscaled {
                rt: A64Reg::x(0),
                mem: off(1),
            },
        )
        .unwrap();
        assert_eq!(state.read_x(0), 0x1817_1615_1413_1211);
        // Halfword and word straddling the page boundary at 0xa000.
        state.write_x(1, PAGE + 0xfff);
        run(
            &mut state,
            A64Insn::LdurshLdursh64LdstUnscaled {
                rt: A64Reg::x(0),
                mem: off(1),
            },
        )
        .unwrap();
        assert_eq!(state.read_x(0), 0x1817);
        state.write_x(1, PAGE + 0xffe);
        run(
            &mut state,
            A64Insn::LdurswLdursw64LdstUnscaled {
                rt: A64Reg::x(0),
                mem: off(1),
            },
        )
        .unwrap();
        assert_eq!(state.read_x(0), 0x1918_1716);
        state.write_x(3, 0xa1b2);
        state.write_x(1, PAGE + 0xfff);
        run(
            &mut state,
            A64Insn::SturhSturh32LdstUnscaled {
                rt: A64Reg::w(3),
                mem: off(1),
            },
        )
        .unwrap();
        assert_eq!(state.read_le(PAGE + 0xfff, 2), 0xa1b2);
    }

    #[test]
    fn page_crossing_into_unmapped_memory_faults_without_side_effects() {
        let mut state = MachineState::new();
        state
            .map_user_range(PAGE, PAGE + 0x1000, PagePerm::ReadWrite)
            .unwrap();
        state.write_x(1, PAGE + 0xffe);
        state.write_x(2, 1);
        state.write_x(0, 0x55);
        let before = state.clone();
        for insn in [
            A64Insn::LdrRegGenLdr32LdstRegoff {
                rm: A64Reg::x(2),
                option: 0b011,
                s: 0,
                rn: A64Reg::x_sp(1),
                rt: A64Reg::w(0),
            },
            A64Insn::LdrhImmLdrh32LdstImmpre {
                rt: A64Reg::w(0),
                mem: A64Mem::pre_index(A64Reg::x_sp(1), A64Imm::signed(1, 9)),
            },
            A64Insn::StpGenStp32LdstpairPost {
                rt2: A64Reg::w(0),
                rt: A64Reg::w(2),
                mem: A64Mem::post_index(A64Reg::x_sp(1), A64Imm::scaled_signed(1, 7, 2)),
            },
            A64Insn::LdpswLdpsw64LdstpairOff {
                rt2: A64Reg::x(3),
                rt: A64Reg::x(0),
                mem: A64Mem::offset(A64Reg::x_sp(1), A64Imm::scaled_signed(0x7f, 7, 2)),
            },
        ] {
            let mut run_state = before.clone();
            match run(&mut run_state, insn) {
                Err(InsnError::Fault(fault)) => {
                    assert_eq!(fault.pc, 0x4000, "{insn:?}");
                }
                other => panic!("{insn:?}: expected a fault, got {other:?}"),
            }
            assert_eq!(run_state, before, "{insn:?} mutated state");
        }
    }

    #[test]
    fn pair_loads_extend_each_element() {
        let mut state = two_pages();
        state.write_le(PAGE, 4, 0x8000_0000);
        state.write_le(PAGE + 4, 4, 0x7fff_ffff);
        state.write_x(3, u64::MAX);
        run(
            &mut state,
            A64Insn::LdpswLdpsw64LdstpairPost {
                rt2: A64Reg::x(3),
                rt: A64Reg::x(0),
                mem: A64Mem::post_index(A64Reg::x_sp(1), A64Imm::scaled_signed(2, 7, 2)),
            },
        )
        .unwrap();
        assert_eq!(state.read_x(0), 0xffff_ffff_8000_0000);
        assert_eq!(state.read_x(3), 0x7fff_ffff);
        assert_eq!(state.read_x(1), PAGE + 8);
        state.write_x(1, PAGE);
        state.write_x(3, u64::MAX);
        run(
            &mut state,
            A64Insn::LdpGenLdp32LdstpairOff {
                rt2: A64Reg::w(3),
                rt: A64Reg::w(0),
                mem: A64Mem::offset(A64Reg::x_sp(1), A64Imm::scaled_signed(0, 7, 2)),
            },
        )
        .unwrap();
        assert_eq!(state.read_x(0), 0x8000_0000);
        assert_eq!(state.read_x(3), 0x7fff_ffff);
    }

    #[test]
    fn literal_loads_address_from_the_pc_and_prefetch_never_faults() {
        let mut state = MachineState::new();
        state
            .map_user_range(0x3000, 0x4000, PagePerm::ReadOnly)
            .unwrap();
        state.write_le(0x3ff8, 8, 0x8000_0000_8000_0001);
        // pc 0x4000, imm19 = -2 words.
        let imm19 = A64Imm::scaled_signed(0x7fffe, 19, 2);
        run(
            &mut state,
            A64Insn::LdrswLitLdrsw64Loadlit {
                imm19,
                rt: A64Reg::x(0),
            },
        )
        .unwrap();
        assert_eq!(state.read_x(0), 0xffff_ffff_8000_0001);
        run(
            &mut state,
            A64Insn::LdrLitGenLdr64Loadlit {
                imm19,
                rt: A64Reg::x(0),
            },
        )
        .unwrap();
        assert_eq!(state.read_x(0), 0x8000_0000_8000_0001);

        // PRFM of an unmapped address: no fault, no state change.
        state.write_x(1, 0xdead_0000);
        let before = state.clone();
        for insn in [
            A64Insn::PrfmImmPrfmPLdstPos {
                imm12: A64Imm::unsigned(1, 12),
                rn: A64Reg::x_sp(1),
                rt: 0,
            },
            A64Insn::PrfmRegPrfmPLdstRegoff {
                rm: A64Reg::x(1),
                option: 0b011,
                s: 1,
                rn: A64Reg::x_sp(1),
                rt: 0b10001,
            },
            A64Insn::PrfmLitPrfmPLoadlit {
                imm19: A64Imm::unsigned(0x40000, 19),
                rt: 0,
            },
        ] {
            assert_eq!(run(&mut state, insn), Ok(0x4004), "{insn:?}");
            assert_eq!(state, before, "{insn:?}");
        }
    }
}
