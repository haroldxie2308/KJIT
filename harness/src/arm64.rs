use crate::model::{ExecutionResult, HaltReason, MachineState};
use crate::shared::arm64::{decode_word, A64Condition, A64Imm, A64Insn, A64Mem, A64Reg};
use crate::shared::trans::cfg::RuntimeExitReason;

pub fn execute_program(
    program: &[u8],
    base_pc: u64,
    initial_state: &MachineState,
) -> Result<ExecutionResult, String> {
    execute_program_from(program, base_pc, base_pc, initial_state)
}

pub fn execute_program_from(
    program: &[u8],
    base_pc: u64,
    entry_pc: u64,
    initial_state: &MachineState,
) -> Result<ExecutionResult, String> {
    let mut stepper = OriginalStepper::new(program, base_pc, entry_pc, initial_state)?;
    let mut steps = 0usize;

    loop {
        let Some(step) = stepper.step()? else {
            return Err("original stepper stopped without a halt reason".to_string());
        };
        if step.executed {
            steps += 1;
        }
        if let Some(halt_reason) = step.halt_reason {
            return Ok(ExecutionResult {
                state: step.state,
                halt_reason,
                steps,
            });
        }
    }
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

#[derive(Debug)]
pub struct OriginalStepper<'a> {
    program: &'a [u8],
    base_pc: u64,
    pc: u64,
    state: MachineState,
    stopped: bool,
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
        })
    }

    pub fn pc(&self) -> u64 {
        self.pc
    }

    pub fn state(&self) -> &MachineState {
        &self.state
    }

    pub fn resume_at(&mut self, pc: u64) {
        self.pc = pc;
        self.stopped = false;
    }

    pub fn step(&mut self) -> Result<Option<OriginalStep>, String> {
        if self.stopped {
            return Ok(None);
        }

        if self.pc < self.base_pc {
            return Err(format!("pc moved before base address: {:#x}", self.pc));
        }

        let offset = self.pc - self.base_pc;
        if offset % 4 != 0 {
            return Err(format!("pc is not word-aligned: {:#x}", self.pc));
        }

        let insn_index = (offset / 4) as usize;
        if insn_index >= self.program.len() / 4 {
            self.stopped = true;
            return Ok(Some(OriginalStep {
                pc: self.pc,
                next_pc: None,
                executed: false,
                runtime_exit: None,
                halt_reason: Some(HaltReason::FellOffEnd),
                state: self.state.clone(),
            }));
        }

        let chunk = &self.program[insn_index * 4..insn_index * 4 + 4];
        let word = u32::from_le_bytes(chunk.try_into().unwrap());
        let decoded = decode_word(word, self.pc).map_err(|err| err.to_string())?;

        if let Some(reason) = decoded.inner.runtime_exit_reason(self.pc) {
            apply_runtime_exit_side_effect(decoded.inner, self.pc, &mut self.state);
            self.stopped = true;
            return Ok(Some(OriginalStep {
                pc: self.pc,
                next_pc: None,
                executed: true,
                runtime_exit: Some(reason),
                halt_reason: Some(HaltReason::RuntimeExit { reason }),
                state: self.state.clone(),
            }));
        }

        let pc = self.pc;
        let next_pc = execute_insn(decoded.inner, pc, &mut self.state)?;
        self.pc = next_pc;
        Ok(Some(OriginalStep {
            pc,
            next_pc: Some(next_pc),
            executed: true,
            runtime_exit: None,
            halt_reason: None,
            state: self.state.clone(),
        }))
    }
}

pub(crate) fn execute_insn(
    insn: A64Insn,
    pc: u64,
    state: &mut MachineState,
) -> Result<u64, String> {
    match insn {
        A64Insn::NopNopHiHints {} => Ok(pc + 4),

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
        A64Insn::OrrLogShiftOrr64LogShift {
            shift,
            rm,
            imm6,
            rn,
            rd,
        } => {
            let shifted = shifted_reg64(state.read_reg(rm), shift, imm6.raw() as u8)?;
            state.write_reg(rd, state.read_reg(rn) | shifted);
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
            let lhs = read_reg_sized(state, rn, 32);
            let rhs = add_sub_imm(sh, imm12, insn)?;
            let result = lhs.wrapping_sub(rhs);
            update_sub_flags_sized(state, lhs, rhs, result, 32);
            write_reg_sized(state, rd, result, 32);
            Ok(pc + 4)
        }
        A64Insn::SubsAddsubImmSubs64sAddsubImm { sh, imm12, rn, rd } => {
            let lhs = state.read_reg(rn);
            let rhs = add_sub_imm(sh, imm12, insn)?;
            let result = lhs.wrapping_sub(rhs);
            state.update_sub_flags(lhs, rhs, result);
            state.write_reg(rd, result);
            Ok(pc + 4)
        }

        A64Insn::BUncondBOnlyBranchImm { .. } => insn
            .direct_branch_target(pc)
            .ok_or_else(|| format!("missing branch target for {}", insn.key())),
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

        A64Insn::LdrImmGenLdr32LdstPos { rt, mem } => {
            let addr = resolve_mem_addr(state, mem);
            state.write_reg(rt, state.read_u32(addr) as u64);
            Ok(pc + 4)
        }
        A64Insn::LdrImmGenLdr64LdstPos { rt, mem } => {
            let addr = resolve_mem_addr(state, mem);
            state.write_reg(rt, state.read_u64(addr));
            Ok(pc + 4)
        }
        A64Insn::StrImmGenStr32LdstPos { rt, mem } => {
            let addr = resolve_mem_addr(state, mem);
            state.write_u32(addr, read_reg_sized(state, rt, 32) as u32);
            Ok(pc + 4)
        }
        A64Insn::StrImmGenStr64LdstPos { rt, mem } => {
            let addr = resolve_mem_addr(state, mem);
            state.write_u64(addr, state.read_reg(rt));
            Ok(pc + 4)
        }

        A64Insn::LdrImmGenLdr32LdstImmpre { rt, mem } => {
            let addr = resolve_mem_addr(state, mem);
            state.write_reg(rt, state.read_u32(addr) as u64);
            Ok(pc + 4)
        }
        A64Insn::LdrImmGenLdr64LdstImmpre { rt, mem } => {
            let addr = resolve_mem_addr(state, mem);
            state.write_reg(rt, state.read_u64(addr));
            Ok(pc + 4)
        }
        A64Insn::StrImmGenStr32LdstImmpre { rt, mem } => {
            let addr = resolve_mem_addr(state, mem);
            state.write_u32(addr, read_reg_sized(state, rt, 32) as u32);
            Ok(pc + 4)
        }
        A64Insn::StrImmGenStr64LdstImmpre { rt, mem } => {
            let addr = resolve_mem_addr(state, mem);
            state.write_u64(addr, state.read_reg(rt));
            Ok(pc + 4)
        }

        A64Insn::LdrImmGenLdr32LdstImmpost { rt, mem } => {
            let addr = resolve_mem_addr(state, mem);
            state.write_reg(rt, state.read_u32(addr) as u64);
            Ok(pc + 4)
        }
        A64Insn::LdrImmGenLdr64LdstImmpost { rt, mem } => {
            let addr = resolve_mem_addr(state, mem);
            state.write_reg(rt, state.read_u64(addr));
            Ok(pc + 4)
        }
        A64Insn::StrImmGenStr32LdstImmpost { rt, mem } => {
            let addr = resolve_mem_addr(state, mem);
            state.write_u32(addr, read_reg_sized(state, rt, 32) as u32);
            Ok(pc + 4)
        }
        A64Insn::StrImmGenStr64LdstImmpost { rt, mem } => {
            let addr = resolve_mem_addr(state, mem);
            state.write_u64(addr, state.read_reg(rt));
            Ok(pc + 4)
        }

        A64Insn::LdpGenLdp64LdstpairPost { rt2, rt, mem } => {
            execute_ldp64(state, mem, rt, rt2)?;
            Ok(pc + 4)
        }
        A64Insn::LdpGenLdp64LdstpairPre { rt2, rt, mem } => {
            execute_ldp64(state, mem, rt, rt2)?;
            Ok(pc + 4)
        }
        A64Insn::LdpGenLdp64LdstpairOff { rt2, rt, mem } => {
            execute_ldp64(state, mem, rt, rt2)?;
            Ok(pc + 4)
        }
        A64Insn::StpGenStp64LdstpairPost { rt2, rt, mem } => {
            execute_stp64(state, mem, rt, rt2);
            Ok(pc + 4)
        }
        A64Insn::StpGenStp64LdstpairPre { rt2, rt, mem } => {
            execute_stp64(state, mem, rt, rt2);
            Ok(pc + 4)
        }
        A64Insn::StpGenStp64LdstpairOff { rt2, rt, mem } => {
            execute_stp64(state, mem, rt, rt2);
            Ok(pc + 4)
        }

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
        A64Insn::SvcSvcExException { .. } => {
            Err("raw SVC is not executable inside the userspace runtime fragment".to_string())
        }
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

fn shifted_reg64(value: u64, shift: u8, amount: u8) -> Result<u64, String> {
    match shift {
        0 => Ok(value << amount),
        1 => Ok(value >> amount),
        2 => Ok(((value as i64) >> amount) as u64),
        3 => Ok(value.rotate_right(amount as u32)),
        _ => Err(format!("unsupported shifted-register shift field: {shift}")),
    }
}

fn execute_ldp64(
    state: &mut MachineState,
    mem: A64Mem,
    rt: A64Reg,
    rt2: A64Reg,
) -> Result<(), String> {
    let base = mem.base();
    if mem_has_writeback(mem)
        && base.enc() != 31
        && (base.enc() == rt.enc() || base.enc() == rt2.enc())
    {
        return Err("writeback LDP with base/target overlap is unsupported".to_string());
    }

    let addr = resolve_mem_addr(state, mem);
    let first = state.read_u64(addr);
    let second = state.read_u64(addr.wrapping_add(8));
    state.write_reg(rt, first);
    state.write_reg(rt2, second);
    Ok(())
}

fn execute_stp64(state: &mut MachineState, mem: A64Mem, rt: A64Reg, rt2: A64Reg) {
    let first = state.read_reg(rt);
    let second = state.read_reg(rt2);
    let addr = resolve_mem_addr(state, mem);
    state.write_u64(addr, first);
    state.write_u64(addr.wrapping_add(8), second);
}

fn mem_has_writeback(mem: A64Mem) -> bool {
    matches!(mem, A64Mem::PreIndex { .. } | A64Mem::PostIndex { .. })
}

fn resolve_mem_addr(state: &mut MachineState, mem: A64Mem) -> u64 {
    let base_reg = mem.base();
    let base = state.read_reg(base_reg);
    let offset = mem.offset_imm().value();

    match mem {
        A64Mem::Offset { .. } => add_signed(base, offset),
        A64Mem::PreIndex { .. } => {
            let addr = add_signed(base, offset);
            state.write_reg(base_reg, addr);
            addr
        }
        A64Mem::PostIndex { .. } => {
            state.write_reg(base_reg, add_signed(base, offset));
            base
        }
    }
}

fn branch_on_zero(
    insn: A64Insn,
    pc: u64,
    state: &MachineState,
    rt: A64Reg,
    bits: u8,
    branch_if_zero: bool,
) -> Result<u64, String> {
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
) -> Result<u64, String> {
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

fn eval_condition(condition: A64Condition, state: &MachineState) -> bool {
    let flags = state.flags;
    match condition {
        A64Condition::Eq => flags.z,
        A64Condition::Ne => !flags.z,
        A64Condition::Ge => flags.n == flags.v,
        A64Condition::Lt => flags.n != flags.v,
        A64Condition::Gt => !flags.z && flags.n == flags.v,
        A64Condition::Le => flags.z || flags.n != flags.v,
        A64Condition::Al => true,
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

fn update_sub_flags_sized(state: &mut MachineState, lhs: u64, rhs: u64, result: u64, bits: u8) {
    let mask = match bits {
        32 => 0xFFFF_FFFF,
        64 => u64::MAX,
        _ => unreachable!("unsupported flag width"),
    };
    let sign = 1_u64 << (bits - 1);
    let lhs = lhs & mask;
    let rhs = rhs & mask;
    let result = result & mask;

    state.flags.n = (result & sign) != 0;
    state.flags.z = result == 0;
    state.flags.c = lhs >= rhs;
    state.flags.v = ((lhs ^ rhs) & (lhs ^ result) & sign) != 0;
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
    use crate::shared::arm64::ergo::{scaled_simm, uimm, x};

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
            execute_insn(A64Insn::BlrBlr64BranchReg { rn: x(30) }, 0x4000, &mut state).unwrap();

        assert_eq!(next_pc, 0x9000);
        assert_eq!(state.read_x(30), 0x4004);
    }

    #[test]
    fn add_sub_immediate_distinguishes_sp_from_xzr() {
        let mut state = MachineState::new();
        state.set_sp(0x1000);

        execute_insn(
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

        execute_insn(
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

    #[test]
    fn ldr_str_use_sp_as_memory_base() {
        let mut state = MachineState::new();
        state.set_sp(0x8000);
        state.write_x(0, 0x1122_3344_5566_7788);

        execute_insn(
            A64Insn::StrImmGenStr64LdstPos {
                rt: A64Reg::x(0),
                mem: A64Mem::offset(A64Reg::x_sp(31), A64Imm::scaled_unsigned(1, 12, 3)),
            },
            0x4000,
            &mut state,
        )
        .unwrap();
        assert_eq!(state.read_u64(0x8008), 0x1122_3344_5566_7788);

        execute_insn(
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
        state.set_sp(0x9000);
        state.write_x(29, 0x1111_2222_3333_4444);
        state.write_x(30, 0xAAAA_BBBB_CCCC_DDDD);

        execute_insn(
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
        execute_insn(
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
