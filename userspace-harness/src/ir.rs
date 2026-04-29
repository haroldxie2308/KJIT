use std::collections::BTreeMap;

use crate::arm64::{
    encode_add_imm, encode_add_reg, encode_b, encode_b_cond, encode_cbnz, encode_cbz,
    encode_cmp_imm, encode_cmp_reg, encode_ldr_imm, encode_movk, encode_movz, encode_str_imm,
    encode_sub_imm, encode_sub_reg, Condition,
};
use crate::model::{ExecutionResult, HaltReason, MachineState};
use crate::shared::trans_core::arm64::BranchCondition;
pub use crate::shared::trans_core::ir::{IrInsn, IrInsnKind, IrProgram, LinkSlot};

const MAX_STEPS: usize = 1024;

impl IrInsn {
    fn encoded_words(self) -> usize {
        match self.kind {
            IrInsnKind::LoadImm64 { .. } => 4,
            _ => 1,
        }
    }
}

pub fn execute_program(
    insns: &[IrInsn],
    initial_state: &MachineState,
) -> Result<ExecutionResult, String> {
    let mut state = initial_state.clone();
    let pc_to_index = build_pc_to_index(insns)?;
    let mut pc = 0_usize;
    let mut steps = 0;

    loop {
        if steps >= MAX_STEPS {
            return Ok(ExecutionResult {
                state,
                halt_reason: HaltReason::StepLimitExceeded,
                steps,
            });
        }

        if pc == insns.len() {
            return Ok(ExecutionResult {
                state,
                halt_reason: HaltReason::FellOffEnd,
                steps,
            });
        }

        let insn = *insns
            .get(pc)
            .ok_or_else(|| format!("IR pc out of range: {pc}"))?;
        steps += 1;

        match insn.kind {
            IrInsnKind::Nop => {
                pc += 1;
            }
            IrInsnKind::LoadImm64 { rd, value } => {
                state.write_reg(rd, value);
                pc += 1;
            }
            IrInsnKind::AddImm { rd, rn, imm12 } => {
                let value = state.read_reg(rn).wrapping_add(imm12 as u64);
                state.write_reg(rd, value);
                pc += 1;
            }
            IrInsnKind::AddReg { rd, rn, rm } => {
                let value = state.read_reg(rn).wrapping_add(state.read_reg(rm));
                state.write_reg(rd, value);
                pc += 1;
            }
            IrInsnKind::SubImm { rd, rn, imm12 } => {
                let value = state.read_reg(rn).wrapping_sub(imm12 as u64);
                state.write_reg(rd, value);
                pc += 1;
            }
            IrInsnKind::SubReg { rd, rn, rm } => {
                let value = state.read_reg(rn).wrapping_sub(state.read_reg(rm));
                state.write_reg(rd, value);
                pc += 1;
            }
            IrInsnKind::CmpImm { rn, imm12 } => {
                let lhs = state.read_reg(rn);
                let rhs = imm12 as u64;
                let result = lhs.wrapping_sub(rhs);
                state.update_sub_flags(lhs, rhs, result);
                pc += 1;
            }
            IrInsnKind::CmpReg { rn, rm } => {
                let lhs = state.read_reg(rn);
                let rhs = state.read_reg(rm);
                let result = lhs.wrapping_sub(rhs);
                state.update_sub_flags(lhs, rhs, result);
                pc += 1;
            }
            IrInsnKind::B { target_pc } => {
                pc = ir_index_for_pc(target_pc, &pc_to_index)?;
            }
            IrInsnKind::BCond { cond, target_pc } => {
                if eval_condition_for_jit(cond, &state) {
                    pc = ir_index_for_pc(target_pc, &pc_to_index)?;
                } else {
                    pc += 1;
                }
            }
            IrInsnKind::Cbz { rt, target_pc } => {
                if state.read_reg(rt) == 0 {
                    pc = ir_index_for_pc(target_pc, &pc_to_index)?;
                } else {
                    pc += 1;
                }
            }
            IrInsnKind::Cbnz { rt, target_pc } => {
                if state.read_reg(rt) != 0 {
                    pc = ir_index_for_pc(target_pc, &pc_to_index)?;
                } else {
                    pc += 1;
                }
            }
            IrInsnKind::StrImm { rt, rn, offset } => {
                let addr = state.read_reg(rn).wrapping_add(offset as u64);
                let value = state.read_reg(rt);
                state.write_u64(addr, value);
                pc += 1;
            }
            IrInsnKind::LdrImm { rt, rn, offset } => {
                let addr = state.read_reg(rn).wrapping_add(offset as u64);
                let value = state.read_u64(addr);
                state.write_reg(rt, value);
                pc += 1;
            }
            IrInsnKind::RuntimeExit { reason, .. } => {
                return Ok(ExecutionResult {
                    state,
                    halt_reason: HaltReason::RuntimeExit { reason },
                    steps,
                });
            }
        }
    }
}

pub fn encode_program(insns: &[IrInsn]) -> Result<Vec<u8>, String> {
    let pc_to_index = build_pc_to_index(insns)?;
    let mut encoded_offsets = Vec::with_capacity(insns.len() + 1);
    let mut total_words = 0_usize;
    for insn in insns.iter().copied() {
        encoded_offsets.push(total_words);
        total_words += insn.encoded_words();
    }
    encoded_offsets.push(total_words);

    let mut bytes = Vec::with_capacity(total_words * 4);
    for (index, insn) in insns.iter().copied().enumerate() {
        let curr_pc = (encoded_offsets[index] * 4) as i64;
        match insn.kind {
            IrInsnKind::Nop => bytes.extend_from_slice(&0xD503201F_u32.to_le_bytes()),
            IrInsnKind::LoadImm64 { rd, value } => {
                let words = [
                    encode_movz(rd, ((value >> 48) & 0xFFFF) as u16, 48)?,
                    encode_movk(rd, ((value >> 32) & 0xFFFF) as u16, 32)?,
                    encode_movk(rd, ((value >> 16) & 0xFFFF) as u16, 16)?,
                    encode_movk(rd, (value & 0xFFFF) as u16, 0)?,
                ];
                for word in words {
                    bytes.extend_from_slice(&word.to_le_bytes());
                }
            }
            IrInsnKind::AddImm { rd, rn, imm12 } => {
                bytes.extend_from_slice(&encode_add_imm(rd, rn, imm12).to_le_bytes());
            }
            IrInsnKind::AddReg { rd, rn, rm } => {
                bytes.extend_from_slice(&encode_add_reg(rd, rn, rm).to_le_bytes());
            }
            IrInsnKind::SubImm { rd, rn, imm12 } => {
                bytes.extend_from_slice(&encode_sub_imm(rd, rn, imm12).to_le_bytes());
            }
            IrInsnKind::SubReg { rd, rn, rm } => {
                bytes.extend_from_slice(&encode_sub_reg(rd, rn, rm).to_le_bytes());
            }
            IrInsnKind::CmpImm { rn, imm12 } => {
                bytes.extend_from_slice(&encode_cmp_imm(rn, imm12).to_le_bytes());
            }
            IrInsnKind::CmpReg { rn, rm } => {
                bytes.extend_from_slice(&encode_cmp_reg(rn, rm).to_le_bytes());
            }
            IrInsnKind::B { target_pc } => {
                let target = ir_index_for_pc(target_pc, &pc_to_index)?;
                let target_pc = (encoded_offsets[target] * 4) as i64;
                let word = encode_b(target_pc - curr_pc)?;
                bytes.extend_from_slice(&word.to_le_bytes());
            }
            IrInsnKind::BCond { cond, target_pc } => {
                let target = ir_index_for_pc(target_pc, &pc_to_index)?;
                let target_pc = (encoded_offsets[target] * 4) as i64;
                let word = encode_b_cond(harness_condition(cond), target_pc - curr_pc)?;
                bytes.extend_from_slice(&word.to_le_bytes());
            }
            IrInsnKind::Cbz { rt, target_pc } => {
                let target = ir_index_for_pc(target_pc, &pc_to_index)?;
                let target_pc = (encoded_offsets[target] * 4) as i64;
                let word = encode_cbz(rt, target_pc - curr_pc)?;
                bytes.extend_from_slice(&word.to_le_bytes());
            }
            IrInsnKind::Cbnz { rt, target_pc } => {
                let target = ir_index_for_pc(target_pc, &pc_to_index)?;
                let target_pc = (encoded_offsets[target] * 4) as i64;
                let word = encode_cbnz(rt, target_pc - curr_pc)?;
                bytes.extend_from_slice(&word.to_le_bytes());
            }
            IrInsnKind::StrImm { rt, rn, offset } => {
                let word = encode_str_imm(rt, rn, offset)?;
                bytes.extend_from_slice(&word.to_le_bytes());
            }
            IrInsnKind::LdrImm { rt, rn, offset } => {
                let word = encode_ldr_imm(rt, rn, offset)?;
                bytes.extend_from_slice(&word.to_le_bytes());
            }
            IrInsnKind::RuntimeExit { .. } => {
                return Err(
                    "cannot encode runtime exits as standalone AArch64 bytes yet".to_string(),
                );
            }
        }
    }
    Ok(bytes)
}

fn build_pc_to_index(insns: &[IrInsn]) -> Result<BTreeMap<u64, usize>, String> {
    let mut map = BTreeMap::new();
    for (index, insn) in insns.iter().enumerate() {
        if map.insert(insn.pc, index).is_some() {
            return Err(format!("duplicate IR pc: {:#x}", insn.pc));
        }
    }
    Ok(map)
}

fn ir_index_for_pc(target_pc: u64, pc_to_index: &BTreeMap<u64, usize>) -> Result<usize, String> {
    pc_to_index
        .get(&target_pc)
        .copied()
        .ok_or_else(|| format!("IR target pc not found: {target_pc:#x}"))
}

pub(crate) fn eval_condition_for_jit(cond: BranchCondition, state: &MachineState) -> bool {
    let flags = state.flags;
    match cond {
        BranchCondition::Eq => flags.z,
        BranchCondition::Ne => !flags.z,
        BranchCondition::Ge => flags.n == flags.v,
        BranchCondition::Lt => flags.n != flags.v,
        BranchCondition::Gt => !flags.z && flags.n == flags.v,
        BranchCondition::Le => flags.z || flags.n != flags.v,
        BranchCondition::Al => true,
    }
}

fn harness_condition(cond: BranchCondition) -> Condition {
    match cond {
        BranchCondition::Eq => Condition::Eq,
        BranchCondition::Ne => Condition::Ne,
        BranchCondition::Ge => Condition::Ge,
        BranchCondition::Lt => Condition::Lt,
        BranchCondition::Gt => Condition::Gt,
        BranchCondition::Le => Condition::Le,
        BranchCondition::Al => Condition::Al,
    }
}
