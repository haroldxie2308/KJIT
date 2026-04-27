use crate::arm64::{
    encode_add_imm, encode_add_reg, encode_b, encode_b_cond, encode_cbnz, encode_cbz,
    encode_cmp_imm, encode_cmp_reg, encode_ldr_imm, encode_movk, encode_movz, encode_str_imm,
    encode_sub_imm, encode_sub_reg, Condition,
};
use crate::model::{ExecutionResult, HaltReason, MachineState};

const MAX_STEPS: usize = 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IrInsn {
    Nop,
    LoadImm64 { rd: u8, value: u64 },
    AddImm { rd: u8, rn: u8, imm12: u16 },
    AddReg { rd: u8, rn: u8, rm: u8 },
    SubImm { rd: u8, rn: u8, imm12: u16 },
    SubReg { rd: u8, rn: u8, rm: u8 },
    CmpImm { rn: u8, imm12: u16 },
    CmpReg { rn: u8, rm: u8 },
    B { target: usize },
    BCond { cond: Condition, target: usize },
    Cbz { rt: u8, target: usize },
    Cbnz { rt: u8, target: usize },
    StrImm { rt: u8, rn: u8, offset: u16 },
    LdrImm { rt: u8, rn: u8, offset: u16 },
}

pub type IrProgram = Vec<IrInsn>;

impl IrInsn {
    fn encoded_words(self) -> usize {
        match self {
            Self::LoadImm64 { .. } => 4,
            _ => 1,
        }
    }
}

pub fn execute_program(
    insns: &[IrInsn],
    initial_state: &MachineState,
) -> Result<ExecutionResult, String> {
    let mut state = initial_state.clone();
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

        match insn {
            IrInsn::Nop => {
                pc += 1;
            }
            IrInsn::LoadImm64 { rd, value } => {
                state.write_reg(rd, value);
                pc += 1;
            }
            IrInsn::AddImm { rd, rn, imm12 } => {
                let value = state.read_reg(rn).wrapping_add(imm12 as u64);
                state.write_reg(rd, value);
                pc += 1;
            }
            IrInsn::AddReg { rd, rn, rm } => {
                let value = state.read_reg(rn).wrapping_add(state.read_reg(rm));
                state.write_reg(rd, value);
                pc += 1;
            }
            IrInsn::SubImm { rd, rn, imm12 } => {
                let value = state.read_reg(rn).wrapping_sub(imm12 as u64);
                state.write_reg(rd, value);
                pc += 1;
            }
            IrInsn::SubReg { rd, rn, rm } => {
                let value = state.read_reg(rn).wrapping_sub(state.read_reg(rm));
                state.write_reg(rd, value);
                pc += 1;
            }
            IrInsn::CmpImm { rn, imm12 } => {
                let lhs = state.read_reg(rn);
                let rhs = imm12 as u64;
                let result = lhs.wrapping_sub(rhs);
                state.update_sub_flags(lhs, rhs, result);
                pc += 1;
            }
            IrInsn::CmpReg { rn, rm } => {
                let lhs = state.read_reg(rn);
                let rhs = state.read_reg(rm);
                let result = lhs.wrapping_sub(rhs);
                state.update_sub_flags(lhs, rhs, result);
                pc += 1;
            }
            IrInsn::B { target } => {
                pc = target;
            }
            IrInsn::BCond { cond, target } => {
                if cond.eval(&state) {
                    pc = target;
                } else {
                    pc += 1;
                }
            }
            IrInsn::Cbz { rt, target } => {
                if state.read_reg(rt) == 0 {
                    pc = target;
                } else {
                    pc += 1;
                }
            }
            IrInsn::Cbnz { rt, target } => {
                if state.read_reg(rt) != 0 {
                    pc = target;
                } else {
                    pc += 1;
                }
            }
            IrInsn::StrImm { rt, rn, offset } => {
                let addr = state.read_reg(rn).wrapping_add(offset as u64);
                let value = state.read_reg(rt);
                state.write_u64(addr, value);
                pc += 1;
            }
            IrInsn::LdrImm { rt, rn, offset } => {
                let addr = state.read_reg(rn).wrapping_add(offset as u64);
                let value = state.read_u64(addr);
                state.write_reg(rt, value);
                pc += 1;
            }
        }
    }
}

pub fn encode_program(insns: &[IrInsn]) -> Result<Vec<u8>, String> {
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
        match insn {
            IrInsn::Nop => bytes.extend_from_slice(&0xD503201F_u32.to_le_bytes()),
            IrInsn::LoadImm64 { rd, value } => {
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
            IrInsn::AddImm { rd, rn, imm12 } => {
                bytes.extend_from_slice(&encode_add_imm(rd, rn, imm12).to_le_bytes());
            }
            IrInsn::AddReg { rd, rn, rm } => {
                bytes.extend_from_slice(&encode_add_reg(rd, rn, rm).to_le_bytes());
            }
            IrInsn::SubImm { rd, rn, imm12 } => {
                bytes.extend_from_slice(&encode_sub_imm(rd, rn, imm12).to_le_bytes());
            }
            IrInsn::SubReg { rd, rn, rm } => {
                bytes.extend_from_slice(&encode_sub_reg(rd, rn, rm).to_le_bytes());
            }
            IrInsn::CmpImm { rn, imm12 } => {
                bytes.extend_from_slice(&encode_cmp_imm(rn, imm12).to_le_bytes());
            }
            IrInsn::CmpReg { rn, rm } => {
                bytes.extend_from_slice(&encode_cmp_reg(rn, rm).to_le_bytes());
            }
            IrInsn::B { target } => {
                let target_pc = (encoded_offsets[target] * 4) as i64;
                let word = encode_b(target_pc - curr_pc)?;
                bytes.extend_from_slice(&word.to_le_bytes());
            }
            IrInsn::BCond { cond, target } => {
                let target_pc = (encoded_offsets[target] * 4) as i64;
                let word = encode_b_cond(cond, target_pc - curr_pc)?;
                bytes.extend_from_slice(&word.to_le_bytes());
            }
            IrInsn::Cbz { rt, target } => {
                let target_pc = (encoded_offsets[target] * 4) as i64;
                let word = encode_cbz(rt, target_pc - curr_pc)?;
                bytes.extend_from_slice(&word.to_le_bytes());
            }
            IrInsn::Cbnz { rt, target } => {
                let target_pc = (encoded_offsets[target] * 4) as i64;
                let word = encode_cbnz(rt, target_pc - curr_pc)?;
                bytes.extend_from_slice(&word.to_le_bytes());
            }
            IrInsn::StrImm { rt, rn, offset } => {
                let word = encode_str_imm(rt, rn, offset)?;
                bytes.extend_from_slice(&word.to_le_bytes());
            }
            IrInsn::LdrImm { rt, rn, offset } => {
                let word = encode_ldr_imm(rt, rn, offset)?;
                bytes.extend_from_slice(&word.to_le_bytes());
            }
        }
    }
    Ok(bytes)
}
