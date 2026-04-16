use crate::model::{ExecutionResult, HaltReason, MachineState};

const MAX_STEPS: usize = 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Condition {
    Eq,
    Ne,
    Ge,
    Lt,
    Gt,
    Le,
    Al,
}

impl Condition {
    pub fn from_bits(bits: u8) -> Result<Self, String> {
        match bits {
            0x0 => Ok(Self::Eq),
            0x1 => Ok(Self::Ne),
            0xA => Ok(Self::Ge),
            0xB => Ok(Self::Lt),
            0xC => Ok(Self::Gt),
            0xD => Ok(Self::Le),
            0xE | 0xF => Ok(Self::Al),
            _ => Err(format!("unsupported condition bits: {bits:#x}")),
        }
    }

    pub fn encode(self) -> u8 {
        match self {
            Self::Eq => 0x0,
            Self::Ne => 0x1,
            Self::Ge => 0xA,
            Self::Lt => 0xB,
            Self::Gt => 0xC,
            Self::Le => 0xD,
            Self::Al => 0xE,
        }
    }

    pub fn eval(self, state: &MachineState) -> bool {
        let flags = state.flags;
        match self {
            Self::Eq => flags.z,
            Self::Ne => !flags.z,
            Self::Ge => flags.n == flags.v,
            Self::Lt => flags.n != flags.v,
            Self::Gt => !flags.z && flags.n == flags.v,
            Self::Le => flags.z || flags.n != flags.v,
            Self::Al => true,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Arm64Insn {
    Nop,
    Movz { rd: u8, imm16: u16, shift: u8 },
    Movk { rd: u8, imm16: u16, shift: u8 },
    Adr { rd: u8, value: u64 },
    Adrp { rd: u8, value: u64 },
    AddImm { rd: u8, rn: u8, imm12: u16 },
    AddReg { rd: u8, rn: u8, rm: u8 },
    SubImm { rd: u8, rn: u8, imm12: u16 },
    SubReg { rd: u8, rn: u8, rm: u8 },
    CmpImm { rn: u8, imm12: u16 },
    CmpReg { rn: u8, rm: u8 },
    B { target_pc: u64 },
    BCond { cond: Condition, target_pc: u64 },
    Cbz { rt: u8, target_pc: u64 },
    Cbnz { rt: u8, target_pc: u64 },
    StrImm { rt: u8, rn: u8, offset: u16 },
    LdrImm { rt: u8, rn: u8, offset: u16 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AsmInsn {
    Nop,
    Movz { rd: u8, imm16: u16, shift: u8 },
    Movk { rd: u8, imm16: u16, shift: u8 },
    Adr { rd: u8, value: u64 },
    Adrp { rd: u8, value: u64 },
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

pub fn decode_program(program: &[u8], base_pc: u64) -> Result<Vec<Arm64Insn>, String> {
    if program.len() % 4 != 0 {
        return Err("program length must be a multiple of 4 bytes".to_string());
    }

    let mut decoded = Vec::with_capacity(program.len() / 4);
    for (index, chunk) in program.chunks_exact(4).enumerate() {
        let pc = base_pc + (index as u64) * 4;
        let word = u32::from_le_bytes(chunk.try_into().unwrap());
        decoded.push(decode_word(word, pc)?);
    }
    Ok(decoded)
}

pub fn execute_program(
    program: &[u8],
    base_pc: u64,
    initial_state: &MachineState,
) -> Result<ExecutionResult, String> {
    if program.len() % 4 != 0 {
        return Err("program length must be a multiple of 4 bytes".to_string());
    }

    let mut state = initial_state.clone();
    let mut pc = base_pc;
    let mut steps = 0;

    loop {
        if steps >= MAX_STEPS {
            return Ok(ExecutionResult {
                state,
                halt_reason: HaltReason::StepLimitExceeded,
                steps,
            });
        }

        if pc < base_pc {
            return Err(format!("pc moved before base address: {pc:#x}"));
        }

        let offset = pc - base_pc;
        if offset % 4 != 0 {
            return Err(format!("pc is not word-aligned: {pc:#x}"));
        }

        let insn_index = (offset / 4) as usize;
        if insn_index >= program.len() / 4 {
            return Ok(ExecutionResult {
                state,
                halt_reason: HaltReason::FellOffEnd,
                steps,
            });
        }

        let chunk = &program[insn_index * 4..insn_index * 4 + 4];
        let word = u32::from_le_bytes(chunk.try_into().unwrap());
        let insn = decode_word(word, pc)?;
        steps += 1;

        match insn {
            Arm64Insn::Nop => {
                pc += 4;
            }
            Arm64Insn::Movz { rd, imm16, shift } => {
                state.write_reg(rd, (imm16 as u64) << shift);
                pc += 4;
            }
            Arm64Insn::Movk { rd, imm16, shift } => {
                let mask = !(0xFFFF_u64 << shift);
                let value = (state.read_reg(rd) & mask) | ((imm16 as u64) << shift);
                state.write_reg(rd, value);
                pc += 4;
            }
            Arm64Insn::Adr { rd, value } | Arm64Insn::Adrp { rd, value } => {
                state.write_reg(rd, value);
                pc += 4;
            }
            Arm64Insn::AddImm { rd, rn, imm12 } => {
                let value = state.read_reg(rn).wrapping_add(imm12 as u64);
                state.write_reg(rd, value);
                pc += 4;
            }
            Arm64Insn::AddReg { rd, rn, rm } => {
                let value = state.read_reg(rn).wrapping_add(state.read_reg(rm));
                state.write_reg(rd, value);
                pc += 4;
            }
            Arm64Insn::SubImm { rd, rn, imm12 } => {
                let value = state.read_reg(rn).wrapping_sub(imm12 as u64);
                state.write_reg(rd, value);
                pc += 4;
            }
            Arm64Insn::SubReg { rd, rn, rm } => {
                let value = state.read_reg(rn).wrapping_sub(state.read_reg(rm));
                state.write_reg(rd, value);
                pc += 4;
            }
            Arm64Insn::CmpImm { rn, imm12 } => {
                let lhs = state.read_reg(rn);
                let rhs = imm12 as u64;
                let result = lhs.wrapping_sub(rhs);
                state.update_sub_flags(lhs, rhs, result);
                pc += 4;
            }
            Arm64Insn::CmpReg { rn, rm } => {
                let lhs = state.read_reg(rn);
                let rhs = state.read_reg(rm);
                let result = lhs.wrapping_sub(rhs);
                state.update_sub_flags(lhs, rhs, result);
                pc += 4;
            }
            Arm64Insn::B { target_pc } => {
                pc = target_pc;
            }
            Arm64Insn::BCond { cond, target_pc } => {
                if cond.eval(&state) {
                    pc = target_pc;
                } else {
                    pc += 4;
                }
            }
            Arm64Insn::Cbz { rt, target_pc } => {
                if state.read_reg(rt) == 0 {
                    pc = target_pc;
                } else {
                    pc += 4;
                }
            }
            Arm64Insn::Cbnz { rt, target_pc } => {
                if state.read_reg(rt) != 0 {
                    pc = target_pc;
                } else {
                    pc += 4;
                }
            }
            Arm64Insn::StrImm { rt, rn, offset } => {
                let addr = state.read_reg(rn).wrapping_add(offset as u64);
                let value = state.read_reg(rt);
                state.write_u64(addr, value);
                pc += 4;
            }
            Arm64Insn::LdrImm { rt, rn, offset } => {
                let addr = state.read_reg(rn).wrapping_add(offset as u64);
                let value = state.read_u64(addr);
                state.write_reg(rt, value);
                pc += 4;
            }
        }
    }
}

pub fn assemble_program(base_pc: u64, insns: &[AsmInsn]) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::with_capacity(insns.len() * 4);
    for (index, insn) in insns.iter().copied().enumerate() {
        let pc = base_pc + (index as u64) * 4;
        let word = match insn {
            AsmInsn::Nop => 0xD503201F,
            AsmInsn::Movz { rd, imm16, shift } => encode_movz(rd, imm16, shift)?,
            AsmInsn::Movk { rd, imm16, shift } => encode_movk(rd, imm16, shift)?,
            AsmInsn::Adr { rd, value } => encode_adr(rd, value, pc)?,
            AsmInsn::Adrp { rd, value } => encode_adrp(rd, value, pc)?,
            AsmInsn::AddImm { rd, rn, imm12 } => encode_add_imm(rd, rn, imm12),
            AsmInsn::AddReg { rd, rn, rm } => encode_add_reg(rd, rn, rm),
            AsmInsn::SubImm { rd, rn, imm12 } => encode_sub_imm(rd, rn, imm12),
            AsmInsn::SubReg { rd, rn, rm } => encode_sub_reg(rd, rn, rm),
            AsmInsn::CmpImm { rn, imm12 } => encode_cmp_imm(rn, imm12),
            AsmInsn::CmpReg { rn, rm } => encode_cmp_reg(rn, rm),
            AsmInsn::B { target } => {
                let target_pc = target_pc(base_pc, target)?;
                encode_b(target_pc as i64 - pc as i64)?
            }
            AsmInsn::BCond { cond, target } => {
                let target_pc = target_pc(base_pc, target)?;
                encode_b_cond(cond, target_pc as i64 - pc as i64)?
            }
            AsmInsn::Cbz { rt, target } => {
                let target_pc = target_pc(base_pc, target)?;
                encode_cbz(rt, target_pc as i64 - pc as i64)?
            }
            AsmInsn::Cbnz { rt, target } => {
                let target_pc = target_pc(base_pc, target)?;
                encode_cbnz(rt, target_pc as i64 - pc as i64)?
            }
            AsmInsn::StrImm { rt, rn, offset } => encode_str_imm(rt, rn, offset)?,
            AsmInsn::LdrImm { rt, rn, offset } => encode_ldr_imm(rt, rn, offset)?,
        };
        bytes.extend_from_slice(&word.to_le_bytes());
    }
    Ok(bytes)
}

pub fn decode_word(word: u32, pc: u64) -> Result<Arm64Insn, String> {
    if word == 0xD503201F {
        return Ok(Arm64Insn::Nop);
    }

    if word & 0x1F00_0000 == 0x1000_0000 {
        let rd = (word & 0x1F) as u8;
        let immlo = ((word >> 29) & 0x3) as u32;
        let immhi = ((word >> 5) & 0x7FFFF) as u32;
        let imm = sign_extend((immhi << 2) | immlo, 21);
        if (word >> 31) & 1 == 0 {
            return Ok(Arm64Insn::Adr {
                rd,
                value: pc.wrapping_add_signed(imm),
            });
        }
        let page_pc = pc & !0xFFF;
        return Ok(Arm64Insn::Adrp {
            rd,
            value: page_pc.wrapping_add_signed(imm << 12),
        });
    }

    if word & 0xFF80_0000 == 0xD280_0000 {
        return Ok(Arm64Insn::Movz {
            rd: (word & 0x1F) as u8,
            imm16: ((word >> 5) & 0xFFFF) as u16,
            shift: (((word >> 21) & 0x3) as u8) * 16,
        });
    }

    if word & 0xFF80_0000 == 0xF280_0000 {
        return Ok(Arm64Insn::Movk {
            rd: (word & 0x1F) as u8,
            imm16: ((word >> 5) & 0xFFFF) as u16,
            shift: (((word >> 21) & 0x3) as u8) * 16,
        });
    }

    if word & 0xFFC0_0000 == 0x9100_0000 {
        return Ok(Arm64Insn::AddImm {
            rd: (word & 0x1F) as u8,
            rn: ((word >> 5) & 0x1F) as u8,
            imm12: ((word >> 10) & 0xFFF) as u16,
        });
    }

    if word & 0xFFE0_FC00 == 0x8B00_0000 {
        return Ok(Arm64Insn::AddReg {
            rd: (word & 0x1F) as u8,
            rn: ((word >> 5) & 0x1F) as u8,
            rm: ((word >> 16) & 0x1F) as u8,
        });
    }

    if word & 0xFFC0_0000 == 0xD100_0000 {
        return Ok(Arm64Insn::SubImm {
            rd: (word & 0x1F) as u8,
            rn: ((word >> 5) & 0x1F) as u8,
            imm12: ((word >> 10) & 0xFFF) as u16,
        });
    }

    if word & 0xFFE0_FC00 == 0xCB00_0000 {
        return Ok(Arm64Insn::SubReg {
            rd: (word & 0x1F) as u8,
            rn: ((word >> 5) & 0x1F) as u8,
            rm: ((word >> 16) & 0x1F) as u8,
        });
    }

    if word & 0xFFC0_0000 == 0xF100_0000 {
        let rd = (word & 0x1F) as u8;
        let rn = ((word >> 5) & 0x1F) as u8;
        let imm12 = ((word >> 10) & 0xFFF) as u16;
        if rd == 31 {
            return Ok(Arm64Insn::CmpImm { rn, imm12 });
        }
    }

    if word & 0xFFE0_FC00 == 0xEB00_0000 {
        let rd = (word & 0x1F) as u8;
        let rn = ((word >> 5) & 0x1F) as u8;
        let rm = ((word >> 16) & 0x1F) as u8;
        if rd == 31 {
            return Ok(Arm64Insn::CmpReg { rn, rm });
        }
    }

    if word & 0x7C00_0000 == 0x1400_0000 {
        let imm26 = word & 0x03FF_FFFF;
        let offset = sign_extend(imm26, 26) << 2;
        return Ok(Arm64Insn::B {
            target_pc: pc.wrapping_add_signed(offset),
        });
    }

    if word & 0xFF00_0010 == 0x5400_0000 {
        let imm19 = (word >> 5) & 0x7FFFF;
        let offset = sign_extend(imm19, 19) << 2;
        let cond = Condition::from_bits((word & 0xF) as u8)?;
        return Ok(Arm64Insn::BCond {
            cond,
            target_pc: pc.wrapping_add_signed(offset),
        });
    }

    if word & 0xFF00_0000 == 0xB400_0000 {
        let imm19 = (word >> 5) & 0x7FFFF;
        let offset = sign_extend(imm19, 19) << 2;
        return Ok(Arm64Insn::Cbz {
            rt: (word & 0x1F) as u8,
            target_pc: pc.wrapping_add_signed(offset),
        });
    }

    if word & 0xFF00_0000 == 0xB500_0000 {
        let imm19 = (word >> 5) & 0x7FFFF;
        let offset = sign_extend(imm19, 19) << 2;
        return Ok(Arm64Insn::Cbnz {
            rt: (word & 0x1F) as u8,
            target_pc: pc.wrapping_add_signed(offset),
        });
    }

    if word & 0xFFC0_0000 == 0xF900_0000 {
        let imm12 = ((word >> 10) & 0xFFF) as u16;
        return Ok(Arm64Insn::StrImm {
            rt: (word & 0x1F) as u8,
            rn: ((word >> 5) & 0x1F) as u8,
            offset: imm12 * 8,
        });
    }

    if word & 0xFFC0_0000 == 0xF940_0000 {
        let imm12 = ((word >> 10) & 0xFFF) as u16;
        return Ok(Arm64Insn::LdrImm {
            rt: (word & 0x1F) as u8,
            rn: ((word >> 5) & 0x1F) as u8,
            offset: imm12 * 8,
        });
    }

    Err(format!(
        "unsupported instruction word {word:#010x} at pc {pc:#x}"
    ))
}

pub fn encode_movz(rd: u8, imm16: u16, shift: u8) -> Result<u32, String> {
    encode_move_wide(0xD280_0000, rd, imm16, shift)
}

pub fn encode_movk(rd: u8, imm16: u16, shift: u8) -> Result<u32, String> {
    encode_move_wide(0xF280_0000, rd, imm16, shift)
}

pub fn encode_add_imm(rd: u8, rn: u8, imm12: u16) -> u32 {
    0x9100_0000 | ((imm12 as u32) << 10) | ((rn as u32) << 5) | rd as u32
}

pub fn encode_add_reg(rd: u8, rn: u8, rm: u8) -> u32 {
    0x8B00_0000 | ((rm as u32) << 16) | ((rn as u32) << 5) | rd as u32
}

pub fn encode_sub_imm(rd: u8, rn: u8, imm12: u16) -> u32 {
    0xD100_0000 | ((imm12 as u32) << 10) | ((rn as u32) << 5) | rd as u32
}

pub fn encode_sub_reg(rd: u8, rn: u8, rm: u8) -> u32 {
    0xCB00_0000 | ((rm as u32) << 16) | ((rn as u32) << 5) | rd as u32
}

pub fn encode_cmp_imm(rn: u8, imm12: u16) -> u32 {
    0xF100_0000 | ((imm12 as u32) << 10) | ((rn as u32) << 5) | 31
}

pub fn encode_cmp_reg(rn: u8, rm: u8) -> u32 {
    0xEB00_0000 | ((rm as u32) << 16) | ((rn as u32) << 5) | 31
}

pub fn encode_b(offset_bytes: i64) -> Result<u32, String> {
    ensure_aligned(offset_bytes)?;
    ensure_signed_fit(offset_bytes >> 2, 26, "B")?;
    Ok(0x1400_0000 | encode_signed_field(offset_bytes >> 2, 26))
}

pub fn encode_b_cond(cond: Condition, offset_bytes: i64) -> Result<u32, String> {
    ensure_aligned(offset_bytes)?;
    ensure_signed_fit(offset_bytes >> 2, 19, "B.cond")?;
    Ok(0x5400_0000 | (encode_signed_field(offset_bytes >> 2, 19) << 5) | cond.encode() as u32)
}

pub fn encode_cbz(rt: u8, offset_bytes: i64) -> Result<u32, String> {
    ensure_aligned(offset_bytes)?;
    ensure_signed_fit(offset_bytes >> 2, 19, "CBZ")?;
    Ok(0xB400_0000 | (encode_signed_field(offset_bytes >> 2, 19) << 5) | rt as u32)
}

pub fn encode_cbnz(rt: u8, offset_bytes: i64) -> Result<u32, String> {
    ensure_aligned(offset_bytes)?;
    ensure_signed_fit(offset_bytes >> 2, 19, "CBNZ")?;
    Ok(0xB500_0000 | (encode_signed_field(offset_bytes >> 2, 19) << 5) | rt as u32)
}

pub fn encode_str_imm(rt: u8, rn: u8, offset: u16) -> Result<u32, String> {
    if offset % 8 != 0 {
        return Err(format!("STR offset must be 8-byte aligned, got {offset}"));
    }
    let scaled = offset / 8;
    Ok(0xF900_0000 | ((scaled as u32) << 10) | ((rn as u32) << 5) | rt as u32)
}

pub fn encode_ldr_imm(rt: u8, rn: u8, offset: u16) -> Result<u32, String> {
    if offset % 8 != 0 {
        return Err(format!("LDR offset must be 8-byte aligned, got {offset}"));
    }
    let scaled = offset / 8;
    Ok(0xF940_0000 | ((scaled as u32) << 10) | ((rn as u32) << 5) | rt as u32)
}

pub fn encode_adr(rd: u8, value: u64, pc: u64) -> Result<u32, String> {
    let delta = value as i128 - pc as i128;
    ensure_signed_fit(delta as i64, 21, "ADR")?;
    let field = encode_signed_field(delta as i64, 21);
    let immlo = field & 0x3;
    let immhi = field >> 2;
    Ok(0x1000_0000 | (immlo << 29) | (immhi << 5) | rd as u32)
}

pub fn encode_adrp(rd: u8, value: u64, pc: u64) -> Result<u32, String> {
    let delta_pages = ((value & !0xFFF) as i128 - (pc & !0xFFF) as i128) >> 12;
    ensure_signed_fit(delta_pages as i64, 21, "ADRP")?;
    let field = encode_signed_field(delta_pages as i64, 21);
    let immlo = field & 0x3;
    let immhi = field >> 2;
    Ok(0x9000_0000 | (immlo << 29) | (immhi << 5) | rd as u32)
}

fn encode_move_wide(base: u32, rd: u8, imm16: u16, shift: u8) -> Result<u32, String> {
    if !matches!(shift, 0 | 16 | 32 | 48) {
        return Err(format!("unsupported move-wide shift: {shift}"));
    }
    Ok(base | (((shift / 16) as u32) << 21) | ((imm16 as u32) << 5) | rd as u32)
}

fn target_pc(base_pc: u64, target: usize) -> Result<u64, String> {
    base_pc
        .checked_add((target as u64) * 4)
        .ok_or_else(|| format!("target index overflow: {target}"))
}

fn ensure_aligned(offset_bytes: i64) -> Result<(), String> {
    if offset_bytes % 4 != 0 {
        Err(format!(
            "branch offset must be 4-byte aligned, got {offset_bytes}"
        ))
    } else {
        Ok(())
    }
}

fn ensure_signed_fit(value: i64, bits: u8, insn: &str) -> Result<(), String> {
    let min = -(1_i64 << (bits - 1));
    let max = (1_i64 << (bits - 1)) - 1;
    if value < min || value > max {
        Err(format!("{insn} signed field out of range: {value}"))
    } else {
        Ok(())
    }
}

fn encode_signed_field(value: i64, bits: u8) -> u32 {
    let mask = (1_u64 << bits) - 1;
    (value as i128 & mask as i128) as u32
}

fn sign_extend(value: u32, bits: u8) -> i64 {
    let shift = 64 - bits as i32;
    ((value as i64) << shift) >> shift
}
