use core::fmt;

use crate::shared::platform::{SharedAllocError, SharedVec, GFP_KERNEL};
use crate::shared::trans::cfg::RuntimeExitReason;

mod generated;

pub use generated::{A64EncodeError, A64Insn};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecodedInsn {
    pub pc: u64,
    pub word: u32,
    pub insn: A64Insn,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
    UnsupportedWord { pc: u64, word: u32 },
    Alloc(SharedAllocError),
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedWord { pc, word } => {
                write!(f, "unsupported instruction word {word:#010x} at pc {pc:#x}")
            }
            Self::Alloc(err) => write!(f, "allocation failed while decoding: {err:?}"),
        }
    }
}

impl A64Insn {
    pub fn direct_branch_target(self, pc: u64) -> Option<u64> {
        match self {
            Self::BUncondBOnlyBranchImm { imm26 } => Some(pc_relative_target(pc, imm26, 26)),
            _ => None,
        }
    }

    pub fn conditional_targets(self, pc: u64) -> Option<(u64, u64)> {
        let taken = match self {
            Self::BCondBOnlyCondbranch { imm19, .. }
            | Self::CbzCbz32Compbranch { imm19, .. }
            | Self::CbzCbz64Compbranch { imm19, .. }
            | Self::CbnzCbnz32Compbranch { imm19, .. }
            | Self::CbnzCbnz64Compbranch { imm19, .. } => pc_relative_target(pc, imm19, 19),
            Self::TbzTbzOnlyTestbranch { imm14, .. }
            | Self::TbnzTbnzOnlyTestbranch { imm14, .. } => {
                pc_relative_target(pc, u32::from(imm14), 14)
            }
            _ => return None,
        };
        Some((taken, pc.wrapping_add(4)))
    }

    pub fn runtime_exit_reason(self, pc: u64) -> Option<RuntimeExitReason> {
        match self {
            Self::BlBlOnlyBranchImm { imm26 } => Some(RuntimeExitReason::Bl {
                target_pc: pc_relative_target(pc, imm26, 26),
                resume_pc: pc.wrapping_add(4),
            }),
            Self::BlrBlr64BranchReg { rn } => Some(RuntimeExitReason::Blr {
                target_reg: rn,
                resume_pc: pc.wrapping_add(4),
            }),
            Self::BrBr64BranchReg { rn } => Some(RuntimeExitReason::Br { target_reg: rn }),
            Self::RetRet64rBranchReg { rn } => Some(RuntimeExitReason::Ret { lr_reg: rn }),
            Self::SvcSvcExException { imm16 } => Some(RuntimeExitReason::Svc {
                imm16,
                resume_pc: pc.wrapping_add(4),
            }),
            _ => None,
        }
    }
}

pub fn decode_word(word: u32, pc: u64) -> Result<DecodedInsn, DecodeError> {
    let insn = A64Insn::decode(word).ok_or(DecodeError::UnsupportedWord { pc, word })?;
    Ok(DecodedInsn { pc, word, insn })
}

pub fn decode_program(program: &[u8], base_pc: u64) -> Result<SharedVec<DecodedInsn>, DecodeError> {
    if program.len() % 4 != 0 {
        return Err(DecodeError::UnsupportedWord {
            pc: base_pc,
            word: 0,
        });
    }

    let mut decoded =
        SharedVec::with_capacity(program.len() / 4, GFP_KERNEL).map_err(DecodeError::Alloc)?;
    for (index, chunk) in program.chunks_exact(4).enumerate() {
        let pc = base_pc + (index as u64) * 4;
        let word = u32::from_le_bytes(chunk.try_into().unwrap());
        decoded
            .push(decode_word(word, pc)?, GFP_KERNEL)
            .map_err(DecodeError::Alloc)?;
    }
    Ok(decoded)
}

fn pc_relative_target(pc: u64, encoded: u32, bits: u8) -> u64 {
    pc.wrapping_add_signed(sign_extend(encoded, bits) << 2)
}

fn sign_extend(value: u32, bits: u8) -> i64 {
    let shift = 64 - bits as u32;
    ((value as i64) << shift) >> shift
}
