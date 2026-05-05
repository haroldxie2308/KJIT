use core::fmt;

use crate::shared::platform::{SharedAllocError, SharedVec, GFP_KERNEL};
use crate::shared::trans::cfg::RuntimeExitReason;

mod generated;

pub use generated::{
    A64EncodeError, A64Imm, A64Insn, A64Mem, A64OperandRole, A64Reg, A64Reg31Mode, A64RegWidth,
    A64RewriteError,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum A64Condition {
    Eq,
    Ne,
    Ge,
    Lt,
    Gt,
    Le,
    Al,
}

impl A64Condition {
    pub const fn from_bits(bits: u8) -> Option<Self> {
        match bits {
            0x0 => Some(Self::Eq),
            0x1 => Some(Self::Ne),
            0xA => Some(Self::Ge),
            0xB => Some(Self::Lt),
            0xC => Some(Self::Gt),
            0xD => Some(Self::Le),
            0xE | 0xF => Some(Self::Al),
            _ => None,
        }
    }

    pub const fn bits(self) -> u8 {
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
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IrInsn {
    pub pc: u64,
    pub word: u32,
    pub inner: A64Insn,
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
    pub fn pc_relative_address(self, pc: u64) -> Option<u64> {
        match self {
            Self::AdrAdrOnlyPcreladdr { immlo, immhi, .. } => {
                let imm = (immhi.raw() << 2) | immlo.raw();
                Some(pc.wrapping_add_signed(sign_extend(imm, 21)))
            }
            Self::AdrpAdrpOnlyPcreladdr { immlo, immhi, .. } => {
                let imm = (immhi.raw() << 2) | immlo.raw();
                let page_pc = pc & !0xFFF;
                Some(page_pc.wrapping_add_signed(sign_extend(imm, 21) << 12))
            }
            _ => None,
        }
    }

    pub const fn condition(self) -> Option<A64Condition> {
        match self {
            Self::BCondBOnlyCondbranch { cond, .. } => A64Condition::from_bits(cond),
            _ => None,
        }
    }

    pub const fn add_sub_imm(sh: u8, imm12: A64Imm) -> Option<u64> {
        match sh {
            0 => Some(imm12.raw() as u64),
            1 => Some((imm12.raw() as u64) << 12),
            _ => None,
        }
    }

    pub const fn move_wide_shift(hw: u8) -> Option<u8> {
        match hw {
            0..=3 => Some(hw * 16),
            _ => None,
        }
    }

    pub fn signed_imm9(imm9: A64Imm) -> i64 {
        imm9.value()
    }

    pub fn direct_branch_target(self, pc: u64) -> Option<u64> {
        match self {
            Self::BUncondBOnlyBranchImm { imm26 } => Some(pc_relative_target(pc, imm26.raw(), 26)),
            _ => None,
        }
    }

    pub fn conditional_targets(self, pc: u64) -> Option<(u64, u64)> {
        let taken = match self {
            Self::BCondBOnlyCondbranch { imm19, .. }
            | Self::CbzCbz32Compbranch { imm19, .. }
            | Self::CbzCbz64Compbranch { imm19, .. }
            | Self::CbnzCbnz32Compbranch { imm19, .. }
            | Self::CbnzCbnz64Compbranch { imm19, .. } => pc_relative_target(pc, imm19.raw(), 19),
            Self::TbzTbzOnlyTestbranch { imm14, .. }
            | Self::TbnzTbnzOnlyTestbranch { imm14, .. } => {
                pc_relative_target(pc, imm14.raw(), 14)
            }
            _ => return None,
        };
        Some((taken, pc.wrapping_add(4)))
    }

    pub fn runtime_exit_reason(self, pc: u64) -> Option<RuntimeExitReason> {
        match self {
            Self::BlBlOnlyBranchImm { imm26 } => Some(RuntimeExitReason::Bl {
                target_pc: pc_relative_target(pc, imm26.raw(), 26),
                resume_pc: pc.wrapping_add(4),
            }),
            Self::BlrBlr64BranchReg { rn } => Some(RuntimeExitReason::Blr {
                target_reg: rn.enc(),
                resume_pc: pc.wrapping_add(4),
            }),
            Self::BrBr64BranchReg { rn } => Some(RuntimeExitReason::Br {
                target_reg: rn.enc(),
            }),
            Self::RetRet64rBranchReg { rn } => Some(RuntimeExitReason::Ret { lr_reg: rn.enc() }),
            Self::SvcSvcExException { imm16 } => Some(RuntimeExitReason::Svc {
                imm16: imm16.raw() as u16,
                resume_pc: pc.wrapping_add(4),
            }),
            _ => None,
        }
    }
}

pub fn decode_word(word: u32, pc: u64) -> Result<IrInsn, DecodeError> {
    let inner = A64Insn::decode(word).ok_or(DecodeError::UnsupportedWord { pc, word })?;
    Ok(IrInsn { pc, word, inner })
}

pub fn decode_program(program: &[u8], base_pc: u64) -> Result<SharedVec<IrInsn>, DecodeError> {
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
