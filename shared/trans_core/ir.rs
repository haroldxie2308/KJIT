extern crate alloc;

use alloc::vec::Vec;

use crate::trans_core::arm64::BranchCondition;
use crate::trans_core::cfg::RuntimeExitReason;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LinkSlot(pub usize);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IrInsn {
    pub pc: u64,
    pub kind: IrInsnKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IrInsnKind {
    Nop,
    LoadImm64 {
        rd: u8,
        value: u64,
    },
    AddImm {
        rd: u8,
        rn: u8,
        imm12: u16,
    },
    AddReg {
        rd: u8,
        rn: u8,
        rm: u8,
    },
    SubImm {
        rd: u8,
        rn: u8,
        imm12: u16,
    },
    SubReg {
        rd: u8,
        rn: u8,
        rm: u8,
    },
    CmpImm {
        rn: u8,
        imm12: u16,
    },
    CmpReg {
        rn: u8,
        rm: u8,
    },
    B {
        target_pc: u64,
    },
    BCond {
        cond: BranchCondition,
        target_pc: u64,
    },
    Cbz {
        rt: u8,
        target_pc: u64,
    },
    Cbnz {
        rt: u8,
        target_pc: u64,
    },
    StrImm {
        rt: u8,
        rn: u8,
        offset: u16,
    },
    LdrImm {
        rt: u8,
        rn: u8,
        offset: u16,
    },
    RuntimeExit {
        slot: LinkSlot,
        reason: RuntimeExitReason,
    },
}

pub type IrProgram = Vec<IrInsn>;
