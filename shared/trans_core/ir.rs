use crate::trans_core::arm64::BranchCondition;
use crate::trans_core::cfg::RuntimeExitReason;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LinkSlot(pub usize);

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
    BCond { cond: BranchCondition, target: usize },
    Cbz { rt: u8, target: usize },
    Cbnz { rt: u8, target: usize },
    StrImm { rt: u8, rn: u8, offset: u16 },
    LdrImm { rt: u8, rn: u8, offset: u16 },
    RuntimeExit {
        slot: LinkSlot,
        reason: RuntimeExitReason,
    },
}

pub type IrProgram = Vec<IrInsn>;
