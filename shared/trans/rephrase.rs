use crate::shared::arm64::{A64Insn, IrInsn};
use crate::shared::platform::{SharedAllocError, SharedResult, SharedVec, GFP_KERNEL};
use crate::shared::trans::cfg::{Cfg, RuntimeExitReason};

const RET_STATUS_REG: u8 = 9;
const RET_PARAM0_REG: u8 = 10;
const RET_PARAM1_REG: u8 = 11;

#[repr(u64)]
enum RetStatus {
    Svc = 0,
    Bl = 1,
    Blr = 2,
    Br = 3,
    Ret = 4,
}

#[derive(Debug, PartialEq, Eq)]
pub struct RephrasedInsn {
    pub original_pc: Option<u64>,
    pub insn: A64Insn,
}

impl RephrasedInsn {
    pub const fn original(original_pc: u64, insn: A64Insn) -> Self {
        Self {
            original_pc: Some(original_pc),
            insn,
        }
    }

    pub const fn synthetic(insn: A64Insn) -> Self {
        Self {
            original_pc: None,
            insn,
        }
    }
}

/// Basic block after rephrasing, still over the original half-open PC range.
#[derive(Debug, PartialEq, Eq)]
pub struct RephrasedBlock {
    pub start_addr: u64,
    pub end_addr: u64,
    pub prev: SharedVec<u64>,
    pub next: SharedVec<u64>,
    pub insns: SharedVec<RephrasedInsn>,
}

pub type RephrasedProgram = SharedVec<RephrasedBlock>;

#[macro_export]
macro_rules! a64seq {
    ($out:expr $(,)?) => {{
        let _ = &$out;
        (|| -> $crate::shared::platform::SharedResult<(), $crate::shared::platform::SharedAllocError> {
            Ok(())
        })()
    }};
    ($out:expr, $($insn:expr),+ $(,)?) => {{
        $crate::a64seq!($out; $crate::shared::platform::GFP_KERNEL, $($insn),+)
    }};
    ($out:expr; $flags:expr $(,)?) => {{
        let _ = &$out;
        let _ = &$flags;
        (|| -> $crate::shared::platform::SharedResult<(), $crate::shared::platform::SharedAllocError> {
            Ok(())
        })()
    }};
    ($out:expr; $flags:expr, $($insn:expr),+ $(,)?) => {{
        (|| -> $crate::shared::platform::SharedResult<(), $crate::shared::platform::SharedAllocError> {
            $(
                $out.push($insn, $flags)?;
            )+
            Ok(())
        })()
    }};
}

fn rephrase_insn(insn: IrInsn) -> SharedResult<SharedVec<RephrasedInsn>, SharedAllocError> {
    let mut ret = SharedVec::with_capacity(10, GFP_KERNEL)?;
    match insn.inner {
        A64Insn::AdrAdrOnlyPcreladdr { rd, .. } | A64Insn::AdrpAdrpOnlyPcreladdr { rd, .. } => {
            let value = insn
                .inner
                .pc_relative_address(insn.pc)
                .expect("ADR/ADRP must have a PC-relative address");
            push_mov_imm64(&mut ret, Some(insn.pc), rd, value)?;
        }
        A64Insn::BlBlOnlyBranchImm { .. } => {
            let Some(RuntimeExitReason::Bl {
                target_pc,
                resume_pc,
            }) = insn.inner.runtime_exit_reason(insn.pc)
            else {
                unreachable!("BL must produce a BL runtime exit reason");
            };

            push_mov_imm64(&mut ret, Some(insn.pc), RET_STATUS_REG, RetStatus::Bl as u64)?;
            push_mov_imm64(&mut ret, None, RET_PARAM0_REG, target_pc)?;
            push_mov_imm64(&mut ret, None, RET_PARAM1_REG, resume_pc)?;
            ret.push(
                RephrasedInsn::synthetic(A64Insn::BUncondBOnlyBranchImm { imm26: 0 }),
                GFP_KERNEL,
            )?;
        }
        A64Insn::BlrBlr64BranchReg { .. } => {
            let Some(RuntimeExitReason::Blr {
                target_reg,
                resume_pc,
            }) = insn.inner.runtime_exit_reason(insn.pc)
            else {
                unreachable!("BLR must produce a BLR runtime exit reason");
            };

            push_mov_imm64(&mut ret, Some(insn.pc), RET_STATUS_REG, RetStatus::Blr as u64)?;
            ret.push(
                RephrasedInsn::synthetic(A64Insn::OrrLogShiftOrr64LogShift {
                    shift: 0,
                    rm: target_reg,
                    imm6: 0,
                    rn: 31,
                    rd: RET_PARAM0_REG,
                }),
                GFP_KERNEL,
            )?;
            push_mov_imm64(&mut ret, None, RET_PARAM1_REG, resume_pc)?;
            ret.push(
                RephrasedInsn::synthetic(A64Insn::BUncondBOnlyBranchImm { imm26: 0 }),
                GFP_KERNEL,
            )?;
        }
        A64Insn::BrBr64BranchReg { .. } => {
            let Some(RuntimeExitReason::Br { target_reg }) =
                insn.inner.runtime_exit_reason(insn.pc)
            else {
                unreachable!("BR must produce a BR runtime exit reason");
            };

            push_mov_imm64(&mut ret, Some(insn.pc), RET_STATUS_REG, RetStatus::Br as u64)?;
            ret.push(
                RephrasedInsn::synthetic(A64Insn::OrrLogShiftOrr64LogShift {
                    shift: 0,
                    rm: target_reg,
                    imm6: 0,
                    rn: 31,
                    rd: RET_PARAM0_REG,
                }),
                GFP_KERNEL,
            )?;
            push_mov_imm64(&mut ret, None, RET_PARAM1_REG, insn.pc.wrapping_add(4))?;
            ret.push(
                RephrasedInsn::synthetic(A64Insn::BUncondBOnlyBranchImm { imm26: 0 }),
                GFP_KERNEL,
            )?;
        }
        A64Insn::RetRet64rBranchReg { .. } => {
            let Some(RuntimeExitReason::Ret { lr_reg }) =
                insn.inner.runtime_exit_reason(insn.pc)
            else {
                unreachable!("RET must produce a RET runtime exit reason");
            };

            push_mov_imm64(&mut ret, Some(insn.pc), RET_STATUS_REG, RetStatus::Ret as u64)?;
            ret.push(
                RephrasedInsn::synthetic(A64Insn::OrrLogShiftOrr64LogShift {
                    shift: 0,
                    rm: lr_reg,
                    imm6: 0,
                    rn: 31,
                    rd: RET_PARAM0_REG,
                }),
                GFP_KERNEL,
            )?;
            push_mov_imm64(&mut ret, None, RET_PARAM1_REG, insn.pc.wrapping_add(4))?;
            ret.push(
                RephrasedInsn::synthetic(A64Insn::BUncondBOnlyBranchImm { imm26: 0 }),
                GFP_KERNEL,
            )?;
        }
        A64Insn::SvcSvcExException { .. } => {
            let Some(RuntimeExitReason::Svc { resume_pc, .. }) =
                insn.inner.runtime_exit_reason(insn.pc)
            else {
                unreachable!("SVC must produce an SVC runtime exit reason");
            };

            push_mov_imm64(&mut ret, Some(insn.pc), RET_STATUS_REG, RetStatus::Svc as u64)?;
            ret.push(
                RephrasedInsn::synthetic(A64Insn::OrrLogShiftOrr64LogShift {
                    shift: 0,
                    rm: 8,
                    imm6: 0,
                    rn: 31,
                    rd: RET_PARAM0_REG,
                }),
                GFP_KERNEL,
            )?;
            push_mov_imm64(&mut ret, None, RET_PARAM1_REG, resume_pc)?;
            ret.push(
                RephrasedInsn::synthetic(A64Insn::BUncondBOnlyBranchImm { imm26: 0 }),
                GFP_KERNEL,
            )?;
        }
        _ => ret.push(RephrasedInsn::original(insn.pc, insn.inner), GFP_KERNEL)?,
    }
    Ok(ret)
}

fn push_mov_imm64(
    out: &mut SharedVec<RephrasedInsn>,
    original_pc: Option<u64>,
    rd: u8,
    value: u64,
) -> SharedResult<(), SharedAllocError> {
    let first = A64Insn::MovzMovz64Movewide {
        hw: 3,
        imm16: ((value >> 48) & 0xFFFF) as u16,
        rd,
    };
    let first = match original_pc {
        Some(pc) => RephrasedInsn::original(pc, first),
        None => RephrasedInsn::synthetic(first),
    };

    a64seq!(
        out,
        first,
        RephrasedInsn::synthetic(A64Insn::MovkMovk64Movewide {
            hw: 2,
            imm16: ((value >> 32) & 0xFFFF) as u16,
            rd,
        }),
        RephrasedInsn::synthetic(A64Insn::MovkMovk64Movewide {
            hw: 1,
            imm16: ((value >> 16) & 0xFFFF) as u16,
            rd,
        }),
        RephrasedInsn::synthetic(A64Insn::MovkMovk64Movewide {
            hw: 0,
            imm16: (value & 0xFFFF) as u16,
            rd,
        }),
    )
}

pub fn rephrase(_cfg: Cfg) -> SharedResult<SharedVec<RephrasedBlock>, SharedAllocError> {
    SharedVec::with_capacity(0, GFP_KERNEL)
}
