use crate::shared::abi::{RetStatus, RET_PARAM0_REG, RET_PARAM1_REG, RET_STATUS_REG};
use crate::shared::arm64::ergo::{scaled_simm, uimm, x, xzr};
use crate::shared::arm64::{A64Insn, A64Reg, IrInsn};
use crate::shared::platform::{SharedAllocError, SharedResult, SharedVec, GFP_KERNEL};
use crate::shared::trans::cfg::{Cfg, RuntimeExitReason};

#[derive(Debug, PartialEq, Eq)]
pub enum RephrasedInsnKind {
    Synthetic,
    RuntimeExitBranch,
    Original,
}

#[derive(Debug, PartialEq, Eq)]
pub struct RephrasedInsn {
    pub kind: RephrasedInsnKind,
    pub original_pc: u64,
    pub insn: A64Insn,
}

impl RephrasedInsn {
    pub const fn original(original_pc: u64, insn: A64Insn) -> Self {
        Self {
            kind: RephrasedInsnKind::Original,
            original_pc,
            insn,
        }
    }

    pub const fn synthetic(original_pc: u64, insn: A64Insn) -> Self {
        Self {
            kind: RephrasedInsnKind::Synthetic,
            original_pc,
            insn,
        }
    }

    pub const fn runtime_exit_branch(original_pc: u64, insn: A64Insn) -> Self {
        Self {
            kind: RephrasedInsnKind::RuntimeExitBranch,
            original_pc,
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
macro_rules! a64_syn {
    ($original_pc:expr $(,)?) => {{
        let _ = &$original_pc;
        $crate::shared::platform::SharedVec::new()
    }};
    ($original_pc:expr, $($insn:expr),+ $(,)?) => {{
        (|| -> $crate::shared::platform::SharedResult<
            $crate::shared::platform::SharedVec<$crate::shared::trans::rephrase::RephrasedInsn>,
            $crate::shared::platform::SharedAllocError,
        > {
            let mut out = $crate::shared::platform::SharedVec::new();
            $(
                out.push(
                    $crate::shared::trans::rephrase::RephrasedInsn::synthetic($original_pc, $insn),
                    $crate::shared::platform::GFP_KERNEL,
                )?;
            )+
            Ok(out)
        })()
    }};
}

#[macro_export]
macro_rules! a64_ori {
    ($original_pc:expr $(,)?) => {{
        let _ = &$original_pc;
        $crate::shared::platform::SharedVec::new()
    }};
    ($original_pc:expr, $($insn:expr),+ $(,)?) => {{
        (|| -> $crate::shared::platform::SharedResult<
            $crate::shared::platform::SharedVec<$crate::shared::trans::rephrase::RephrasedInsn>,
            $crate::shared::platform::SharedAllocError,
        > {
            let mut out = $crate::shared::platform::SharedVec::new();
            $(
                out.push(
                    $crate::shared::trans::rephrase::RephrasedInsn::original($original_pc, $insn),
                    $crate::shared::platform::GFP_KERNEL,
                )?;
            )+
            Ok(out)
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
            push_mov_imm64(&mut ret, insn.pc, rd, value)?;
        }
        A64Insn::BlBlOnlyBranchImm { .. } => {
            let Some(RuntimeExitReason::Bl {
                target_pc,
                resume_pc,
            }) = insn.inner.runtime_exit_reason(insn.pc)
            else {
                unreachable!("BL must produce a BL runtime exit reason");
            };

            push_mov_imm64(&mut ret, insn.pc, x(RET_STATUS_REG), RetStatus::Bl.as_reg())?;
            push_mov_imm64(&mut ret, insn.pc, x(RET_PARAM0_REG), target_pc)?;
            push_mov_imm64(&mut ret, insn.pc, x(RET_PARAM1_REG), resume_pc)?;
            push_branch_to_stub(&mut ret, insn.pc)?;
        }
        A64Insn::BlrBlr64BranchReg { .. } => {
            let Some(RuntimeExitReason::Blr {
                target_reg,
                resume_pc,
            }) = insn.inner.runtime_exit_reason(insn.pc)
            else {
                unreachable!("BLR must produce a BLR runtime exit reason");
            };

            push_mov_imm64(
                &mut ret,
                insn.pc,
                x(RET_STATUS_REG),
                RetStatus::Blr.as_reg(),
            )?;
            ret.append(
                a64_syn!(
                    insn.pc,
                    A64Insn::OrrLogShiftOrr64LogShift {
                        shift: 0,
                        rm: x(target_reg),
                        imm6: uimm(0, 6),
                        rn: xzr(),
                        rd: x(RET_PARAM0_REG),
                    }
                )?,
                GFP_KERNEL,
            )?;
            push_mov_imm64(&mut ret, insn.pc, x(RET_PARAM1_REG), resume_pc)?;
            push_branch_to_stub(&mut ret, insn.pc)?;
        }
        A64Insn::BrBr64BranchReg { .. } => {
            let Some(RuntimeExitReason::Br { target_reg }) =
                insn.inner.runtime_exit_reason(insn.pc)
            else {
                unreachable!("BR must produce a BR runtime exit reason");
            };

            push_mov_imm64(&mut ret, insn.pc, x(RET_STATUS_REG), RetStatus::Br.as_reg())?;
            ret.append(
                a64_syn!(
                    insn.pc,
                    A64Insn::OrrLogShiftOrr64LogShift {
                        shift: 0,
                        rm: x(target_reg),
                        imm6: uimm(0, 6),
                        rn: xzr(),
                        rd: x(RET_PARAM0_REG),
                    }
                )?,
                GFP_KERNEL,
            )?;
            push_mov_imm64(
                &mut ret,
                insn.pc,
                x(RET_PARAM1_REG),
                insn.pc.wrapping_add(4),
            )?;
            push_branch_to_stub(&mut ret, insn.pc)?;
        }
        A64Insn::RetRet64rBranchReg { .. } => {
            let Some(RuntimeExitReason::Ret { lr_reg }) = insn.inner.runtime_exit_reason(insn.pc)
            else {
                unreachable!("RET must produce a RET runtime exit reason");
            };

            push_mov_imm64(
                &mut ret,
                insn.pc,
                x(RET_STATUS_REG),
                RetStatus::Ret.as_reg(),
            )?;
            ret.append(
                a64_syn!(
                    insn.pc,
                    A64Insn::OrrLogShiftOrr64LogShift {
                        shift: 0,
                        rm: x(lr_reg),
                        imm6: uimm(0, 6),
                        rn: xzr(),
                        rd: x(RET_PARAM0_REG),
                    }
                )?,
                GFP_KERNEL,
            )?;
            push_mov_imm64(
                &mut ret,
                insn.pc,
                x(RET_PARAM1_REG),
                insn.pc.wrapping_add(4),
            )?;
            push_branch_to_stub(&mut ret, insn.pc)?;
        }
        A64Insn::SvcSvcExException { .. } => {
            let Some(RuntimeExitReason::Svc { resume_pc, .. }) =
                insn.inner.runtime_exit_reason(insn.pc)
            else {
                unreachable!("SVC must produce an SVC runtime exit reason");
            };

            push_mov_imm64(
                &mut ret,
                insn.pc,
                x(RET_STATUS_REG),
                RetStatus::Svc.as_reg(),
            )?;
            ret.append(
                a64_syn!(
                    insn.pc,
                    A64Insn::OrrLogShiftOrr64LogShift {
                        shift: 0,
                        rm: x(8),
                        imm6: uimm(0, 6),
                        rn: xzr(),
                        rd: x(RET_PARAM0_REG),
                    }
                )?,
                GFP_KERNEL,
            )?;
            push_mov_imm64(&mut ret, insn.pc, x(RET_PARAM1_REG), resume_pc)?;
            push_branch_to_stub(&mut ret, insn.pc)?;
        }
        _ => ret.append(a64_ori!(insn.pc, insn.inner)?, GFP_KERNEL)?,
    }
    Ok(ret)
}

fn push_mov_imm64(
    out: &mut SharedVec<RephrasedInsn>,
    original_pc: u64,
    rd: A64Reg,
    value: u64,
) -> SharedResult<(), SharedAllocError> {
    out.append(
        a64_syn!(
            original_pc,
            A64Insn::MovzMovz64Movewide {
                hw: 3,
                imm16: uimm(((value >> 48) & 0xFFFF) as u32, 16),
                rd,
            },
            A64Insn::MovkMovk64Movewide {
                hw: 2,
                imm16: uimm(((value >> 32) & 0xFFFF) as u32, 16),
                rd,
            },
            A64Insn::MovkMovk64Movewide {
                hw: 1,
                imm16: uimm(((value >> 16) & 0xFFFF) as u32, 16),
                rd,
            },
            A64Insn::MovkMovk64Movewide {
                hw: 0,
                imm16: uimm((value & 0xFFFF) as u32, 16),
                rd,
            },
        )?,
        GFP_KERNEL,
    )
}

fn push_branch_to_stub(
    out: &mut SharedVec<RephrasedInsn>,
    original_pc: u64,
) -> SharedResult<(), SharedAllocError> {
    out.push(
        RephrasedInsn::runtime_exit_branch(
            original_pc,
            A64Insn::BUncondBOnlyBranchImm {
                imm26: scaled_simm(0, 26, 2),
            },
        ),
        GFP_KERNEL,
    )
}

pub fn rephrase(cfg: Cfg) -> SharedResult<RephrasedProgram, SharedAllocError> {
    let mut blocks = SharedVec::with_capacity(cfg.blocks.len(), GFP_KERNEL)?;
    for block in &cfg.blocks {
        let mut insns = SharedVec::with_capacity(block.insns.len() * 10, GFP_KERNEL)?;
        for insn in &block.insns {
            insns.append(rephrase_insn(*insn)?, GFP_KERNEL)?;
        }

        blocks.push(
            RephrasedBlock {
                start_addr: block.start_addr,
                end_addr: block.end_addr,
                prev: copy_u64_vec(&block.prev)?,
                next: copy_u64_vec(&block.next)?,
                insns,
            },
            GFP_KERNEL,
        )?;
    }
    Ok(blocks)
}

fn copy_u64_vec(values: &SharedVec<u64>) -> SharedResult<SharedVec<u64>, SharedAllocError> {
    let mut copied = SharedVec::with_capacity(values.len(), GFP_KERNEL)?;
    for value in values {
        copied.push(*value, GFP_KERNEL)?;
    }
    Ok(copied)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::arm64::A64Imm;

    #[test]
    fn runtime_exit_rewrites_have_explicit_exit_branch_only() {
        let cases = [
            A64Insn::BlBlOnlyBranchImm {
                imm26: scaled_simm(2, 26, 2),
            },
            A64Insn::BlrBlr64BranchReg { rn: x(4) },
            A64Insn::BrBr64BranchReg { rn: x(5) },
            A64Insn::RetRet64rBranchReg { rn: x(30) },
            A64Insn::SvcSvcExException {
                imm16: A64Imm::unsigned(0, 16),
            },
        ];

        for insn in cases {
            let rephrased = rephrase_insn(IrInsn {
                pc: 0x1000,
                word: 0,
                inner: insn,
            })
            .unwrap();

            assert_eq!(
                rephrased
                    .iter()
                    .filter(|insn| insn.kind == RephrasedInsnKind::RuntimeExitBranch)
                    .count(),
                1,
                "expected one runtime-exit branch for {}",
                insn.key()
            );
            assert!(
                rephrased
                    .iter()
                    .all(|insn| insn.insn.runtime_exit_reason(insn.original_pc).is_none()),
                "raw runtime-exit instruction survived rephrase for {}",
                insn.key()
            );
        }
    }
}
