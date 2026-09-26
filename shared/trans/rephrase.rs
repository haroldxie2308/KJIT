use crate::shared::abi::{
    RetStatus, ABI_LINK_REG, REG_VIRT_SCRATCH_GPR_START, RET_PARAM0_REG, RET_PARAM1_REG,
    RET_STATUS_REG, RUNTIME_FRAME_BUDGET_OFFSET, UNSUPPORTED_WORD_UNREADABLE,
};
use crate::shared::arm64::ergo::{ldst64_offset, mem_off, scaled_simm, sp, uimm, x, xzr};
use crate::shared::arm64::{A64Insn, A64Reg, IrInsn};
use crate::shared::platform::{SharedAllocError, SharedResult, SharedVec, GFP_KERNEL};
use crate::shared::trans::cfg::{layout_block_order, Cfg, RuntimeExitReason};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RephrasedInsnKind {
    Original,
    UserSynthetic,
    RegVirtHelper,
    /// A user memory access (`LDTR`/`STTR`) emitted by reg-virt. It is a fault site:
    /// a fault on it resumes at the `Mem` stub of the same `ori_pc` (one stub per
    /// original instruction, so `ori_pc` alone names the stub; no extra field).
    UserAccess,
    /// One instruction of the back-edge budget check (`budget_check`) that rephrase
    /// puts before a back-edge's lowered sequence. Runtime-owned: reg-virt passes it
    /// through unchanged; its `CBZ` targets the `Budget` stub of the same `ori_pc`.
    BudgetCheck,
    /// One instruction of an alignment check reg-virt puts before a user access
    /// that faults natively on alignment where its `LDTR*`/`STTR*` would not. It
    /// ends in a `CBNZ` to the Mem stub of the same `ori_pc`, so the fragment
    /// leaves and userspace takes the fault itself:
    /// - SP base: `and xS, x17, #15; cbnz xS` (EL0 SP alignment checking; the
    ///   mapped SP in x17 is never checked);
    /// - acquire/release wider than a byte: `and xS, xN, #15; add xS, xS,
    ///   #(size - 1); and xS, xS, #16; cbnz xS` (the access crosses a 16-byte
    ///   boundary, which alignment-faults natively).
    AlignCheck,
    RuntimeExitPayload,
    RuntimeExitBranch,
}

impl RephrasedInsnKind {
    pub const fn is_user_semantic(self) -> bool {
        match self {
            Self::Original | Self::UserSynthetic => true,
            Self::RegVirtHelper
            | Self::UserAccess
            | Self::BudgetCheck
            | Self::AlignCheck
            | Self::RuntimeExitPayload
            | Self::RuntimeExitBranch => false,
        }
    }

    pub const fn is_runtime_exit(self) -> bool {
        match self {
            Self::RuntimeExitPayload | Self::RuntimeExitBranch => true,
            Self::Original
            | Self::UserSynthetic
            | Self::RegVirtHelper
            | Self::UserAccess
            | Self::BudgetCheck
            | Self::AlignCheck => false,
        }
    }

    pub const fn is_runtime_exit_payload(self) -> bool {
        matches!(self, Self::RuntimeExitPayload)
    }

    pub const fn is_runtime_exit_branch(self) -> bool {
        matches!(self, Self::RuntimeExitBranch)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RephrasedInsn {
    pub kind: RephrasedInsnKind,
    pub ori_pc: u64,
    pub insn: A64Insn,
}

impl RephrasedInsn {
    pub const fn original(ori_pc: u64, insn: A64Insn) -> Self {
        Self {
            kind: RephrasedInsnKind::Original,
            ori_pc,
            insn,
        }
    }

    pub const fn user_synthetic(ori_pc: u64, insn: A64Insn) -> Self {
        Self {
            kind: RephrasedInsnKind::UserSynthetic,
            ori_pc,
            insn,
        }
    }

    pub const fn synthetic(ori_pc: u64, insn: A64Insn) -> Self {
        Self::user_synthetic(ori_pc, insn)
    }

    pub const fn reg_virt_helper(ori_pc: u64, insn: A64Insn) -> Self {
        Self {
            kind: RephrasedInsnKind::RegVirtHelper,
            ori_pc,
            insn,
        }
    }

    pub const fn user_access(ori_pc: u64, insn: A64Insn) -> Self {
        Self {
            kind: RephrasedInsnKind::UserAccess,
            ori_pc,
            insn,
        }
    }

    pub const fn budget_check(ori_pc: u64, insn: A64Insn) -> Self {
        Self {
            kind: RephrasedInsnKind::BudgetCheck,
            ori_pc,
            insn,
        }
    }

    pub const fn align_check(ori_pc: u64, insn: A64Insn) -> Self {
        Self {
            kind: RephrasedInsnKind::AlignCheck,
            ori_pc,
            insn,
        }
    }

    pub const fn runtime_exit_payload(ori_pc: u64, insn: A64Insn) -> Self {
        Self {
            kind: RephrasedInsnKind::RuntimeExitPayload,
            ori_pc,
            insn,
        }
    }

    pub const fn runtime_exit_branch(ori_pc: u64, insn: A64Insn) -> Self {
        Self {
            kind: RephrasedInsnKind::RuntimeExitBranch,
            ori_pc,
            insn,
        }
    }
}

/// Basic block after rephrasing, still over the original half-open PC range.
///
/// `cold` holds out-of-line runtime-exit groups, in instruction order: one
/// `RetStatus::Mem` fault stub per original memory instruction and one
/// `RetStatus::Budget` stub per back-edge of this block. A branch never accesses
/// memory, so each original instruction has at most one stub. Layout places every
/// block's `cold` after all block bodies, so nothing falls through into it.
#[derive(Debug, PartialEq, Eq)]
pub struct RephrasedBlock {
    pub start_addr: u64,
    pub end_addr: u64,
    pub prev: SharedVec<u64>,
    pub next: SharedVec<u64>,
    pub insns: SharedVec<RephrasedInsn>,
    pub cold: SharedVec<RephrasedInsn>,
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
                    $crate::shared::trans::rephrase::RephrasedInsn::user_synthetic(
                        $original_pc,
                        $insn,
                    ),
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

pub(crate) fn rephrase_insn(
    insn: IrInsn,
) -> SharedResult<SharedVec<RephrasedInsn>, SharedAllocError> {
    let mut ret = SharedVec::with_capacity(10, GFP_KERNEL)?;
    match insn.inner {
        A64Insn::AdrAdrOnlyPcreladdr { rd, .. } | A64Insn::AdrpAdrpOnlyPcreladdr { rd, .. } => {
            let value = insn
                .inner
                .pc_relative_address(insn.pc)
                .expect("ADR/ADRP must have a PC-relative address");
            push_mov_imm64(
                &mut ret,
                insn.pc,
                rd,
                value,
                RephrasedInsnKind::UserSynthetic,
            )?;
        }
        A64Insn::BlBlOnlyBranchImm { .. } => {
            let Some(RuntimeExitReason::Bl {
                target_pc,
                resume_pc,
            }) = insn.inner.runtime_exit_reason(insn.pc)
            else {
                unreachable!("BL must produce a BL runtime exit reason");
            };

            push_mov_imm64(
                &mut ret,
                insn.pc,
                x(ABI_LINK_REG),
                resume_pc,
                RephrasedInsnKind::UserSynthetic,
            )?;
            push_mov_imm64(
                &mut ret,
                insn.pc,
                x(RET_STATUS_REG),
                RetStatus::Bl.as_reg(),
                RephrasedInsnKind::RuntimeExitPayload,
            )?;
            push_mov_imm64(
                &mut ret,
                insn.pc,
                x(RET_PARAM0_REG),
                target_pc,
                RephrasedInsnKind::RuntimeExitPayload,
            )?;
            push_mov_imm64(
                &mut ret,
                insn.pc,
                x(RET_PARAM1_REG),
                resume_pc,
                RephrasedInsnKind::RuntimeExitPayload,
            )?;
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

            // BLR X30 must capture the old LR target before the user-visible link update.
            push_runtime_exit_payload(
                &mut ret,
                insn.pc,
                A64Insn::OrrLogShiftOrr64LogShift {
                    shift: 0,
                    rm: x(target_reg),
                    imm6: uimm(0, 6),
                    rn: xzr(),
                    rd: x(RET_PARAM0_REG),
                },
            )?;
            push_mov_imm64(
                &mut ret,
                insn.pc,
                x(ABI_LINK_REG),
                resume_pc,
                RephrasedInsnKind::UserSynthetic,
            )?;
            push_mov_imm64(
                &mut ret,
                insn.pc,
                x(RET_STATUS_REG),
                RetStatus::Blr.as_reg(),
                RephrasedInsnKind::RuntimeExitPayload,
            )?;
            push_mov_imm64(
                &mut ret,
                insn.pc,
                x(RET_PARAM1_REG),
                resume_pc,
                RephrasedInsnKind::RuntimeExitPayload,
            )?;
            push_branch_to_stub(&mut ret, insn.pc)?;
        }
        A64Insn::BrBr64BranchReg { .. } => {
            let Some(RuntimeExitReason::Br { target_reg }) =
                insn.inner.runtime_exit_reason(insn.pc)
            else {
                unreachable!("BR must produce a BR runtime exit reason");
            };

            push_mov_imm64(
                &mut ret,
                insn.pc,
                x(RET_STATUS_REG),
                RetStatus::Br.as_reg(),
                RephrasedInsnKind::RuntimeExitPayload,
            )?;
            push_runtime_exit_payload(
                &mut ret,
                insn.pc,
                A64Insn::OrrLogShiftOrr64LogShift {
                    shift: 0,
                    rm: x(target_reg),
                    imm6: uimm(0, 6),
                    rn: xzr(),
                    rd: x(RET_PARAM0_REG),
                },
            )?;
            push_mov_imm64(
                &mut ret,
                insn.pc,
                x(RET_PARAM1_REG),
                insn.pc.wrapping_add(4),
                RephrasedInsnKind::RuntimeExitPayload,
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
                RephrasedInsnKind::RuntimeExitPayload,
            )?;
            push_runtime_exit_payload(
                &mut ret,
                insn.pc,
                A64Insn::OrrLogShiftOrr64LogShift {
                    shift: 0,
                    rm: x(lr_reg),
                    imm6: uimm(0, 6),
                    rn: xzr(),
                    rd: x(RET_PARAM0_REG),
                },
            )?;
            push_mov_imm64(
                &mut ret,
                insn.pc,
                x(RET_PARAM1_REG),
                insn.pc.wrapping_add(4),
                RephrasedInsnKind::RuntimeExitPayload,
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
                RephrasedInsnKind::RuntimeExitPayload,
            )?;
            push_runtime_exit_payload(
                &mut ret,
                insn.pc,
                A64Insn::OrrLogShiftOrr64LogShift {
                    shift: 0,
                    rm: x(8),
                    imm6: uimm(0, 6),
                    rn: xzr(),
                    rd: x(RET_PARAM0_REG),
                },
            )?;
            push_mov_imm64(
                &mut ret,
                insn.pc,
                x(RET_PARAM1_REG),
                resume_pc,
                RephrasedInsnKind::RuntimeExitPayload,
            )?;
            push_branch_to_stub(&mut ret, insn.pc)?;
        }
        // PRFM is a hint: no architectural effect, and it never raises a data abort.
        // Dropping it is exact; one NOP keeps the original PC mapped to fragment code.
        inner if inner.is_prefetch() => ret.push(
            RephrasedInsn::user_synthetic(insn.pc, A64Insn::NopNopHiHints {}),
            GFP_KERNEL,
        )?,
        _ => ret.append(a64_ori!(insn.pc, insn.inner)?, GFP_KERNEL)?,
    }
    Ok(ret)
}

fn push_mov_imm64(
    out: &mut SharedVec<RephrasedInsn>,
    original_pc: u64,
    rd: A64Reg,
    value: u64,
    kind: RephrasedInsnKind,
) -> SharedResult<(), SharedAllocError> {
    out.push(
        RephrasedInsn {
            kind,
            ori_pc: original_pc,
            insn: A64Insn::MovzMovz64Movewide {
                hw: 3,
                imm16: uimm(((value >> 48) & 0xFFFF) as u32, 16),
                rd,
            },
        },
        GFP_KERNEL,
    )?;
    out.push(
        RephrasedInsn {
            kind,
            ori_pc: original_pc,
            insn: A64Insn::MovkMovk64Movewide {
                hw: 2,
                imm16: uimm(((value >> 32) & 0xFFFF) as u32, 16),
                rd,
            },
        },
        GFP_KERNEL,
    )?;
    out.push(
        RephrasedInsn {
            kind,
            ori_pc: original_pc,
            insn: A64Insn::MovkMovk64Movewide {
                hw: 1,
                imm16: uimm(((value >> 16) & 0xFFFF) as u32, 16),
                rd,
            },
        },
        GFP_KERNEL,
    )?;
    out.push(
        RephrasedInsn {
            kind,
            ori_pc: original_pc,
            insn: A64Insn::MovkMovk64Movewide {
                hw: 0,
                imm16: uimm((value & 0xFFFF) as u32, 16),
                rd,
            },
        },
        GFP_KERNEL,
    )
}

fn push_runtime_exit_payload(
    out: &mut SharedVec<RephrasedInsn>,
    original_pc: u64,
    insn: A64Insn,
) -> SharedResult<(), SharedAllocError> {
    out.push(
        RephrasedInsn::runtime_exit_payload(original_pc, insn),
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

/// Exit group that returns to userspace at `pc` so the instruction there executes
/// natively: `Unsupported` (undecodable, rejected or unreadable), `Mem` (fault
/// stub) and `Budget` (budget stub). `param0` is the raw word, or
/// `UNSUPPORTED_WORD_UNREADABLE`.
fn push_native_resume_exit(
    out: &mut SharedVec<RephrasedInsn>,
    status: RetStatus,
    pc: u64,
    param0: u64,
) -> SharedResult<(), SharedAllocError> {
    push_mov_imm64(
        out,
        pc,
        x(RET_STATUS_REG),
        status.as_reg(),
        RephrasedInsnKind::RuntimeExitPayload,
    )?;
    push_mov_imm64(
        out,
        pc,
        x(RET_PARAM0_REG),
        param0,
        RephrasedInsnKind::RuntimeExitPayload,
    )?;
    push_mov_imm64(
        out,
        pc,
        x(RET_PARAM1_REG),
        pc,
        RephrasedInsnKind::RuntimeExitPayload,
    )?;
    push_branch_to_stub(out, pc)
}

/// Scratch register of the budget check. Reg-virt scratch is dead at every original
/// instruction boundary, which is where the check runs (before the back-edge's fills).
const BUDGET_CHECK_SCRATCH_REG: u8 = REG_VIRT_SCRATCH_GPR_START;

/// The back-edge budget check (tmp/pipeline.md, "Execution budget (A6)"):
///
/// ```text
/// ldr x12, [sp, #RUNTIME_FRAME_BUDGET_OFFSET]
/// sub x12, x12, #1
/// str x12, [sp, #RUNTIME_FRAME_BUDGET_OFFSET]
/// cbz x12, <Budget stub of pc>
/// ```
///
/// Plain `LDR`/`STR` on `sp` are runtime accesses to the frame. `SUB` (not `SUBS`)
/// and `CBZ` leave NZCV, which is user state here, untouched. The `CBZ` offset is 0
/// until layout resolves it to the stub.
pub fn budget_check(pc: u64) -> [RephrasedInsn; 4] {
    let scratch = x(BUDGET_CHECK_SCRATCH_REG);
    let slot = mem_off(sp(), ldst64_offset(RUNTIME_FRAME_BUDGET_OFFSET));
    [
        RephrasedInsn::budget_check(
            pc,
            A64Insn::LdrImmGenLdr64LdstPos {
                rt: scratch,
                mem: slot,
            },
        ),
        RephrasedInsn::budget_check(
            pc,
            A64Insn::SubAddsubImmSub64AddsubImm {
                sh: 0,
                imm12: uimm(1, 12),
                rn: A64Reg::x_sp(BUDGET_CHECK_SCRATCH_REG),
                rd: A64Reg::x_sp(BUDGET_CHECK_SCRATCH_REG),
            },
        ),
        RephrasedInsn::budget_check(
            pc,
            A64Insn::StrImmGenStr64LdstPos {
                rt: scratch,
                mem: slot,
            },
        ),
        RephrasedInsn::budget_check(
            pc,
            A64Insn::CbzCbz64Compbranch {
                imm19: scaled_simm(0, 19, 2),
                rt: scratch,
            },
        ),
    ]
}

/// Target of a user branch (B, B.cond, CBZ/CBNZ, TBZ/TBNZ): the forms layout
/// relocates as user branches. BL never reaches here as a user instruction; rephrase
/// lowers it to a runtime exit.
fn user_branch_target(insn: A64Insn, pc: u64) -> Option<u64> {
    insn.direct_branch_target(pc)
        .or_else(|| insn.conditional_targets(pc).map(|(taken, _)| taken))
}

/// Whether the lowered sequence of one original instruction contains a back-edge: a
/// user-semantic branch whose target label is at or before it in layout order
/// (`layout_block_order`). A PC's label is its first emitted instruction, so that is
/// exactly "the target PC is in `placed`" (every PC emitted so far in layout order,
/// this instruction's own included). Layout re-checks it on final offsets
/// (`LayoutError::UnguardedBackEdge`).
fn is_back_edge(lowered: &[RephrasedInsn], placed: &[u64]) -> bool {
    lowered
        .iter()
        .filter(|insn| insn.kind.is_user_semantic())
        .filter_map(|insn| user_branch_target(insn.insn, insn.ori_pc))
        .any(|target| placed.contains(&target))
}

/// Rephrases every block. The output keeps the CFG's block order (the entry block
/// first); blocks are visited in layout order only to find back-edges.
pub fn rephrase(cfg: Cfg) -> SharedResult<RephrasedProgram, SharedAllocError> {
    let order = layout_block_order(cfg.blocks.iter().map(|block| block.start_addr))?;
    let mut rephrased: SharedVec<Option<RephrasedBlock>> =
        SharedVec::with_capacity(cfg.blocks.len(), GFP_KERNEL)?;
    for _ in 0..cfg.blocks.len() {
        rephrased.push(None, GFP_KERNEL)?;
    }
    // Original PCs whose body label is placed so far, in layout order.
    let mut placed = SharedVec::new();
    for &index in order.iter() {
        let block = &cfg.blocks[index];
        let mut insns = SharedVec::with_capacity(block.insns.len() * 10, GFP_KERNEL)?;
        let mut cold = SharedVec::new();
        for insn in &block.insns {
            placed.push(insn.pc, GFP_KERNEL)?;
            let lowered = rephrase_insn(*insn)?;
            if is_back_edge(&lowered, &placed) {
                // The check precedes the whole lowered sequence, so the Budget exit
                // leaves with the state before the instruction and userspace
                // re-executes the branch natively.
                for check in budget_check(insn.pc) {
                    insns.push(check, GFP_KERNEL)?;
                }
                push_native_resume_exit(
                    &mut cold,
                    RetStatus::Budget,
                    insn.pc,
                    u64::from(insn.word),
                )?;
            }
            insns.append(lowered, GFP_KERNEL)?;
            if insn.inner.accesses_memory() {
                // Fault stub: userspace re-executes the instruction and takes the fault.
                push_native_resume_exit(&mut cold, RetStatus::Mem, insn.pc, u64::from(insn.word))?;
            }
        }
        if let Some(exit) = block.unsupported_exit {
            placed.push(exit.pc(), GFP_KERNEL)?;
            let param0 = exit.word().map_or(UNSUPPORTED_WORD_UNREADABLE, u64::from);
            push_native_resume_exit(&mut insns, RetStatus::Unsupported, exit.pc(), param0)?;
        }

        rephrased[index] = Some(RephrasedBlock {
            start_addr: block.start_addr,
            end_addr: block.end_addr,
            prev: copy_u64_vec(&block.prev)?,
            next: copy_u64_vec(&block.next)?,
            insns,
            cold,
        });
    }

    let mut blocks = SharedVec::with_capacity(rephrased.len(), GFP_KERNEL)?;
    for block in rephrased.iter_mut() {
        // `order` is a permutation of the block indices, so every slot is filled.
        let block = block.take().expect("layout order visits every block once");
        blocks.push(block, GFP_KERNEL)?;
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
                    .filter(|insn| insn.kind.is_runtime_exit_branch())
                    .count(),
                1,
                "expected one runtime-exit branch for {}",
                insn.key()
            );
            assert!(
                rephrased
                    .iter()
                    .filter(|insn| !insn.kind.is_runtime_exit_branch())
                    .all(|insn| matches!(
                        insn.kind,
                        RephrasedInsnKind::RuntimeExitPayload | RephrasedInsnKind::UserSynthetic
                    )),
                "expected runtime-exit lowering instructions to be payload or user-synthetic for {}",
                insn.key()
            );
            assert!(
                rephrased
                    .iter()
                    .all(|insn| insn.kind.is_runtime_exit() || insn.kind.is_user_semantic()),
                "expected only runtime-exit or user-semantic lowering instructions for {}",
                insn.key()
            );
            assert!(
                rephrased
                    .iter()
                    .all(|insn| insn.insn.runtime_exit_reason(insn.ori_pc).is_none()),
                "raw runtime-exit instruction survived rephrase for {}",
                insn.key()
            );
        }
    }

    #[test]
    fn bl_and_blr_emit_user_semantic_link_update() {
        let cases = [
            A64Insn::BlBlOnlyBranchImm {
                imm26: scaled_simm(2, 26, 2),
            },
            A64Insn::BlrBlr64BranchReg { rn: x(4) },
        ];

        for insn in cases {
            let rephrased = rephrase_insn(IrInsn {
                pc: 0x1000,
                word: 0,
                inner: insn,
            })
            .unwrap();

            assert!(
                rephrased.iter().any(|insn| {
                    insn.kind == RephrasedInsnKind::UserSynthetic
                        && matches!(
                            insn.insn,
                            A64Insn::MovzMovz64Movewide { rd, .. }
                                | A64Insn::MovkMovk64Movewide { rd, .. }
                                if rd.enc == ABI_LINK_REG
                        )
                }),
                "expected {} to write user LR as user-semantic code",
                insn.key()
            );
        }
    }

    #[test]
    fn blr_x30_captures_old_lr_before_link_update() {
        let rephrased = rephrase_insn(IrInsn {
            pc: 0x1000,
            word: 0,
            inner: A64Insn::BlrBlr64BranchReg {
                rn: x(ABI_LINK_REG),
            },
        })
        .unwrap();

        assert_eq!(
            rephrased[0],
            RephrasedInsn::runtime_exit_payload(
                0x1000,
                A64Insn::OrrLogShiftOrr64LogShift {
                    shift: 0,
                    rm: x(ABI_LINK_REG),
                    imm6: uimm(0, 6),
                    rn: xzr(),
                    rd: x(RET_PARAM0_REG),
                },
            )
        );
        assert_eq!(rephrased[1].kind, RephrasedInsnKind::UserSynthetic);
    }

    #[test]
    fn adr_expansions_are_user_synthetic() {
        let cases = [
            A64Insn::AdrAdrOnlyPcreladdr {
                immlo: A64Imm::unsigned(0, 2),
                immhi: A64Imm::unsigned(1, 19),
                rd: x(3),
            },
            A64Insn::AdrpAdrpOnlyPcreladdr {
                immlo: A64Imm::unsigned(0, 2),
                immhi: A64Imm::unsigned(0, 19),
                rd: x(4),
            },
        ];

        for insn in cases {
            let rephrased = rephrase_insn(IrInsn {
                pc: 0x1000,
                word: 0,
                inner: insn,
            })
            .unwrap();

            assert_eq!(rephrased.len(), 4);
            assert!(
                rephrased
                    .iter()
                    .all(|insn| insn.kind == RephrasedInsnKind::UserSynthetic),
                "expected ADR/ADRP expansion to be user synthetic for {}",
                insn.key()
            );
            assert!(
                rephrased.iter().all(|insn| insn.kind.is_user_semantic()),
                "expected ADR/ADRP expansion to stay user-semantic for {}",
                insn.key()
            );
        }
    }

    #[test]
    fn memory_instructions_get_one_mem_fault_stub_in_the_cold_region() {
        use crate::shared::arm64::{A64Mem, A64Reg};
        use crate::shared::trans::cfg::BasicBlock;

        let ldp = A64Insn::LdpGenLdp64LdstpairOff {
            rt2: x(1),
            rt: x(0),
            mem: A64Mem::offset(A64Reg::x_sp(2), scaled_simm(0, 7, 3)),
        };
        let mut insns = SharedVec::new();
        for (pc, inner) in [(0x1000, A64Insn::NopNopHiHints {}), (0x1004, ldp)] {
            insns
                .push(
                    IrInsn {
                        pc,
                        word: inner.encode().unwrap(),
                        inner,
                    },
                    GFP_KERNEL,
                )
                .unwrap();
        }
        let mut blocks = SharedVec::new();
        blocks
            .push(
                BasicBlock {
                    start_addr: 0x1000,
                    end_addr: 0x1008,
                    insns,
                    prev: SharedVec::new(),
                    next: SharedVec::new(),
                    unsupported_exit: None,
                },
                GFP_KERNEL,
            )
            .unwrap();
        let program = rephrase(Cfg {
            entry_pc: 0x1000,
            blocks,
        })
        .unwrap();

        let cold = &program[0].cold;
        assert!(cold.iter().all(|insn| insn.ori_pc == 0x1004));
        assert_eq!(
            cold.iter()
                .filter(|insn| insn.kind.is_runtime_exit_branch())
                .count(),
            1
        );
        assert!(cold[..cold.len() - 1]
            .iter()
            .all(|insn| insn.kind == RephrasedInsnKind::RuntimeExitPayload));
        // x9 = Mem, x10 = the original word, x11 = its PC (MOVZ/MOVK x3 of four).
        let imm = |index: usize| match cold[index].insn {
            A64Insn::MovzMovz64Movewide { imm16, .. }
            | A64Insn::MovkMovk64Movewide { imm16, .. } => {
                u64::from(imm16.raw()) << (16 * (3 - index % 4))
            }
            other => panic!("unexpected payload {other:?}"),
        };
        let value = |group: usize| (0..4).map(|i| imm(group * 4 + i)).sum::<u64>();
        assert_eq!(value(0), RetStatus::Mem.as_reg());
        assert_eq!(value(1), u64::from(ldp.encode().unwrap()));
        assert_eq!(value(2), 0x1004);
    }

    fn branch_forms(delta: i64) -> [A64Insn; 8] {
        let words = delta / 4;
        let imm = |bits: u8| scaled_simm((words as u32) & ((1 << bits) - 1), bits, 2);
        [
            A64Insn::BUncondBOnlyBranchImm { imm26: imm(26) },
            A64Insn::BCondBOnlyCondbranch {
                imm19: imm(19),
                cond: 1,
            },
            A64Insn::CbzCbz32Compbranch {
                imm19: imm(19),
                rt: crate::shared::arm64::ergo::w(1),
            },
            A64Insn::CbzCbz64Compbranch {
                imm19: imm(19),
                rt: x(1),
            },
            A64Insn::CbnzCbnz32Compbranch {
                imm19: imm(19),
                rt: crate::shared::arm64::ergo::w(1),
            },
            A64Insn::CbnzCbnz64Compbranch {
                imm19: imm(19),
                rt: x(1),
            },
            A64Insn::TbzTbzOnlyTestbranch {
                b5: 0,
                b40: 3,
                imm14: imm(14),
                rt: x(1),
            },
            A64Insn::TbnzTbnzOnlyTestbranch {
                b5: 1,
                b40: 3,
                imm14: imm(14),
                rt: x(1),
            },
        ]
    }

    /// One CFG block per slice, in the given (layout) order.
    fn cfg_of(blocks: &[&[(u64, A64Insn)]]) -> Cfg {
        use crate::shared::trans::cfg::BasicBlock;

        let mut out = SharedVec::new();
        for block in blocks {
            let mut insns = SharedVec::new();
            for &(pc, inner) in *block {
                insns
                    .push(
                        IrInsn {
                            pc,
                            word: inner.encode().unwrap(),
                            inner,
                        },
                        GFP_KERNEL,
                    )
                    .unwrap();
            }
            out.push(
                BasicBlock {
                    start_addr: block[0].0,
                    end_addr: block[block.len() - 1].0 + 4,
                    insns,
                    prev: SharedVec::new(),
                    next: SharedVec::new(),
                    unsupported_exit: None,
                },
                GFP_KERNEL,
            )
            .unwrap();
        }
        Cfg {
            entry_pc: blocks[0][0].0,
            blocks: out,
        }
    }

    /// The four MOVZ/MOVK x3 values of a native-resume exit group:
    /// (status, x10 = word, x11 = pc).
    fn native_resume_values(group: &[RephrasedInsn]) -> (u64, u64, u64) {
        assert_eq!(group.len(), 13);
        assert!(group[12].kind.is_runtime_exit_branch());
        let imm = |index: usize| match group[index].insn {
            A64Insn::MovzMovz64Movewide { imm16, .. }
            | A64Insn::MovkMovk64Movewide { imm16, .. } => {
                u64::from(imm16.raw()) << (16 * (3 - index % 4))
            }
            other => panic!("unexpected payload {other:?}"),
        };
        let value = |g: usize| (0..4).map(|i| imm(g * 4 + i)).sum::<u64>();
        (value(0), value(1), value(2))
    }

    fn assert_budget_checked(block: &RephrasedBlock, branch: A64Insn, pc: u64) {
        let check = budget_check(pc);
        assert_eq!(
            &block.insns[block.insns.len() - 5..block.insns.len() - 1],
            &check
        );
        assert_eq!(
            block.insns[block.insns.len() - 1],
            RephrasedInsn::original(pc, branch)
        );
        assert_eq!(
            native_resume_values(&block.cold),
            (
                RetStatus::Budget.as_reg(),
                u64::from(branch.encode().unwrap()),
                pc
            ),
            "{}",
            branch.key()
        );
        assert!(block.cold.iter().all(|insn| insn.ori_pc == pc));
    }

    fn assert_not_budget_checked(block: &RephrasedBlock) {
        assert!(block
            .insns
            .iter()
            .all(|insn| insn.kind != RephrasedInsnKind::BudgetCheck));
        assert!(block.cold.is_empty());
    }

    #[test]
    fn every_user_branch_form_to_itself_gets_the_budget_check() {
        for branch in branch_forms(0) {
            let program = rephrase(cfg_of(&[&[(0x1000, branch)]])).unwrap();
            assert_budget_checked(&program[0], branch, 0x1000);
        }
    }

    #[test]
    fn every_user_branch_form_to_an_earlier_block_gets_the_budget_check() {
        let nop = A64Insn::NopNopHiHints {};
        for branch in branch_forms(-8) {
            let program = rephrase(cfg_of(&[
                &[(0x1000, nop)],
                &[(0x1004, nop), (0x1008, branch)],
            ]))
            .unwrap();
            assert_not_budget_checked(&program[0]);
            assert_budget_checked(&program[1], branch, 0x1008);
        }
    }

    #[test]
    fn forward_user_branches_get_no_budget_check() {
        let nop = A64Insn::NopNopHiHints {};
        for branch in branch_forms(8) {
            let program = rephrase(cfg_of(&[
                &[(0x1000, branch)],
                &[(0x1004, nop)],
                &[(0x1008, nop)],
            ]))
            .unwrap();
            for block in program.iter() {
                assert_not_budget_checked(block);
            }
        }
    }

    /// Back-edge means "at or before in layout order" (`layout_block_order`: ascending
    /// block start), whatever order the CFG discovered the blocks in.
    #[test]
    fn back_edges_follow_layout_order_not_cfg_discovery_order() {
        let nop = A64Insn::NopNopHiHints {};
        // Target block discovered later but laid out first: back-edge.
        for branch in branch_forms(-8) {
            let program = rephrase(cfg_of(&[&[(0x1008, branch)], &[(0x1000, nop)]])).unwrap();
            // The output keeps CFG order (entry block first).
            assert_eq!(program[0].start_addr, 0x1008);
            assert_budget_checked(&program[0], branch, 0x1008);
            assert_not_budget_checked(&program[1]);
        }
        // Target block discovered first but laid out later: forward.
        for branch in branch_forms(0x10) {
            let program = rephrase(cfg_of(&[&[(0x1010, nop)], &[(0x1000, branch)]])).unwrap();
            assert_not_budget_checked(&program[0]);
            assert_not_budget_checked(&program[1]);
        }
    }

    #[test]
    fn branch_inside_a_user_synthetic_sequence_is_a_back_edge_too() {
        let mov = A64Insn::MovzMovz64Movewide {
            hw: 0,
            imm16: uimm(1, 16),
            rd: x(3),
        };
        let lowered = [
            RephrasedInsn::user_synthetic(0x1004, mov),
            RephrasedInsn::user_synthetic(0x1004, branch_forms(-4)[0]),
        ];
        assert!(is_back_edge(&lowered, &[0x1000, 0x1004]));
        assert!(!is_back_edge(&lowered, &[0x1004]));
        // Runtime-exit branches are never user branches.
        let exit = [RephrasedInsn::runtime_exit_branch(
            0x1004,
            branch_forms(0)[0],
        )];
        assert!(!is_back_edge(&exit, &[0x1004]));
    }

    #[test]
    fn budget_check_is_runtime_owned_and_leaves_nzcv_alone() {
        use crate::shared::arm64::A64OperandRole;

        let check = budget_check(0x1000);
        for insn in &check {
            assert_eq!(insn.kind, RephrasedInsnKind::BudgetCheck);
            assert!(!insn.kind.is_user_semantic() && !insn.kind.is_runtime_exit());
            assert!(!insn.insn.operand_roles().iter().any(|role| matches!(
                role,
                A64OperandRole::FlagsWrite | A64OperandRole::FlagsRead
            )));
            insn.insn.encode().unwrap();
        }
    }
}
