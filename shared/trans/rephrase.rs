use crate::shared::abi::{
    RetStatus, ABI_LINK_REG, BUDGET_COUNTER_REG, DISPATCH_TARGET_REG, KJIT_DISPATCH_TEMPLATE,
    RET_PARAM0_REG, RET_PARAM1_REG, RET_STATUS_REG, UNSUPPORTED_WORD_UNREADABLE,
};
use crate::shared::arm64::ergo::{scaled_simm, uimm, x, xzr};
use crate::shared::arm64::{A64Insn, A64Reg, IrInsn};
use crate::shared::platform::{SharedAllocError, SharedResult, SharedVec, GFP_KERNEL};
use crate::shared::trans::cfg::{layout_block_order, Cfg, RuntimeExitReason};
use crate::shared::trans::reg_virt::{sp_write, SpWrite};

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
    /// One instruction of an alignment check reg-virt emits. It ends in a `CBNZ` to
    /// the Mem stub of the same `ori_pc`, so the fragment leaves and userspace takes
    /// the fault itself:
    /// - guard of a write to user SP that may misalign it (A22): `and xT, xS, #15;
    ///   cbnz xT` on the new SP value, before the instruction commits;
    /// - acquire/release or atomic wider than a byte: `and xS, xN, #15; add xS, xS,
    ///   #(size - 1); and xS, xS, #16; cbnz xS` (the access crosses a 16-byte
    ///   boundary, which alignment-faults natively).
    AlignCheck,
    /// Window range check (A8, A15; docs/pipeline.md, "LSE atomics through a PAN
    /// window (A8)"), emitted by reg-virt right before a window access:
    /// `ubfx sB, sA, #48, #8; cbnz sB, <Mem stub>`. Its `CBNZ` targets the `Mem` stub
    /// of the same `ori_pc`.
    RangeCheck,
    /// The window access -- an LSE atomic (A8) or an A9a SIMD&FP load/store in its
    /// base-only encoding: a privileged access to user memory, run with PAN clear
    /// (A15; reg-virt output). It is a fault site whose stub is the `Mem` stub of
    /// the same `ori_pc`.
    WindowAccess,
    /// A branch site's target move (A11): writes the target T into
    /// `DISPATCH_TARGET_REG` (physical x13, never user x13). Either `movz`/`movk x13`
    /// of a constant (BL), or `orr x13, xzr, Xm` where `Xm` is the *user* register
    /// holding the target, which reg-virt maps like any user source (fill from its
    /// frame slot, x16/x17 for x29/sp). Runtime-owned: x13 is scratch.
    DispatchTarget,
    /// One word of the dispatch template (`KJIT_DISPATCH_TEMPLATE`), in the body of a
    /// branch site between its target move (and, for a BL, its link slot) and its exit
    /// group. Runtime-owned, reg-virt passes it through; layout resolves its miss branches (the main probe's
    /// to the victim probe's first word, the victim probe's to the exit group that
    /// follows the final `br`).
    DispatchLookup,
    /// A static `BL` site's link slot (A16; docs/pipeline.md, "Direct BL links
    /// (A16)"): one `nop` right after the link write, ahead of the target move (A20)
    /// and the dispatch template, that the runtime may turn into
    /// `b <host of target_pc>`. Runtime-owned, reg-virt passes it through; layout
    /// lists it in `ExecutionFragment::link_sites`.
    LinkSlot {
        target_pc: u64,
    },
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
            | Self::RangeCheck
            | Self::WindowAccess
            | Self::DispatchTarget
            | Self::DispatchLookup
            | Self::LinkSlot { .. }
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
            | Self::AlignCheck
            | Self::RangeCheck
            | Self::WindowAccess
            | Self::DispatchTarget
            | Self::DispatchLookup
            | Self::LinkSlot { .. } => false,
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

    pub const fn range_check(ori_pc: u64, insn: A64Insn) -> Self {
        Self {
            kind: RephrasedInsnKind::RangeCheck,
            ori_pc,
            insn,
        }
    }

    pub const fn window_access(ori_pc: u64, insn: A64Insn) -> Self {
        Self {
            kind: RephrasedInsnKind::WindowAccess,
            ori_pc,
            insn,
        }
    }

    pub const fn dispatch_target(ori_pc: u64, insn: A64Insn) -> Self {
        Self {
            kind: RephrasedInsnKind::DispatchTarget,
            ori_pc,
            insn,
        }
    }

    pub const fn dispatch_lookup(ori_pc: u64, insn: A64Insn) -> Self {
        Self {
            kind: RephrasedInsnKind::DispatchLookup,
            ori_pc,
            insn,
        }
    }

    pub const fn link_slot(ori_pc: u64, target_pc: u64) -> Self {
        Self {
            kind: RephrasedInsnKind::LinkSlot { target_pc },
            ori_pc,
            insn: A64Insn::NopNopHiHints {},
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
/// `RetStatus::Budget` stub per back-edge or dispatch site (BL/BLR/BR/RET, A11) of
/// this block. A branch never accesses
/// memory, so each original instruction has at most one plain stub. That includes an
/// LSE atomic (A8) or SIMD&FP load/store (A9a): its range check, alignment checks
/// and fault site all leave through its `Mem` stub (A15).
/// Layout places every block's `cold` after all block bodies, so nothing falls
/// through into it.
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
        // Branch sites (A11, docs/pipeline.md "In-fragment branch dispatch (A11)",
        // Lowering). The budget
        // check that precedes the whole sequence is added by `rephrase`. Order: for
        // BLR/BR/RET the target into x13 (before any x30 write, so `blr x30` stays
        // correct), then the link write; for BL (A16, A20) the link write, the link slot,
        // the target into x13. Then the dispatch template, then the exit group a miss
        // takes: the same status and x11 as before the template existed, x10 = x13.
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
            // A16: the target is a translation-time constant, so the site can be linked.
            ret.push(RephrasedInsn::link_slot(insn.pc, target_pc), GFP_KERNEL)?;
            // A20: the target move follows the slot, so a linked transfer skips it. Only
            // the template reads x13, and the link write above is independent of it.
            push_mov_imm64(
                &mut ret,
                insn.pc,
                x(DISPATCH_TARGET_REG),
                target_pc,
                RephrasedInsnKind::DispatchTarget,
            )?;
            push_dispatch_template(&mut ret, insn.pc)?;
            push_dispatch_miss_exit(&mut ret, insn.pc, RetStatus::Bl, resume_pc)?;
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
            push_dispatch_target_capture(&mut ret, insn.pc, target_reg)?;
            push_mov_imm64(
                &mut ret,
                insn.pc,
                x(ABI_LINK_REG),
                resume_pc,
                RephrasedInsnKind::UserSynthetic,
            )?;
            push_dispatch_template(&mut ret, insn.pc)?;
            push_dispatch_miss_exit(&mut ret, insn.pc, RetStatus::Blr, resume_pc)?;
        }
        A64Insn::BrBr64BranchReg { .. } => {
            let Some(RuntimeExitReason::Br { target_reg }) =
                insn.inner.runtime_exit_reason(insn.pc)
            else {
                unreachable!("BR must produce a BR runtime exit reason");
            };

            push_dispatch_target_capture(&mut ret, insn.pc, target_reg)?;
            push_dispatch_template(&mut ret, insn.pc)?;
            push_dispatch_miss_exit(&mut ret, insn.pc, RetStatus::Br, insn.pc.wrapping_add(4))?;
        }
        A64Insn::RetRet64rBranchReg { .. } => {
            let Some(RuntimeExitReason::Ret { lr_reg }) = insn.inner.runtime_exit_reason(insn.pc)
            else {
                unreachable!("RET must produce a RET runtime exit reason");
            };

            push_dispatch_target_capture(&mut ret, insn.pc, lr_reg)?;
            push_dispatch_template(&mut ret, insn.pc)?;
            push_dispatch_miss_exit(&mut ret, insn.pc, RetStatus::Ret, insn.pc.wrapping_add(4))?;
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
        // BTI executed in sequence is a NOP. Its only effect is the landing-pad check
        // of an indirect branch into a guarded page: fragment code is never one
        // (entries come from the runtime, kernel BTI is off, K1), and a runtime exit
        // does not carry PSTATE.BTYPE into the target (K3 BTI limitation). So a NOP
        // is exact for every correct program, and no BTI reaches EL1.
        A64Insn::BtiBtiHbHints { .. } => ret.push(
            RephrasedInsn::user_synthetic(insn.pc, A64Insn::NopNopHiHints {}),
            GFP_KERNEL,
        )?,
        _ => ret.append(a64_ori!(insn.pc, insn.inner)?, GFP_KERNEL)?,
    }
    Ok(ret)
}

/// `rd = value` (docs/pipeline.md, "Hot-path word reduction (A21)"): the one helper
/// behind every 64-bit constant the translator writes (ADR/ADRP results, link writes,
/// BL targets, exit payloads, literal addresses). One word per non-zero halfword: a
/// `movz` of the lowest non-zero halfword (with its `hw`), then a `movk` for each
/// higher non-zero halfword; `movz rd, #0` for zero. The result is `value` exactly,
/// and only `rd` is written, so nothing between the words can observe a partial value.
pub(crate) fn push_mov_imm64(
    out: &mut SharedVec<RephrasedInsn>,
    original_pc: u64,
    rd: A64Reg,
    value: u64,
    kind: RephrasedInsnKind,
) -> SharedResult<(), SharedAllocError> {
    let halfword = |hw: u8| ((value >> (16 * u32::from(hw))) & 0xFFFF) as u32;
    let Some(lowest) = (0..4_u8).find(|&hw| halfword(hw) != 0) else {
        return out.push(
            RephrasedInsn {
                kind,
                ori_pc: original_pc,
                insn: A64Insn::MovzMovz64Movewide {
                    hw: 0,
                    imm16: uimm(0, 16),
                    rd,
                },
            },
            GFP_KERNEL,
        );
    };
    out.push(
        RephrasedInsn {
            kind,
            ori_pc: original_pc,
            insn: A64Insn::MovzMovz64Movewide {
                hw: lowest,
                imm16: uimm(halfword(lowest), 16),
                rd,
            },
        },
        GFP_KERNEL,
    )?;
    for hw in (lowest + 1)..4 {
        if halfword(hw) != 0 {
            out.push(
                RephrasedInsn {
                    kind,
                    ori_pc: original_pc,
                    insn: A64Insn::MovkMovk64Movewide {
                        hw,
                        imm16: uimm(halfword(hw), 16),
                        rd,
                    },
                },
                GFP_KERNEL,
            )?;
        }
    }
    Ok(())
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

/// `orr x13, xzr, X<source>`: T into `DISPATCH_TARGET_REG`. `source` is a *user*
/// register number; reg-virt maps it (`DispatchTarget`).
fn push_dispatch_target_capture(
    out: &mut SharedVec<RephrasedInsn>,
    original_pc: u64,
    source: u8,
) -> SharedResult<(), SharedAllocError> {
    out.push(
        RephrasedInsn::dispatch_target(
            original_pc,
            A64Insn::OrrLogShiftOrr64LogShift {
                shift: 0,
                rm: x(source),
                imm6: uimm(0, 6),
                rn: xzr(),
                rd: x(DISPATCH_TARGET_REG),
            },
        ),
        GFP_KERNEL,
    )
}

/// The dispatch template (`KJIT_DISPATCH_TEMPLATE`), miss branches unresolved.
fn push_dispatch_template(
    out: &mut SharedVec<RephrasedInsn>,
    original_pc: u64,
) -> SharedResult<(), SharedAllocError> {
    for insn in KJIT_DISPATCH_TEMPLATE {
        out.push(RephrasedInsn::dispatch_lookup(original_pc, insn), GFP_KERNEL)?;
    }
    Ok(())
}

/// `add x10, x13, #0`: the miss exit group's RET_PARAM0 = T. Not the `orr x10, xzr,
/// Xm` shape reg-virt treats as a param0 capture of a *user* register: x13 here is
/// the physical dispatch scratch, so reg-virt allows exactly this word to read it
/// (`is_dispatch_miss_param0_copy`).
pub(crate) fn dispatch_miss_param0_copy() -> A64Insn {
    A64Insn::AddAddsubImmAdd64AddsubImm {
        sh: 0,
        imm12: uimm(0, 12),
        rn: A64Reg::x_sp(DISPATCH_TARGET_REG),
        rd: A64Reg::x_sp(RET_PARAM0_REG),
    }
}

pub(crate) fn is_dispatch_miss_param0_copy(insn: A64Insn) -> bool {
    insn == dispatch_miss_param0_copy()
}

/// The exit group of a dispatch miss: today's branch exit (`status`, x11 =
/// `resume_pc`) with RET_PARAM0 taken from x13.
fn push_dispatch_miss_exit(
    out: &mut SharedVec<RephrasedInsn>,
    original_pc: u64,
    status: RetStatus,
    resume_pc: u64,
) -> SharedResult<(), SharedAllocError> {
    push_mov_imm64(
        out,
        original_pc,
        x(RET_STATUS_REG),
        status.as_reg(),
        RephrasedInsnKind::RuntimeExitPayload,
    )?;
    push_runtime_exit_payload(out, original_pc, dispatch_miss_param0_copy())?;
    push_mov_imm64(
        out,
        original_pc,
        x(RET_PARAM1_REG),
        resume_pc,
        RephrasedInsnKind::RuntimeExitPayload,
    )?;
    push_branch_to_stub(out, original_pc)
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

/// Words of the budget check.
const BUDGET_CHECK_LEN: usize = 2;

/// The budget check (docs/pipeline.md, "Execution budget (A6)", A12):
///
/// ```text
/// sub x18, x18, #1                  ; d1000652
/// cbz x18, <Budget stub of pc>
/// ```
///
/// Physical x18 is the budget counter for the whole run (`BUDGET_COUNTER_REG`; user
/// x18 is stack-backed), so the check touches no memory and no scratch register.
/// `SUB` (not `SUBS`) and `CBZ` leave NZCV, which is user state here, untouched. The
/// `CBZ` offset is 0 until layout resolves it to the stub.
pub fn budget_check(pc: u64) -> [RephrasedInsn; BUDGET_CHECK_LEN] {
    [
        RephrasedInsn::budget_check(
            pc,
            A64Insn::SubAddsubImmSub64AddsubImm {
                sh: 0,
                imm12: uimm(1, 12),
                rn: A64Reg::x_sp(BUDGET_COUNTER_REG),
                rd: A64Reg::x_sp(BUDGET_COUNTER_REG),
            },
        ),
        RephrasedInsn::budget_check(
            pc,
            A64Insn::CbzCbz64Compbranch {
                imm19: scaled_simm(0, 19, 2),
                rt: x(BUDGET_COUNTER_REG),
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

/// A branch site whose lowering ends in the dispatch template: the original BL, BLR,
/// BR and RET. Each dispatch attempt is charged to the budget (A11), so the check
/// precedes the whole lowered site exactly as it does a back-edge.
fn is_dispatch_site(insn: &IrInsn) -> bool {
    matches!(
        insn.inner.runtime_exit_reason(insn.pc),
        Some(
            RuntimeExitReason::Bl { .. }
                | RuntimeExitReason::Blr { .. }
                | RuntimeExitReason::Br { .. }
                | RuntimeExitReason::Ret { .. }
        )
    )
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
            if is_back_edge(&lowered, &placed) || is_dispatch_site(insn) {
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
            if insn.inner.accesses_memory() || sp_write(insn.inner) == SpWrite::Guarded {
                // Fault stub: userspace re-executes the instruction and takes the fault
                // (for a guarded write to SP, the misaligned SP it leaves behind).
                push_native_resume_exit(
                    &mut cold,
                    RetStatus::Mem,
                    insn.pc,
                    u64::from(insn.word),
                )?;
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
    use crate::shared::abi::DISPATCH_TEMPLATE_LEN;
    use crate::shared::arm64::A64Imm;

    /// The values a run of `movz`/`movk` words builds: a `movz` starts a value, each
    /// `movk` replaces its halfword. Every word must write `rd`'s own chain.
    fn const_chains(words: &[RephrasedInsn]) -> Vec<(u8, u64)> {
        let mut chains: Vec<(u8, u64)> = Vec::new();
        for word in words {
            match word.insn {
                A64Insn::MovzMovz64Movewide { hw, imm16, rd } => {
                    chains.push((rd.enc, u64::from(imm16.raw()) << (16 * u32::from(hw))));
                }
                A64Insn::MovkMovk64Movewide { hw, imm16, rd } => {
                    let (chain_rd, value) = chains.last_mut().expect("a movk follows a movz");
                    assert_eq!(*chain_rd, rd.enc, "one chain writes one register");
                    let shift = 16 * u32::from(hw);
                    *value = (*value & !(0xFFFF << shift)) | u64::from(imm16.raw()) << shift;
                }
                other => panic!("not a constant word: {other:?}"),
            }
        }
        chains
    }

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
            // A11: BL/BLR/BR/RET are dispatch sites (target move, template, then the
            // exit group a miss takes); SVC is a plain exit group.
            let dispatch_site = !matches!(insn, A64Insn::SvcSvcExException { .. });
            let dispatch_kind = |kind: RephrasedInsnKind| {
                matches!(
                    kind,
                    RephrasedInsnKind::DispatchTarget
                        | RephrasedInsnKind::DispatchLookup
                        | RephrasedInsnKind::LinkSlot { .. }
                )
            };
            assert!(
                rephrased
                    .iter()
                    .filter(|insn| !insn.kind.is_runtime_exit_branch())
                    .all(|insn| matches!(
                        insn.kind,
                        RephrasedInsnKind::RuntimeExitPayload | RephrasedInsnKind::UserSynthetic
                    ) || (dispatch_site && dispatch_kind(insn.kind))),
                "expected runtime-exit lowering instructions to be payload, user-synthetic or dispatch for {}",
                insn.key()
            );
            assert!(
                rephrased.iter().all(|insn| insn.kind.is_runtime_exit()
                    || insn.kind.is_user_semantic()
                    || (dispatch_site && dispatch_kind(insn.kind))),
                "expected only runtime-exit, user-semantic or dispatch lowering instructions for {}",
                insn.key()
            );
            let template = rephrased
                .iter()
                .filter(|insn| insn.kind == RephrasedInsnKind::DispatchLookup)
                .map(|insn| insn.insn)
                .collect::<Vec<_>>();
            if dispatch_site {
                assert_eq!(
                    template,
                    KJIT_DISPATCH_TEMPLATE,
                    "expected the byte-exact dispatch template for {}",
                    insn.key()
                );
                // The template is followed by the exit group, which copies T from x13.
                let after_br = rephrased
                    .iter()
                    .rposition(|insn| matches!(insn.insn, A64Insn::BrBr64BranchReg { .. }))
                    .expect("template ends in br")
                    + 1;
                assert!(
                    rephrased[after_br..]
                        .iter()
                        .any(|insn| insn.kind == RephrasedInsnKind::RuntimeExitPayload
                            && is_dispatch_miss_param0_copy(insn.insn)),
                    "expected the miss exit group to take RET_PARAM0 from x13 for {}",
                    insn.key()
                );
            } else {
                assert!(template.is_empty(), "SVC has no dispatch template");
            }
            // (Except the template's own `br x12`, which only the verifier admits.)
            assert!(
                rephrased
                    .iter()
                    .filter(|insn| insn.kind != RephrasedInsnKind::DispatchLookup)
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
            RephrasedInsn::dispatch_target(
                0x1000,
                A64Insn::OrrLogShiftOrr64LogShift {
                    shift: 0,
                    rm: x(ABI_LINK_REG),
                    imm6: uimm(0, 6),
                    rn: xzr(),
                    rd: x(DISPATCH_TARGET_REG),
                },
            )
        );
        assert_eq!(rephrased[1].kind, RephrasedInsnKind::UserSynthetic);
    }

    #[test]
    fn only_a_static_bl_gets_a_link_slot_right_before_the_template() {
        let lower = |inner| {
            rephrase_insn(IrInsn {
                pc: 0x1000,
                word: 0,
                inner,
            })
            .unwrap()
        };
        let slots = |lowered: &[RephrasedInsn]| {
            lowered
                .iter()
                .enumerate()
                .filter(|(_, insn)| matches!(insn.kind, RephrasedInsnKind::LinkSlot { .. }))
                .map(|(index, _)| index)
                .collect::<Vec<_>>()
        };

        let bl = lower(A64Insn::BlBlOnlyBranchImm {
            imm26: scaled_simm(2, 26, 2),
        });
        let [slot] = slots(&bl)[..] else {
            panic!("a BL has exactly one link slot");
        };
        assert_eq!(
            bl[slot],
            RephrasedInsn::link_slot(0x1000, 0x1008),
            "the slot is a nop that carries the BL's target"
        );
        assert_eq!(bl[slot].insn, A64Insn::NopNopHiHints {});
        assert_eq!(bl[slot - 1].kind, RephrasedInsnKind::UserSynthetic);
        assert!(matches!(
            bl[slot - 1].insn,
            A64Insn::MovzMovz64Movewide { rd, .. } | A64Insn::MovkMovk64Movewide { rd, .. }
                if rd.enc == ABI_LINK_REG
        ));
        // A20: slot, then the x13 movz/movk run, then the template.
        let moves = bl[slot + 1..]
            .iter()
            .take_while(|insn| insn.kind == RephrasedInsnKind::DispatchTarget)
            .count();
        assert_eq!(moves, 1, "0x1008 has one non-zero halfword: a lone movz");
        assert!(bl[slot + 1..slot + 1 + moves].iter().all(|insn| matches!(
            insn.insn,
            A64Insn::MovzMovz64Movewide { rd, .. } | A64Insn::MovkMovk64Movewide { rd, .. }
                if rd.enc == DISPATCH_TARGET_REG
        )));
        assert_eq!(bl[slot + 1 + moves].kind, RephrasedInsnKind::DispatchLookup);

        // A target with every halfword non-zero takes the full movz + three movk.
        let far = rephrase_insn(IrInsn {
            pc: 0x0001_0002_0003_6000,
            word: 0,
            inner: A64Insn::BlBlOnlyBranchImm {
                imm26: scaled_simm(2, 26, 2),
            },
        })
        .unwrap();
        let far_slot = slots(&far)[0];
        assert!(matches!(
            far[far_slot].kind,
            RephrasedInsnKind::LinkSlot { target_pc: 0x0001_0002_0003_6008 }
        ));
        let far_moves: Vec<_> = far[far_slot + 1..]
            .iter()
            .take_while(|insn| insn.kind == RephrasedInsnKind::DispatchTarget)
            .copied()
            .collect();
        assert_eq!(
            const_chains(&far_moves),
            [(DISPATCH_TARGET_REG, 0x0001_0002_0003_6008)]
        );
        assert_eq!(far_moves.len(), 4);

        for inner in [
            A64Insn::BlrBlr64BranchReg { rn: x(4) },
            A64Insn::BrBr64BranchReg { rn: x(5) },
            A64Insn::RetRet64rBranchReg { rn: x(30) },
            A64Insn::SvcSvcExException {
                imm16: A64Imm::unsigned(0, 16),
            },
        ] {
            assert!(
                slots(&lower(inner)).is_empty(),
                "{} has a dynamic target: no link slot",
                inner.key()
            );
        }
    }

    /// A21: the one constant helper. `(hw, imm16)` words, `movz` first.
    #[test]
    fn mov_imm64_emits_one_word_per_non_zero_halfword() {
        let words = |value: u64| {
            let mut out = SharedVec::new();
            push_mov_imm64(&mut out, 0x1000, x(7), value, RephrasedInsnKind::UserSynthetic)
                .unwrap();
            assert!(out.iter().all(|word| word.ori_pc == 0x1000
                && word.kind == RephrasedInsnKind::UserSynthetic));
            out.iter()
                .map(|word| match word.insn {
                    A64Insn::MovzMovz64Movewide { hw, imm16, rd } => {
                        assert_eq!(rd, x(7));
                        ("movz", hw, imm16.raw())
                    }
                    A64Insn::MovkMovk64Movewide { hw, imm16, rd } => {
                        assert_eq!(rd, x(7));
                        ("movk", hw, imm16.raw())
                    }
                    other => panic!("not a move: {other:?}"),
                })
                .collect::<Vec<_>>()
        };

        // Zero is a single `movz #0`.
        assert_eq!(words(0), [("movz", 0, 0)]);
        // Only the lowest halfword: no movk.
        assert_eq!(words(0x5a5a), [("movz", 0, 0x5a5a)]);
        // Only the highest halfword: the movz carries its hw.
        assert_eq!(words(0xbeef_0000_0000_0000), [("movz", 3, 0xbeef)]);
        // A gap: the movz is the lowest non-zero halfword, the movk the next one up.
        assert_eq!(
            words(0x0000_0123_0000_4000),
            [("movz", 0, 0x4000), ("movk", 2, 0x123)]
        );
        assert_eq!(
            words(0x1111_2222_3333_4444),
            [
                ("movz", 0, 0x4444),
                ("movk", 1, 0x3333),
                ("movk", 2, 0x2222),
                ("movk", 3, 0x1111),
            ]
        );
        // A user address has a zero top halfword (and often a zero low one).
        assert_eq!(
            words(0x0000_0055_0025_f000),
            [("movz", 0, 0xf000), ("movk", 1, 0x25), ("movk", 2, 0x55)]
        );
        assert_eq!(
            words(0x0000_0055_0025_0000),
            [("movz", 1, 0x25), ("movk", 2, 0x55)]
        );
        // Whatever the value, the chain builds exactly it.
        for value in [0, 1, 0xffff, 0x1_0000, u64::MAX, 0x8000_0000_0000_0001, 0x0000_ffff_0000_ffff] {
            let mut out = SharedVec::new();
            push_mov_imm64(&mut out, 0, x(3), value, RephrasedInsnKind::UserSynthetic).unwrap();
            assert_eq!(const_chains(&out), [(3, value)]);
        }
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

            // Both results are below 64 KiB: a lone `movz` (A21).
            assert_eq!(rephrased.len(), 1);
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
        // x9 = Mem, x10 = the original word, x11 = its PC (A21: one word per non-zero
        // halfword).
        let values = const_chains(&cold[..cold.len() - 1]);
        assert_eq!(
            values,
            [
                (RET_STATUS_REG, RetStatus::Mem.as_reg()),
                (RET_PARAM0_REG, u64::from(ldp.encode().unwrap())),
                (RET_PARAM1_REG, 0x1004),
            ]
        );
    }

    /// A22: a guarded write to SP leaves through its `Mem` stub (the guard's `cbnz`
    /// targets it), so it gets one even without a memory access; a write that
    /// preserves SP's alignment and any other instruction gets none.
    #[test]
    fn a_guarded_sp_write_gets_a_mem_stub_and_a_preserving_one_does_not() {
        use crate::shared::arm64::{A64Reg, A64Reg31Mode};
        use crate::shared::trans::cfg::BasicBlock;

        let sp = A64Reg::new(31, crate::shared::arm64::A64RegWidth::X64, A64Reg31Mode::Sp);
        let add_sp = |imm: u32, rn: A64Reg| A64Insn::AddAddsubImmAdd64AddsubImm {
            sh: 0,
            imm12: uimm(imm, 12),
            rn,
            rd: sp,
        };
        // pc 0x1000: sub-16 add (preserving); 0x1004: add sp, sp, #8 (guarded);
        // 0x1008: mov sp, x0 (guarded); 0x100c: add x1, x1, #8 (not an SP write).
        let insns_in = [
            (0x1000, add_sp(16, sp)),
            (0x1004, add_sp(8, sp)),
            (0x1008, add_sp(0, x(0))),
            (
                0x100c,
                A64Insn::AddAddsubImmAdd64AddsubImm {
                    sh: 0,
                    imm12: uimm(8, 12),
                    rn: x(1),
                    rd: x(1),
                },
            ),
        ];
        let mut insns = SharedVec::new();
        for (pc, inner) in insns_in {
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
                    end_addr: 0x1010,
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

        let mut stub_pcs: Vec<u64> = program[0].cold.iter().map(|insn| insn.ori_pc).collect();
        stub_pcs.dedup();
        assert_eq!(stub_pcs, [0x1004, 0x1008]);
        let params = const_chains(
            &program[0]
                .cold
                .iter()
                .filter(|insn| insn.kind == RephrasedInsnKind::RuntimeExitPayload)
                .copied()
                .collect::<Vec<_>>(),
        );
        let statuses: Vec<u64> = params
            .iter()
            .filter(|&&(reg, _)| reg == RET_STATUS_REG)
            .map(|&(_, value)| value)
            .collect();
        assert_eq!(statuses, [RetStatus::Mem.as_reg(); 2]);
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

    /// The three constants of a native-resume exit group: (status, x10 = word, x11 = pc).
    fn native_resume_values(group: &[RephrasedInsn]) -> (u64, u64, u64) {
        let (branch, payload) = group.split_last().expect("a group ends in its branch");
        assert!(branch.kind.is_runtime_exit_branch());
        let values = const_chains(payload);
        assert_eq!(
            values.iter().map(|&(rd, _)| rd).collect::<Vec<_>>(),
            [RET_STATUS_REG, RET_PARAM0_REG, RET_PARAM1_REG]
        );
        (values[0].1, values[1].1, values[2].1)
    }

    fn assert_budget_checked(block: &RephrasedBlock, branch: A64Insn, pc: u64) {
        let check = budget_check(pc);
        assert_eq!(
            &block.insns[block.insns.len() - BUDGET_CHECK_LEN - 1..block.insns.len() - 1],
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

    /// A11: every dispatch attempt costs one budget unit, hit or miss, so BL, BLR, BR
    /// and RET get the check before their whole lowered site (target move, link
    /// write, template, exit group), with the Budget stub of the same pc in the
    /// block's cold region: a Budget exit leaves the state from before the
    /// instruction.
    #[test]
    fn dispatch_sites_get_the_budget_check_before_the_whole_site() {
        let sites = [
            A64Insn::BlBlOnlyBranchImm {
                imm26: scaled_simm(8, 26, 2),
            },
            A64Insn::BlrBlr64BranchReg { rn: x(5) },
            A64Insn::BrBr64BranchReg { rn: x(17) },
            A64Insn::RetRet64rBranchReg { rn: x(30) },
        ];
        for site in sites {
            let program = rephrase(cfg_of(&[&[(0x1000, site)]])).unwrap();
            let block = &program[0];
            assert_eq!(&block.insns[..BUDGET_CHECK_LEN], &budget_check(0x1000), "{}", site.key());
            assert_eq!(
                native_resume_values(&block.cold),
                (
                    RetStatus::Budget.as_reg(),
                    u64::from(site.encode().unwrap()),
                    0x1000
                ),
                "{}",
                site.key()
            );
            let template_at = block
                .insns
                .iter()
                .position(|insn| insn.kind == RephrasedInsnKind::DispatchLookup)
                .unwrap();
            assert!(template_at > BUDGET_CHECK_LEN);
            assert!(block.insns[BUDGET_CHECK_LEN..template_at]
                .iter()
                .all(|insn| insn.kind != RephrasedInsnKind::BudgetCheck));
            assert_eq!(
                block.insns[template_at..template_at + DISPATCH_TEMPLATE_LEN]
                    .iter()
                    .map(|insn| insn.insn)
                    .collect::<Vec<_>>(),
                KJIT_DISPATCH_TEMPLATE
            );
            // The exit group of a miss follows the template and ends the site.
            assert!(block.insns[template_at + DISPATCH_TEMPLATE_LEN..]
                .iter()
                .all(|insn| insn.kind.is_runtime_exit()));
        }
        // SVC is not a branch of the translated code: no check, no template.
        let svc = A64Insn::SvcSvcExException {
            imm16: A64Imm::unsigned(0, 16),
        };
        assert_not_budget_checked(&rephrase(cfg_of(&[&[(0x1000, svc)]])).unwrap()[0]);
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
        // `sub x18, x18, #1` as `llvm-mc` encodes it.
        assert_eq!(check[0].insn.encode().unwrap(), 0xd100_0652);
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
