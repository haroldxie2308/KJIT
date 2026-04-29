use crate::trans_core::arm64::{
    AddSubOp, DecodedInsnKind, GprWidth, LoadStoreAddressing, LoadStoreOp, MoveWideOp,
};
use crate::trans_core::cfg::{build_cfg, CfgError, RuntimeExitReason};
use crate::trans_core::input::{CodeProvider, TranslationRequest};
use crate::trans_core::ir::{IrInsn, IrInsnKind, IrProgram, LinkSlot};
use crate::trans_core::platform::{SharedAllocError, SharedResult, GFP_KERNEL};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TranslateError {
    Cfg(CfgError),
    Alloc(SharedAllocError),
    StandaloneMovk,
    UnsupportedMoveWide {
        width: GprWidth,
    },
    UnsupportedAddSubImm {
        width: GprWidth,
        shift12: bool,
    },
    UnsupportedCompareBranch {
        width: GprWidth,
    },
    UnsupportedLoadStore {
        op: LoadStoreOp,
        width: GprWidth,
        addressing: LoadStoreAddressing,
    },
    UnsupportedTestBitBranch,
    LoadStoreOffsetOutOfRange {
        offset: i32,
    },
    ExpectedLoadStore,
}

impl From<CfgError> for TranslateError {
    fn from(err: CfgError) -> Self {
        Self::Cfg(err)
    }
}

impl core::fmt::Display for TranslateError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Cfg(err) => write!(f, "{err}"),
            Self::Alloc(err) => write!(f, "allocation failed while translating: {err:?}"),
            Self::StandaloneMovk => {
                write!(
                    f,
                    "MOVK is not accepted as a standalone original instruction in this harness"
                )
            }
            Self::UnsupportedMoveWide { width } => {
                write!(
                    f,
                    "only 64-bit move-wide instructions are supported in IR translation, got {width:?}"
                )
            }
            Self::UnsupportedAddSubImm { width, shift12 } => {
                write!(
                    f,
                    "unsupported add/sub immediate IR translation: width={width:?}, shift12={shift12}"
                )
            }
            Self::UnsupportedCompareBranch { width } => {
                write!(
                    f,
                    "only 64-bit compare-and-branch is supported in IR translation, got {width:?}"
                )
            }
            Self::UnsupportedLoadStore {
                op,
                width,
                addressing,
            } => {
                write!(
                    f,
                    "unsupported load/store IR translation: op={op:?}, width={width:?}, addressing={addressing:?}"
                )
            }
            Self::UnsupportedTestBitBranch => {
                write!(
                    f,
                    "TBZ/TBNZ IR translation is not wired into the harness yet"
                )
            }
            Self::LoadStoreOffsetOutOfRange { offset } => {
                write!(f, "load/store offset out of range: {offset}")
            }
            Self::ExpectedLoadStore => write!(f, "expected load/store instruction"),
        }
    }
}

pub fn translate_request<P: CodeProvider>(
    request: &TranslationRequest,
    code: &P,
) -> SharedResult<IrProgram, TranslateError> {
    let cfg = build_cfg(request, code)?;
    let mut next_link_slot = 0usize;

    let mut ir = IrProgram::with_capacity(
        cfg.blocks.iter().map(|block| block.insns.len()).sum(),
        GFP_KERNEL,
    )
    .map_err(TranslateError::Alloc)?;
    for block in &cfg.blocks {
        for insn in &block.insns {
            let ir_insn = translate_insn_to_ir(insn.pc, insn.kind, &mut next_link_slot)?;
            ir.push(ir_insn, GFP_KERNEL)
                .map_err(TranslateError::Alloc)?;
        }
    }

    Ok(ir)
}

fn translate_insn_to_ir(
    pc: u64,
    kind: DecodedInsnKind,
    next_link_slot: &mut usize,
) -> SharedResult<IrInsn, TranslateError> {
    let ir_kind = match kind {
        DecodedInsnKind::Nop => IrInsnKind::Nop,
        DecodedInsnKind::MoveWide {
            op: MoveWideOp::Zero,
            width: GprWidth::X64,
            rd,
            imm16,
            shift,
        } => {
            let value = (imm16 as u64) << shift;
            IrInsnKind::LoadImm64 { rd, value }
        }
        DecodedInsnKind::MoveWide {
            op: MoveWideOp::Keep,
            ..
        } => return Err(TranslateError::StandaloneMovk),
        DecodedInsnKind::MoveWide { width, .. } => {
            return Err(TranslateError::UnsupportedMoveWide { width });
        }
        DecodedInsnKind::PcRelAddress { rd, target, .. } => {
            IrInsnKind::LoadImm64 { rd, value: target }
        }
        DecodedInsnKind::AddSubImm {
            op: AddSubOp::Add,
            width: GprWidth::X64,
            set_flags: false,
            rd,
            rn,
            imm12,
            shift12: false,
        } => IrInsnKind::AddImm { rd, rn, imm12 },
        DecodedInsnKind::AddSubImm {
            op: AddSubOp::Sub,
            width: GprWidth::X64,
            set_flags: false,
            rd,
            rn,
            imm12,
            shift12: false,
        } => IrInsnKind::SubImm { rd, rn, imm12 },
        DecodedInsnKind::AddSubImm {
            op: AddSubOp::Sub,
            width: GprWidth::X64,
            set_flags: true,
            rd: 31,
            rn,
            imm12,
            shift12: false,
        } => IrInsnKind::CmpImm { rn, imm12 },
        DecodedInsnKind::AddSubImm { width, shift12, .. } => {
            return Err(TranslateError::UnsupportedAddSubImm { width, shift12 });
        }
        DecodedInsnKind::Branch { target } => IrInsnKind::B { target_pc: target },
        DecodedInsnKind::CondBranch { cond, target } => IrInsnKind::BCond {
            cond,
            target_pc: target,
        },
        DecodedInsnKind::CompareBranch {
            nonzero: false,
            width: GprWidth::X64,
            rt,
            target,
        } => IrInsnKind::Cbz {
            rt,
            target_pc: target,
        },
        DecodedInsnKind::CompareBranch {
            nonzero: true,
            width: GprWidth::X64,
            rt,
            target,
        } => IrInsnKind::Cbnz {
            rt,
            target_pc: target,
        },
        DecodedInsnKind::CompareBranch { width, .. } => {
            return Err(TranslateError::UnsupportedCompareBranch { width });
        }
        DecodedInsnKind::LoadStoreImm {
            op: LoadStoreOp::Store,
            width: GprWidth::X64,
            rt,
            rn,
            addressing: LoadStoreAddressing::UnsignedScaledOffset { .. },
        } => IrInsnKind::StrImm {
            rt,
            rn,
            offset: insn_load_store_offset(kind)?,
        },
        DecodedInsnKind::LoadStoreImm {
            op: LoadStoreOp::Load,
            width: GprWidth::X64,
            rt,
            rn,
            addressing: LoadStoreAddressing::UnsignedScaledOffset { .. },
        } => IrInsnKind::LdrImm {
            rt,
            rn,
            offset: insn_load_store_offset(kind)?,
        },
        DecodedInsnKind::LoadStoreImm {
            op,
            width,
            addressing,
            ..
        } => {
            return Err(TranslateError::UnsupportedLoadStore {
                op,
                width,
                addressing,
            });
        }
        DecodedInsnKind::TestBitBranch { .. } => {
            return Err(TranslateError::UnsupportedTestBitBranch);
        }
        DecodedInsnKind::BranchLink { target } => runtime_exit(
            RuntimeExitReason::Bl {
                target_pc: target,
                resume_pc: pc + 4,
            },
            next_link_slot,
        ),
        DecodedInsnKind::BranchLinkReg { rn } => runtime_exit(
            RuntimeExitReason::Blr {
                target_reg: rn,
                resume_pc: pc + 4,
            },
            next_link_slot,
        ),
        DecodedInsnKind::BranchReg { rn } => {
            runtime_exit(RuntimeExitReason::Br { target_reg: rn }, next_link_slot)
        }
        DecodedInsnKind::Ret { rn } => {
            runtime_exit(RuntimeExitReason::Ret { lr_reg: rn }, next_link_slot)
        }
        DecodedInsnKind::Svc { imm16 } => runtime_exit(
            RuntimeExitReason::Svc {
                imm16,
                resume_pc: pc + 4,
            },
            next_link_slot,
        ),
    };

    Ok(IrInsn { pc, kind: ir_kind })
}

fn runtime_exit(reason: RuntimeExitReason, next_link_slot: &mut usize) -> IrInsnKind {
    let slot = LinkSlot(*next_link_slot);
    *next_link_slot += 1;
    IrInsnKind::RuntimeExit { slot, reason }
}

fn insn_load_store_offset(kind: DecodedInsnKind) -> SharedResult<u16, TranslateError> {
    match kind {
        DecodedInsnKind::LoadStoreImm {
            width, addressing, ..
        } => {
            let offset = addressing.byte_offset(width);
            u16::try_from(offset).map_err(|_| TranslateError::LoadStoreOffsetOutOfRange { offset })
        }
        _ => Err(TranslateError::ExpectedLoadStore),
    }
}
