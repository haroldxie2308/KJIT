extern crate alloc;

use alloc::string::{String, ToString};

use crate::trans_core::arm64::{
    AddSubOp, DecodedInsnKind, GprWidth, LoadStoreAddressing, LoadStoreOp, MoveWideOp,
};
use crate::trans_core::cfg::{build_cfg, RuntimeExitReason};
use crate::trans_core::input::{CodeProvider, TranslationRequest};
use crate::trans_core::ir::{IrInsn, IrInsnKind, IrProgram, LinkSlot};

pub fn translate_request<P: CodeProvider>(
    request: &TranslationRequest,
    code: &P,
) -> Result<IrProgram, String> {
    let cfg = build_cfg(request, code).map_err(|err| err.to_string())?;
    let mut next_link_slot = 0usize;

    let mut ir = IrProgram::with_capacity(cfg.blocks.iter().map(|block| block.insns.len()).sum());
    for block in &cfg.blocks {
        for insn in &block.insns {
            let ir_insn = translate_insn_to_ir(insn.pc, insn.kind, &mut next_link_slot)?;
            ir.push(ir_insn);
        }
    }

    Ok(ir)
}

fn translate_insn_to_ir(
    pc: u64,
    kind: DecodedInsnKind,
    next_link_slot: &mut usize,
) -> Result<IrInsn, String> {
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
        } => {
            return Err(
                "MOVK is not accepted as a standalone original instruction in this harness"
                    .to_string(),
            );
        }
        DecodedInsnKind::MoveWide { width, .. } => {
            return Err(format!(
                "only 64-bit move-wide instructions are supported in IR translation, got {width:?}"
            ));
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
            return Err(format!(
                "unsupported add/sub immediate IR translation: width={width:?}, shift12={shift12}"
            ));
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
            return Err(format!(
                "only 64-bit compare-and-branch is supported in IR translation, got {width:?}"
            ));
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
            return Err(format!(
                "unsupported load/store IR translation: op={op:?}, width={width:?}, addressing={addressing:?}"
            ));
        }
        DecodedInsnKind::TestBitBranch { .. } => {
            return Err("TBZ/TBNZ IR translation is not wired into the harness yet".to_string());
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

fn insn_load_store_offset(kind: DecodedInsnKind) -> Result<u16, String> {
    match kind {
        DecodedInsnKind::LoadStoreImm {
            width, addressing, ..
        } => {
            let offset = addressing.byte_offset(width);
            u16::try_from(offset).map_err(|_| format!("load/store offset out of range: {offset}"))
        }
        _ => Err("expected load/store instruction".to_string()),
    }
}
