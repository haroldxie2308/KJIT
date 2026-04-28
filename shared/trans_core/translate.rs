extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};

use crate::trans_core::arm64::{
    AddSubOp, DecodedInsnKind, GprWidth, LoadStoreAddressing, LoadStoreOp, MoveWideOp,
};
use crate::trans_core::cfg::{build_cfg, BlockId, Cfg, RuntimeExitReason};
use crate::trans_core::input::{CodeProvider, TranslationRequest};
use crate::trans_core::ir::{IrInsn, IrProgram, LinkSlot};

pub fn translate_request<P: CodeProvider>(
    request: &TranslationRequest,
    code: &P,
) -> Result<IrProgram, String> {
    let cfg = build_cfg(request, code).map_err(|err| err.to_string())?;
    let ir_index_by_block = ir_index_by_block(&cfg);
    let mut next_link_slot = 0usize;

    let mut ir = IrProgram::with_capacity(cfg.blocks.iter().map(|block| block.insns.len()).sum());
    for block in &cfg.blocks {
        for insn in &block.insns {
            let ir_insn = translate_insn_to_ir(
                insn.pc,
                insn.kind,
                &cfg,
                &ir_index_by_block,
                &mut next_link_slot,
            )?;
            ir.push(ir_insn);
        }
    }

    Ok(ir)
}

fn ir_index_by_block(cfg: &Cfg) -> BTreeMap<BlockId, usize> {
    let mut map = BTreeMap::new();
    let mut next_index = 0usize;
    for block in &cfg.blocks {
        map.insert(block.id, next_index);
        next_index += block.insns.len();
    }
    map
}

fn translate_insn_to_ir(
    pc: u64,
    kind: DecodedInsnKind,
    cfg: &Cfg,
    ir_index_by_block: &BTreeMap<BlockId, usize>,
    next_link_slot: &mut usize,
) -> Result<IrInsn, String> {
    let ir_insn = match kind {
        DecodedInsnKind::Nop => IrInsn::Nop,
        DecodedInsnKind::MoveWide {
            op: MoveWideOp::Zero,
            width: GprWidth::X64,
            rd,
            imm16,
            shift,
        } => {
            let value = (imm16 as u64) << shift;
            IrInsn::LoadImm64 { rd, value }
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
        DecodedInsnKind::PcRelAddress { rd, target, .. } => IrInsn::LoadImm64 { rd, value: target },
        DecodedInsnKind::AddSubImm {
            op: AddSubOp::Add,
            width: GprWidth::X64,
            set_flags: false,
            rd,
            rn,
            imm12,
            shift12: false,
        } => IrInsn::AddImm { rd, rn, imm12 },
        DecodedInsnKind::AddSubImm {
            op: AddSubOp::Sub,
            width: GprWidth::X64,
            set_flags: false,
            rd,
            rn,
            imm12,
            shift12: false,
        } => IrInsn::SubImm { rd, rn, imm12 },
        DecodedInsnKind::AddSubImm {
            op: AddSubOp::Sub,
            width: GprWidth::X64,
            set_flags: true,
            rd: 31,
            rn,
            imm12,
            shift12: false,
        } => IrInsn::CmpImm { rn, imm12 },
        DecodedInsnKind::AddSubImm { width, shift12, .. } => {
            return Err(format!(
                "unsupported add/sub immediate IR translation: width={width:?}, shift12={shift12}"
            ));
        }
        DecodedInsnKind::Branch { target } => IrInsn::B {
            target: resolve_target(target, cfg, ir_index_by_block)?,
        },
        DecodedInsnKind::CondBranch { cond, target } => IrInsn::BCond {
            cond,
            target: resolve_target(target, cfg, ir_index_by_block)?,
        },
        DecodedInsnKind::CompareBranch {
            nonzero: false,
            width: GprWidth::X64,
            rt,
            target,
        } => IrInsn::Cbz {
            rt,
            target: resolve_target(target, cfg, ir_index_by_block)?,
        },
        DecodedInsnKind::CompareBranch {
            nonzero: true,
            width: GprWidth::X64,
            rt,
            target,
        } => IrInsn::Cbnz {
            rt,
            target: resolve_target(target, cfg, ir_index_by_block)?,
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
        } => IrInsn::StrImm {
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
        } => IrInsn::LdrImm {
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

    Ok(ir_insn)
}

fn runtime_exit(reason: RuntimeExitReason, next_link_slot: &mut usize) -> IrInsn {
    let slot = LinkSlot(*next_link_slot);
    *next_link_slot += 1;
    IrInsn::RuntimeExit { slot, reason }
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

fn resolve_target(
    target_pc: u64,
    cfg: &Cfg,
    ir_index_by_block: &BTreeMap<BlockId, usize>,
) -> Result<usize, String> {
    let block =
        cfg.pc_to_block.get(&target_pc).copied().ok_or_else(|| {
            format!("branch target {target_pc:#x} is outside the supported program")
        })?;
    ir_index_by_block
        .get(&block)
        .copied()
        .ok_or_else(|| format!("missing IR block for target pc {target_pc:#x}"))
}
