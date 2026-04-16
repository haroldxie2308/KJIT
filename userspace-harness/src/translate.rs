use std::collections::BTreeMap;

use crate::trans_core::cfg::{build_cfg, BlockId, Cfg};
use crate::lowered::LoweredInsn;
use crate::trans_core::arm64::{
    decode_program, AddSubOp, BranchCondition, DecodedInsnKind, GprWidth, LoadStoreAddressing,
    LoadStoreOp, MoveWideOp,
};

pub fn translate_program(program: &[u8], base_pc: u64) -> Result<Vec<LoweredInsn>, String> {
    let decoded = decode_program(program, base_pc).map_err(|err| err.to_string())?;
    let cfg = build_cfg(&decoded).map_err(|err| err.to_string())?;
    let lowered_index_by_block = lowered_index_by_block(&cfg);

    let mut lowered = Vec::with_capacity(decoded.len());
    for block in &cfg.blocks {
        for insn in &block.insns {
            let lower = lower_insn(insn.kind, &cfg, &lowered_index_by_block)?;
            lowered.push(lower);
        }
    }

    Ok(lowered)
}

fn lowered_index_by_block(cfg: &Cfg) -> BTreeMap<BlockId, usize> {
    let mut map = BTreeMap::new();
    let mut next_index = 0usize;
    for block in &cfg.blocks {
        map.insert(block.id, next_index);
        next_index += block.insns.len();
    }
    map
}

fn lower_insn(
    kind: DecodedInsnKind,
    cfg: &Cfg,
    lowered_index_by_block: &BTreeMap<BlockId, usize>,
) -> Result<LoweredInsn, String> {
    let lower = match kind {
            DecodedInsnKind::Nop => LoweredInsn::Nop,
            DecodedInsnKind::MoveWide {
                op: MoveWideOp::Zero,
                width: GprWidth::X64,
                rd,
                imm16,
                shift,
            } => {
                let value = (imm16 as u64) << shift;
                LoweredInsn::LoadImm64 { rd, value }
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
                    "only 64-bit move-wide instructions are supported in harness lowering, got {width:?}"
                ));
            }
            DecodedInsnKind::PcRelAddress { rd, target, .. } => {
                LoweredInsn::LoadImm64 { rd, value: target }
            }
            DecodedInsnKind::AddSubImm {
                op: AddSubOp::Add,
                width: GprWidth::X64,
                set_flags: false,
                rd,
                rn,
                imm12,
                shift12: false,
            } => LoweredInsn::AddImm { rd, rn, imm12 },
            DecodedInsnKind::AddSubImm {
                op: AddSubOp::Sub,
                width: GprWidth::X64,
                set_flags: false,
                rd,
                rn,
                imm12,
                shift12: false,
            } => LoweredInsn::SubImm { rd, rn, imm12 },
            DecodedInsnKind::AddSubImm {
                op: AddSubOp::Sub,
                width: GprWidth::X64,
                set_flags: true,
                rd: 31,
                rn,
                imm12,
                shift12: false,
            } => LoweredInsn::CmpImm { rn, imm12 },
            DecodedInsnKind::AddSubImm { width, shift12, .. } => {
                return Err(format!(
                    "unsupported add/sub immediate lowering in harness: width={width:?}, shift12={shift12}"
                ));
            }
            DecodedInsnKind::Branch { target } => LoweredInsn::B {
                target: resolve_target(target, cfg, lowered_index_by_block)?,
            },
            DecodedInsnKind::CondBranch { cond, target } => LoweredInsn::BCond {
                cond: lower_condition(cond),
                target: resolve_target(target, cfg, lowered_index_by_block)?,
            },
            DecodedInsnKind::CompareBranch {
                nonzero: false,
                width: GprWidth::X64,
                rt,
                target,
            } => LoweredInsn::Cbz {
                rt,
                target: resolve_target(target, cfg, lowered_index_by_block)?,
            },
            DecodedInsnKind::CompareBranch {
                nonzero: true,
                width: GprWidth::X64,
                rt,
                target,
            } => LoweredInsn::Cbnz {
                rt,
                target: resolve_target(target, cfg, lowered_index_by_block)?,
            },
            DecodedInsnKind::CompareBranch { width, .. } => {
                return Err(format!(
                    "only 64-bit compare-and-branch is supported in harness lowering, got {width:?}"
                ));
            }
            DecodedInsnKind::LoadStoreImm {
                op: LoadStoreOp::Store,
                width: GprWidth::X64,
                rt,
                rn,
                addressing: LoadStoreAddressing::UnsignedScaledOffset { .. },
            } => LoweredInsn::StrImm {
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
            } => LoweredInsn::LdrImm {
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
                    "unsupported load/store lowering in harness: op={op:?}, width={width:?}, addressing={addressing:?}"
                ));
            }
            DecodedInsnKind::TestBitBranch { .. } => {
                return Err("TBZ/TBNZ lowering is not wired into the harness yet".to_string());
            }
        };

    Ok(lower)
}

fn lower_condition(cond: BranchCondition) -> crate::arm64::Condition {
    match cond {
        BranchCondition::Eq => crate::arm64::Condition::Eq,
        BranchCondition::Ne => crate::arm64::Condition::Ne,
        BranchCondition::Ge => crate::arm64::Condition::Ge,
        BranchCondition::Lt => crate::arm64::Condition::Lt,
        BranchCondition::Gt => crate::arm64::Condition::Gt,
        BranchCondition::Le => crate::arm64::Condition::Le,
        BranchCondition::Al => crate::arm64::Condition::Al,
    }
}

fn insn_load_store_offset(kind: DecodedInsnKind) -> Result<u16, String> {
    match kind {
        DecodedInsnKind::LoadStoreImm {
            width,
            addressing,
            ..
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
    lowered_index_by_block: &BTreeMap<BlockId, usize>,
) -> Result<usize, String> {
    let block = cfg
        .pc_to_block
        .get(&target_pc)
        .copied()
        .ok_or_else(|| format!("branch target {target_pc:#x} is outside the supported program"))?;
    lowered_index_by_block
        .get(&block)
        .copied()
        .ok_or_else(|| format!("missing lowered block for target pc {target_pc:#x}"))
}
