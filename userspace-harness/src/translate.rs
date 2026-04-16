use std::collections::BTreeMap;

use crate::lowered::LoweredInsn;
use crate::trans_core::arm64::{
    decode_program, AddSubOp, BranchCondition, DecodedInsnKind, GprWidth, LoadStoreAddressing,
    LoadStoreOp, MoveWideOp,
};

pub fn translate_program(program: &[u8], base_pc: u64) -> Result<Vec<LoweredInsn>, String> {
    let decoded = decode_program(program, base_pc).map_err(|err| err.to_string())?;
    let mut pc_to_index = BTreeMap::new();
    for index in 0..decoded.len() {
        pc_to_index.insert(base_pc + (index as u64) * 4, index);
    }
    let end_pc = base_pc + (decoded.len() as u64) * 4;

    let mut lowered = Vec::with_capacity(decoded.len());
    for insn in decoded {
        let lower = match insn.kind {
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
                target: resolve_target(target, &pc_to_index, end_pc)?,
            },
            DecodedInsnKind::CondBranch { cond, target } => LoweredInsn::BCond {
                cond: lower_condition(cond),
                target: resolve_target(target, &pc_to_index, end_pc)?,
            },
            DecodedInsnKind::CompareBranch {
                nonzero: false,
                width: GprWidth::X64,
                rt,
                target,
            } => LoweredInsn::Cbz {
                rt,
                target: resolve_target(target, &pc_to_index, end_pc)?,
            },
            DecodedInsnKind::CompareBranch {
                nonzero: true,
                width: GprWidth::X64,
                rt,
                target,
            } => LoweredInsn::Cbnz {
                rt,
                target: resolve_target(target, &pc_to_index, end_pc)?,
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
                offset: insn_load_store_offset(insn.kind)?,
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
                offset: insn_load_store_offset(insn.kind)?,
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
        lowered.push(lower);
    }

    Ok(lowered)
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
    pc_to_index: &BTreeMap<u64, usize>,
    end_pc: u64,
) -> Result<usize, String> {
    if target_pc == end_pc {
        return Ok(pc_to_index.len());
    }
    pc_to_index
        .get(&target_pc)
        .copied()
        .ok_or_else(|| format!("branch target {target_pc:#x} is outside the supported program"))
}
