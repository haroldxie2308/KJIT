use std::collections::BTreeMap;

use crate::arm64::{decode_program, Arm64Insn};
use crate::lowered::LoweredInsn;

pub fn translate_program(program: &[u8], base_pc: u64) -> Result<Vec<LoweredInsn>, String> {
    let decoded = decode_program(program, base_pc)?;
    let mut pc_to_index = BTreeMap::new();
    for index in 0..decoded.len() {
        pc_to_index.insert(base_pc + (index as u64) * 4, index);
    }
    let end_pc = base_pc + (decoded.len() as u64) * 4;

    let mut lowered = Vec::with_capacity(decoded.len());
    for insn in decoded {
        let lower = match insn {
            Arm64Insn::Nop => LoweredInsn::Nop,
            Arm64Insn::Movz { rd, imm16, shift } => {
                let value = (imm16 as u64) << shift;
                LoweredInsn::LoadImm64 { rd, value }
            }
            Arm64Insn::Movk { .. } => {
                return Err(
                    "MOVK is not accepted as a standalone original instruction in this harness"
                        .to_string(),
                );
            }
            Arm64Insn::Adr { rd, value } | Arm64Insn::Adrp { rd, value } => {
                LoweredInsn::LoadImm64 { rd, value }
            }
            Arm64Insn::AddImm { rd, rn, imm12 } => LoweredInsn::AddImm { rd, rn, imm12 },
            Arm64Insn::AddReg { rd, rn, rm } => LoweredInsn::AddReg { rd, rn, rm },
            Arm64Insn::SubImm { rd, rn, imm12 } => LoweredInsn::SubImm { rd, rn, imm12 },
            Arm64Insn::SubReg { rd, rn, rm } => LoweredInsn::SubReg { rd, rn, rm },
            Arm64Insn::CmpImm { rn, imm12 } => LoweredInsn::CmpImm { rn, imm12 },
            Arm64Insn::CmpReg { rn, rm } => LoweredInsn::CmpReg { rn, rm },
            Arm64Insn::B { target_pc } => LoweredInsn::B {
                target: resolve_target(target_pc, &pc_to_index, end_pc)?,
            },
            Arm64Insn::BCond { cond, target_pc } => LoweredInsn::BCond {
                cond,
                target: resolve_target(target_pc, &pc_to_index, end_pc)?,
            },
            Arm64Insn::Cbz { rt, target_pc } => LoweredInsn::Cbz {
                rt,
                target: resolve_target(target_pc, &pc_to_index, end_pc)?,
            },
            Arm64Insn::Cbnz { rt, target_pc } => LoweredInsn::Cbnz {
                rt,
                target: resolve_target(target_pc, &pc_to_index, end_pc)?,
            },
            Arm64Insn::StrImm { rt, rn, offset } => LoweredInsn::StrImm { rt, rn, offset },
            Arm64Insn::LdrImm { rt, rn, offset } => LoweredInsn::LdrImm { rt, rn, offset },
        };
        lowered.push(lower);
    }

    Ok(lowered)
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
