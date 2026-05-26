use crate::shared::arm64::{A64Insn, A64OperandRole, A64RewriteError};
use crate::shared::platform::{SharedAllocError, SharedResult, SharedVec, GFP_KERNEL};
use crate::shared::trans::rephrase::{RephrasedInsnKind, RephrasedProgram};

pub type LayoutVLabels = SharedVec<(u64, usize)>;

#[derive(Debug, PartialEq, Eq)]
pub struct ExecutionFragment {
    pub insns: SharedVec<A64Insn>,
    pub entry_offset: usize,
    pub vlabels: LayoutVLabels,
}

impl ExecutionFragment {
    pub fn len_bytes(&self) -> usize {
        self.insns.len() * 4
    }

    pub fn offset_for_pc(&self, original_pc: u64) -> Option<usize> {
        find_vlabel(&self.vlabels, original_pc)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LayoutError {
    Alloc(SharedAllocError),
    MissingLabel {
        target_original_pc: u64,
    },
    BranchOutOfRange {
        insn_index: usize,
        target_original_pc: u64,
    },
    UnalignedBranchTarget {
        insn_index: usize,
        target_original_pc: u64,
    },
    UnsupportedBranchField {
        insn_index: usize,
        field: &'static str,
    },
}

impl From<SharedAllocError> for LayoutError {
    fn from(err: SharedAllocError) -> Self {
        Self::Alloc(err)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) struct BranchReloc {
    pub(crate) insn_index: usize,
    pub(crate) target_original_pc: u64,
    pub(crate) kind: BranchRelocKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) enum BranchRelocKind {
    B,
    BCond,
    Bl,
    Cbz,
    Cbnz,
    Tbz,
    Tbnz,
}

pub fn layout_program(program: RephrasedProgram) -> SharedResult<ExecutionFragment, LayoutError> {
    let insn_count = program.iter().map(|block| block.insns.len()).sum::<usize>();
    let mut fragment = ExecutionFragment {
        insns: SharedVec::with_capacity(insn_count, GFP_KERNEL)?,
        entry_offset: 0,
        vlabels: SharedVec::with_capacity(insn_count, GFP_KERNEL)?,
    };
    let mut relocs = SharedVec::with_capacity(insn_count, GFP_KERNEL)?;

    for block in &program {
        for rephrased in &block.insns {
            let insn_index = fragment.insns.len();
            let output_offset = insn_index * 4;
            insert_vlabel_once(&mut fragment.vlabels, rephrased.original_pc, output_offset)?;

            if rephrased.kind == RephrasedInsnKind::Original {
                if let Some(reloc) =
                    branch_reloc_for(rephrased.insn, rephrased.original_pc, insn_index)?
                {
                    relocs.push(reloc, GFP_KERNEL)?;
                }
            }

            fragment.insns.push(rephrased.insn, GFP_KERNEL)?;
        }
    }

    resolve_branch_relocs(&mut fragment, &relocs)?;
    Ok(fragment)
}

fn insert_vlabel_once(
    vlabels: &mut LayoutVLabels,
    original_pc: u64,
    output_offset: usize,
) -> SharedResult<(), LayoutError> {
    if find_vlabel(vlabels, original_pc).is_none() {
        vlabels.push((original_pc, output_offset), GFP_KERNEL)?;
    }
    Ok(())
}

fn find_vlabel(vlabels: &LayoutVLabels, original_pc: u64) -> Option<usize> {
    vlabels
        .iter()
        .find(|(pc, _)| *pc == original_pc)
        .map(|(_, offset)| *offset)
}

fn branch_reloc_for(
    insn: A64Insn,
    original_pc: u64,
    insn_index: usize,
) -> SharedResult<Option<BranchReloc>, LayoutError> {
    let Some((field, scale, bits)) = branch_target_role(insn) else {
        return Ok(None);
    };
    let Some(encoded) = insn.branch_target_imm(field) else {
        return Err(LayoutError::UnsupportedBranchField { insn_index, field });
    };
    let Some(kind) = BranchRelocKind::from_insn(insn) else {
        return Ok(None);
    };

    Ok(Some(BranchReloc {
        insn_index,
        target_original_pc: pc_relative_target(original_pc, encoded, bits, scale),
        kind,
    }))
}

fn branch_target_role(insn: A64Insn) -> Option<(&'static str, u8, u8)> {
    for role in insn.operand_roles() {
        if let A64OperandRole::BranchTarget { field, scale, bits } = *role {
            return Some((field, scale, bits));
        }
    }
    None
}

fn resolve_branch_relocs(
    fragment: &mut ExecutionFragment,
    relocs: &SharedVec<BranchReloc>,
) -> SharedResult<(), LayoutError> {
    for reloc in relocs {
        let target_offset = find_vlabel(&fragment.vlabels, reloc.target_original_pc).ok_or(
            LayoutError::MissingLabel {
                target_original_pc: reloc.target_original_pc,
            },
        )?;
        let Some(insn) = fragment.insns.get_mut(reloc.insn_index) else {
            return Err(LayoutError::BranchOutOfRange {
                insn_index: reloc.insn_index,
                target_original_pc: reloc.target_original_pc,
            });
        };
        let Some((field, scale, bits)) = branch_target_role(*insn) else {
            return Err(LayoutError::UnsupportedBranchField {
                insn_index: reloc.insn_index,
                field: "",
            });
        };
        let encoded = encode_branch_delta(
            reloc.insn_index * 4,
            target_offset,
            scale,
            bits,
            reloc.insn_index,
            reloc.target_original_pc,
        )?;

        *insn = insn
            .set_branch_target_imm(field, encoded)
            .map_err(|err| match err {
                A64RewriteError::UnsupportedField { field, .. } => {
                    LayoutError::UnsupportedBranchField {
                        insn_index: reloc.insn_index,
                        field,
                    }
                }
                A64RewriteError::FieldOutOfRange { .. } => LayoutError::BranchOutOfRange {
                    insn_index: reloc.insn_index,
                    target_original_pc: reloc.target_original_pc,
                },
            })?;
    }
    Ok(())
}

fn encode_branch_delta(
    source_offset: usize,
    target_offset: usize,
    scale: u8,
    bits: u8,
    insn_index: usize,
    target_original_pc: u64,
) -> SharedResult<u32, LayoutError> {
    if bits == 0 || bits >= 32 || scale >= 32 {
        return Err(LayoutError::BranchOutOfRange {
            insn_index,
            target_original_pc,
        });
    }

    let align = 1_i128 << scale;
    let delta = target_offset as i128 - source_offset as i128;
    if delta % align != 0 {
        return Err(LayoutError::UnalignedBranchTarget {
            insn_index,
            target_original_pc,
        });
    }

    let scaled = delta / align;
    let min = -(1_i128 << (bits - 1));
    let max = (1_i128 << (bits - 1)) - 1;
    if scaled < min || scaled > max {
        return Err(LayoutError::BranchOutOfRange {
            insn_index,
            target_original_pc,
        });
    }

    Ok((scaled & ((1_i128 << bits) - 1)) as u32)
}

fn pc_relative_target(pc: u64, encoded: u32, bits: u8, scale: u8) -> u64 {
    pc.wrapping_add_signed(sign_extend(encoded, bits) << scale)
}

fn sign_extend(value: u32, bits: u8) -> i64 {
    let shift = 64 - bits;
    ((value as i64) << shift) >> shift
}

impl BranchRelocKind {
    fn from_insn(insn: A64Insn) -> Option<Self> {
        match insn {
            A64Insn::BUncondBOnlyBranchImm { .. } => Some(Self::B),
            A64Insn::BCondBOnlyCondbranch { .. } => Some(Self::BCond),
            A64Insn::BlBlOnlyBranchImm { .. } => Some(Self::Bl),
            A64Insn::CbzCbz32Compbranch { .. } | A64Insn::CbzCbz64Compbranch { .. } => {
                Some(Self::Cbz)
            }
            A64Insn::CbnzCbnz32Compbranch { .. } | A64Insn::CbnzCbnz64Compbranch { .. } => {
                Some(Self::Cbnz)
            }
            A64Insn::TbzTbzOnlyTestbranch { .. } => Some(Self::Tbz),
            A64Insn::TbnzTbnzOnlyTestbranch { .. } => Some(Self::Tbnz),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::arm64::{A64Imm, A64Reg};
    use crate::shared::trans::rephrase::{RephrasedBlock, RephrasedInsn};

    fn one_block(insns: SharedVec<RephrasedInsn>) -> RephrasedProgram {
        let mut program = SharedVec::new();
        program
            .push(
                RephrasedBlock {
                    start_addr: 0x1000,
                    end_addr: 0x100c,
                    prev: SharedVec::new(),
                    next: SharedVec::new(),
                    insns,
                },
                GFP_KERNEL,
            )
            .unwrap();
        program
    }

    #[test]
    fn rewrites_forward_branch_to_layout_offset() {
        let mut insns = SharedVec::new();
        insns
            .push(
                RephrasedInsn::original(
                    0x1000,
                    A64Insn::BUncondBOnlyBranchImm {
                        imm26: A64Imm::scaled_signed(2, 26, 2),
                    },
                ),
                GFP_KERNEL,
            )
            .unwrap();
        insns
            .push(
                RephrasedInsn::synthetic(0x1004, A64Insn::NopNopHiHints {}),
                GFP_KERNEL,
            )
            .unwrap();
        insns
            .push(
                RephrasedInsn::synthetic(0x1004, A64Insn::NopNopHiHints {}),
                GFP_KERNEL,
            )
            .unwrap();
        insns
            .push(
                RephrasedInsn::original(0x1008, A64Insn::NopNopHiHints {}),
                GFP_KERNEL,
            )
            .unwrap();

        let layout = layout_program(one_block(insns)).unwrap();

        assert_eq!(layout.entry_offset, 0);
        assert_eq!(layout.vlabels[2], (0x1008, 12));
        assert_eq!(layout.insns[0].branch_target_imm("imm26"), Some(3));
    }

    #[test]
    fn rewrites_backward_cond_branch_to_layout_offset() {
        let mut insns = SharedVec::new();
        insns
            .push(
                RephrasedInsn::original(0x1000, A64Insn::NopNopHiHints {}),
                GFP_KERNEL,
            )
            .unwrap();
        insns
            .push(
                RephrasedInsn::synthetic(0x1004, A64Insn::NopNopHiHints {}),
                GFP_KERNEL,
            )
            .unwrap();
        insns
            .push(
                RephrasedInsn::synthetic(0x1004, A64Insn::NopNopHiHints {}),
                GFP_KERNEL,
            )
            .unwrap();
        insns
            .push(
                RephrasedInsn::original(
                    0x1008,
                    A64Insn::CbnzCbnz64Compbranch {
                        imm19: A64Imm::scaled_signed(524286, 19, 2),
                        rt: A64Reg::x(0),
                    },
                ),
                GFP_KERNEL,
            )
            .unwrap();

        let layout = layout_program(one_block(insns)).unwrap();

        assert_eq!(layout.insns[3].branch_target_imm("imm19"), Some(524285));
    }
}
