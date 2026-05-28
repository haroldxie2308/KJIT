use crate::shared::abi::{
    append_epilogue, append_prologue, EPILOGUE_LEN_BYTES, EPILOGUE_OFFSET,
    PROLOGUE_ENTRY_BRANCH_OFFSET, PROLOGUE_LEN_BYTES,
};
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
    EmptyProgram,
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

impl core::fmt::Display for LayoutError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Alloc(err) => write!(f, "allocation failed during layout: {err:?}"),
            Self::EmptyProgram => write!(f, "cannot layout an empty rephrased program"),
            Self::MissingLabel { target_original_pc } => {
                write!(
                    f,
                    "missing layout label for original pc {target_original_pc:#x}"
                )
            }
            Self::BranchOutOfRange {
                insn_index,
                target_original_pc,
            } => write!(
                f,
                "branch at instruction {insn_index} cannot reach target {target_original_pc:#x}"
            ),
            Self::UnalignedBranchTarget {
                insn_index,
                target_original_pc,
            } => write!(
                f,
                "branch at instruction {insn_index} has unaligned target {target_original_pc:#x}"
            ),
            Self::UnsupportedBranchField { insn_index, field } => write!(
                f,
                "unsupported branch field `{field}` at instruction {insn_index}"
            ),
        }
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
    let entry_pc = program.first().ok_or(LayoutError::EmptyProgram)?.start_addr;
    let mut fragment = ExecutionFragment {
        insns: SharedVec::with_capacity(
            insn_count + (PROLOGUE_LEN_BYTES + EPILOGUE_LEN_BYTES) / 4,
            GFP_KERNEL,
        )?,
        entry_offset: 0,
        vlabels: SharedVec::with_capacity(insn_count, GFP_KERNEL)?,
    };
    let mut relocs = SharedVec::with_capacity(insn_count, GFP_KERNEL)?;
    let mut runtime_exit_branches = SharedVec::with_capacity(insn_count, GFP_KERNEL)?;

    append_prologue(&mut fragment.insns, GFP_KERNEL)?;
    append_epilogue(&mut fragment.insns, GFP_KERNEL)?;

    for block in &program {
        for rephrased in &block.insns {
            let insn_index = fragment.insns.len();
            let output_offset = insn_index * 4;
            insert_vlabel_once(&mut fragment.vlabels, rephrased.ori_pc, output_offset)?;

            if rephrased.kind == RephrasedInsnKind::Original {
                if let Some(reloc) = branch_reloc_for(rephrased.insn, rephrased.ori_pc, insn_index)?
                {
                    relocs.push(reloc, GFP_KERNEL)?;
                }
            } else if rephrased.kind == RephrasedInsnKind::RuntimeExitBranch {
                runtime_exit_branches.push(insn_index, GFP_KERNEL)?;
            }

            fragment.insns.push(rephrased.insn, GFP_KERNEL)?;
        }
    }

    fragment.entry_offset =
        find_vlabel(&fragment.vlabels, entry_pc).ok_or(LayoutError::MissingLabel {
            target_original_pc: entry_pc,
        })?;

    resolve_prologue_entry_branch(&mut fragment)?;
    resolve_runtime_exit_branches(&mut fragment, &runtime_exit_branches)?;
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
        rewrite_branch_to_offset(
            fragment,
            reloc.insn_index,
            target_offset,
            reloc.target_original_pc,
        )?;
    }
    Ok(())
}

fn resolve_prologue_entry_branch(
    fragment: &mut ExecutionFragment,
) -> SharedResult<(), LayoutError> {
    rewrite_branch_to_offset(
        fragment,
        PROLOGUE_ENTRY_BRANCH_OFFSET / 4,
        fragment.entry_offset,
        u64::MAX,
    )
}

fn resolve_runtime_exit_branches(
    fragment: &mut ExecutionFragment,
    branches: &SharedVec<usize>,
) -> SharedResult<(), LayoutError> {
    for insn_index in branches {
        rewrite_branch_to_offset(fragment, *insn_index, EPILOGUE_OFFSET, u64::MAX)?;
    }
    Ok(())
}

fn rewrite_branch_to_offset(
    fragment: &mut ExecutionFragment,
    insn_index: usize,
    target_offset: usize,
    target_original_pc: u64,
) -> SharedResult<(), LayoutError> {
    let Some(insn) = fragment.insns.get_mut(insn_index) else {
        return Err(LayoutError::BranchOutOfRange {
            insn_index,
            target_original_pc,
        });
    };
    let Some((field, scale, bits)) = branch_target_role(*insn) else {
        return Err(LayoutError::UnsupportedBranchField {
            insn_index,
            field: "",
        });
    };
    let encoded = encode_branch_delta(
        insn_index * 4,
        target_offset,
        scale,
        bits,
        insn_index,
        target_original_pc,
    )?;

    *insn = insn
        .set_branch_target_imm(field, encoded)
        .map_err(|err| match err {
            A64RewriteError::UnsupportedField { field, .. } => {
                LayoutError::UnsupportedBranchField { insn_index, field }
            }
            A64RewriteError::FieldOutOfRange { .. } => LayoutError::BranchOutOfRange {
                insn_index,
                target_original_pc,
            },
        })?;
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

    fn body_start_offset() -> usize {
        PROLOGUE_LEN_BYTES + EPILOGUE_LEN_BYTES
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
        let body_index = body_start_offset() / 4;

        assert_eq!(layout.entry_offset, body_start_offset());
        assert_eq!(layout.vlabels[2], (0x1008, body_start_offset() + 12));
        assert_eq!(layout.insns[body_index].branch_target_imm("imm26"), Some(3));
        assert_eq!(
            layout.insns[body_index].direct_branch_target(body_start_offset() as u64),
            Some((body_start_offset() + 12) as u64)
        );
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
        let body_index = body_start_offset() / 4;

        assert_eq!(
            layout.insns[body_index + 3].branch_target_imm("imm19"),
            Some(524285)
        );
    }

    #[test]
    fn wraps_body_with_prologue_and_epilogue() {
        let mut insns = SharedVec::new();
        insns
            .push(
                RephrasedInsn::original(0x1000, A64Insn::NopNopHiHints {}),
                GFP_KERNEL,
            )
            .unwrap();

        let layout = layout_program(one_block(insns)).unwrap();

        assert_eq!(layout.insns.len(), (body_start_offset() / 4) + 1);
        assert_eq!(layout.entry_offset, body_start_offset());
        assert_eq!(layout.vlabels[0], (0x1000, body_start_offset()));
    }

    #[test]
    fn resolves_prologue_entry_branch_to_entry_offset() {
        let mut insns = SharedVec::new();
        insns
            .push(
                RephrasedInsn::original(0x1000, A64Insn::NopNopHiHints {}),
                GFP_KERNEL,
            )
            .unwrap();

        let layout = layout_program(one_block(insns)).unwrap();
        let prologue_branch_index = PROLOGUE_ENTRY_BRANCH_OFFSET / 4;

        assert_eq!(
            layout.insns[prologue_branch_index]
                .direct_branch_target(PROLOGUE_ENTRY_BRANCH_OFFSET as u64),
            Some(layout.entry_offset as u64)
        );
    }

    #[test]
    fn resolves_runtime_exit_branch_to_epilogue() {
        let mut insns = SharedVec::new();
        insns
            .push(
                RephrasedInsn::runtime_exit_branch(
                    0x1000,
                    A64Insn::BUncondBOnlyBranchImm {
                        imm26: A64Imm::scaled_signed(0, 26, 2),
                    },
                ),
                GFP_KERNEL,
            )
            .unwrap();

        let layout = layout_program(one_block(insns)).unwrap();
        let runtime_branch_index = body_start_offset() / 4;

        assert_eq!(
            layout.insns[runtime_branch_index].direct_branch_target(body_start_offset() as u64),
            Some(EPILOGUE_OFFSET as u64)
        );
    }
}
