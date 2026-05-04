use crate::shared::arm64::A64Insn;
use crate::shared::platform::SharedVec;

pub type LayoutVLabels = SharedVec<(u64, usize)>;

#[derive(Debug, PartialEq, Eq)]
pub struct LayoutProgram {
    pub insns: SharedVec<LayoutInsn>,
    pub vlabels: LayoutVLabels,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LayoutInsn {
    pub output_offset: usize,
    pub original_pc: Option<u64>,
    pub inner: A64Insn,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LayoutError {
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
