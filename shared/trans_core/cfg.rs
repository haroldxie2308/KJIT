extern crate alloc;

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use crate::trans_core::arm64::{DecodedInsn, DecodedInsnKind};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BlockId(pub usize);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockTerminator {
    Fallthrough { next: Option<BlockId> },
    Branch { target: BlockId },
    CondBranch { taken: BlockId, fallthrough: BlockId },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BasicBlock {
    pub id: BlockId,
    pub start_pc: u64,
    pub start_index: usize,
    pub end_index: usize,
    pub insns: Vec<DecodedInsn>,
    pub terminator: BlockTerminator,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cfg {
    pub entry: BlockId,
    pub blocks: Vec<BasicBlock>,
    pub pc_to_block: BTreeMap<u64, BlockId>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CfgError {
    BranchTargetOutsideProgram { source_pc: u64, target_pc: u64 },
}

impl core::fmt::Display for CfgError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BranchTargetOutsideProgram {
                source_pc,
                target_pc,
            } => write!(
                f,
                "branch target {target_pc:#x} from source pc {source_pc:#x} is outside the decoded program"
            ),
        }
    }
}

fn branch_target(kind: &DecodedInsnKind) -> Option<u64> {
    match kind {
        DecodedInsnKind::Branch { target }
        | DecodedInsnKind::CondBranch { target, .. }
        | DecodedInsnKind::CompareBranch { target, .. }
        | DecodedInsnKind::TestBitBranch { target, .. } => Some(*target),
        _ => None,
    }
}

fn is_conditional(kind: &DecodedInsnKind) -> bool {
    matches!(
        kind,
        DecodedInsnKind::CondBranch { .. }
            | DecodedInsnKind::CompareBranch { .. }
            | DecodedInsnKind::TestBitBranch { .. }
    )
}

pub fn build_cfg(decoded: &[DecodedInsn]) -> Result<Cfg, CfgError> {
    let mut leaders = BTreeSet::new();
    if decoded.is_empty() {
        return Ok(Cfg {
            entry: BlockId(0),
            blocks: Vec::new(),
            pc_to_block: BTreeMap::new(),
        });
    }

    let end_pc = decoded
        .last()
        .map(|insn| insn.pc + 4)
        .expect("non-empty decoded program");
    let mut pc_to_index = BTreeMap::new();
    for (index, insn) in decoded.iter().enumerate() {
        pc_to_index.insert(insn.pc, index);
    }

    leaders.insert(0usize);
    for (index, insn) in decoded.iter().enumerate() {
        if let Some(target_pc) = branch_target(&insn.kind) {
            if target_pc != end_pc && !pc_to_index.contains_key(&target_pc) {
                return Err(CfgError::BranchTargetOutsideProgram {
                    source_pc: insn.pc,
                    target_pc,
                });
            }

            if let Some(&target_index) = pc_to_index.get(&target_pc) {
                leaders.insert(target_index);
            }
        }

        if is_conditional(&insn.kind) {
            let next_index = index + 1;
            if next_index < decoded.len() {
                leaders.insert(next_index);
            }
        }
    }

    let leader_indices: Vec<usize> = leaders.into_iter().collect();
    let mut blocks = Vec::with_capacity(leader_indices.len());
    let mut pc_to_block = BTreeMap::new();

    for (block_index, &start_index) in leader_indices.iter().enumerate() {
        let end_index = leader_indices
            .get(block_index + 1)
            .copied()
            .unwrap_or(decoded.len());
        let id = BlockId(block_index);
        let insns = decoded[start_index..end_index].to_vec();
        let start_pc = insns[0].pc;
        pc_to_block.insert(start_pc, id);
        blocks.push(BasicBlock {
            id,
            start_pc,
            start_index,
            end_index,
            insns,
            terminator: BlockTerminator::Fallthrough { next: None },
        });
    }

    let blocks_len = blocks.len();
    for block_index in 0..blocks_len {
        let block = &blocks[block_index];
        let last = block
            .insns
            .last()
            .expect("basic block must contain at least one instruction");
        let terminator = match &last.kind {
            DecodedInsnKind::Branch { target } => BlockTerminator::Branch {
                target: *pc_to_block.get(target).expect("validated branch target"),
            },
            DecodedInsnKind::CondBranch { target, .. }
            | DecodedInsnKind::CompareBranch { target, .. }
            | DecodedInsnKind::TestBitBranch { target, .. } => {
                let taken = *pc_to_block.get(target).expect("validated branch target");
                let fallthrough = BlockId(block.id.0 + 1);
                BlockTerminator::CondBranch { taken, fallthrough }
            }
            _ => {
                let next = blocks.get(block.id.0 + 1).map(|next_block| next_block.id);
                BlockTerminator::Fallthrough { next }
            }
        };
        blocks[block_index].terminator = terminator;
    }

    Ok(Cfg {
        entry: BlockId(0),
        blocks,
        pc_to_block,
    })
}
