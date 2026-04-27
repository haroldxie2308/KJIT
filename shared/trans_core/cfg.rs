extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::trans_core::arm64::{decode_word, DecodeError, DecodedInsn, DecodedInsnKind};
use crate::trans_core::input::{CodeProvider, CodeReadError, TranslationRequest};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BlockId(pub usize);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeExitReason {
    Bl { target_pc: u64, resume_pc: u64 },
    Blr { target_reg: u8, resume_pc: u64 },
    Br { target_reg: u8 },
    Ret { lr_reg: u8 },
    Svc { resume_pc: u64 },
    Unsupported,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockTerminator {
    Fallthrough {
        next: Option<BlockId>,
    },
    Branch {
        target: BlockId,
    },
    CondBranch {
        taken: BlockId,
        fallthrough: BlockId,
    },
    RuntimeExit {
        reason: RuntimeExitReason,
    },
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CfgError {
    CodeRead(CodeReadError),
    Decode(DecodeError),
    EmptyBlock {
        start_pc: u64,
    },
    BranchIntoExistingBlock {
        target_pc: u64,
        block_start_pc: u64,
        block_end_pc: u64,
    },
}

impl core::fmt::Display for CfgError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::CodeRead(err) => write!(f, "{err}"),
            Self::Decode(err) => write!(f, "{err}"),
            Self::EmptyBlock { start_pc } => {
                write!(f, "no instructions decoded for block at pc {start_pc:#x}")
            }
            Self::BranchIntoExistingBlock {
                target_pc,
                block_start_pc,
                block_end_pc,
            } => write!(
                f,
                "branch target {target_pc:#x} lands inside existing block [{block_start_pc:#x}, {block_end_pc:#x}]"
            ),
        }
    }
}

pub fn build_cfg<P: CodeProvider>(request: &TranslationRequest, code: &P) -> Result<Cfg, CfgError> {
    let mut blocks = Vec::new();
    let mut pc_to_block = BTreeMap::new();
    let mut pending = Vec::new();

    enqueue_block(request.entry_pc, &mut pc_to_block, &mut pending);

    let mut pending_index = 0usize;
    let mut decoded_index = 0usize;
    while pending_index < pending.len() {
        let start_pc = pending[pending_index];
        pending_index += 1;

        if blocks
            .iter()
            .any(|block: &BasicBlock| block.start_pc == start_pc)
        {
            continue;
        }

        reject_inside_existing_block(start_pc, &blocks)?;

        let id = *pc_to_block
            .get(&start_pc)
            .expect("pending block must have an assigned id");
        let start_index = decoded_index;
        let mut pc = start_pc;
        let mut insns = Vec::new();

        let terminator = loop {
            if !insns.is_empty() {
                if let Some(next) = pc_to_block.get(&pc).copied() {
                    break BlockTerminator::Fallthrough { next: Some(next) };
                }
            }

            let insn = match read_insn(code, pc) {
                Ok(insn) => insn,
                Err(CfgError::CodeRead(_)) if !insns.is_empty() => {
                    break BlockTerminator::Fallthrough { next: None };
                }
                Err(err) => return Err(err),
            };
            pc = pc.wrapping_add(4);
            decoded_index += 1;

            match insn.kind {
                DecodedInsnKind::Branch { target } => {
                    let target = enqueue_block(target, &mut pc_to_block, &mut pending);
                    insns.push(insn);
                    break BlockTerminator::Branch { target };
                }
                DecodedInsnKind::CondBranch { target, .. }
                | DecodedInsnKind::CompareBranch { target, .. }
                | DecodedInsnKind::TestBitBranch { target, .. } => {
                    let fallthrough = enqueue_block(pc, &mut pc_to_block, &mut pending);
                    let taken = enqueue_block(target, &mut pc_to_block, &mut pending);
                    insns.push(insn);
                    break BlockTerminator::CondBranch { taken, fallthrough };
                }
                _ => {
                    insns.push(insn);
                }
            }
        };

        if insns.is_empty() {
            return Err(CfgError::EmptyBlock { start_pc });
        }

        blocks.push(BasicBlock {
            id,
            start_pc,
            start_index,
            end_index: decoded_index,
            insns,
            terminator,
        });
    }

    Ok(Cfg {
        entry: BlockId(0),
        blocks,
        pc_to_block,
    })
}

fn enqueue_block(
    pc: u64,
    pc_to_block: &mut BTreeMap<u64, BlockId>,
    pending: &mut Vec<u64>,
) -> BlockId {
    if let Some(id) = pc_to_block.get(&pc).copied() {
        return id;
    }

    let id = BlockId(pc_to_block.len());
    pc_to_block.insert(pc, id);
    pending.push(pc);
    id
}

fn read_insn<P: CodeProvider>(code: &P, pc: u64) -> Result<DecodedInsn, CfgError> {
    let mut bytes = [0_u8; 4];
    code.read_exact(pc, &mut bytes)
        .map_err(CfgError::CodeRead)?;
    let word = u32::from_le_bytes(bytes);
    decode_word(word, pc).map_err(CfgError::Decode)
}

fn reject_inside_existing_block(pc: u64, blocks: &[BasicBlock]) -> Result<(), CfgError> {
    for block in blocks {
        let block_end = block.start_pc + (block.insns.len() as u64) * 4;
        if block.start_pc < pc && pc < block_end {
            return Err(CfgError::BranchIntoExistingBlock {
                target_pc: pc,
                block_start_pc: block.start_pc,
                block_end_pc: block_end,
            });
        }
    }
    Ok(())
}
