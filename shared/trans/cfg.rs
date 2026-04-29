use crate::shared::arm64::{decode_word, DecodeError, DecodedInsn};
use crate::shared::platform::{SharedAllocError, SharedVec, GFP_KERNEL};
use crate::shared::trans::input::{CodeProvider, CodeReadError, TranslationRequest};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeExitReason {
    Bl { target_pc: u64, resume_pc: u64 },
    Blr { target_reg: u8, resume_pc: u64 },
    Br { target_reg: u8 },
    Ret { lr_reg: u8 },
    Svc { imm16: u16, resume_pc: u64 },
    Unsupported,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockTerminator {
    Fallthrough { next_pc: Option<u64> },
    Branch { target_pc: u64 },
    CondBranch { taken_pc: u64, fallthrough_pc: u64 },
    RuntimeExit { reason: RuntimeExitReason },
}

/// Basic block over a half-open PC range: [start_addr, end_addr).
#[derive(Debug, PartialEq, Eq)]
pub struct BasicBlock {
    pub start_addr: u64,
    pub end_addr: u64,
    pub insns: SharedVec<DecodedInsn>,
    pub terminator: BlockTerminator,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Cfg {
    pub entry_pc: u64,
    pub blocks: SharedVec<BasicBlock>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CfgError {
    CodeRead(CodeReadError),
    Decode(DecodeError),
    Alloc(SharedAllocError),
    EmptyBlock { start_addr: u64 },
}

impl core::fmt::Display for CfgError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::CodeRead(err) => write!(f, "{err}"),
            Self::Decode(err) => write!(f, "{err}"),
            Self::Alloc(err) => write!(f, "allocation failed while building CFG: {err:?}"),
            Self::EmptyBlock { start_addr } => {
                write!(f, "no instructions decoded for block at pc {start_addr:#x}")
            }
        }
    }
}

pub fn build_cfg<P: CodeProvider>(request: &TranslationRequest, code: &P) -> Result<Cfg, CfgError> {
    let mut blocks = SharedVec::new();
    let mut pending = SharedVec::new();

    enqueue_block(request.entry_pc, &mut pending)?;

    let mut pending_index = 0usize;
    while pending_index < pending.len() {
        let start_addr = pending[pending_index];
        pending_index += 1;

        if ensure_block_boundary(start_addr, &mut blocks)? {
            continue;
        }

        let mut pc = start_addr;
        let mut insns = SharedVec::new();

        let terminator = loop {
            if !insns.is_empty() {
                // If we have current pc already explored
                if pending.contains(&pc) || ensure_block_boundary(pc, &mut blocks)? {
                    break BlockTerminator::Fallthrough { next_pc: Some(pc) };
                }
            }

            let insn = match read_insn(code, pc) {
                Ok(insn) => insn,
                Err(CfgError::CodeRead(_)) if !insns.is_empty() => {
                    break BlockTerminator::Fallthrough { next_pc: None };
                }
                Err(err) => return Err(err),
            };
            pc = pc.wrapping_add(4);

            insns.push(insn, GFP_KERNEL).map_err(CfgError::Alloc)?;
            if let Some(target) = insn.insn.direct_branch_target(insn.pc) {
                enqueue_block(target, &mut pending)?;
                break BlockTerminator::Branch { target_pc: target };
            }
            if let Some(reason) = insn.insn.runtime_exit_reason(insn.pc) {
                break BlockTerminator::RuntimeExit { reason };
            }
            if let Some((taken_pc, fallthrough_pc)) = insn.insn.conditional_targets(insn.pc) {
                enqueue_block(fallthrough_pc, &mut pending)?;
                enqueue_block(taken_pc, &mut pending)?;
                break BlockTerminator::CondBranch {
                    taken_pc,
                    fallthrough_pc,
                };
            }
        };

        if insns.is_empty() {
            return Err(CfgError::EmptyBlock { start_addr });
        }

        blocks
            .push(
                BasicBlock {
                    start_addr,
                    end_addr: pc,
                    insns,
                    terminator,
                },
                GFP_KERNEL,
            )
            .map_err(CfgError::Alloc)?;
    }

    Ok(Cfg {
        entry_pc: request.entry_pc,
        blocks,
    })
}

fn enqueue_block(pc: u64, pending: &mut SharedVec<u64>) -> Result<(), CfgError> {
    if !pending.contains(&pc) {
        pending.push(pc, GFP_KERNEL).map_err(CfgError::Alloc)?;
    }
    Ok(())
}

fn read_insn<P: CodeProvider>(code: &P, pc: u64) -> Result<DecodedInsn, CfgError> {
    let mut bytes = [0_u8; 4];
    code.read_exact(pc, &mut bytes)
        .map_err(CfgError::CodeRead)?;
    let word = u32::from_le_bytes(bytes);
    decode_word(word, pc).map_err(CfgError::Decode)
}

fn ensure_block_boundary(pc: u64, blocks: &mut SharedVec<BasicBlock>) -> Result<bool, CfgError> {
    if blocks.iter().any(|block| block.start_addr == pc) {
        return Ok(true);
    }

    split_existing_block_at(pc, blocks)
}

fn split_existing_block_at(pc: u64, blocks: &mut SharedVec<BasicBlock>) -> Result<bool, CfgError> {
    for index in 0..blocks.len() {
        let block_start = blocks[index].start_addr;
        if !(block_start < pc && pc < blocks[index].end_addr) {
            continue;
        }

        let split_offset = ((pc - block_start) / 4) as usize;
        let tail_end_addr = blocks[index].end_addr;
        let tail_terminator = blocks[index].terminator;
        let tail_insns = blocks[index]
            .insns
            .split_off_copy(split_offset, GFP_KERNEL)
            .map_err(CfgError::Alloc)?;

        blocks[index].end_addr = pc;
        blocks[index].terminator = BlockTerminator::Fallthrough { next_pc: Some(pc) };

        blocks
            .insert(
                index + 1,
                BasicBlock {
                    start_addr: pc,
                    end_addr: tail_end_addr,
                    insns: tail_insns,
                    terminator: tail_terminator,
                },
                GFP_KERNEL,
            )
            .map_err(CfgError::Alloc)?;
        return Ok(true);
    }

    Ok(false)
}
