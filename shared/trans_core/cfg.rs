use crate::trans_core::arm64::{decode_word, DecodeError, DecodedInsn, DecodedInsnKind};
use crate::trans_core::input::{CodeProvider, CodeReadError, TranslationRequest};
use crate::trans_core::platform::{SharedAllocError, SharedVec, GFP_KERNEL};

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

#[derive(Debug, PartialEq, Eq)]
pub struct BasicBlock {
    pub start_addr: u64,
    pub end_addr: u64,
    pub start_index: usize,
    pub end_index: usize,
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
    let mut decoded_index = 0usize;
    while pending_index < pending.len() {
        let start_addr = pending[pending_index];
        pending_index += 1;

        if ensure_block_boundary(start_addr, &mut blocks)? {
            continue;
        }

        let start_index = decoded_index;
        let mut pc = start_addr;
        let mut insns = SharedVec::new();

        let terminator = loop {
            if !insns.is_empty() {
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
            decoded_index += 1;

            match insn.kind {
                DecodedInsnKind::Branch { target } => {
                    enqueue_block(target, &mut pending)?;
                    insns.push(insn, GFP_KERNEL).map_err(CfgError::Alloc)?;
                    break BlockTerminator::Branch { target_pc: target };
                }
                DecodedInsnKind::BranchLink { target } => {
                    let reason = RuntimeExitReason::Bl {
                        target_pc: target,
                        resume_pc: pc,
                    };
                    insns.push(insn, GFP_KERNEL).map_err(CfgError::Alloc)?;
                    break BlockTerminator::RuntimeExit { reason };
                }
                DecodedInsnKind::BranchLinkReg { rn } => {
                    let reason = RuntimeExitReason::Blr {
                        target_reg: rn,
                        resume_pc: pc,
                    };
                    insns.push(insn, GFP_KERNEL).map_err(CfgError::Alloc)?;
                    break BlockTerminator::RuntimeExit { reason };
                }
                DecodedInsnKind::BranchReg { rn } => {
                    let reason = RuntimeExitReason::Br { target_reg: rn };
                    insns.push(insn, GFP_KERNEL).map_err(CfgError::Alloc)?;
                    break BlockTerminator::RuntimeExit { reason };
                }
                DecodedInsnKind::Ret { rn } => {
                    let reason = RuntimeExitReason::Ret { lr_reg: rn };
                    insns.push(insn, GFP_KERNEL).map_err(CfgError::Alloc)?;
                    break BlockTerminator::RuntimeExit { reason };
                }
                DecodedInsnKind::Svc { imm16 } => {
                    let reason = RuntimeExitReason::Svc {
                        imm16,
                        resume_pc: pc,
                    };
                    insns.push(insn, GFP_KERNEL).map_err(CfgError::Alloc)?;
                    break BlockTerminator::RuntimeExit { reason };
                }
                DecodedInsnKind::CondBranch { target, .. }
                | DecodedInsnKind::CompareBranch { target, .. }
                | DecodedInsnKind::TestBitBranch { target, .. } => {
                    enqueue_block(pc, &mut pending)?;
                    enqueue_block(target, &mut pending)?;
                    insns.push(insn, GFP_KERNEL).map_err(CfgError::Alloc)?;
                    break BlockTerminator::CondBranch {
                        taken_pc: target,
                        fallthrough_pc: pc,
                    };
                }
                _ => {
                    insns.push(insn, GFP_KERNEL).map_err(CfgError::Alloc)?;
                }
            }
        };

        if insns.is_empty() {
            return Err(CfgError::EmptyBlock { start_addr });
        }

        blocks
            .push(
                BasicBlock {
                    start_addr,
                    end_addr: pc.wrapping_sub(4),
                    start_index,
                    end_index: decoded_index,
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
        let block_end = block_start + (blocks[index].insns.len() as u64) * 4;
        if !(block_start < pc && pc < block_end) {
            continue;
        }

        let split_offset = ((pc - block_start) / 4) as usize;
        let tail_start_index = blocks[index].start_index + split_offset;
        let tail_end_index = blocks[index].end_index;
        let tail_terminator = blocks[index].terminator;
        let tail_insns = blocks[index]
            .insns
            .split_off_copy(split_offset, GFP_KERNEL)
            .map_err(CfgError::Alloc)?;

        blocks[index].end_addr = pc - 4;
        blocks[index].end_index = tail_start_index;
        blocks[index].terminator = BlockTerminator::Fallthrough { next_pc: Some(pc) };

        blocks
            .insert(
                index + 1,
                BasicBlock {
                    start_addr: pc,
                    end_addr: block_end,
                    start_index: tail_start_index,
                    end_index: tail_end_index,
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
