extern crate alloc;

use alloc::vec::Vec;

use crate::trans_core::arm64::{decode_word, DecodeError, DecodedInsn, DecodedInsnKind};
use crate::trans_core::input::{CodeProvider, CodeReadError, TranslationRequest};

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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BasicBlock {
    pub start_pc: u64,
    pub start_index: usize,
    pub end_index: usize,
    pub insns: Vec<DecodedInsn>,
    pub terminator: BlockTerminator,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cfg {
    pub entry_pc: u64,
    pub blocks: Vec<BasicBlock>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CfgError {
    CodeRead(CodeReadError),
    Decode(DecodeError),
    EmptyBlock { start_pc: u64 },
}

impl core::fmt::Display for CfgError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::CodeRead(err) => write!(f, "{err}"),
            Self::Decode(err) => write!(f, "{err}"),
            Self::EmptyBlock { start_pc } => {
                write!(f, "no instructions decoded for block at pc {start_pc:#x}")
            }
        }
    }
}

pub fn build_cfg<P: CodeProvider>(request: &TranslationRequest, code: &P) -> Result<Cfg, CfgError> {
    let mut blocks = Vec::new();
    let mut pending = Vec::new();

    enqueue_block(request.entry_pc, &mut pending);

    let mut pending_index = 0usize;
    let mut decoded_index = 0usize;
    while pending_index < pending.len() {
        let start_pc = pending[pending_index];
        pending_index += 1;

        if ensure_block_boundary(start_pc, &mut blocks) {
            continue;
        }

        let start_index = decoded_index;
        let mut pc = start_pc;
        let mut insns = Vec::new();

        let terminator = loop {
            if !insns.is_empty() {
                if pending.contains(&pc) || ensure_block_boundary(pc, &mut blocks) {
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
                    enqueue_block(target, &mut pending);
                    insns.push(insn);
                    break BlockTerminator::Branch { target_pc: target };
                }
                DecodedInsnKind::BranchLink { target } => {
                    let reason = RuntimeExitReason::Bl {
                        target_pc: target,
                        resume_pc: pc,
                    };
                    insns.push(insn);
                    break BlockTerminator::RuntimeExit { reason };
                }
                DecodedInsnKind::BranchLinkReg { rn } => {
                    let reason = RuntimeExitReason::Blr {
                        target_reg: rn,
                        resume_pc: pc,
                    };
                    insns.push(insn);
                    break BlockTerminator::RuntimeExit { reason };
                }
                DecodedInsnKind::BranchReg { rn } => {
                    let reason = RuntimeExitReason::Br { target_reg: rn };
                    insns.push(insn);
                    break BlockTerminator::RuntimeExit { reason };
                }
                DecodedInsnKind::Ret { rn } => {
                    let reason = RuntimeExitReason::Ret { lr_reg: rn };
                    insns.push(insn);
                    break BlockTerminator::RuntimeExit { reason };
                }
                DecodedInsnKind::Svc { imm16 } => {
                    let reason = RuntimeExitReason::Svc {
                        imm16,
                        resume_pc: pc,
                    };
                    insns.push(insn);
                    break BlockTerminator::RuntimeExit { reason };
                }
                DecodedInsnKind::CondBranch { target, .. }
                | DecodedInsnKind::CompareBranch { target, .. }
                | DecodedInsnKind::TestBitBranch { target, .. } => {
                    enqueue_block(pc, &mut pending);
                    enqueue_block(target, &mut pending);
                    insns.push(insn);
                    break BlockTerminator::CondBranch {
                        taken_pc: target,
                        fallthrough_pc: pc,
                    };
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
            start_pc,
            start_index,
            end_index: decoded_index,
            insns,
            terminator,
        });
    }

    Ok(Cfg {
        entry_pc: request.entry_pc,
        blocks,
    })
}

fn enqueue_block(pc: u64, pending: &mut Vec<u64>) {
    if !pending.contains(&pc) {
        pending.push(pc);
    }
}

fn read_insn<P: CodeProvider>(code: &P, pc: u64) -> Result<DecodedInsn, CfgError> {
    let mut bytes = [0_u8; 4];
    code.read_exact(pc, &mut bytes)
        .map_err(CfgError::CodeRead)?;
    let word = u32::from_le_bytes(bytes);
    decode_word(word, pc).map_err(CfgError::Decode)
}

fn ensure_block_boundary(pc: u64, blocks: &mut Vec<BasicBlock>) -> bool {
    if blocks.iter().any(|block| block.start_pc == pc) {
        return true;
    }

    split_existing_block_at(pc, blocks)
}

fn split_existing_block_at(pc: u64, blocks: &mut Vec<BasicBlock>) -> bool {
    for index in 0..blocks.len() {
        let block_start = blocks[index].start_pc;
        let block_end = block_start + (blocks[index].insns.len() as u64) * 4;
        if !(block_start < pc && pc < block_end) {
            continue;
        }

        let split_offset = ((pc - block_start) / 4) as usize;
        let tail_start_index = blocks[index].start_index + split_offset;
        let tail_end_index = blocks[index].end_index;
        let tail_terminator = blocks[index].terminator;
        let tail_insns = blocks[index].insns.split_off(split_offset);

        blocks[index].end_index = tail_start_index;
        blocks[index].terminator = BlockTerminator::Fallthrough { next_pc: Some(pc) };

        blocks.insert(
            index + 1,
            BasicBlock {
                start_pc: pc,
                start_index: tail_start_index,
                end_index: tail_end_index,
                insns: tail_insns,
                terminator: tail_terminator,
            },
        );
        return true;
    }

    false
}
