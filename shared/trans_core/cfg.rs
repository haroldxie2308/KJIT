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
    let mut pending = Vec::new();

    enqueue_block(request.entry_pc, &mut pending);

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

        let start_index = decoded_index;
        let mut pc = start_pc;
        let mut insns = Vec::new();

        let terminator = loop {
            if !insns.is_empty() {
                if block_exists_or_pending(pc, &blocks, &pending) {
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

fn block_exists_or_pending(pc: u64, blocks: &[BasicBlock], pending: &[u64]) -> bool {
    blocks.iter().any(|block| block.start_pc == pc) || pending.contains(&pc)
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
