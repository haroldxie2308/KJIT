use crate::shared::arm64::{decode_word, DecodeError, IrInsn};
use crate::shared::platform::{SharedAllocError, SharedVec, GFP_KERNEL};
use crate::shared::trans::input::{CodeProvider, CodeReadError, TranslationRequest};
use crate::shared::trans::reg_virt::{admit_insn, RegVirtError};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeExitReason {
    Bl { target_pc: u64, resume_pc: u64 },
    Blr { target_reg: u8, resume_pc: u64 },
    Br { target_reg: u8 },
    Ret { lr_reg: u8 },
    Svc { imm16: u16, resume_pc: u64 },
    Unsupported { pc: u64, word: u32 },
}

/// Reachable instruction word that userspace must execute natively: either the
/// generated subset decoder rejects it, or it decodes but reg-virt rejects it for an
/// instruction-intrinsic reason (see `admit_word`). `word` is the exact raw word in
/// both cases, so the two are told apart by decoding it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnsupportedInsn {
    pub pc: u64,
    pub word: u32,
}

/// Basic block over a half-open PC range: [start_addr, end_addr).
///
/// When `unsupported_exit` is `Some(u)`, the block ends with a runtime exit to
/// userspace at `u.pc`: `u.pc == end_addr`, the unsupported instruction is not in
/// `insns`, `next` is empty, and `insns` may be empty.
#[derive(Debug, PartialEq, Eq)]
pub struct BasicBlock {
    pub start_addr: u64,
    pub end_addr: u64,
    pub insns: SharedVec<IrInsn>,
    pub prev: SharedVec<u64>,
    pub next: SharedVec<u64>,
    pub unsupported_exit: Option<UnsupportedInsn>,
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
    RegVirt(RegVirtError),
    Alloc(SharedAllocError),
    EmptyBlock { start_addr: u64 },
}

impl core::fmt::Display for CfgError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::CodeRead(err) => write!(f, "{err}"),
            Self::Decode(err) => write!(f, "{err}"),
            Self::RegVirt(err) => {
                write!(f, "reg-virt admission failed: {err:?}")
            }
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
        let mut unsupported_exit = None;

        let next = loop {
            if !insns.is_empty() {
                // If we have current pc already explored
                if pending.contains(&pc) || ensure_block_boundary(pc, &mut blocks)? {
                    break next_from_one(pc)?;
                }
            }

            let insn = match read_insn(code, pc) {
                Ok(Ok(insn)) => insn,
                Ok(Err(unsupported)) => {
                    unsupported_exit = Some(unsupported);
                    break SharedVec::new();
                }
                Err(CfgError::CodeRead(_)) if !insns.is_empty() => {
                    break SharedVec::new();
                }
                Err(err) => return Err(err),
            };
            pc = pc.wrapping_add(4);

            insns.push(insn, GFP_KERNEL).map_err(CfgError::Alloc)?;
            if let Some(target) = insn.inner.direct_branch_target(insn.pc) {
                enqueue_block(target, &mut pending)?;
                break next_from_one(target)?;
            }
            if let Some(reason) = insn.inner.runtime_exit_reason(insn.pc) {
                if let RuntimeExitReason::Svc { resume_pc, .. } = reason {
                    enqueue_block(resume_pc, &mut pending)?;
                    break next_from_one(resume_pc)?;
                }
                break SharedVec::new();
            }
            if let Some((taken_pc, fallthrough_pc)) = insn.inner.conditional_targets(insn.pc) {
                enqueue_block(fallthrough_pc, &mut pending)?;
                enqueue_block(taken_pc, &mut pending)?;
                break next_from_two(taken_pc, fallthrough_pc)?;
            }
        };

        if insns.is_empty() && unsupported_exit.is_none() {
            return Err(CfgError::EmptyBlock { start_addr });
        }

        blocks
            .push(
                BasicBlock {
                    start_addr,
                    end_addr: pc,
                    insns,
                    prev: SharedVec::new(),
                    next,
                    unsupported_exit,
                },
                GFP_KERNEL,
            )
            .map_err(CfgError::Alloc)?;
    }

    populate_prev(&mut blocks)?;

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

fn next_from_one(pc: u64) -> Result<SharedVec<u64>, CfgError> {
    let mut next = SharedVec::with_capacity(1, GFP_KERNEL).map_err(CfgError::Alloc)?;
    next.push(pc, GFP_KERNEL).map_err(CfgError::Alloc)?;
    Ok(next)
}

fn next_from_two(first: u64, second: u64) -> Result<SharedVec<u64>, CfgError> {
    let mut next = SharedVec::with_capacity(2, GFP_KERNEL).map_err(CfgError::Alloc)?;
    next.push(first, GFP_KERNEL).map_err(CfgError::Alloc)?;
    next.push(second, GFP_KERNEL).map_err(CfgError::Alloc)?;
    Ok(next)
}

fn read_insn<P: CodeProvider>(
    code: &P,
    pc: u64,
) -> Result<Result<IrInsn, UnsupportedInsn>, CfgError> {
    let mut bytes = [0_u8; 4];
    code.read_exact(pc, &mut bytes)
        .map_err(CfgError::CodeRead)?;
    admit_word(u32::from_le_bytes(bytes), pc)
}

/// The single decision on whether the word at `pc` joins a translated block.
/// `Ok(Ok(insn))`: translate it. `Ok(Err(u))`: end the block before it with an
/// Unsupported exit. `Err`: translator bug. Shared with the harness original-code
/// interpreters so they stop exactly where the translated code exits.
pub fn admit_word(word: u32, pc: u64) -> Result<Result<IrInsn, UnsupportedInsn>, CfgError> {
    let insn = match decode_word(word, pc) {
        Ok(insn) => insn,
        Err(DecodeError::UnsupportedWord { pc, word }) => {
            return Ok(Err(UnsupportedInsn { pc, word }));
        }
        Err(err) => return Err(CfgError::Decode(err)),
    };
    match admit_insn(insn) {
        Ok(()) => Ok(Ok(insn)),
        Err(err) if err.is_instruction_intrinsic() => Ok(Err(UnsupportedInsn { pc, word })),
        Err(err) => Err(CfgError::RegVirt(err)),
    }
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
        let tail_next = core::mem::replace(&mut blocks[index].next, SharedVec::new());
        let tail_unsupported_exit = blocks[index].unsupported_exit.take();
        let tail_insns = blocks[index]
            .insns
            .split_off_copy(split_offset, GFP_KERNEL)
            .map_err(CfgError::Alloc)?;

        blocks[index].end_addr = pc;
        blocks[index]
            .next
            .push(pc, GFP_KERNEL)
            .map_err(CfgError::Alloc)?;

        blocks
            .insert(
                index + 1,
                BasicBlock {
                    start_addr: pc,
                    end_addr: tail_end_addr,
                    insns: tail_insns,
                    prev: SharedVec::new(),
                    next: tail_next,
                    unsupported_exit: tail_unsupported_exit,
                },
                GFP_KERNEL,
            )
            .map_err(CfgError::Alloc)?;
        return Ok(true);
    }

    Ok(false)
}

fn populate_prev(blocks: &mut SharedVec<BasicBlock>) -> Result<(), CfgError> {
    for index in 0..blocks.len() {
        blocks[index].prev = SharedVec::new();
    }

    for source_index in 0..blocks.len() {
        let source = blocks[source_index].start_addr;
        for next_index in 0..blocks[source_index].next.len() {
            let target = blocks[source_index].next[next_index];
            if let Some(block_index) = blocks.iter().position(|block| block.start_addr == target) {
                blocks[block_index]
                    .prev
                    .push(source, GFP_KERNEL)
                    .map_err(CfgError::Alloc)?;
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::arm64::ergo::{scaled_simm, uimm, x};
    use crate::shared::arm64::{A64Imm, A64Insn, A64Mem, A64Reg};
    use crate::shared::trans::input::TranslationTrigger;
    use crate::shared::trans::translate::compile_request;

    const BASE: u64 = 0x1000;
    // `mrs x0, tpidrro_el0`: outside the decoded subset (MRS decodes only for
    // TPIDR_EL0, which differs from this word in op2 alone).
    const UNDECODABLE: u32 = 0xd53b_d060;

    struct SliceCode<'a> {
        base: u64,
        bytes: &'a [u8],
    }

    impl CodeProvider for SliceCode<'_> {
        fn entry_addr(&self) -> u64 {
            self.base
        }

        fn read_exact(&self, pc: u64, dst: &mut [u8]) -> Result<(), CodeReadError> {
            let unmapped = CodeReadError::Unmapped { pc, len: dst.len() };
            let start = pc.checked_sub(self.base).ok_or(unmapped)? as usize;
            let src = self.bytes.get(start..start + dst.len()).ok_or(unmapped)?;
            dst.copy_from_slice(src);
            Ok(())
        }
    }

    fn assemble(words: &[u32]) -> alloc::vec::Vec<u8> {
        assert!(A64Insn::decode(UNDECODABLE).is_none());
        words.iter().flat_map(|word| word.to_le_bytes()).collect()
    }

    fn enc(insn: A64Insn) -> u32 {
        insn.encode().unwrap()
    }

    fn request() -> TranslationRequest {
        TranslationRequest {
            entry_pc: BASE,
            trigger: TranslationTrigger::Manual,
            regs: None,
        }
    }

    fn cfg_for(bytes: &[u8]) -> Cfg {
        let code = SliceCode { base: BASE, bytes };
        build_cfg(&request(), &code).unwrap()
    }

    /// `ldr x1, [x1], #8`: decodes, but writeback base == Rt is CONSTRAINED UNPREDICTABLE.
    fn unpredictable_ldr() -> u32 {
        enc(A64Insn::LdrImmGenLdr64LdstImmpost {
            rt: x(1),
            mem: A64Mem::post_index(A64Reg::x_sp(1), A64Imm::signed(8, 9)),
        })
    }

    #[test]
    fn undecodable_entry_yields_empty_block_with_unsupported_exit() {
        let cfg = cfg_for(&assemble(&[UNDECODABLE]));

        assert_eq!(cfg.blocks.len(), 1);
        let block = &cfg.blocks[0];
        assert_eq!((block.start_addr, block.end_addr), (BASE, BASE));
        assert!(block.insns.is_empty());
        assert!(block.next.is_empty());
        assert_eq!(
            block.unsupported_exit,
            Some(UnsupportedInsn {
                pc: BASE,
                word: UNDECODABLE
            })
        );
    }

    #[test]
    fn undecodable_word_mid_block_ends_block_before_it() {
        let movz = enc(A64Insn::MovzMovz64Movewide {
            hw: 0,
            imm16: uimm(1, 16),
            rd: x(0),
        });
        let cfg = cfg_for(&assemble(&[movz, UNDECODABLE, movz]));

        assert_eq!(cfg.blocks.len(), 1);
        let block = &cfg.blocks[0];
        assert_eq!((block.start_addr, block.end_addr), (BASE, BASE + 4));
        assert_eq!(block.insns.len(), 1);
        assert!(block.next.is_empty());
        assert_eq!(
            block.unsupported_exit,
            Some(UnsupportedInsn {
                pc: BASE + 4,
                word: UNDECODABLE
            })
        );
    }

    #[test]
    fn split_keeps_unsupported_exit_on_tail_block() {
        let nop = enc(A64Insn::NopNopHiHints {});
        let cfg = cfg_for(&assemble(&[
            // BASE: cbz x0, BASE+16
            enc(A64Insn::CbzCbz64Compbranch {
                imm19: scaled_simm(4, 19, 2),
                rt: x(0),
            }),
            nop,
            nop,
            UNDECODABLE,
            // BASE+16: b BASE+8 (into the middle of the fallthrough block)
            enc(A64Insn::BUncondBOnlyBranchImm {
                imm26: scaled_simm((-2_i32) as u32 & 0x3ff_ffff, 26, 2),
            }),
        ]));

        let find = |start| {
            cfg.blocks
                .iter()
                .find(|block| block.start_addr == start)
                .unwrap()
        };
        let head = find(BASE + 4);
        assert_eq!(head.end_addr, BASE + 8);
        assert_eq!(&*head.next, &[BASE + 8]);
        assert_eq!(head.unsupported_exit, None);

        let tail = find(BASE + 8);
        assert_eq!(tail.end_addr, BASE + 12);
        assert_eq!(tail.insns.len(), 1);
        assert!(tail.next.is_empty());
        assert_eq!(&*tail.prev, &[BASE + 4, BASE + 16]);
        assert_eq!(
            tail.unsupported_exit,
            Some(UnsupportedInsn {
                pc: BASE + 12,
                word: UNDECODABLE
            })
        );
    }

    #[test]
    fn reg_virt_rejected_insn_ends_block_with_unsupported_exit() {
        let movz = enc(A64Insn::MovzMovz64Movewide {
            hw: 0,
            imm16: uimm(1, 16),
            rd: x(0),
        });
        let rejected = unpredictable_ldr();
        let bytes = assemble(&[movz, rejected, movz]);
        let cfg = cfg_for(&bytes);

        assert_eq!(cfg.blocks.len(), 1);
        let block = &cfg.blocks[0];
        assert_eq!((block.start_addr, block.end_addr), (BASE, BASE + 4));
        assert_eq!(block.insns.len(), 1);
        assert!(block.next.is_empty());
        assert_eq!(
            block.unsupported_exit,
            Some(UnsupportedInsn {
                pc: BASE + 4,
                word: rejected
            })
        );

        let code = SliceCode {
            base: BASE,
            bytes: &bytes,
        };
        compile_request(&request(), &code).unwrap();
    }

    #[test]
    fn admit_word_distinguishes_translate_exit_and_undecodable() {
        let admitted = enc(A64Insn::LdrImmGenLdr64LdstImmpost {
            rt: x(0),
            mem: A64Mem::post_index(A64Reg::x_sp(1), A64Imm::signed(8, 9)),
        });
        assert!(matches!(admit_word(admitted, BASE), Ok(Ok(insn)) if insn.word == admitted));
        assert_eq!(
            admit_word(unpredictable_ldr(), BASE),
            Ok(Err(UnsupportedInsn {
                pc: BASE,
                word: unpredictable_ldr()
            }))
        );
        assert_eq!(
            admit_word(UNDECODABLE, BASE),
            Ok(Err(UnsupportedInsn {
                pc: BASE,
                word: UNDECODABLE
            }))
        );
    }
}
