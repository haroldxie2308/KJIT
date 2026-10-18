use crate::shared::arm64::{decode_word, DecodeError, IrInsn};
use crate::shared::platform::{SharedAllocError, SharedVec, GFP_KERNEL};
use crate::shared::trans::input::{CodeProvider, CodeReadError, TranslationRequest};
use crate::shared::trans::reg_virt::{admit_insn, RegVirtError};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeExitReason {
    Bl {
        target_pc: u64,
        resume_pc: u64,
    },
    Blr {
        target_reg: u8,
        resume_pc: u64,
    },
    Br {
        target_reg: u8,
    },
    Ret {
        lr_reg: u8,
    },
    Svc {
        imm16: u16,
        resume_pc: u64,
    },
    /// `word` is `None` when `pc` is past the readable text (`UnsupportedExit::Unreadable`).
    Unsupported {
        pc: u64,
        word: Option<u32>,
    },
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

/// Why a block ends in a native-resume `Unsupported` exit: userspace resumes at
/// `pc` and executes whatever is there itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnsupportedExit {
    /// The word at `pc` is outside the subset or reg-virt rejects it.
    Insn(UnsupportedInsn),
    /// `pc` is past the readable text: there is no word to translate. Natively the
    /// CPU fetches (or faults) there, which is exactly what resuming at `pc` gives.
    Unreadable { pc: u64 },
}

impl UnsupportedExit {
    pub const fn pc(self) -> u64 {
        match self {
            Self::Insn(insn) => insn.pc,
            Self::Unreadable { pc } => pc,
        }
    }

    /// The raw word, if one could be read.
    pub const fn word(self) -> Option<u32> {
        match self {
            Self::Insn(insn) => Some(insn.word),
            Self::Unreadable { .. } => None,
        }
    }
}

/// Basic block over a half-open PC range: [start_addr, end_addr).
///
/// When `unsupported_exit` is `Some(u)`, the block ends with a runtime exit to
/// userspace at `u.pc()`: `u.pc() == end_addr`, the unsupported instruction is not
/// in `insns`, `next` is empty, and `insns` may be empty.
#[derive(Debug, PartialEq, Eq)]
pub struct BasicBlock {
    pub start_addr: u64,
    pub end_addr: u64,
    pub insns: SharedVec<IrInsn>,
    pub prev: SharedVec<u64>,
    pub next: SharedVec<u64>,
    pub unsupported_exit: Option<UnsupportedExit>,
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

    // An unreadable entry is a translation request for code that does not exist.
    // Every other unreadable PC is an `Unreadable` exit (`admit_at`).
    code.read_exact(request.entry_pc, &mut [0_u8; 4])
        .map_err(CfgError::CodeRead)?;
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

            let insn = match admit_at(code, pc)? {
                Ok(insn) => insn,
                Err(unsupported) => {
                    unsupported_exit = Some(unsupported);
                    break SharedVec::new();
                }
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

/// The single decision on what translation does at `pc`: `admit_word` on the word
/// there, or an `Unreadable` exit when `pc` is past the readable text. Shared with
/// the harness original-code interpreters, so running off the end of the text
/// stops them exactly where the translated code exits.
pub fn admit_at<P: CodeProvider>(
    code: &P,
    pc: u64,
) -> Result<Result<IrInsn, UnsupportedExit>, CfgError> {
    let mut bytes = [0_u8; 4];
    match code.read_exact(pc, &mut bytes) {
        Ok(()) => Ok(admit_word(u32::from_le_bytes(bytes), pc)?.map_err(UnsupportedExit::Insn)),
        Err(CodeReadError::Unmapped { .. }) => Ok(Err(UnsupportedExit::Unreadable { pc })),
    }
}

/// Final layout order of a program's blocks, as indices into the sequence of their
/// start addresses: ascending start address. This is the single definition of
/// "layout order": rephrase derives back-edges from it (a branch whose target is at
/// or before it in this order), layout emits block bodies and cold regions in it,
/// and the harness trace reconstructs offsets from it. Blocks partition the PC
/// space, so starts are distinct, and a fall-through successor (which starts at its
/// predecessor's end) is the next block in this order.
pub fn layout_block_order(
    starts: impl IntoIterator<Item = u64>,
) -> Result<SharedVec<usize>, SharedAllocError> {
    let mut keyed: SharedVec<(u64, usize)> = SharedVec::new();
    for (index, start) in starts.into_iter().enumerate() {
        keyed.push((start, index), GFP_KERNEL)?;
    }
    keyed.sort_unstable();
    let mut order = SharedVec::with_capacity(keyed.len(), GFP_KERNEL)?;
    for &(_, index) in keyed.iter() {
        order.push(index, GFP_KERNEL)?;
    }
    Ok(order)
}

/// Index of the block containing `pc`: the last block in layout `order` whose start
/// is at or before `pc` (blocks partition the PC space). `None` if `pc` is below the
/// first block. A `pc` past the last block's end is attributed to that block; callers
/// ask only about PCs that carry a label, which lie inside a block.
pub fn block_containing(
    order: &[usize],
    start_of: impl Fn(usize) -> u64,
    pc: u64,
) -> Option<usize> {
    let after = order.partition_point(|&index| start_of(index) <= pc);
    after.checked_sub(1).map(|position| order[position])
}

/// Strongly connected components of the fragment's body graph (docs/pipeline.md,
/// "Budgeted back-edges (A22)"): one component id per block, indexed like `blocks`
/// (`order` is `layout_block_order` of them). Nodes are the blocks. Edges are the
/// fall-through and the direct B/B.cond/CBZ/CBNZ/TBZ/TBNZ targets, which is
/// `BasicBlock::next` -- except that a block ending in a runtime exit (BL, BLR, BR,
/// RET, SVC) is a sink: it leaves through a dispatch site or the runtime, each already
/// charged a budget unit, whatever `next` names (an SVC's resume block).
///
/// Iterative Tarjan: this runs in the kernel on a small stack.
pub fn body_components(
    blocks: &[BasicBlock],
    order: &[usize],
) -> Result<SharedVec<usize>, SharedAllocError> {
    let successor = |block: usize, slot: usize| -> Option<usize> {
        let node = &blocks[block];
        if node.insns.last().is_some_and(|insn| insn.inner.runtime_exit_reason(insn.pc).is_some())
        {
            return None;
        }
        let target = *node.next.get(slot)?;
        // `build_cfg` creates a block for every PC it records in `next`.
        let successor = block_containing(order, |index| blocks[index].start_addr, target)
            .filter(|&successor| blocks[successor].start_addr == target)
            .expect("every CFG successor is a block start");
        Some(successor)
    };
    strongly_connected_components(blocks.len(), successor)
}

/// Tarjan's algorithm with an explicit stack: component ids (numbered in the order
/// components complete) of the graph on `0..count` whose `slot`-th successor of
/// `node` is `successor(node, slot)` (`None`: no more). O(nodes + edges).
fn strongly_connected_components(
    count: usize,
    successor: impl Fn(usize, usize) -> Option<usize>,
) -> Result<SharedVec<usize>, SharedAllocError> {
    const UNSET: usize = usize::MAX;
    let filled = |value: usize| -> Result<SharedVec<usize>, SharedAllocError> {
        let mut out = SharedVec::with_capacity(count, GFP_KERNEL)?;
        for _ in 0..count {
            out.push(value, GFP_KERNEL)?;
        }
        Ok(out)
    };
    // Discovery number, lowest discovery number reachable, component id (`UNSET`
    // while the node is unvisited or still on the Tarjan stack).
    let mut number = filled(UNSET)?;
    let mut low = filled(0)?;
    let mut component = filled(UNSET)?;
    // Tarjan stack and call stack (node, next successor slot), each at most one
    // entry per node; the `*_len` fields are their heights.
    let mut open = filled(0)?;
    let mut open_len = 0;
    let mut calls = filled(0)?;
    let mut call_slots = filled(0)?;
    let mut calls_len;
    let mut discovered = 0;
    let mut components = 0;

    for root in 0..count {
        if number[root] != UNSET {
            continue;
        }
        number[root] = discovered;
        low[root] = discovered;
        discovered += 1;
        open[open_len] = root;
        open_len += 1;
        calls[0] = root;
        call_slots[0] = 0;
        calls_len = 1;

        while calls_len > 0 {
            let node = calls[calls_len - 1];
            let slot = call_slots[calls_len - 1];
            if let Some(next) = successor(node, slot) {
                call_slots[calls_len - 1] += 1;
                if number[next] == UNSET {
                    number[next] = discovered;
                    low[next] = discovered;
                    discovered += 1;
                    open[open_len] = next;
                    open_len += 1;
                    calls[calls_len] = next;
                    call_slots[calls_len] = 0;
                    calls_len += 1;
                } else if component[next] == UNSET {
                    // On the Tarjan stack: part of the current search tree.
                    low[node] = low[node].min(number[next]);
                }
                continue;
            }
            calls_len -= 1;
            if low[node] == number[node] {
                loop {
                    open_len -= 1;
                    let member = open[open_len];
                    component[member] = components;
                    if member == node {
                        break;
                    }
                }
                components += 1;
            }
            if calls_len > 0 {
                let parent = calls[calls_len - 1];
                low[parent] = low[parent].min(low[node]);
            }
        }
    }
    Ok(component)
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
    // TPIDR_EL0, CNTVCT_EL0 and CNTFRQ_EL0; TPIDR_EL0 differs from this word in
    // op2 alone).
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
            Some(UnsupportedExit::Insn(UnsupportedInsn {
                pc: BASE,
                word: UNDECODABLE
            }))
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
            Some(UnsupportedExit::Insn(UnsupportedInsn {
                pc: BASE + 4,
                word: UNDECODABLE
            }))
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
            Some(UnsupportedExit::Insn(UnsupportedInsn {
                pc: BASE + 12,
                word: UNDECODABLE
            }))
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
            Some(UnsupportedExit::Insn(UnsupportedInsn {
                pc: BASE + 4,
                word: rejected
            }))
        );

        let code = SliceCode {
            base: BASE,
            bytes: &bytes,
        };
        compile_request(&request(), &code).unwrap();
    }

    #[test]
    fn running_off_the_text_ends_the_block_with_an_unreadable_exit() {
        let movz = enc(A64Insn::MovzMovz64Movewide {
            hw: 0,
            imm16: uimm(1, 16),
            rd: x(0),
        });
        let cfg = cfg_for(&assemble(&[movz]));

        assert_eq!(cfg.blocks.len(), 1);
        let block = &cfg.blocks[0];
        assert_eq!((block.start_addr, block.end_addr), (BASE, BASE + 4));
        assert!(block.next.is_empty());
        assert_eq!(
            block.unsupported_exit,
            Some(UnsupportedExit::Unreadable { pc: BASE + 4 })
        );
    }

    /// A branch whose fall-through is past the text: that successor is an empty
    /// block holding only the `Unreadable` exit.
    #[test]
    fn unreadable_successor_is_an_empty_exit_block() {
        let cbz = enc(A64Insn::CbzCbz64Compbranch {
            imm19: scaled_simm(0, 19, 2),
            rt: x(0),
        });
        let cfg = cfg_for(&assemble(&[cbz]));

        let tail = cfg
            .blocks
            .iter()
            .find(|block| block.start_addr == BASE + 4)
            .unwrap();
        assert_eq!(tail.end_addr, BASE + 4);
        assert!(tail.insns.is_empty());
        assert_eq!(
            tail.unsupported_exit,
            Some(UnsupportedExit::Unreadable { pc: BASE + 4 })
        );
    }

    #[test]
    fn unreadable_entry_is_a_hard_error() {
        let code = SliceCode {
            base: BASE,
            bytes: &[],
        };
        assert_eq!(
            build_cfg(&request(), &code),
            Err(CfgError::CodeRead(CodeReadError::Unmapped {
                pc: BASE,
                len: 4
            }))
        );
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

    /// The search is iterative: a path of 300000 nodes would overflow a recursive
    /// one's stack.
    #[test]
    fn components_of_a_very_long_path_do_not_recurse() {
        const NODES: usize = 300_000;
        let path = |node: usize, slot: usize| (slot == 0 && node + 1 < NODES).then_some(node + 1);
        let open = strongly_connected_components(NODES, path).unwrap();
        assert_ne!(open[0], open[NODES - 1]);
        let closed = strongly_connected_components(NODES, |node, slot| match (node, slot) {
            (last, 0) if last + 1 == NODES => Some(0),
            (node, 0) => Some(node + 1),
            _ => None,
        })
        .unwrap();
        assert!(closed.iter().all(|&component| component == closed[0]));
    }

    fn words(pc: u64, target: u64) -> i64 {
        (target as i64 - pc as i64) / 4
    }

    fn b_to(pc: u64, target: u64) -> u32 {
        enc(A64Insn::BUncondBOnlyBranchImm {
            imm26: scaled_simm(words(pc, target) as u32 & 0x3ff_ffff, 26, 2),
        })
    }

    fn bl_to(pc: u64, target: u64) -> u32 {
        enc(A64Insn::BlBlOnlyBranchImm {
            imm26: scaled_simm(words(pc, target) as u32 & 0x3ff_ffff, 26, 2),
        })
    }

    fn cbnz_to(pc: u64, target: u64) -> u32 {
        enc(A64Insn::CbnzCbnz64Compbranch {
            imm19: scaled_simm(words(pc, target) as u32 & 0x7_ffff, 19, 2),
            rt: x(0),
        })
    }

    fn ret() -> u32 {
        enc(A64Insn::RetRet64rBranchReg { rn: x(30) })
    }

    fn nop() -> u32 {
        enc(A64Insn::NopNopHiHints {})
    }

    /// Component ids of the blocks starting at `starts`, in that order.
    fn components_of(bytes: &[u8], starts: &[u64]) -> alloc::vec::Vec<usize> {
        let cfg = cfg_for(bytes);
        assert_eq!(cfg.blocks.len(), starts.len(), "blocks {:?}", cfg.blocks);
        let order = layout_block_order(cfg.blocks.iter().map(|block| block.start_addr)).unwrap();
        let component = body_components(&cfg.blocks, &order).unwrap();
        starts
            .iter()
            .map(|&start| {
                let index = cfg.blocks.iter().position(|b| b.start_addr == start).unwrap();
                component[index]
            })
            .collect()
    }

    /// A22: loops are components, and a jump back to a block that cannot reach the
    /// jump again is not.
    #[test]
    fn components_group_exactly_the_blocks_on_a_cycle() {
        let at = |i: u64| BASE + 4 * i;
        // A self-loop block, and its exit.
        let ids = components_of(
            &assemble(&[nop(), cbnz_to(at(1), at(0)), ret()]),
            &[at(0), at(2)],
        );
        assert_ne!(ids[0], ids[1]);

        // A loop entered from outside and left through its conditional back-edge:
        // 0, then the loop block [1, 3), then 3.
        let ids = components_of(
            &assemble(&[nop(), nop(), cbnz_to(at(2), at(1)), ret()]),
            &[at(0), at(1), at(3)],
        );
        assert_ne!(ids[0], ids[1]);
        assert_ne!(ids[1], ids[2]);

        // Nested loops: the inner body [2, 4) inside the outer loop 1..=4; a single
        // component holds both.
        let ids = components_of(
            &assemble(&[
                nop(),
                nop(),
                nop(),
                cbnz_to(at(3), at(2)),
                cbnz_to(at(4), at(1)),
                ret(),
            ]),
            &[at(0), at(1), at(2), at(4), at(5)],
        );
        assert_eq!(ids[1], ids[2]);
        assert_eq!(ids[1], ids[3]);
        assert_ne!(ids[0], ids[1]);
        assert_ne!(ids[4], ids[1]);
    }

    #[test]
    fn a_jump_back_to_a_shared_ret_is_on_no_cycle() {
        let at = |i: u64| BASE + 4 * i;
        // 0: cbnz -> 3; 1: nop; 2: ret; 3: b 2. Blocks 0, 1, 2, 3.
        let ids = components_of(
            &assemble(&[cbnz_to(at(0), at(3)), nop(), ret(), b_to(at(3), at(2))]),
            &[at(0), at(1), at(2), at(3)],
        );
        for first in 0..ids.len() {
            for second in first + 1..ids.len() {
                assert_ne!(ids[first], ids[second]);
            }
        }
    }

    /// BL, BLR, BR, RET and SVC are sinks: a path through one is no edge, even when
    /// the CFG names the block after an SVC as its successor.
    #[test]
    fn transfers_and_exits_are_sinks() {
        let at = |i: u64| BASE + 4 * i;
        let svc = enc(A64Insn::SvcSvcExException {
            imm16: uimm(0, 16),
        });
        // 0: svc (resume block 1); 1: b 0.
        let bytes = assemble(&[svc, b_to(at(1), at(0))]);
        let cfg = cfg_for(&bytes);
        assert_eq!(&*cfg.blocks[0].next, &[at(1)]);
        let ids = components_of(&bytes, &[at(0), at(1)]);
        assert_ne!(ids[0], ids[1]);

        // The return site of a call (entered at 1) jumps back to the call at 0.
        let bytes = assemble(&[bl_to(at(0), at(8)), cbnz_to(at(1), at(0)), ret()]);
        let code = SliceCode {
            base: BASE,
            bytes: &bytes,
        };
        let request = TranslationRequest {
            entry_pc: at(1),
            trigger: TranslationTrigger::Manual,
            regs: None,
        };
        let cfg = build_cfg(&request, &code).unwrap();
        let order = layout_block_order(cfg.blocks.iter().map(|block| block.start_addr)).unwrap();
        let component = body_components(&cfg.blocks, &order).unwrap();
        let of = |start| {
            component[cfg.blocks.iter().position(|b| b.start_addr == start).unwrap()]
        };
        assert_ne!(of(at(0)), of(at(1)));
    }
}
