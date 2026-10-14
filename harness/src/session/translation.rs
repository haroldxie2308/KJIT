//! The record of one translation request: every pass of the pipeline run one at a
//! time on the same text the code cache translated, plus the verifier's verdict.
//!
//! The passes are the shared ones (`build_cfg`, `rephrase`, `virtualize_registers`,
//! `layout_program`); this module only keeps their outputs. The recorder checks that
//! the layout words equal what the cache installed (`check_installed`), so the record
//! cannot drift from the code that runs.

use std::ops::Range;

use crate::shared::abi::{EPILOGUE_LEN_BYTES, LINK_NOP_WORD, PROLOGUE_LEN_BYTES};
use crate::shared::arm64::{A64Insn, IrInsn};
use crate::shared::emit::layout::{layout_program, FaultSite};
use crate::shared::trans::cfg::{admit_at, build_cfg, layout_block_order, UnsupportedExit};
use crate::shared::trans::input::{TranslationRequest, TranslationTrigger};
use crate::shared::trans::reg_virt::virtualize_registers;
use crate::shared::trans::rephrase::{rephrase, RephrasedInsn, RephrasedInsnKind, RephrasedProgram};
use crate::shared::verify::VerifyError;
use crate::code_cache::CachedFragment;
use crate::{encode_fragment, verify_encoded_fragment, MockCodeProvider};

/// Where a translation request came from (docs/pipeline.md, section 9, "Profiler").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Trigger {
    /// The pc userspace resumes at after a syscall, with no fragment for it.
    SvcResume,
    /// The target of a `BL`/`BLR`/`BR`/`RET` exit no fragment resolved (exit-target
    /// learning).
    ExitTarget,
}

/// The shared passes, in order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pass {
    Cfg,
    Rephrase,
    RegVirt,
    Layout,
}

/// Why a request installed nothing. Every one of them is a final failure: the pc
/// enters the negative cache (section 9) and is never requested again.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Rejection {
    /// The entry word itself would take the `Unsupported` exit (`cfg::admit_at`): the
    /// kernel refuses such a translation (`-ENOEXEC`).
    EntryUnsupported(UnsupportedExit),
    /// A pass failed; `message` is its error.
    Compile { pass: Pass, message: String },
    /// The fragment does not encode.
    Encode(String),
    /// The independent verifier rejected the encoded fragment.
    Verify(VerifyError),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Accepted { uses_fpsimd: bool },
    Rejected(VerifyError),
}

/// A position in a pass's output: block, instruction in the block's body (or in its
/// cold region).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InsnPos {
    pub block: usize,
    pub index: usize,
    pub cold: bool,
}

/// A basic block of the CFG pass. Its instructions are `decoded[insns]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CfgBlockRecord {
    pub index: usize,
    pub start_pc: u64,
    pub end_pc: u64,
    pub prev: Vec<u64>,
    pub next: Vec<u64>,
    pub insns: Range<usize>,
    /// The block ends in a native-resume `Unsupported` exit instead of a successor.
    pub unsupported_exit: Option<UnsupportedExit>,
}

/// A block of the rephrase or the register-virtualization pass. The kind of every
/// instruction says who owns it (user semantics, a reg-virt helper, a budget check,
/// a dispatch template word, ...).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PassBlock {
    pub index: usize,
    pub start_pc: u64,
    pub end_pc: u64,
    pub prev: Vec<u64>,
    pub next: Vec<u64>,
    pub insns: Vec<RephrasedInsn>,
    /// Out-of-line exit groups (fault and budget stubs), laid out after every body.
    pub cold: Vec<RephrasedInsn>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LayoutRegion {
    Prologue,
    Epilogue,
    Body,
    Cold,
}

/// One word of the laid-out fragment, as translated (a link slot is a `nop` here
/// whatever the cache later patched into it).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LayoutWord {
    pub offset: usize,
    pub word: u32,
    pub insn: A64Insn,
    /// `None` for the prologue and epilogue.
    pub kind: Option<RephrasedInsnKind>,
    pub ori_pc: Option<u64>,
    pub region: LayoutRegion,
    /// The virtualized-pass instruction this word is (the same instruction, with
    /// branch offsets resolved by the layout).
    pub source: Option<InsnPos>,
}

/// Everything a request produced. Pass outputs that were not reached (the request
/// was rejected earlier) are empty.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TranslationRecord {
    pub index: usize,
    /// Ticks executed when the request ran.
    pub t: u64,
    pub entry_pc: u64,
    pub trigger: Trigger,
    /// The `SVC` (`SvcResume`) or branch (`ExitTarget`) whose hit made the pc hot.
    pub source_pc: u64,
    /// Pass 1: the instructions of the reachable CFG, in block order.
    pub decoded: Vec<IrInsn>,
    pub cfg: Vec<CfgBlockRecord>,
    /// Pass 2 and 3, per block in layout order.
    pub rephrased: Vec<PassBlock>,
    pub virtualized: Vec<PassBlock>,
    /// Pass 4: the whole fragment.
    pub layout: Vec<LayoutWord>,
    pub entry_offset: usize,
    /// Body map by original pc (every original instruction's first word).
    pub vlabels: Vec<(u64, usize)>,
    /// Entry labels (A20): `entry_pc` and every block start; the labels the cache publishes.
    pub entry_labels: Vec<(u64, usize)>,
    pub fault_sites: Vec<FaultSite>,
    /// A16 link slots: byte offset of the `nop` and the pc its `BL` targets.
    pub link_sites: Vec<(usize, u64)>,
    /// `None`: the request never reached the verifier.
    pub verdict: Option<Verdict>,
    /// Exactly one of the two is `Some` in a finished record: the code cache fragment
    /// the request installed, or why it installed nothing.
    pub installed: Option<usize>,
    pub rejection: Option<Rejection>,
}

impl TranslationRecord {
    pub fn word_at(&self, offset: usize) -> Option<&LayoutWord> {
        self.layout.get(offset / 4).filter(|word| word.offset == offset)
    }

    /// The decoded instruction at original pc `pc`.
    pub fn decoded_at(&self, pc: u64) -> Option<usize> {
        self.decoded.iter().position(|insn| insn.pc == pc)
    }

    /// The CFG block holding original pc `pc`.
    pub fn cfg_block_for(&self, pc: u64) -> Option<usize> {
        self.cfg
            .iter()
            .position(|block| block.start_pc <= pc && pc < block.end_pc)
    }

    /// Every instruction of the rephrase pass that carries original pc `pc`.
    pub fn rephrased_for(&self, pc: u64) -> Vec<InsnPos> {
        positions_for(&self.rephrased, pc)
    }

    /// The offsets of every word of the fragment that carries original pc `pc`, in
    /// layout order (bodies, then cold groups).
    pub fn offsets_for(&self, pc: u64) -> Vec<usize> {
        self.layout
            .iter()
            .filter(|word| word.ori_pc == Some(pc))
            .map(|word| word.offset)
            .collect()
    }
}

fn positions_for(blocks: &[PassBlock], pc: u64) -> Vec<InsnPos> {
    let mut positions = Vec::new();
    for block in blocks {
        for (cold, insns) in [(false, &block.insns), (true, &block.cold)] {
            for (index, insn) in insns.iter().enumerate() {
                if insn.ori_pc == pc {
                    positions.push(InsnPos {
                        block: block.index,
                        index,
                        cold,
                    });
                }
            }
        }
    }
    positions
}

fn pass_blocks(program: &RephrasedProgram) -> Vec<PassBlock> {
    program
        .iter()
        .enumerate()
        .map(|(index, block)| PassBlock {
            index,
            start_pc: block.start_addr,
            end_pc: block.end_addr,
            prev: block.prev.iter().copied().collect(),
            next: block.next.iter().copied().collect(),
            insns: block.insns.iter().copied().collect(),
            cold: block.cold.iter().copied().collect(),
        })
        .collect()
}

/// The layout origin of every word of `layout_program(program)`: the wrapper words
/// (no origin), then each block's body in layout order, then every block's cold group
/// in the same order. Must agree with `layout_program`; `translate` checks the length
/// and the recorder compares the words with the installed fragment.
fn layout_origins(program: &RephrasedProgram) -> Result<Vec<LayoutOrigin>, String> {
    let wrapper = (PROLOGUE_LEN_BYTES + EPILOGUE_LEN_BYTES) / 4;
    let mut origins = Vec::new();
    for word in 0..wrapper {
        let region = if word * 4 < PROLOGUE_LEN_BYTES {
            LayoutRegion::Prologue
        } else {
            LayoutRegion::Epilogue
        };
        origins.push(LayoutOrigin {
            kind: None,
            ori_pc: None,
            region,
            source: None,
        });
    }
    let order = layout_block_order(program.iter().map(|block| block.start_addr))
        .map_err(|err| format!("layout order: {err:?}"))?;
    for cold in [false, true] {
        for &block_index in order.iter() {
            let block = &program[block_index];
            let insns = if cold { &block.cold } else { &block.insns };
            for (index, insn) in insns.iter().enumerate() {
                origins.push(LayoutOrigin {
                    kind: Some(insn.kind),
                    ori_pc: Some(insn.ori_pc),
                    region: if cold {
                        LayoutRegion::Cold
                    } else {
                        LayoutRegion::Body
                    },
                    source: Some(InsnPos {
                        block: block_index,
                        index,
                        cold,
                    }),
                });
            }
        }
    }
    Ok(origins)
}

struct LayoutOrigin {
    kind: Option<RephrasedInsnKind>,
    ori_pc: Option<u64>,
    region: LayoutRegion,
    source: Option<InsnPos>,
}

/// Runs the pipeline for `entry_pc` over `code` one pass at a time. `rejection` of the
/// result says why a request installs nothing; the caller sets `installed` after the
/// cache installed the fragment (`check_installed` first).
pub(crate) fn translate(
    index: usize,
    t: u64,
    entry_pc: u64,
    trigger: Trigger,
    source_pc: u64,
    code: &MockCodeProvider<Vec<u8>>,
) -> TranslationRecord {
    let mut record = TranslationRecord {
        index,
        t,
        entry_pc,
        trigger,
        source_pc,
        decoded: Vec::new(),
        cfg: Vec::new(),
        rephrased: Vec::new(),
        virtualized: Vec::new(),
        layout: Vec::new(),
        entry_offset: 0,
        vlabels: Vec::new(),
        entry_labels: Vec::new(),
        fault_sites: Vec::new(),
        link_sites: Vec::new(),
        verdict: None,
        installed: None,
        rejection: None,
    };
    record.rejection = run_passes(&mut record, code).err();
    record
}

fn run_passes(
    record: &mut TranslationRecord,
    code: &MockCodeProvider<Vec<u8>>,
) -> Result<(), Rejection> {
    let compile = |pass| move |message: String| Rejection::Compile { pass, message };
    let request = TranslationRequest {
        entry_pc: record.entry_pc,
        trigger: match record.trigger {
            Trigger::SvcResume => TranslationTrigger::HotSvc,
            Trigger::ExitTarget => TranslationTrigger::BranchDiscovery {
                source_pc: record.source_pc,
            },
        },
        regs: None,
    };

    // The kernel refuses a translation whose entry word is itself unsupported.
    match admit_at(code, record.entry_pc).map_err(|err| compile(Pass::Cfg)(err.to_string()))? {
        Ok(_) => {}
        Err(exit) => return Err(Rejection::EntryUnsupported(exit)),
    }

    let cfg = build_cfg(&request, code).map_err(|err| compile(Pass::Cfg)(err.to_string()))?;
    for (index, block) in cfg.blocks.iter().enumerate() {
        let first = record.decoded.len();
        record.decoded.extend(block.insns.iter().copied());
        record.cfg.push(CfgBlockRecord {
            index,
            start_pc: block.start_addr,
            end_pc: block.end_addr,
            prev: block.prev.iter().copied().collect(),
            next: block.next.iter().copied().collect(),
            insns: first..record.decoded.len(),
            unsupported_exit: block.unsupported_exit,
        });
    }

    let rephrased = rephrase(cfg).map_err(|err| compile(Pass::Rephrase)(format!("{err:?}")))?;
    record.rephrased = pass_blocks(&rephrased);

    let virtualized = virtualize_registers(rephrased)
        .map_err(|err| compile(Pass::RegVirt)(format!("{err:?}")))?;
    record.virtualized = pass_blocks(&virtualized);
    let origins = layout_origins(&virtualized).map_err(compile(Pass::Layout))?;

    let fragment =
        layout_program(virtualized).map_err(|err| compile(Pass::Layout)(err.to_string()))?;
    if fragment.insns.len() != origins.len() {
        return Err(compile(Pass::Layout)(format!(
            "the layout has {} words but its pass outputs account for {}",
            fragment.insns.len(),
            origins.len()
        )));
    }
    record.entry_offset = fragment.entry_offset;
    record.vlabels = fragment.vlabels.iter().copied().collect();
    record.entry_labels = fragment.entry_labels.iter().copied().collect();
    record.fault_sites = fragment.fault_sites.iter().copied().collect();
    record.link_sites = fragment.link_sites.iter().copied().collect();
    for (index, (insn, origin)) in fragment.insns.iter().zip(&origins).enumerate() {
        let word = insn
            .encode()
            .map_err(|err| Rejection::Encode(format!("{}: {err:?}", insn.key())))?;
        record.layout.push(LayoutWord {
            offset: index * 4,
            word,
            insn: *insn,
            kind: origin.kind,
            ori_pc: origin.ori_pc,
            region: origin.region,
            source: origin.source,
        });
    }

    let encoded = encode_fragment(&fragment).map_err(Rejection::Encode)?;
    match verify_encoded_fragment(&fragment, &encoded) {
        Ok(ok) => {
            record.verdict = Some(Verdict::Accepted {
                uses_fpsimd: ok.uses_fpsimd,
            });
            Ok(())
        }
        Err(err) => {
            record.verdict = Some(Verdict::Rejected(err));
            Err(Rejection::Verify(err))
        }
    }
}

/// The record must be exactly the fragment the cache installed: every word (a link
/// slot may hold `nop` or the `b` the cache patched into it), the labels, the entry,
/// the fault and link tables and the verifier's `uses_fpsimd`.
pub(crate) fn check_installed(
    record: &TranslationRecord,
    installed: &CachedFragment,
) -> Result<(), String> {
    let fragment = &installed.fragment;
    if record.layout.len() != fragment.insns.len() {
        return Err(format!(
            "the record has {} words, the installed fragment {}",
            record.layout.len(),
            fragment.insns.len()
        ));
    }
    for word in &record.layout {
        let is_link_slot = record.link_sites.iter().any(|&(slot, _)| slot == word.offset);
        if is_link_slot {
            if word.word != LINK_NOP_WORD {
                return Err(format!(
                    "link slot {:#x} is {:#010x} in the record, not a nop",
                    word.offset, word.word
                ));
            }
            continue;
        }
        let bytes = installed
            .encoded
            .get(word.offset..word.offset + 4)
            .ok_or_else(|| format!("installed fragment has no word at {:#x}", word.offset))?;
        if bytes != word.word.to_le_bytes() {
            return Err(format!(
                "word at {:#x}: record {:#010x}, installed {:#010x}",
                word.offset,
                word.word,
                u32::from_le_bytes(bytes.try_into().expect("4 bytes"))
            ));
        }
    }
    let same = fragment.entry_offset == record.entry_offset
        && fragment.vlabels.iter().eq(record.vlabels.iter())
        && fragment.entry_labels.iter().eq(record.entry_labels.iter())
        && fragment.fault_sites.iter().eq(record.fault_sites.iter())
        && fragment.link_sites.iter().eq(record.link_sites.iter());
    if !same {
        return Err("entry offset, labels, fault sites or link sites differ".to_string());
    }
    match record.verdict {
        Some(Verdict::Accepted { uses_fpsimd }) if uses_fpsimd == installed.uses_fpsimd => Ok(()),
        other => Err(format!(
            "verdict {other:?} against installed uses_fpsimd = {}",
            installed.uses_fpsimd
        )),
    }
}
