//! The read-only query API of a recorded `Session`.

use std::collections::BTreeMap;
use std::fmt;

use crate::code_cache::Occupant;
use crate::model::MachineState;
use crate::shared::abi::{link_branch_word, LINK_NOP_WORD};
use crate::shared::trans::rephrase::RephrasedInsnKind;

use super::steps::apply_step;
use super::translation::{InsnPos, LayoutRegion};
use super::{Event, EventKind, Outcome, Session};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QueryError {
    /// `t` is past the last tick.
    TickOutOfRange { t: u64, ticks: u64 },
    /// No syscall `k` (1-based) in the run.
    SyscallOutOfRange { k: u64, syscalls: u64 },
}

impl fmt::Display for QueryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TickOutOfRange { t, ticks } => {
                write!(f, "tick {t} is past the last tick ({ticks})")
            }
            Self::SyscallOutOfRange { k, syscalls } => {
                write!(f, "syscall {k} is not in the run ({syscalls} syscalls)")
            }
        }
    }
}

impl std::error::Error for QueryError {}

/// The label a link slot is patched to jump to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LinkTarget {
    pub fragment: usize,
    pub pc: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FragmentView {
    pub fragment: usize,
    pub entry_pc: u64,
    pub translation: usize,
    pub retired: bool,
}

/// One link slot (A16) of a fragment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LinkView {
    pub fragment: usize,
    pub slot_offset: usize,
    /// The pc the slot's `BL` targets.
    pub target_pc: u64,
    /// `Some`: the slot holds `b <the label>`; `None`: a `nop`, waiting for a label.
    pub linked_to: Option<LinkTarget>,
    /// The word in the slot.
    pub word: u32,
}

/// The code cache after some tick.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CacheView {
    pub t: u64,
    /// Every fragment installed so far, by fragment index.
    pub fragments: Vec<FragmentView>,
    /// Slot index -> the record in it. Slots not listed are empty.
    pub table_all: BTreeMap<usize, Occupant>,
    pub table_nofp: BTreeMap<usize, Occupant>,
    /// Every link slot of the fragments installed so far.
    pub links: Vec<LinkView>,
}

/// Where a fragment word comes from, pass by pass.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Lineage {
    /// The instruction of the CFG pass at the word's original pc.
    pub decoded: Option<usize>,
    pub cfg_block: Option<usize>,
    /// Every instruction of the rephrase pass with the word's original pc (the group
    /// it was expanded from or with).
    pub rephrased: Vec<InsnPos>,
    /// The virtualized-pass instruction the word is.
    pub virtualized: Option<InsnPos>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Origin {
    pub translation: usize,
    /// Index into `TranslationRecord::layout` (`offset / 4`).
    pub layout_index: usize,
    /// `None` for the prologue and the epilogue.
    pub ori_pc: Option<u64>,
    pub kind: Option<RephrasedInsnKind>,
    pub region: LayoutRegion,
    pub lineage: Lineage,
}

impl Session {
    /// The KJIT world's state after `t` ticks: the latest checkpoint at or before `t`,
    /// with the steps after it replayed. `state_at(0)` is the initial state.
    pub fn state_at(&self, t: u64) -> Result<MachineState, QueryError> {
        if t > self.ticks() {
            return Err(QueryError::TickOutOfRange {
                t,
                ticks: self.ticks(),
            });
        }
        let every = self.config.limits.checkpoint_every;
        let checkpoint = t / every;
        let mut state = self.checkpoints[checkpoint as usize].clone();
        for tick in checkpoint * every + 1..=t {
            let step = self.steps.get(tick).expect("tick in range");
            apply_step(&mut state, &step);
        }
        Ok(state)
    }

    /// The code cache after `t` ticks, replayed from the cache events up to and
    /// including those with `Event::t == t`.
    pub fn cache_at(&self, t: u64) -> Result<CacheView, QueryError> {
        if t > self.ticks() {
            return Err(QueryError::TickOutOfRange {
                t,
                ticks: self.ticks(),
            });
        }
        let mut view = CacheView {
            t,
            fragments: Vec::new(),
            table_all: BTreeMap::new(),
            table_nofp: BTreeMap::new(),
            links: Vec::new(),
        };
        for event in self.events_between(0, t + 1) {
            match event.kind {
                EventKind::Installed {
                    fragment,
                    translation,
                } => {
                    assert_eq!(
                        view.fragments.len(),
                        fragment,
                        "fragments are installed in index order"
                    );
                    let record = &self.translations[translation];
                    view.fragments.push(FragmentView {
                        fragment,
                        entry_pc: record.entry_pc,
                        translation,
                        retired: false,
                    });
                    for &(slot_offset, target_pc) in &record.link_sites {
                        view.links.push(LinkView {
                            fragment,
                            slot_offset,
                            target_pc,
                            linked_to: None,
                            word: LINK_NOP_WORD,
                        });
                    }
                }
                EventKind::Published {
                    table,
                    slot,
                    pc,
                    fragment,
                    ..
                } => {
                    let tables = match table {
                        crate::code_cache::TableId::All => &mut view.table_all,
                        crate::code_cache::TableId::NoFp => &mut view.table_nofp,
                    };
                    tables.insert(slot, Occupant { pc, fragment });
                }
                EventKind::Linked {
                    fragment,
                    slot_offset,
                    target,
                } => {
                    let word = self.link_word(fragment, slot_offset, target);
                    let link = link_mut(&mut view.links, fragment, slot_offset);
                    link.linked_to = Some(target);
                    link.word = word;
                }
                EventKind::Restored {
                    fragment,
                    slot_offset,
                    ..
                } => {
                    let link = link_mut(&mut view.links, fragment, slot_offset);
                    link.linked_to = None;
                    link.word = LINK_NOP_WORD;
                }
                EventKind::Retired { fragment } => {
                    view.fragments[fragment].retired = true;
                    view.table_all.retain(|_, occupant| occupant.fragment != fragment);
                    view.table_nofp.retain(|_, occupant| occupant.fragment != fragment);
                }
                _ => {}
            }
        }
        Ok(view)
    }

    /// The `b` the cache patched into a link slot, from the final cache's addresses
    /// (fragments never move).
    fn link_word(&self, fragment: usize, slot_offset: usize, target: LinkTarget) -> u32 {
        let site = &self.cache.fragments[fragment];
        let host = {
            let target_fragment = &self.cache.fragments[target.fragment];
            let label = target_fragment
                .label_for_pc(target.pc)
                .expect("a link targets a label of the target fragment");
            target_fragment.host(label)
        };
        link_branch_word(site.base + slot_offset as u64, host)
            .expect("the cache linked this slot, so `b` reaches")
    }

    /// The events with `t0 <= t < t1`.
    pub fn events_between(&self, t0: u64, t1: u64) -> &[Event] {
        let start = self.events.partition_point(|event| event.t < t0);
        let end = self.events.partition_point(|event| event.t < t1);
        &self.events[start..end.max(start)]
    }

    /// Where the word of `fragment` at byte `offset` comes from; `None` for an
    /// unknown fragment or an offset past its end.
    pub fn origin(&self, fragment: usize, offset: usize) -> Option<Origin> {
        let translation = self.translation_of(fragment)?;
        let record = &self.translations[translation];
        let word = record.word_at(offset)?;
        let lineage = match word.ori_pc {
            Some(pc) => Lineage {
                decoded: record.decoded_at(pc),
                cfg_block: record.cfg_block_for(pc),
                rephrased: record.rephrased_for(pc),
                virtualized: word.source,
            },
            None => Lineage {
                decoded: None,
                cfg_block: None,
                rephrased: Vec::new(),
                virtualized: None,
            },
        };
        Some(Origin {
            translation,
            layout_index: offset / 4,
            ori_pc: word.ori_pc,
            kind: word.kind,
            region: word.region,
            lineage,
        })
    }

    /// The reverse of `origin`: the byte offsets of every word of `fragment` that
    /// carries original pc `ori_pc`, in layout order. Empty for an unknown fragment.
    pub fn words_for(&self, fragment: usize, ori_pc: u64) -> Vec<usize> {
        match self.translation_of(fragment) {
            Some(translation) => self.translations[translation].offsets_for(ori_pc),
            None => Vec::new(),
        }
    }

    /// The reference world's state at the `k`-th syscall (1-based). The recorder
    /// compared the worlds there and they agreed, so this is the KJIT state at that
    /// tick; at the syscall of a `Divergence` it is the reference's own, which differs.
    pub fn reference_at_syscall(&self, k: u64) -> Result<MachineState, QueryError> {
        if let Outcome::Divergence(divergence) = &self.outcome {
            if divergence.syscall == Some(k) {
                return Ok(divergence.reference.clone());
            }
        }
        let syscall = k
            .checked_sub(1)
            .and_then(|index| self.syscalls.get(index as usize))
            .ok_or(QueryError::SyscallOutOfRange {
                k,
                syscalls: self.syscalls.len() as u64,
            })?;
        self.state_at(syscall.t)
    }
}

fn link_mut(links: &mut [LinkView], fragment: usize, slot_offset: usize) -> &mut LinkView {
    links
        .iter_mut()
        .find(|link| link.fragment == fragment && link.slot_offset == slot_offset)
        .expect("a linked slot is a site of an installed fragment")
}
