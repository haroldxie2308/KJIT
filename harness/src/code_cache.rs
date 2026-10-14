//! The harness code cache: a mirror of the kernel runtime's fragment store
//! (docs/pipeline.md, "Dispatch tables (A11, kernel side)" and "Code cache and
//! cached runs (A11a)").
//!
//! - Fragments by entry pc (`by_entry`), each with its labels as records
//!   `{ u64 pc; u64 host }` (`IBTC_RECORD_*`): the verified entries of the fragment,
//!   `host` = the absolute address of the label's word in the code space.
//! - Two dispatch tables, `table_all` and `table_nofp` (`IBTC_TABLE_WORDS` slots each:
//!   the main part, slot `ibtc_slot_index(pc)`, then the victim part, slot
//!   `ibtc_victim_index(pc)`; A11c). A slot is 0 or a record address. `table_nofp`
//!   never holds a record of a `uses_fpsimd` fragment (`check_invariants`).
//! - Insert on resolution (`publish`; the stores are `ibtc_plan_publish`, the function
//!   the kernel runtime executes: an evicted main-slot record moves to its victim
//!   slot first); `retire` clears the fragment's main and victim slots that still
//!   hold its records, and its entry.
//! - The runtime decision for a fragment return (`decide`): continue at the
//!   resolved fragment's label, translate on a miss (the harness translates a
//!   branch exit's target at once, where the kernel's profiler learns it after a
//!   hit count: K3 "exit-target learning"), or stop. `MissPolicy::ReturnToUser` is
//!   the kernel's own decision instead (a miss returns to the target for the caller to
//!   profile; used by the session recorder); `Translate` is the default.
//! - An opt-in event log (`with_event_log`, `drain_events`) of every install, table
//!   store, link, restore and retire.
//!
//! - Direct BL links (A16, docs/pipeline.md "Direct BL links (A16)", the kernel side in
//!   "Direct BL links (A16, kernel side)"): every fragment's link slots are `nop`
//!   until a label of a live fragment translated for the slot's target satisfies the
//!   link condition (`try_link`); install links a fragment's sites and the pending
//!   sites its labels satisfy, retire restores the sites linked into it. The patch is
//!   made on the cache's own copy of the fragment (`fragment.insns`, `encoded`) and
//!   queued for a backend that holds another (`drain_code_patches`).
//!
//! The cache is pure bookkeeping over an address space it is told about
//! (`CacheLayout`): it never touches machine memory. Every change to a table or a
//! record is queued as an 8-byte `(address, value)` write (`drain_writes`), and
//! `image` lists the whole current content, so a backend (the interpreter's
//! `MachineState`, or the native runner's mappings) applies them in its own memory.

use std::collections::BTreeMap;

use crate::model::PAGE_SIZE;
use crate::runtime::URuntimeHalt;
use crate::shared::abi::{
    ibtc_lookup_slots, ibtc_plan_publish, link_branch_word, IbtcSource, RetStatus, LINK_NOP_WORD,
    IBTC_RECORD_BYTES,
    IBTC_RECORD_HOST_OFFSET, IBTC_RECORD_PC_OFFSET, IBTC_SLOT_BYTES, IBTC_TABLE_BYTES,
    IBTC_TABLE_WORDS,
};
use crate::shared::arm64::A64Insn;
use crate::shared::emit::layout::ExecutionFragment;
use crate::shared::trans::cfg::CfgError;
use crate::shared::trans::input::{TranslationRequest, TranslationTrigger};
use crate::shared::trans::translate::{compile_request, CompileError};
use crate::{encode_fragment, verify_encoded_fragment, MockCodeProvider};

/// Where the cache's memory lives in the backend's address space. The tables are
/// `IBTC_TABLE_BYTES` each; the record area holds `records_len / IBTC_RECORD_BYTES`
/// records.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CacheLayout {
    pub table_all: u64,
    pub table_nofp: u64,
    pub records: u64,
    pub records_len: usize,
}

impl CacheLayout {
    /// The cache's runtime-owned ranges (tables and record area).
    pub fn ranges(&self) -> [(u64, u64); 3] {
        [
            (self.table_all, self.table_all + IBTC_TABLE_BYTES as u64),
            (self.table_nofp, self.table_nofp + IBTC_TABLE_BYTES as u64),
            (self.records, self.records + self.records_len as u64),
        ]
    }
}

/// One verified entry of a fragment: the pc it was translated for, its offset in the
/// fragment and the address of its record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Label {
    pub pc: u64,
    pub offset: usize,
    pub record: u64,
}

/// One link slot (A16) of a fragment: the offset of its `nop` and the pc its `BL`
/// targets. Either `linked_to` a label (the slot holds `b <host of that label>`) or
/// pending (the slot is a `nop` and the site is in `CodeCache::pending`): exactly one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LinkSite {
    pub slot: usize,
    pub target_pc: u64,
    /// (fragment, label index) of the target label.
    pub linked_to: Option<(usize, usize)>,
}

/// One word of fragment code the cache patched (a link made or restored), for a
/// backend that holds its own copy of the code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CodePatch {
    pub fragment: usize,
    pub offset: usize,
    pub word: u32,
}

/// What the runtime does with a branch exit whose target no live fragment translates.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum MissPolicy {
    /// Translate the target at once and continue there (the differential suite, A11a).
    #[default]
    Translate,
    /// The kernel's chaining (docs/pipeline.md, K3 "Chaining rules"): a target the
    /// current fragment has no label for, and no fragment is translated for, returns to
    /// userspace at the target, where the caller profiles it. The chain budget bounds
    /// every branch exit, and an `SVC` exit always returns (the syscall runs, then the
    /// hook looks the resume pc up again).
    ReturnToUser,
}

/// One of the two dispatch tables.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TableId {
    All,
    NoFp,
}

/// The record in a table slot: the label of `fragment` translated for `pc`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Occupant {
    pub pc: u64,
    pub fragment: usize,
}

/// A change of the cache, queued like `drain_writes` when the log is on
/// (`with_event_log`) and read with `drain_events`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CacheEvent {
    Installed { fragment: usize, entry_pc: u64 },
    /// One table store of `publish`: `slot` of `table` now holds the record of `pc` in
    /// `fragment` (a moved record included: it lands in its victim slot), over
    /// `replaced`.
    Published {
        table: TableId,
        slot: usize,
        pc: u64,
        fragment: usize,
        replaced: Option<Occupant>,
    },
    /// Link slot `slot_offset` of `fragment` was patched `nop` -> `b` to the label of
    /// `target_pc` in `target_fragment` (A16).
    Linked {
        fragment: usize,
        slot_offset: usize,
        target_fragment: usize,
        target_pc: u64,
    },
    /// ... and back to `nop` because `target_fragment` was retired.
    Restored {
        fragment: usize,
        slot_offset: usize,
        target_fragment: usize,
        target_pc: u64,
    },
    /// `fragment` left the cache; every slot that held one of its records is clear.
    Retired { fragment: usize },
}

#[derive(Debug)]
pub struct CachedFragment {
    pub entry_pc: u64,
    pub fragment: ExecutionFragment,
    pub encoded: Vec<u8>,
    /// The verifier's `uses_fpsimd` (the kernel's value), or, for a fragment the
    /// caller installed without verifying (`install_unverified`), the translator's
    /// view.
    pub uses_fpsimd: bool,
    /// Address of offset 0 in the code space.
    pub base: u64,
    pub retired: bool,
    /// Sorted by pc.
    pub labels: Vec<Label>,
    /// The fragment's link slots, in `ExecutionFragment::link_sites` order.
    pub links: Vec<LinkSite>,
    /// The sites (fragment, link index) currently linked to one of this fragment's
    /// labels, own sites included.
    incoming: Vec<(usize, usize)>,
}

impl CachedFragment {
    pub fn label_for_pc(&self, pc: u64) -> Option<&Label> {
        self.labels
            .binary_search_by_key(&pc, |label| label.pc)
            .ok()
            .map(|index| &self.labels[index])
    }

    pub fn host(&self, label: &Label) -> u64 {
        self.base + label.offset as u64
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CacheStats {
    pub translations: u64,
    pub ibtc_insert: u64,
    /// A slot that held another record.
    pub ibtc_replace: u64,
    pub ibtc_clear: u64,
    /// A branch exit of a non-FP/SIMD run whose target resolved to an FP/SIMD
    /// fragment.
    pub ibtc_fpsimd_boundary: u64,
    /// A16: slots patched `nop` -> `b`, and restored `b` -> `nop` by a retire.
    pub link_made: u64,
    pub link_restored: u64,
    /// A site no candidate label could take: every class-eligible label out of `b`'s
    /// range, or only labels the class rule refuses (counted once per attempt).
    pub link_out_of_range: u64,
    pub link_class_refused: u64,
}

/// What the runtime does after a fragment returned.
#[derive(Debug, PartialEq, Eq)]
pub enum CacheAction {
    /// Call the fragment `fragment` (an index into `CodeCache::fragments`), entering
    /// its body at `offset`.
    ContinueAt { fragment: usize, offset: usize },
    Stop(URuntimeHalt),
}

/// Hands out the address of a new fragment's code: the interpreter's synthetic code
/// space, or a native mapping.
pub type FragmentLoader = Box<dyn FnMut(&CachedFragment) -> Result<u64, String>>;

pub struct CodeCache {
    layout: CacheLayout,
    /// The text new fragments are translated from; `None`: a cache that never
    /// translates (`single`).
    text: Option<MockCodeProvider<Vec<u8>>>,
    loader: FragmentLoader,
    pub fragments: Vec<CachedFragment>,
    by_entry: BTreeMap<u64, usize>,
    /// Record address per slot, 0 = empty. These are the values of the table words.
    slots_all: Vec<u64>,
    slots_nofp: Vec<u64>,
    /// Record number -> (fragment, label index), for the invariant check.
    record_owner: Vec<(usize, usize)>,
    writes: Vec<(u64, u64)>,
    /// A16: whether installs link at all (`without_links`), the sites not linked
    /// (their target pc -> (fragment, link index)), and the code words patched since
    /// the last `drain_code_patches`.
    linking: bool,
    pending: BTreeMap<u64, Vec<(usize, usize)>>,
    code_patches: Vec<CodePatch>,
    /// Fragment entries per run before the next `SVC` exit returns to userspace
    /// (the kernel's `chain_budget`, K3 "Chaining rules"); `None` never stops. Fixture
    /// text is not always a terminating program once branches are followed: an
    /// endless cycle passes the runtime at an SVC (a loop without one is bounded by
    /// the back-edge budget), so stopping there bounds the run, and the original is
    /// stopped before the same SVC.
    chain_budget: Option<usize>,
    run_entries: usize,
    miss_policy: MissPolicy,
    /// The fragment the run last entered through the runtime (`note_entry`): the
    /// kernel's `run`, whose labels a branch exit resolves against first
    /// (`MissPolicy::ReturnToUser`).
    entered: usize,
    /// A `decide` stopped the run because the chain budget was spent; cleared by
    /// `begin_run`.
    chain_capped: bool,
    /// `None`: events are not logged.
    events: Option<Vec<CacheEvent>>,
    pub stats: CacheStats,
}

impl CodeCache {
    pub fn new(
        layout: CacheLayout,
        text: Option<MockCodeProvider<Vec<u8>>>,
        loader: FragmentLoader,
    ) -> Self {
        Self {
            layout,
            text,
            loader,
            fragments: Vec::new(),
            by_entry: BTreeMap::new(),
            slots_all: vec![0; IBTC_TABLE_WORDS],
            slots_nofp: vec![0; IBTC_TABLE_WORDS],
            record_owner: Vec::new(),
            writes: Vec::new(),
            linking: true,
            pending: BTreeMap::new(),
            code_patches: Vec::new(),
            chain_budget: None,
            run_entries: 0,
            miss_policy: MissPolicy::Translate,
            entered: 0,
            chain_capped: false,
            events: None,
            stats: CacheStats::default(),
        }
    }

    /// A cache that never links (the single-fragment run of `URuntime::new`: its
    /// tables stay empty and every exit takes the runtime path).
    pub fn without_links(mut self) -> Self {
        self.linking = false;
        self
    }

    pub fn with_chain_budget(mut self, entries: usize) -> Self {
        self.chain_budget = Some(entries);
        self
    }

    pub fn with_miss_policy(mut self, policy: MissPolicy) -> Self {
        self.miss_policy = policy;
        self
    }

    /// Logs every change as a `CacheEvent` for `drain_events`. Off by default: a cache
    /// nobody drains would grow the log without bound.
    pub fn with_event_log(mut self) -> Self {
        self.events = Some(Vec::new());
        self
    }

    /// The events logged since the last call, oldest first. Panics without
    /// `with_event_log`.
    pub fn drain_events(&mut self) -> Vec<CacheEvent> {
        std::mem::take(
            self.events
                .as_mut()
                .expect("drain_events without with_event_log"),
        )
    }

    fn log(&mut self, event: CacheEvent) {
        if let Some(events) = self.events.as_mut() {
            events.push(event);
        }
    }

    /// A new run starts: its first entry counts against the chain budget.
    pub fn begin_run(&mut self) {
        self.run_entries = 1;
        self.chain_capped = false;
    }

    /// The runtime entered `fragment` (a run's first entry or a chained one).
    pub fn note_entry(&mut self, fragment: usize) {
        self.entered = fragment;
    }

    /// Whether the last `decide` returned to userspace because the chain budget was
    /// spent: the target is then not a miss to profile (K3 "Chaining rules").
    pub fn chain_capped(&self) -> bool {
        self.chain_capped
    }

    pub fn layout(&self) -> CacheLayout {
        self.layout
    }

    /// The table a run of a fragment with this `uses_fpsimd` dispatches through
    /// (docs/pipeline.md "Dispatch tables (A11, kernel side)", Run): a run of an
    /// FP/SIMD fragment, inside the bracket, may continue into any code; every other
    /// run only into non-FP/SIMD code.
    pub fn table_for(&self, uses_fpsimd: bool) -> u64 {
        if uses_fpsimd {
            self.layout.table_all
        } else {
            self.layout.table_nofp
        }
    }

    /// The fragment holding code address `pc` and the offset in it.
    pub fn locate(&self, pc: u64) -> Option<(usize, usize)> {
        self.fragments.iter().enumerate().find_map(|(index, frag)| {
            let offset = pc.checked_sub(frag.base)?;
            (offset < frag.fragment.len_bytes() as u64).then_some((index, offset as usize))
        })
    }

    /// The live fragment translated for `entry_pc`.
    pub fn fragment_for_entry(&self, entry_pc: u64) -> Option<usize> {
        self.by_entry.get(&entry_pc).copied()
    }

    /// Installs an already compiled, encoded and verified fragment.
    pub fn install(
        &mut self,
        entry_pc: u64,
        fragment: ExecutionFragment,
        encoded: Vec<u8>,
        uses_fpsimd: bool,
    ) -> Result<usize, String> {
        let index = self.fragments.len();
        let mut cached = CachedFragment {
            entry_pc,
            fragment,
            encoded,
            uses_fpsimd,
            base: 0,
            retired: false,
            labels: Vec::new(),
            links: Vec::new(),
            incoming: Vec::new(),
        };
        cached.base = (self.loader)(&cached)?;
        let mut labels = cached
            .fragment
            .entry_labels
            .iter()
            .map(|&(pc, offset)| (pc, offset))
            .collect::<Vec<_>>();
        labels.sort_unstable();
        for (pc, offset) in labels {
            let record_number = self.record_owner.len();
            let record = self.layout.records + (record_number * IBTC_RECORD_BYTES) as u64;
            if record + IBTC_RECORD_BYTES as u64 > self.layout.records + self.layout.records_len as u64
            {
                return Err("code cache record area is full".to_string());
            }
            self.record_owner.push((index, cached.labels.len()));
            let label = Label { pc, offset, record };
            self.writes.push((
                record + u64::from(IBTC_RECORD_PC_OFFSET),
                label.pc,
            ));
            self.writes.push((
                record + u64::from(IBTC_RECORD_HOST_OFFSET),
                cached.host(&label),
            ));
            cached.labels.push(label);
        }
        if self.by_entry.insert(entry_pc, index).is_some() {
            return Err(format!(
                "a live fragment for entry {entry_pc:#x} is already installed"
            ));
        }
        self.fragments.push(cached);
        self.log(CacheEvent::Installed {
            fragment: index,
            entry_pc,
        });
        if self.linking {
            self.link_install(index);
        }
        Ok(index)
    }

    /// Install of fragment `index` (A16): its sites are pending, then each is linked
    /// if a label satisfies the link condition; then every other fragment's pending
    /// site that one of its labels satisfies is linked.
    fn link_install(&mut self, index: usize) {
        let sites = self.fragments[index]
            .fragment
            .link_sites
            .iter()
            .map(|&(slot, target_pc)| LinkSite {
                slot,
                target_pc,
                linked_to: None,
            })
            .collect::<Vec<_>>();
        self.fragments[index].links = sites;
        for link in 0..self.fragments[index].links.len() {
            let target = self.fragments[index].links[link].target_pc;
            self.pending.entry(target).or_default().push((index, link));
        }
        for link in 0..self.fragments[index].links.len() {
            let target = self.fragments[index].links[link].target_pc;
            let candidates = self.labels_for(target);
            self.try_link(index, link, &candidates);
        }
        for label in 0..self.fragments[index].labels.len() {
            let pc = self.fragments[index].labels[label].pc;
            let waiting = self.pending.get(&pc).cloned().unwrap_or_default();
            // The fragment's own sites were tried against all of its labels above.
            for (site_fragment, link) in waiting.into_iter().filter(|&(f, _)| f != index) {
                self.try_link(site_fragment, link, &[(index, label)]);
            }
        }
    }

    /// Every label of a live fragment for `pc` as (fragment, label index): the
    /// fragment translated for `pc` first.
    fn labels_for(&self, pc: u64) -> Vec<(usize, usize)> {
        let entry = self.by_entry.get(&pc).copied();
        entry
            .into_iter()
            .chain((0..self.fragments.len()).filter(|&fragment| Some(fragment) != entry))
            .filter_map(|fragment| {
                let frag = &self.fragments[fragment];
                if frag.retired {
                    return None;
                }
                let label = frag.labels.binary_search_by_key(&pc, |label| label.pc).ok()?;
                Some((fragment, label))
            })
            .collect()
    }

    /// Links site `link` of `fragment` to the first of `candidates` (labels for its
    /// target pc of live fragments) that the class rule allows and `b` reaches. With
    /// none, counts why. Returns whether it linked.
    fn try_link(&mut self, fragment: usize, link: usize, candidates: &[(usize, usize)]) -> bool {
        let site = self.fragments[fragment].links[link];
        debug_assert!(site.linked_to.is_none(), "only pending sites are tried");
        let slot_addr = self.fragments[fragment].base + site.slot as u64;
        let site_uses_fpsimd = self.fragments[fragment].uses_fpsimd;
        let (mut class_refused, mut out_of_range) = (false, false);
        for &(target_fragment, label) in candidates {
            let target = &self.fragments[target_fragment];
            debug_assert!(!target.retired && target.labels[label].pc == site.target_pc);
            // A run outside the FP/SIMD bracket never reaches FP/SIMD code.
            if !site_uses_fpsimd && target.uses_fpsimd {
                class_refused = true;
                continue;
            }
            match link_branch_word(slot_addr, target.host(&target.labels[label])) {
                Some(word) => {
                    self.patch_code(fragment, site.slot, word);
                    self.fragments[fragment].links[link].linked_to = Some((target_fragment, label));
                    if let Some(waiting) = self.pending.get_mut(&site.target_pc) {
                        waiting.retain(|&entry| entry != (fragment, link));
                        if waiting.is_empty() {
                            self.pending.remove(&site.target_pc);
                        }
                    }
                    self.fragments[target_fragment].incoming.push((fragment, link));
                    self.stats.link_made += 1;
                    self.log(CacheEvent::Linked {
                        fragment,
                        slot_offset: site.slot,
                        target_fragment,
                        target_pc: site.target_pc,
                    });
                    return true;
                }
                None => out_of_range = true,
            }
        }
        self.stats.link_class_refused += u64::from(class_refused);
        self.stats.link_out_of_range += u64::from(out_of_range);
        false
    }

    /// Restores a linked site to `nop` and back to pending.
    fn restore_link(&mut self, fragment: usize, link: usize) {
        let site = self.fragments[fragment].links[link];
        let (target_fragment, _) = site.linked_to.expect("only linked sites are restored");
        self.patch_code(fragment, site.slot, LINK_NOP_WORD);
        self.fragments[fragment].links[link].linked_to = None;
        self.pending
            .entry(site.target_pc)
            .or_default()
            .push((fragment, link));
        self.stats.link_restored += 1;
        self.log(CacheEvent::Restored {
            fragment,
            slot_offset: site.slot,
            target_fragment,
            target_pc: site.target_pc,
        });
    }

    /// Writes `word` at `offset` of the cache's copy of the fragment and queues it
    /// for a backend with another copy.
    fn patch_code(&mut self, fragment: usize, offset: usize, word: u32) {
        let frag = &mut self.fragments[fragment];
        frag.fragment.insns[offset / 4] =
            A64Insn::decode(word).expect("a link slot word is a `nop` or a `b`");
        // A cache of fragments installed without their bytes (`URuntime::new`) has none.
        if let Some(bytes) = frag.encoded.get_mut(offset..offset + 4) {
            bytes.copy_from_slice(&word.to_le_bytes());
        }
        self.code_patches.push(CodePatch {
            fragment,
            offset,
            word,
        });
    }

    /// The code words patched since the last call, oldest first.
    pub fn drain_code_patches(&mut self) -> Vec<CodePatch> {
        std::mem::take(&mut self.code_patches)
    }

    /// Translates, encodes, verifies and installs the fragment for `entry_pc`
    /// (`BranchDiscovery` from `source_pc`). `Ok(None)`: the entry is not readable
    /// text, which has no fragment.
    pub fn translate(&mut self, entry_pc: u64, source_pc: u64) -> Result<Option<usize>, String> {
        let text = self
            .text
            .as_ref()
            .ok_or("this code cache has no text to translate from")?;
        let request = TranslationRequest {
            entry_pc,
            trigger: TranslationTrigger::BranchDiscovery { source_pc },
            regs: None,
        };
        let fragment = match compile_request(&request, text) {
            Ok(fragment) => fragment,
            Err(CompileError::Cfg(CfgError::CodeRead(_))) => return Ok(None),
            Err(err) => return Err(format!("translating {entry_pc:#x}: {err}")),
        };
        let encoded = encode_fragment(&fragment)?;
        let verified = verify_encoded_fragment(&fragment, &encoded)
            .map_err(|err| format!("verifier rejected the fragment for {entry_pc:#x}: {err:?}"))?;
        self.stats.translations += 1;
        self.install(entry_pc, fragment, encoded, verified.uses_fpsimd)
            .map(Some)
    }

    /// Publishes the label of `fragment` for `pc` (insert on resolution): into
    /// `table_all`, and into `table_nofp` unless the fragment uses FP/SIMD. A
    /// retired fragment is never published.
    pub fn publish(&mut self, fragment: usize, pc: u64) -> Result<(), String> {
        let frag = &self.fragments[fragment];
        if frag.retired {
            return Err(format!("publishing a record of retired fragment {fragment}"));
        }
        let label = *frag
            .label_for_pc(pc)
            .ok_or_else(|| format!("fragment {fragment} has no label for pc {pc:#x}"))?;
        let uses_fpsimd = frag.uses_fpsimd;
        self.publish_into(true, label.record, pc);
        if !uses_fpsimd {
            self.publish_into(false, label.record, pc);
        }
        Ok(())
    }

    /// The pc of the record `record` (0: no record).
    fn record_pc(&self, record: u64) -> Option<u64> {
        self.occupant(record).map(|occupant| occupant.pc)
    }

    /// Applies the shared publish plan (`ibtc_plan_publish`) for `pc` to `table_all`
    /// (`all`) or `table_nofp`, store by store in the planned order.
    fn publish_into(&mut self, all: bool, new_record: u64, pc: u64) {
        let plan = {
            let slots = if all { &self.slots_all } else { &self.slots_nofp };
            ibtc_plan_publish(pc, &|slot| self.record_pc(slots[slot]))
        };
        for store in plan.stores() {
            let slots = if all { &self.slots_all } else { &self.slots_nofp };
            let value = match store.src {
                IbtcSource::New => new_record,
                IbtcSource::Slot(slot) => slots[slot],
            };
            self.set_slot(all, store.dst, value);
        }
    }

    /// The label a record belongs to.
    fn occupant(&self, record: u64) -> Option<Occupant> {
        if record == 0 {
            return None;
        }
        let number = ((record - self.layout.records) / IBTC_RECORD_BYTES as u64) as usize;
        let (fragment, label) = self.record_owner[number];
        Some(Occupant {
            pc: self.fragments[fragment].labels[label].pc,
            fragment,
        })
    }

    fn set_slot(&mut self, all: bool, slot: usize, record: u64) {
        let previous = if all {
            self.slots_all[slot]
        } else {
            self.slots_nofp[slot]
        };
        if previous == record {
            return;
        }
        let replaced = self.occupant(previous);
        let stored = self
            .occupant(record)
            .expect("a publish store writes a record, never 0");
        let (slots, table) = if all {
            (&mut self.slots_all, self.layout.table_all)
        } else {
            (&mut self.slots_nofp, self.layout.table_nofp)
        };
        self.stats.ibtc_insert += 1;
        self.stats.ibtc_replace += u64::from(previous != 0);
        slots[slot] = record;
        self.writes
            .push((table + slot as u64 * u64::from(IBTC_SLOT_BYTES), record));
        self.log(CacheEvent::Published {
            table: if all { TableId::All } else { TableId::NoFp },
            slot,
            pc: stored.pc,
            fragment: stored.fragment,
            replaced,
        });
    }

    /// Retires a fragment: clears every table slot that points at one of its
    /// labels, and its entry. Its code stays mapped (the kernel frees it after a
    /// grace period; the harness never frees).
    pub fn retire(&mut self, fragment: usize) {
        // A16: every site linked into the fragment goes back to `nop` and pending,
        // then the fragment's own sites leave pending and their targets' incoming
        // lists. Before the fragment is marked retired.
        for (site_fragment, link) in std::mem::take(&mut self.fragments[fragment].incoming) {
            self.restore_link(site_fragment, link);
        }
        for link in 0..self.fragments[fragment].links.len() {
            let site = self.fragments[fragment].links[link];
            match site.linked_to {
                Some((target_fragment, _)) => self.fragments[target_fragment]
                    .incoming
                    .retain(|&entry| entry != (fragment, link)),
                None => {
                    if let Some(waiting) = self.pending.get_mut(&site.target_pc) {
                        waiting.retain(|&entry| entry != (fragment, link));
                        if waiting.is_empty() {
                            self.pending.remove(&site.target_pc);
                        }
                    }
                }
            }
        }
        let frag = &mut self.fragments[fragment];
        frag.retired = true;
        if self.by_entry.get(&frag.entry_pc) == Some(&fragment) {
            self.by_entry.remove(&frag.entry_pc);
        }
        for label in frag.labels.clone() {
            for slot in ibtc_lookup_slots(label.pc) {
                for all in [true, false] {
                    let (slots, table) = if all {
                        (&mut self.slots_all, self.layout.table_all)
                    } else {
                        (&mut self.slots_nofp, self.layout.table_nofp)
                    };
                    if slots[slot] == label.record {
                        slots[slot] = 0;
                        self.stats.ibtc_clear += 1;
                        self.writes
                            .push((table + slot as u64 * u64::from(IBTC_SLOT_BYTES), 0));
                    }
                }
            }
        }
        self.log(CacheEvent::Retired { fragment });
    }

    /// The kernel's table invariant: every non-zero slot (main or victim part) points
    /// at a label of a non-retired fragment, at that label's pc's main or victim
    /// index, and `table_nofp` never points into an FP/SIMD fragment.
    pub fn check_invariants(&self) -> Result<(), String> {
        for (name, slots, nofp) in [
            ("table_all", &self.slots_all, false),
            ("table_nofp", &self.slots_nofp, true),
        ] {
            for (slot, &record) in slots.iter().enumerate() {
                if record == 0 {
                    continue;
                }
                let number = usize::try_from((record - self.layout.records) / IBTC_RECORD_BYTES as u64)
                    .map_err(|_| format!("{name}[{slot}] = {record:#x} is not a record"))?;
                let (fragment, label) = *self
                    .record_owner
                    .get(number)
                    .ok_or_else(|| format!("{name}[{slot}] = {record:#x} is not a record"))?;
                let frag = &self.fragments[fragment];
                let label = frag.labels[label];
                if frag.retired {
                    return Err(format!("{name}[{slot}] points into retired fragment {fragment}"));
                }
                if !ibtc_lookup_slots(label.pc).contains(&slot) {
                    return Err(format!(
                        "{name}[{slot}] holds the record of pc {:#x}, which hashes elsewhere",
                        label.pc
                    ));
                }
                if nofp && frag.uses_fpsimd {
                    return Err(format!(
                        "table_nofp[{slot}] holds a record of FP/SIMD fragment {fragment} (pc {:#x})",
                        label.pc
                    ));
                }
            }
        }
        self.check_link_invariants()?;
        Ok(())
    }

    /// The link invariant (docs/pipeline.md, "Direct BL links (A16, kernel side)"):
    /// every site of a live fragment is pending with a `nop` in its slot, or linked,
    /// with `b <host of the label>` in its slot, to a label of a live fragment
    /// translated for exactly the site's target, never from a non-FP/SIMD fragment
    /// into an FP/SIMD one; the pending map and the incoming lists hold exactly those
    /// sites; the encoded bytes agree with the typed code.
    fn check_link_invariants(&self) -> Result<(), String> {
        let mut pending = 0;
        let mut incoming = 0;
        for (index, frag) in self.fragments.iter().enumerate() {
            if frag.retired {
                if !frag.incoming.is_empty() {
                    return Err(format!("retired fragment {index} still has incoming links"));
                }
                continue;
            }
            for (link, site) in frag.links.iter().enumerate() {
                let slot_addr = frag.base + site.slot as u64;
                let word = match frag.fragment.insns[site.slot / 4].encode() {
                    Ok(word) => word,
                    Err(err) => return Err(format!("fragment {index} slot {:#x}: {err:?}", site.slot)),
                };
                if let Some(bytes) = frag.encoded.get(site.slot..site.slot + 4) {
                    if bytes != word.to_le_bytes() {
                        return Err(format!(
                            "fragment {index} slot {:#x}: the encoded bytes differ from the code",
                            site.slot
                        ));
                    }
                }
                match site.linked_to {
                    None => {
                        pending += 1;
                        if word != LINK_NOP_WORD {
                            return Err(format!(
                                "pending site {index}/{link} (slot {:#x}) holds {word:#010x}, not a nop",
                                site.slot
                            ));
                        }
                        let listed = self
                            .pending
                            .get(&site.target_pc)
                            .is_some_and(|waiting| waiting.iter().filter(|&&e| e == (index, link)).count() == 1);
                        if !listed {
                            return Err(format!("pending site {index}/{link} is not in the pending map once"));
                        }
                    }
                    Some((target, label)) => {
                        incoming += 1;
                        let target_frag = &self.fragments[target];
                        let label = target_frag.labels[label];
                        if target_frag.retired {
                            return Err(format!("site {index}/{link} is linked into retired fragment {target}"));
                        }
                        if label.pc != site.target_pc {
                            return Err(format!(
                                "site {index}/{link} targets {:#x} but is linked to a label for {:#x}",
                                site.target_pc, label.pc
                            ));
                        }
                        if !frag.uses_fpsimd && target_frag.uses_fpsimd {
                            return Err(format!(
                                "site {index}/{link} of a non-FP/SIMD fragment is linked into FP/SIMD fragment {target}"
                            ));
                        }
                        if link_branch_word(slot_addr, target_frag.host(&label)) != Some(word) {
                            return Err(format!(
                                "site {index}/{link} (slot {:#x}) holds {word:#010x}, not `b` to {:#x}",
                                site.slot,
                                target_frag.host(&label)
                            ));
                        }
                        if target_frag.incoming.iter().filter(|&&e| e == (index, link)).count() != 1 {
                            return Err(format!("site {index}/{link} is not on fragment {target}'s incoming list once"));
                        }
                    }
                }
            }
        }
        let listed_pending = self.pending.values().map(Vec::len).sum::<usize>();
        let listed_incoming = self.fragments.iter().map(|frag| frag.incoming.len()).sum::<usize>();
        if listed_pending != pending || listed_incoming != incoming {
            return Err(format!(
                "pending map has {listed_pending} sites for {pending} pending, incoming lists {listed_incoming} for {incoming} linked"
            ));
        }
        Ok(())
    }

    /// What the dispatch template finds for `pc` in `table_all` (`all`) or `table_nofp`:
    /// the fragment of the main slot's record if it is `pc`'s, else of the victim
    /// slot's if it is, else `None` (a miss).
    pub fn lookup(&self, all: bool, pc: u64) -> Option<usize> {
        let slots = if all { &self.slots_all } else { &self.slots_nofp };
        ibtc_lookup_slots(pc).into_iter().find_map(|slot| {
            let record = slots[slot];
            (self.record_pc(record) == Some(pc)).then(|| {
                let number = ((record - self.layout.records) / IBTC_RECORD_BYTES as u64) as usize;
                self.record_owner[number].0
            })
        })
    }

    /// The pc of the record in table word `slot` of `table_all` / `table_nofp`.
    pub fn resident_pc(&self, all: bool, slot: usize) -> Option<u64> {
        let slots = if all { &self.slots_all } else { &self.slots_nofp };
        self.record_pc(slots[slot])
    }

    /// The queued memory writes, oldest first.
    pub fn drain_writes(&mut self) -> Vec<(u64, u64)> {
        std::mem::take(&mut self.writes)
    }

    /// The whole current content: every record's words and every non-zero slot.
    /// Applying it to zeroed memory reproduces the cache's memory (the queued writes
    /// are subsumed, so a backend that applies `image` discards them).
    pub fn image(&mut self) -> Vec<(u64, u64)> {
        self.writes.clear();
        let mut image = Vec::new();
        for frag in self.fragments.iter() {
            for label in &frag.labels {
                image.push((label.record + u64::from(IBTC_RECORD_PC_OFFSET), label.pc));
                image.push((
                    label.record + u64::from(IBTC_RECORD_HOST_OFFSET),
                    frag.host(label),
                ));
            }
        }
        for (slots, table) in [
            (&self.slots_all, self.layout.table_all),
            (&self.slots_nofp, self.layout.table_nofp),
        ] {
            for (slot, &record) in slots.iter().enumerate() {
                if record != 0 {
                    image.push((table + slot as u64 * u64::from(IBTC_SLOT_BYTES), record));
                }
            }
        }
        image
    }

    /// Finds a live label for `pc`: the fragment translated for exactly `pc` first,
    /// else the first live fragment holding a label for it.
    fn resolve(&self, pc: u64) -> Option<(usize, usize)> {
        if let Some(&fragment) = self.by_entry.get(&pc) {
            let label = self.fragments[fragment].label_for_pc(pc)?;
            return Some((fragment, label.offset));
        }
        self.fragments
            .iter()
            .enumerate()
            .filter(|(_, frag)| !frag.retired)
            .find_map(|(index, frag)| Some((index, frag.label_for_pc(pc)?.offset)))
    }

    /// The runtime's decision after a fragment returned through its epilogue
    /// (`run_fpsimd`: the entered fragment uses FP/SIMD). Mirrors the kernel's
    /// chaining: a branch exit resolves its target to a live fragment's label and
    /// publishes it. On a miss the harness translates the target (`RET` targets too:
    /// a return point is never a fragment entry until it is learned, so without this
    /// no `RET` site could ever hit). A target that is not readable text has no
    /// fragment: userspace fetches (and faults) there itself, which is what an
    /// `Unsupported` exit at the target does, and what the following original run
    /// halts on.
    pub fn decide(
        &mut self,
        run_fpsimd: bool,
        raw_status: u64,
        param0: u64,
        param1: u64,
    ) -> Result<CacheAction, String> {
        let status = RetStatus::from_reg(raw_status);
        let userspace = |status: RetStatus, target_pc: u64| {
            CacheAction::Stop(URuntimeHalt::ReturnedToUserspace { status, target_pc })
        };
        match status {
            // The kernel runs the syscall and calls the hook again at the resume pc,
            // which looks up and starts a new chain: the session models that, not
            // this run.
            RetStatus::Svc if self.miss_policy == MissPolicy::ReturnToUser => {
                Ok(userspace(status, param1))
            }
            RetStatus::Svc => match self.resolve(param1) {
                Some(_) if self.chain_budget.is_some_and(|budget| self.run_entries >= budget) => {
                    Ok(userspace(status, param1))
                }
                Some((fragment, offset)) => {
                    self.run_entries += 1;
                    Ok(CacheAction::ContinueAt { fragment, offset })
                }
                None => Ok(userspace(status, param1)),
            },
            RetStatus::Bl | RetStatus::Blr | RetStatus::Br | RetStatus::Ret
                if self.miss_policy == MissPolicy::ReturnToUser =>
            {
                self.decide_return_to_user(run_fpsimd, status, param0)
            }
            RetStatus::Bl | RetStatus::Blr | RetStatus::Br | RetStatus::Ret => {
                let target = param0;
                let mut resolved = self.resolve(target);
                if resolved.is_none() {
                    let source_pc = param1.wrapping_sub(4);
                    match self.translate(target, source_pc)? {
                        Some(fragment) => {
                            let offset = self.fragments[fragment]
                                .label_for_pc(target)
                                .ok_or("a fresh fragment has no label for its own entry")?
                                .offset;
                            resolved = Some((fragment, offset));
                        }
                        None => return Ok(userspace(RetStatus::Unsupported, target)),
                    }
                }
                let Some((fragment, offset)) = resolved else {
                    unreachable!("a miss either translated the target or returned above");
                };
                if self.fragments[fragment].uses_fpsimd && !run_fpsimd {
                    self.stats.ibtc_fpsimd_boundary += 1;
                }
                self.publish(fragment, target)?;
                self.run_entries += 1;
                Ok(CacheAction::ContinueAt { fragment, offset })
            }
            // Resuming at this pc would re-enter the same exit; userspace runs it.
            RetStatus::Unsupported | RetStatus::Mem | RetStatus::Budget => {
                Ok(userspace(status, param1))
            }
            RetStatus::Invalid(_) => Ok(CacheAction::Stop(URuntimeHalt::InvalidReturnStatus {
                raw: raw_status,
            })),
            RetStatus::Debug => Ok(CacheAction::Stop(URuntimeHalt::UnsupportedRuntimeExit {
                status,
            })),
        }
    }
}

impl CodeCache {
    /// A branch exit under `MissPolicy::ReturnToUser`, as the kernel's `run_chain`
    /// decides it (runtime/exec.rs): past the chain budget, return to the target (the
    /// target is not profiled, see `chain_capped`); else continue at the label of the
    /// target in the fragment the run entered, else in the fragment translated for
    /// exactly the target, publishing the label; else return to the target, a miss
    /// the caller profiles.
    fn decide_return_to_user(
        &mut self,
        run_fpsimd: bool,
        status: RetStatus,
        target: u64,
    ) -> Result<CacheAction, String> {
        let userspace =
            CacheAction::Stop(URuntimeHalt::ReturnedToUserspace { status, target_pc: target });
        if self.chain_budget.is_some_and(|budget| self.run_entries >= budget) {
            self.chain_capped = true;
            return Ok(userspace);
        }
        let entered = &self.fragments[self.entered];
        let own = (!entered.retired)
            .then(|| entered.label_for_pc(target))
            .flatten()
            .map(|label| (self.entered, label.offset));
        let resolved = own.or_else(|| {
            let fragment = *self.by_entry.get(&target)?;
            let label = self.fragments[fragment].label_for_pc(target)?;
            Some((fragment, label.offset))
        });
        let Some((fragment, offset)) = resolved else {
            return Ok(userspace);
        };
        if self.fragments[fragment].uses_fpsimd && !run_fpsimd {
            self.stats.ibtc_fpsimd_boundary += 1;
        }
        self.publish(fragment, target)?;
        self.run_entries += 1;
        Ok(CacheAction::ContinueAt { fragment, offset })
    }
}

impl std::fmt::Debug for CodeCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CodeCache")
            .field("layout", &self.layout)
            .field("fragments", &self.fragments.len())
            .field("stats", &self.stats)
            .finish()
    }
}

/// The interpreter's synthetic code space: fragments are laid out one after another
/// from `first`, each page-aligned with a guard page, so a branch off the end of one
/// never lands in the next.
pub fn synthetic_loader(first: u64) -> FragmentLoader {
    let mut next = first;
    Box::new(move |frag| {
        let base = next;
        let pages = (frag.fragment.len_bytes() as u64 + PAGE_SIZE - 1) / PAGE_SIZE + 1;
        next += pages * PAGE_SIZE;
        Ok(base)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::DEFAULT_CACHE_LAYOUT;
    use crate::shared::abi::{ibtc_slot_index, ibtc_victim_index};
    use crate::shared::arm64::ergo::{mem_off, scaled_uimm, sp, x};
    use crate::shared::arm64::A64Insn;

    const TEXT_BASE: u64 = 0x1000;

    fn word(insn: A64Insn) -> [u8; 4] {
        insn.encode().unwrap().to_le_bytes()
    }

    fn ret() -> A64Insn {
        A64Insn::RetRet64rBranchReg { rn: x(30) }
    }

    /// `[ret]` at 0x1000, `[ldr q0, [sp]; ret]` at 0x2000 (FP/SIMD), `[ret]` at 0x5000:
    /// 0x1000 and 0x5000 are 0x4000 apart, so they share their main slot.
    fn cache() -> CodeCache {
        let mut text = vec![0u8; 0x4004];
        text[0..4].copy_from_slice(&word(ret()));
        text[0x1000..0x1004].copy_from_slice(&word(A64Insn::LdrImmFpsimdLdrQLdstPos {
            rt: 0,
            mem: mem_off(sp(), scaled_uimm(0, 12, 4)),
        }));
        text[0x1004..0x1008].copy_from_slice(&word(ret()));
        text[0x4000..0x4004].copy_from_slice(&word(ret()));
        CodeCache::new(
            DEFAULT_CACHE_LAYOUT,
            Some(MockCodeProvider::new(TEXT_BASE, text)),
            synthetic_loader(0x400000),
        )
    }

    #[test]
    fn aliasing_publishes_move_the_old_record_to_the_victim_part_and_retire_clears_both() {
        let mut cache = cache();
        let a = cache.translate(0x1000, 0).unwrap().unwrap();
        let b = cache.translate(0x5000, 0).unwrap().unwrap();
        assert_eq!(ibtc_slot_index(0x1000), ibtc_slot_index(0x5000));
        assert_ne!(ibtc_victim_index(0x1000), ibtc_victim_index(0x5000));

        cache.publish(a, 0x1000).unwrap();
        assert_eq!(cache.lookup(false, 0x1000), Some(a));
        assert_eq!(cache.resident_pc(false, ibtc_slot_index(0x1000)), Some(0x1000));
        cache.publish(b, 0x5000).unwrap();
        // b takes the main slot, a moves to its victim slot, in both tables; the main
        // store replaced a's record, the victim store filled an empty slot.
        for all in [true, false] {
            assert_eq!(cache.lookup(all, 0x5000), Some(b));
            assert_eq!(cache.lookup(all, 0x1000), Some(a));
            assert_eq!(cache.resident_pc(all, ibtc_slot_index(0x5000)), Some(0x5000));
            assert_eq!(cache.resident_pc(all, ibtc_victim_index(0x1000)), Some(0x1000));
        }
        assert_eq!(cache.stats.ibtc_replace, 2);
        assert_eq!(cache.stats.ibtc_insert, 2 + 2 + 2, "a: 2, b: 2 per table");
        cache.check_invariants().unwrap();
        // Publishing a pc that is resident (in either part) stores nothing.
        cache.drain_writes();
        cache.publish(a, 0x1000).unwrap();
        cache.publish(b, 0x5000).unwrap();
        assert_eq!(cache.drain_writes(), [], "nothing is stored for a resident pc");

        // Retiring `a` clears its victim records (one per table); `b` stays.
        cache.retire(a);
        assert_eq!(cache.stats.ibtc_clear, 2);
        assert_eq!(cache.lookup(true, 0x1000), None);
        assert_eq!(cache.lookup(true, 0x5000), Some(b));
        assert_eq!(cache.fragment_for_entry(0x1000), None);
        cache.retire(b);
        assert_eq!(cache.stats.ibtc_clear, 4);
        assert_eq!(cache.lookup(true, 0x5000), None);
        assert_eq!(cache.lookup(false, 0x5000), None);
        cache.check_invariants().unwrap();
        // A retired fragment is never published again.
        assert!(cache.publish(a, 0x1000).is_err());
    }

    /// The stores of a conflicting publish reach the backend victim-first.
    #[test]
    fn a_conflicting_publish_queues_the_victim_store_before_the_main_store() {
        let mut cache = cache();
        let a = cache.translate(0x1000, 0).unwrap().unwrap();
        let b = cache.translate(0x5000, 0).unwrap().unwrap();
        cache.publish(a, 0x1000).unwrap();
        cache.drain_writes();
        cache.publish(b, 0x5000).unwrap();
        let writes = cache.drain_writes();
        let table = DEFAULT_CACHE_LAYOUT.table_all;
        let slot = |index: usize| table + (index as u64) * 8;
        let a_record = cache.fragments[a].label_for_pc(0x1000).unwrap().record;
        let b_record = cache.fragments[b].label_for_pc(0x5000).unwrap().record;
        let all = writes
            .iter()
            .copied()
            .filter(|&(addr, _)| addr >= table && addr < table + crate::shared::abi::IBTC_TABLE_BYTES as u64)
            .collect::<Vec<_>>();
        assert_eq!(
            all,
            [
                (slot(ibtc_victim_index(0x1000)), a_record),
                (slot(ibtc_slot_index(0x5000)), b_record),
            ]
        );
    }

    #[test]
    fn an_fpsimd_fragment_is_published_in_table_all_only() {
        let mut cache = cache();
        let fp = cache.translate(0x2000, 0).unwrap().unwrap();
        assert!(cache.fragments[fp].uses_fpsimd);
        cache.publish(fp, 0x2000).unwrap();
        assert_eq!(cache.lookup(true, 0x2000), Some(fp));
        assert_eq!(cache.lookup(false, 0x2000), None);
        cache.check_invariants().unwrap();
    }

    /// The invariant check itself: a `table_nofp` slot that points into an FP/SIMD
    /// fragment, or any slot into a retired fragment or at the wrong pc, is reported.
    #[test]
    fn the_table_invariants_are_enforced() {
        let mut cache = cache();
        let fp = cache.translate(0x2000, 0).unwrap().unwrap();
        let plain = cache.translate(0x1000, 0).unwrap().unwrap();
        let record = |cache: &CodeCache, fragment: usize, pc: u64| {
            cache.fragments[fragment].label_for_pc(pc).unwrap().record
        };

        let fp_record = record(&cache, fp, 0x2000);
        let slot = ibtc_slot_index(0x2000);
        cache.slots_nofp[slot] = fp_record;
        let err = cache.check_invariants().unwrap_err();
        assert!(err.contains("FP/SIMD"), "{err}");
        cache.slots_nofp[slot] = 0;
        // ... in the victim part too.
        cache.slots_nofp[ibtc_victim_index(0x2000)] = fp_record;
        let err = cache.check_invariants().unwrap_err();
        assert!(err.contains("FP/SIMD"), "{err}");
        cache.slots_nofp[ibtc_victim_index(0x2000)] = 0;

        // A record under a slot its pc is not looked up in: next to its main slot, and
        // next to its victim slot.
        for elsewhere in [slot + 1, ibtc_victim_index(0x2000) + 1] {
            cache.slots_all[elsewhere] = fp_record;
            let err = cache.check_invariants().unwrap_err();
            assert!(err.contains("hashes elsewhere"), "{err}");
            cache.slots_all[elsewhere] = 0;
        }
        // A record in either of its slots is fine (a published record may be in the
        // victim part).
        cache.slots_all[ibtc_victim_index(0x2000)] = fp_record;
        cache.check_invariants().unwrap();
        cache.slots_all[ibtc_victim_index(0x2000)] = 0;

        // A slot into a retired fragment.
        cache.retire(plain);
        let plain_record = record(&cache, plain, 0x1000);
        cache.slots_all[ibtc_slot_index(0x1000)] = plain_record;
        let err = cache.check_invariants().unwrap_err();
        assert!(err.contains("retired"), "{err}");
    }

    #[test]
    fn decide_translates_return_targets_and_stops_at_unreadable_text() {
        let mut cache = cache();
        // A BL to readable text: translated, published, continued.
        let action = cache.decide(false, RetStatus::Bl.as_reg(), 0x1000, 0x2004).unwrap();
        assert!(matches!(action, CacheAction::ContinueAt { .. }), "{action:?}");
        assert_eq!(cache.stats.translations, 1);
        assert!(cache.lookup(false, 0x1000).is_some());
        // The same target again resolves without translating.
        cache.decide(false, RetStatus::Ret.as_reg(), 0x1000, 0x3004).unwrap();
        assert_eq!(cache.stats.translations, 1);
        // Unreadable text is an `Unsupported` return to userspace at the target, for
        // every branch kind.
        for status in [RetStatus::Bl, RetStatus::Blr, RetStatus::Br, RetStatus::Ret] {
            let action = cache.decide(false, status.as_reg(), 0x9_0000, 0x1004).unwrap();
            assert_eq!(
                action,
                CacheAction::Stop(URuntimeHalt::ReturnedToUserspace {
                    status: RetStatus::Unsupported,
                    target_pc: 0x9_0000,
                })
            );
        }
        assert_eq!(cache.stats.translations, 1);
    }

    #[test]
    fn the_chain_budget_stops_at_an_svc_exit_only() {
        let mut cache = cache().with_chain_budget(2);
        let fragment = cache.translate(0x1000, 0).unwrap().unwrap();
        cache.begin_run();
        let svc = |cache: &mut CodeCache| {
            cache
                .decide(false, RetStatus::Svc.as_reg(), 0, 0x1000)
                .unwrap()
        };
        // Entry 1 is the run's first; the SVC exit makes entry 2, within the budget.
        assert!(matches!(svc(&mut cache), CacheAction::ContinueAt { .. }));
        // A branch exit is never stopped by the budget.
        let action = cache.decide(false, RetStatus::Br.as_reg(), 0x1000, 0x2004).unwrap();
        assert!(matches!(action, CacheAction::ContinueAt { fragment: f, .. } if f == fragment));
        // The budget is spent: the next SVC returns to userspace at its resume pc.
        assert_eq!(
            svc(&mut cache),
            CacheAction::Stop(URuntimeHalt::ReturnedToUserspace {
                status: RetStatus::Svc,
                target_pc: 0x1000
            })
        );
    }

    // ---- Direct BL links (A16) ----

    fn bl(from: u64, to: u64) -> [u8; 4] {
        let words = ((to as i64 - from as i64) / 4) as u32 & 0x03ff_ffff;
        word(A64Insn::BlBlOnlyBranchImm {
            imm26: crate::shared::arm64::ergo::scaled_simm(words, 26, 2),
        })
    }

    fn ldr_q0() -> [u8; 4] {
        word(A64Insn::LdrImmFpsimdLdrQLdstPos {
            rt: 0,
            mem: mem_off(sp(), scaled_uimm(0, 12, 4)),
        })
    }

    /// 0x1000 `bl 0x2000; ret`, 0x2000 `ret` (the callee), 0x3000 `bl 0x4000; ret`,
    /// 0x4000 `ldr q0, [sp]; ret` (an FP/SIMD callee), 0x5000 `ldr q0, [sp]; bl 0x2000;
    /// ret` (an FP/SIMD caller), 0x6000 `bl 0x6000; ret` (a self-recursive call).
    fn link_text() -> Vec<u8> {
        let mut text = vec![0u8; 0x6010];
        let mut put = |pc: u64, words: &[[u8; 4]]| {
            let at = (pc - TEXT_BASE) as usize;
            for (index, bytes) in words.iter().enumerate() {
                text[at + index * 4..at + index * 4 + 4].copy_from_slice(bytes);
            }
        };
        put(0x1000, &[bl(0x1000, 0x2000), word(ret())]);
        put(0x2000, &[word(ret())]);
        put(0x3000, &[bl(0x3000, 0x4000), word(ret())]);
        put(0x4000, &[ldr_q0(), word(ret())]);
        put(0x5000, &[ldr_q0(), bl(0x5004, 0x2000), word(ret())]);
        put(0x6000, &[bl(0x6000, 0x6000), word(ret())]);
        text
    }

    fn link_cache() -> CodeCache {
        CodeCache::new(
            DEFAULT_CACHE_LAYOUT,
            Some(MockCodeProvider::new(TEXT_BASE, link_text())),
            synthetic_loader(0x400000),
        )
    }

    const CALLER: u64 = 0x1000;
    const CALLEE: u64 = 0x2000;
    const PLAIN_TO_FP: u64 = 0x3000;
    const FP_CALLEE: u64 = 0x4000;
    const FP_CALLER: u64 = 0x5000;
    const SELF_CALLER: u64 = 0x6000;

    /// The slot word of link `link` of `fragment`.
    fn slot_word(cache: &CodeCache, fragment: usize, link: usize) -> u32 {
        let frag = &cache.fragments[fragment];
        frag.fragment.insns[frag.links[link].slot / 4].encode().unwrap()
    }

    fn b_to(cache: &CodeCache, fragment: usize, link: usize, target: usize) -> u32 {
        let frag = &cache.fragments[fragment];
        let (g, l) = frag.links[link].linked_to.expect("linked");
        assert_eq!(g, target);
        link_branch_word(
            frag.base + frag.links[link].slot as u64,
            cache.fragments[g].host(&cache.fragments[g].labels[l]),
        )
        .expect("in range")
    }

    #[test]
    fn a_site_links_when_its_target_installs() {
        let mut cache = link_cache();
        let caller = cache.translate(CALLER, 0).unwrap().unwrap();
        // No label for the target yet: the slot stays a nop, the site pending.
        assert_eq!(cache.fragments[caller].links.len(), 1);
        assert_eq!(cache.fragments[caller].links[0].target_pc, CALLEE);
        assert_eq!(slot_word(&cache, caller, 0), LINK_NOP_WORD);
        assert_eq!(cache.stats.link_made, 0);
        assert!(cache.drain_code_patches().is_empty());
        cache.check_invariants().unwrap();

        let callee = cache.translate(CALLEE, CALLER).unwrap().unwrap();
        assert_eq!(cache.stats.link_made, 1);
        assert_eq!(slot_word(&cache, caller, 0), b_to(&cache, caller, 0, callee));
        // The bytes follow the typed code, and the backend is told once.
        let slot = cache.fragments[caller].links[0].slot;
        assert_eq!(
            cache.fragments[caller].encoded[slot..slot + 4],
            slot_word(&cache, caller, 0).to_le_bytes()
        );
        assert_eq!(
            cache.drain_code_patches(),
            [CodePatch {
                fragment: caller,
                offset: slot,
                word: slot_word(&cache, caller, 0)
            }]
        );
        cache.check_invariants().unwrap();
    }

    #[test]
    fn a_site_links_at_its_own_install_when_the_target_is_already_there() {
        let mut cache = link_cache();
        let callee = cache.translate(CALLEE, 0).unwrap().unwrap();
        let caller = cache.translate(CALLER, 0).unwrap().unwrap();
        assert_eq!(cache.stats.link_made, 1);
        assert_eq!(slot_word(&cache, caller, 0), b_to(&cache, caller, 0, callee));
        // A label inside a larger fragment satisfies the condition too: the fragment
        // translated for 0x4000 holds a label for 0x4004 only if the CFG reaches it, so
        // use the self-recursive caller, whose own label is the target.
        let me = cache.translate(SELF_CALLER, 0).unwrap().unwrap();
        assert_eq!(cache.stats.link_made, 2);
        assert_eq!(slot_word(&cache, me, 0), b_to(&cache, me, 0, me));
        cache.check_invariants().unwrap();
    }

    #[test]
    fn retire_restores_the_sites_linked_into_the_fragment_and_they_link_again() {
        let mut cache = link_cache();
        let caller = cache.translate(CALLER, 0).unwrap().unwrap();
        let fp_caller = cache.translate(FP_CALLER, 0).unwrap().unwrap();
        let callee = cache.translate(CALLEE, CALLER).unwrap().unwrap();
        assert_eq!(cache.stats.link_made, 2, "both callers link into the callee");
        cache.drain_code_patches();

        cache.retire(callee);
        assert_eq!(cache.stats.link_restored, 2);
        for fragment in [caller, fp_caller] {
            let link = cache.fragments[fragment].links.iter().position(|l| l.target_pc == CALLEE).unwrap();
            assert_eq!(slot_word(&cache, fragment, link), LINK_NOP_WORD);
            assert_eq!(cache.fragments[fragment].links[link].linked_to, None);
        }
        assert_eq!(cache.drain_code_patches().len(), 2);
        cache.check_invariants().unwrap();

        // The target translated again: the pending sites link to the new fragment.
        let again = cache.translate(CALLEE, CALLER).unwrap().unwrap();
        assert_ne!(again, callee);
        assert_eq!(cache.stats.link_made, 4);
        cache.check_invariants().unwrap();

        // Retiring a caller takes its site off the callee's incoming list: retiring
        // the callee then restores only the other caller's.
        cache.retire(caller);
        cache.retire(again);
        assert_eq!(cache.stats.link_restored, 3);
        cache.check_invariants().unwrap();
    }

    #[test]
    fn a_self_recursive_site_links_to_its_own_fragment_and_retires_cleanly() {
        let mut cache = link_cache();
        let me = cache.translate(SELF_CALLER, 0).unwrap().unwrap();
        assert_eq!(cache.stats.link_made, 1);
        assert_eq!(cache.fragments[me].links[0].linked_to.map(|(g, _)| g), Some(me));
        cache.retire(me);
        assert_eq!(cache.stats.link_restored, 1);
        cache.check_invariants().unwrap();
        // Nothing is left waiting for the retired fragment's site.
        assert!(cache.pending.is_empty());
    }

    #[test]
    fn the_class_rule_refuses_a_non_fpsimd_site_into_fpsimd_code_only() {
        let mut cache = link_cache();
        // A non-FP/SIMD caller (`bl 0x4000`) against the FP/SIMD callee: refused, the
        // site stays pending.
        let fp_callee = cache.translate(FP_CALLEE, 0).unwrap().unwrap();
        assert!(cache.fragments[fp_callee].uses_fpsimd);
        let plain_caller = cache.translate(PLAIN_TO_FP, 0).unwrap().unwrap();
        assert!(!cache.fragments[plain_caller].uses_fpsimd);
        assert_eq!(cache.stats.link_class_refused, 1);
        assert_eq!(cache.stats.link_made, 0);
        assert_eq!(cache.fragments[plain_caller].links[0].linked_to, None);
        assert_eq!(slot_word(&cache, plain_caller, 0), LINK_NOP_WORD);
        // The refusal is counted when a pending site meets a label, too.
        cache.retire(fp_callee);
        let fp_callee = cache.translate(FP_CALLEE, 0).unwrap().unwrap();
        assert_eq!(cache.stats.link_class_refused, 2);
        cache.check_invariants().unwrap();
        let _ = fp_callee;

        // The other way round is allowed: an FP/SIMD fragment's site into non-FP/SIMD
        // code (the bracketed run may continue into it).
        let plain = cache.translate(CALLEE, 0).unwrap().unwrap();
        let fp_caller = cache.translate(FP_CALLER, 0).unwrap().unwrap();
        assert!(cache.fragments[fp_caller].uses_fpsimd && !cache.fragments[plain].uses_fpsimd);
        assert_eq!(cache.stats.link_made, 1);
        assert_eq!(b_to(&cache, fp_caller, 0, plain), slot_word(&cache, fp_caller, 0));
        cache.check_invariants().unwrap();
    }

    #[test]
    fn a_target_out_of_the_reach_of_b_stays_a_pending_nop() {
        let mut next = 0x400000_u64;
        let loader: FragmentLoader = Box::new(move |_| {
            // Fragments 256 MiB apart: beyond `b`'s +-128 MiB.
            let base = next;
            next += 0x1000_0000;
            Ok(base)
        });
        let mut cache = CodeCache::new(
            DEFAULT_CACHE_LAYOUT,
            Some(MockCodeProvider::new(TEXT_BASE, link_text())),
            loader,
        );
        let caller = cache.translate(CALLER, 0).unwrap().unwrap();
        cache.translate(CALLEE, CALLER).unwrap().unwrap();
        assert_eq!(cache.stats.link_made, 0);
        assert_eq!(cache.stats.link_out_of_range, 1);
        assert_eq!(slot_word(&cache, caller, 0), LINK_NOP_WORD);
        cache.check_invariants().unwrap();
    }

    #[test]
    fn a_cache_without_links_never_patches() {
        let mut cache = link_cache().without_links();
        cache.translate(CALLEE, 0).unwrap().unwrap();
        let caller = cache.translate(CALLER, 0).unwrap().unwrap();
        assert!(cache.fragments[caller].links.is_empty());
        assert_eq!(cache.stats.link_made, 0);
        assert!(cache.drain_code_patches().is_empty());
        cache.check_invariants().unwrap();
    }

    #[test]
    fn the_link_invariant_is_enforced() {
        let mut cache = link_cache();
        let caller = cache.translate(CALLER, 0).unwrap().unwrap();
        let callee = cache.translate(CALLEE, CALLER).unwrap().unwrap();
        cache.check_invariants().unwrap();
        let slot = cache.fragments[caller].links[0].slot;
        let good = cache.fragments[caller].fragment.insns[slot / 4];

        // A linked slot that holds something else (code and bytes agree on it).
        let good_bytes = cache.fragments[caller].encoded[slot..slot + 4].to_vec();
        cache.fragments[caller].fragment.insns[slot / 4] = A64Insn::NopNopHiHints {};
        cache.fragments[caller].encoded[slot..slot + 4].copy_from_slice(&LINK_NOP_WORD.to_le_bytes());
        assert!(cache.check_invariants().unwrap_err().contains("not `b`"));
        cache.fragments[caller].encoded[slot..slot + 4].copy_from_slice(&good_bytes);
        // Only the typed code changed: the bytes disagree.
        assert!(cache.check_invariants().unwrap_err().contains("encoded bytes"));
        cache.fragments[caller].fragment.insns[slot / 4] = good;
        // The bytes and the typed code disagree.
        cache.fragments[caller].encoded[slot] ^= 1;
        assert!(cache.check_invariants().unwrap_err().contains("encoded bytes"));
        cache.fragments[caller].encoded[slot] ^= 1;
        // A pending site holding a branch.
        let link = cache.fragments[caller].links[0];
        cache.fragments[caller].links[0].linked_to = None;
        cache.fragments[callee].incoming.clear();
        cache.pending.entry(CALLEE).or_default().push((caller, 0));
        assert!(cache.check_invariants().unwrap_err().contains("not a nop"));
        cache.pending.clear();
        cache.fragments[caller].links[0] = link;
        cache.fragments[callee].incoming.push((caller, 0));
        cache.check_invariants().unwrap();
        // A site linked into a retired fragment.
        cache.fragments[callee].retired = true;
        assert!(cache.check_invariants().unwrap_err().contains("retired"));
    }

    /// `MissPolicy::ReturnToUser` is the kernel's `run_chain` (runtime/exec.rs): a miss
    /// returns to the target untranslated, a label of the entered fragment or a
    /// fragment translated for the target continues and publishes, the budget stops
    /// every branch exit, and an SVC exit always returns.
    #[test]
    fn return_to_user_follows_the_kernels_chaining() {
        let mut cache = cache()
            .with_miss_policy(MissPolicy::ReturnToUser)
            .with_chain_budget(3);
        let a = cache.translate(0x1000, 0).unwrap().unwrap();
        cache.begin_run();
        cache.note_entry(a);
        let returned = |status: RetStatus, target_pc: u64| {
            CacheAction::Stop(URuntimeHalt::ReturnedToUserspace { status, target_pc })
        };

        // 0x5000 has no fragment: back to userspace at it, nothing translated.
        let action = cache.decide(false, RetStatus::Bl.as_reg(), 0x5000, 0x1004).unwrap();
        assert_eq!(action, returned(RetStatus::Bl, 0x5000));
        assert!(!cache.chain_capped());
        assert_eq!(cache.stats.translations, 1);
        assert_eq!(cache.fragment_for_entry(0x5000), None);
        // Unreadable text is a miss like any other (the caller profiles it).
        let action = cache.decide(false, RetStatus::Ret.as_reg(), 0x9_0000, 0x1004).unwrap();
        assert_eq!(action, returned(RetStatus::Ret, 0x9_0000));

        // A label of the entered fragment: continue there and publish it.
        let action = cache.decide(false, RetStatus::Ret.as_reg(), 0x1000, 0x1004).unwrap();
        let offset = cache.fragments[a].label_for_pc(0x1000).unwrap().offset;
        assert_eq!(action, CacheAction::ContinueAt { fragment: a, offset });
        assert_eq!(cache.lookup(false, 0x1000), Some(a));

        // A fragment translated for the target.
        let b = cache.translate(0x5000, 0).unwrap().unwrap();
        let action = cache.decide(false, RetStatus::Br.as_reg(), 0x5000, 0x1004).unwrap();
        let offset = cache.fragments[b].label_for_pc(0x5000).unwrap().offset;
        assert_eq!(action, CacheAction::ContinueAt { fragment: b, offset });
        assert_eq!(cache.lookup(false, 0x5000), Some(b));

        // Three entries made: the budget is spent. Every branch exit returns, hit or
        // not, and says it was the budget.
        let action = cache.decide(false, RetStatus::Bl.as_reg(), 0x1000, 0x1004).unwrap();
        assert_eq!(action, returned(RetStatus::Bl, 0x1000));
        assert!(cache.chain_capped());
        // A new run starts afresh.
        cache.begin_run();
        assert!(!cache.chain_capped());

        // An SVC exit returns whatever the cache holds for the resume pc.
        let action = cache.decide(false, RetStatus::Svc.as_reg(), 0, 0x1000).unwrap();
        assert_eq!(action, returned(RetStatus::Svc, 0x1000));
        // The entered fragment is the one the runtime last entered: from `b`, 0x1000 is
        // `a`'s entry label, found by the fragment translated for it.
        cache.note_entry(b);
        let action = cache.decide(false, RetStatus::Bl.as_reg(), 0x1000, 0x1004).unwrap();
        assert!(matches!(action, CacheAction::ContinueAt { fragment, .. } if fragment == a));
    }

    #[test]
    fn the_event_log_has_every_change_in_order() {
        let mut cache = link_cache().with_event_log();
        let callee = cache.translate(CALLEE, 0).unwrap().unwrap();
        let caller = cache.translate(CALLER, 0).unwrap().unwrap();
        let slot = cache.fragments[caller].links[0].slot;
        cache.publish(callee, CALLEE).unwrap();
        cache.retire(callee);
        let slot_all = ibtc_slot_index(CALLEE);
        assert_eq!(
            cache.drain_events(),
            [
                CacheEvent::Installed { fragment: callee, entry_pc: CALLEE },
                CacheEvent::Installed { fragment: caller, entry_pc: CALLER },
                CacheEvent::Linked {
                    fragment: caller,
                    slot_offset: slot,
                    target_fragment: callee,
                    target_pc: CALLEE,
                },
                CacheEvent::Published {
                    table: TableId::All,
                    slot: slot_all,
                    pc: CALLEE,
                    fragment: callee,
                    replaced: None,
                },
                CacheEvent::Published {
                    table: TableId::NoFp,
                    slot: slot_all,
                    pc: CALLEE,
                    fragment: callee,
                    replaced: None,
                },
                CacheEvent::Restored {
                    fragment: caller,
                    slot_offset: slot,
                    target_fragment: callee,
                    target_pc: CALLEE,
                },
                CacheEvent::Retired { fragment: callee },
            ]
        );
        assert!(cache.drain_events().is_empty());
    }

    /// An evicting publish logs the moved record's store first, then the new one,
    /// each with the record it replaced.
    #[test]
    fn an_evicting_publish_logs_both_stores() {
        let mut cache = cache().with_event_log();
        let a = cache.translate(0x1000, 0).unwrap().unwrap();
        let b = cache.translate(0x5000, 0).unwrap().unwrap();
        cache.publish(a, 0x1000).unwrap();
        cache.drain_events();
        cache.publish(b, 0x5000).unwrap();
        let published = cache
            .drain_events()
            .into_iter()
            .filter(|event| matches!(event, CacheEvent::Published { table: TableId::All, .. }))
            .collect::<Vec<_>>();
        assert_eq!(
            published,
            [
                CacheEvent::Published {
                    table: TableId::All,
                    slot: ibtc_victim_index(0x1000),
                    pc: 0x1000,
                    fragment: a,
                    replaced: None,
                },
                CacheEvent::Published {
                    table: TableId::All,
                    slot: ibtc_slot_index(0x5000),
                    pc: 0x5000,
                    fragment: b,
                    replaced: Some(Occupant { pc: 0x1000, fragment: a }),
                },
            ]
        );
    }
}
