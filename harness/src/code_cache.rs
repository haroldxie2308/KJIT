//! The harness code cache: a mirror of the kernel runtime's fragment store
//! (docs/pipeline.md, "Dispatch tables (A11, kernel side)" and "Code cache and
//! cached runs (A11a)").
//!
//! - Fragments by entry pc (`by_entry`), each with its labels as records
//!   `{ u64 pc; u64 host }` (`IBTC_RECORD_*`): the verified entries of the fragment,
//!   `host` = the absolute address of the label's word in the code space.
//! - Two direct-mapped dispatch tables, `table_all` and `table_nofp` (`IBTC_BITS`,
//!   slot = `ibtc_slot_index(pc)`). A slot is 0 or a record address. `table_nofp`
//!   never holds a record of a `uses_fpsimd` fragment (`check_invariants`).
//! - Insert on resolution (`publish`), replacing a live slot allowed (last writer
//!   wins); `retire` clears the fragment's slots and its entry.
//! - The runtime decision for a fragment return (`decide`): continue at the
//!   resolved fragment's label, translate on a miss (the harness translates a
//!   branch exit's target at once, where the kernel's profiler learns it after a
//!   hit count: K3 "exit-target learning"), or stop.
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
    ibtc_slot_index, RetStatus, IBTC_RECORD_BYTES, IBTC_RECORD_HOST_OFFSET, IBTC_RECORD_PC_OFFSET,
    IBTC_SLOTS, IBTC_SLOT_BYTES, IBTC_TABLE_BYTES,
};
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
    /// Fragment entries per run before the next `SVC` exit returns to userspace
    /// (the kernel's `chain_budget`, K3 "Chaining rules"); `None` never stops. Fixture
    /// text is not always a terminating program once branches are followed: an
    /// endless cycle passes the runtime at an SVC (a loop without one is bounded by
    /// the back-edge budget), so stopping there bounds the run, and the original is
    /// stopped before the same SVC.
    chain_budget: Option<usize>,
    run_entries: usize,
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
            slots_all: vec![0; IBTC_SLOTS],
            slots_nofp: vec![0; IBTC_SLOTS],
            record_owner: Vec::new(),
            writes: Vec::new(),
            chain_budget: None,
            run_entries: 0,
            stats: CacheStats::default(),
        }
    }

    pub fn with_chain_budget(mut self, entries: usize) -> Self {
        self.chain_budget = Some(entries);
        self
    }

    /// A new run starts: its first entry counts against the chain budget.
    pub fn begin_run(&mut self) {
        self.run_entries = 1;
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
        };
        cached.base = (self.loader)(&cached)?;
        let mut labels = cached
            .fragment
            .vlabels
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
        Ok(index)
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
        let slot = ibtc_slot_index(pc);
        let uses_fpsimd = frag.uses_fpsimd;
        self.set_slot(true, slot, label.record);
        if !uses_fpsimd {
            self.set_slot(false, slot, label.record);
        }
        Ok(())
    }

    fn set_slot(&mut self, all: bool, slot: usize, record: u64) {
        let (slots, table) = if all {
            (&mut self.slots_all, self.layout.table_all)
        } else {
            (&mut self.slots_nofp, self.layout.table_nofp)
        };
        match slots[slot] {
            old if old == record => return,
            0 => self.stats.ibtc_insert += 1,
            _ => {
                self.stats.ibtc_insert += 1;
                self.stats.ibtc_replace += 1;
            }
        }
        slots[slot] = record;
        self.writes
            .push((table + slot as u64 * u64::from(IBTC_SLOT_BYTES), record));
    }

    /// Retires a fragment: clears every table slot that points at one of its
    /// labels, and its entry. Its code stays mapped (the kernel frees it after a
    /// grace period; the harness never frees).
    pub fn retire(&mut self, fragment: usize) {
        let frag = &mut self.fragments[fragment];
        frag.retired = true;
        if self.by_entry.get(&frag.entry_pc) == Some(&fragment) {
            self.by_entry.remove(&frag.entry_pc);
        }
        for label in frag.labels.clone() {
            let slot = ibtc_slot_index(label.pc);
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

    /// The kernel's table invariant: every non-zero slot points at a label of a
    /// non-retired fragment, for exactly the slot's pc index, and `table_nofp`
    /// never points into an FP/SIMD fragment.
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
                if ibtc_slot_index(label.pc) != slot {
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
        Ok(())
    }

    /// The label a table slot of `pc` points at, as (fragment, label pc): `table_all`
    /// when `all`, else `table_nofp`.
    pub fn slot_target(&self, all: bool, pc: u64) -> Option<(usize, u64)> {
        let slots = if all { &self.slots_all } else { &self.slots_nofp };
        let record = slots[ibtc_slot_index(pc)];
        if record == 0 {
            return None;
        }
        let number = ((record - self.layout.records) / IBTC_RECORD_BYTES as u64) as usize;
        let (fragment, label) = self.record_owner[number];
        Some((fragment, self.fragments[fragment].labels[label].pc))
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
    /// 0x1000 and 0x5000 are 0x4000 apart, so they share a table slot.
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
    fn aliasing_publishes_replace_and_retire_clears_only_the_live_records() {
        let mut cache = cache();
        let a = cache.translate(0x1000, 0).unwrap().unwrap();
        let b = cache.translate(0x5000, 0).unwrap().unwrap();
        assert_eq!(ibtc_slot_index(0x1000), ibtc_slot_index(0x5000));

        cache.publish(a, 0x1000).unwrap();
        assert_eq!(cache.slot_target(false, 0x1000), Some((a, 0x1000)));
        cache.publish(b, 0x5000).unwrap();
        // Last writer wins, in both tables; one replace per table.
        assert_eq!(cache.slot_target(true, 0x1000), Some((b, 0x5000)));
        assert_eq!(cache.slot_target(false, 0x1000), Some((b, 0x5000)));
        assert_eq!(cache.stats.ibtc_replace, 2);
        cache.check_invariants().unwrap();

        // `a`'s record is no longer in a slot: retiring `a` clears nothing.
        cache.retire(a);
        assert_eq!(cache.stats.ibtc_clear, 0);
        assert_eq!(cache.slot_target(true, 0x5000), Some((b, 0x5000)));
        assert_eq!(cache.fragment_for_entry(0x1000), None);
        cache.retire(b);
        assert_eq!(cache.stats.ibtc_clear, 2);
        assert_eq!(cache.slot_target(true, 0x5000), None);
        assert_eq!(cache.slot_target(false, 0x5000), None);
        cache.check_invariants().unwrap();
        // A retired fragment is never published again.
        assert!(cache.publish(a, 0x1000).is_err());
    }

    #[test]
    fn an_fpsimd_fragment_is_published_in_table_all_only() {
        let mut cache = cache();
        let fp = cache.translate(0x2000, 0).unwrap().unwrap();
        assert!(cache.fragments[fp].uses_fpsimd);
        cache.publish(fp, 0x2000).unwrap();
        assert_eq!(cache.slot_target(true, 0x2000), Some((fp, 0x2000)));
        assert_eq!(cache.slot_target(false, 0x2000), None);
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

        // A record under a slot its pc does not hash to.
        cache.slots_all[slot + 1] = fp_record;
        let err = cache.check_invariants().unwrap_err();
        assert!(err.contains("hashes elsewhere"), "{err}");
        cache.slots_all[slot + 1] = 0;

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
        assert!(cache.slot_target(false, 0x1000).is_some());
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
}
