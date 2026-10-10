base='/Volumes/CaseSentitiveLocal/KJIT/.claude/worktrees/agent-a4b243dcf4b342be4/harness/src/'
def edit(path, pairs):
    s=open(base+path).read()
    for old,new in pairs:
        assert s.count(old)==1, (path, s.count(old), old[:80])
        s=s.replace(old,new)
    open(base+path,'w').write(s)

edit('code_cache.rs', [
('''//! - Two direct-mapped dispatch tables, `table_all` and `table_nofp` (`IBTC_BITS`,
//!   slot = `ibtc_slot_index(pc)`). A slot is 0 or a record address. `table_nofp`
//!   never holds a record of a `uses_fpsimd` fragment (`check_invariants`).
//! - Insert on resolution (`publish`), replacing a live slot allowed (last writer
//!   wins); `retire` clears the fragment's slots and its entry.''','''//! - Two dispatch tables, `table_all` and `table_nofp`, of the selected variant
//!   (`shared::abi` dispatch: direct, hash, two-way, victim; `ibtc_table_words()`
//!   slots, a pc's slots are `ibtc_lookup_slots(pc)`). A slot is 0 or a record
//!   address. `table_nofp` never holds a record of a `uses_fpsimd` fragment
//!   (`check_invariants`).
//! - Insert on resolution (`publish`, the policy is `ibtc_plan_publish`, the same
//!   function the kernel runtime executes); `retire` clears the slots that hold the
//!   fragment's records, and its entry.'''),
('''use crate::shared::abi::{
    ibtc_slot_index, RetStatus, IBTC_RECORD_BYTES, IBTC_RECORD_HOST_OFFSET, IBTC_RECORD_PC_OFFSET,
    IBTC_SLOTS, IBTC_SLOT_BYTES, IBTC_TABLE_BYTES,
};''','''use crate::shared::abi::{
    ibtc_lookup_slots, ibtc_plan_publish, ibtc_table_bytes, ibtc_table_words, IbtcSource,
    RetStatus, IBTC_RECORD_BYTES, IBTC_RECORD_HOST_OFFSET, IBTC_RECORD_PC_OFFSET,
    IBTC_SLOT_BYTES,
};'''),
('''/// Where the cache's memory lives in the backend's address space. The tables are
/// `IBTC_TABLE_BYTES` each; the record area holds `records_len / IBTC_RECORD_BYTES`
/// records.''','''/// Where the cache's memory lives in the backend's address space. The tables are
/// `ibtc_table_bytes()` each; the record area holds `records_len / IBTC_RECORD_BYTES`
/// records.'''),
('''            (self.table_all, self.table_all + IBTC_TABLE_BYTES as u64),
            (self.table_nofp, self.table_nofp + IBTC_TABLE_BYTES as u64),''','''            (self.table_all, self.table_all + ibtc_table_bytes() as u64),
            (self.table_nofp, self.table_nofp + ibtc_table_bytes() as u64),'''),
('''            slots_all: vec![0; IBTC_SLOTS],
            slots_nofp: vec![0; IBTC_SLOTS],''','''            slots_all: vec![0; ibtc_table_words()],
            slots_nofp: vec![0; ibtc_table_words()],'''),
('''    /// Publishes the label of `fragment` for `pc` (insert on resolution): into
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
''','''    /// Publishes the label of `fragment` for `pc` (insert on resolution): into
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
        if record == 0 {
            return None;
        }
        let number = ((record - self.layout.records) / IBTC_RECORD_BYTES as u64) as usize;
        let (fragment, label) = self.record_owner[number];
        Some(self.fragments[fragment].labels[label].pc)
    }

    /// Applies the runtime's publish policy (`ibtc_plan_publish`) to one table.
    fn publish_into(&mut self, all: bool, new_record: u64, pc: u64) {
        let plan = {
            let slots = if all { &self.slots_all } else { &self.slots_nofp };
            ibtc_plan_publish(pc, &|slot| self.record_pc(slots[slot]))
        };
        for store in plan.stores() {
            let value = match store.src {
                IbtcSource::New => new_record,
                IbtcSource::Slot(slot) => {
                    if all {
                        self.slots_all[slot]
                    } else {
                        self.slots_nofp[slot]
                    }
                }
            };
            self.set_slot(all, store.dst, value);
        }
    }
'''),
('''        for label in frag.labels.clone() {
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
        }''','''        for label in frag.labels.clone() {
            let (candidates, probes) = ibtc_lookup_slots(label.pc);
            for &slot in &candidates[..probes] {
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
        }'''),
('''    /// The kernel's table invariant: every non-zero slot points at a label of a
    /// non-retired fragment, for exactly the slot's pc index, and `table_nofp`
    /// never points into an FP/SIMD fragment.''','''    /// The kernel's table invariant: every non-zero slot points at a label of a
    /// non-retired fragment, in one of the slots the label's pc is looked up in, and
    /// `table_nofp` never points into an FP/SIMD fragment.'''),
('''                if ibtc_slot_index(label.pc) != slot {''','''                let (candidates, probes) = ibtc_lookup_slots(label.pc);
                if !candidates[..probes].contains(&slot) {'''),
('''    /// The label a table slot of `pc` points at, as (fragment, label pc): `table_all`
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
    }''','''    /// What the dispatch template finds for `pc` in `table_all` (`all`) or
    /// `table_nofp`: probes the slots of `ibtc_lookup_slots(pc)` in order and returns
    /// the fragment of the first record whose pc is `pc` (a hit), or `None` (a miss).
    pub fn lookup(&self, all: bool, pc: u64) -> Option<usize> {
        let slots = if all { &self.slots_all } else { &self.slots_nofp };
        let (candidates, probes) = ibtc_lookup_slots(pc);
        candidates[..probes].iter().find_map(|&slot| {
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
    }'''),
])

edit('code_cache.rs', [
('''    #[test]
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
    }''','''    /// Two pcs 16 KiB apart share the main slot of the direct and victim variants and
    /// the set of the two-way ones; the hash variant separates them.
    #[test]
    fn aliasing_publishes_follow_the_variant_and_retire_clears_only_the_live_records() {
        let mut cache = cache();
        let a = cache.translate(0x1000, 0).unwrap().unwrap();
        let b = cache.translate(0x5000, 0).unwrap().unwrap();
        let variant = ibtc_variant();
        let both_resident = !matches!(variant, IbtcVariant::Direct);

        cache.publish(a, 0x1000).unwrap();
        assert_eq!(cache.lookup(false, 0x1000), Some(a));
        cache.publish(b, 0x5000).unwrap();
        assert_eq!(cache.lookup(true, 0x5000), Some(b));
        assert_eq!(cache.lookup(false, 0x5000), Some(b));
        // Direct mapped: last writer wins, in both tables, one replace per table.
        // Every other variant keeps `a` too (hash: another slot; two-way: the other
        // way; victim: the evicted record moves to the victim table).
        assert_eq!(cache.lookup(true, 0x1000).is_some(), both_resident);
        assert_eq!(cache.lookup(false, 0x1000).is_some(), both_resident);
        match variant {
            IbtcVariant::Direct => assert_eq!(cache.stats.ibtc_replace, 2),
            IbtcVariant::Hash | IbtcVariant::TwoWay { .. } => {
                assert_eq!(cache.stats.ibtc_replace, 0)
            }
            // The moved record lands on an empty victim slot.
            IbtcVariant::Victim { .. } => assert_eq!(cache.stats.ibtc_replace, 2),
        }
        cache.check_invariants().unwrap();

        // Direct mapped: `a`'s record is no longer in a slot, retiring `a` clears
        // nothing. Otherwise its two records (one per table) are cleared.
        cache.retire(a);
        assert_eq!(cache.stats.ibtc_clear, if both_resident { 2 } else { 0 });
        assert_eq!(cache.lookup(true, 0x1000), None);
        assert_eq!(cache.lookup(true, 0x5000), Some(b));
        assert_eq!(cache.fragment_for_entry(0x1000), None);
        let cleared = cache.stats.ibtc_clear;
        cache.retire(b);
        assert_eq!(cache.stats.ibtc_clear, cleared + 2);
        assert_eq!(cache.lookup(true, 0x5000), None);
        assert_eq!(cache.lookup(false, 0x5000), None);
        cache.check_invariants().unwrap();
        // A retired fragment is never published again.
        assert!(cache.publish(a, 0x1000).is_err());
    }'''),
('''        cache.publish(fp, 0x2000).unwrap();
        assert_eq!(cache.slot_target(true, 0x2000), Some((fp, 0x2000)));
        assert_eq!(cache.slot_target(false, 0x2000), None);''','''        cache.publish(fp, 0x2000).unwrap();
        assert_eq!(cache.lookup(true, 0x2000), Some(fp));
        assert_eq!(cache.lookup(false, 0x2000), None);'''),
('''        let fp_record = record(&cache, fp, 0x2000);
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
        cache.slots_all[ibtc_slot_index(0x1000)] = plain_record;''','''        let fp_record = record(&cache, fp, 0x2000);
        let (candidates, probes) = ibtc_lookup_slots(0x2000);
        let slot = candidates[0];
        cache.slots_nofp[slot] = fp_record;
        let err = cache.check_invariants().unwrap_err();
        assert!(err.contains("FP/SIMD"), "{err}");
        cache.slots_nofp[slot] = 0;

        // A record under a slot its pc is not looked up in.
        let elsewhere = (0..ibtc_table_words())
            .find(|slot| !candidates[..probes].contains(slot))
            .unwrap();
        cache.slots_all[elsewhere] = fp_record;
        let err = cache.check_invariants().unwrap_err();
        assert!(err.contains("hashes elsewhere"), "{err}");
        cache.slots_all[elsewhere] = 0;

        // A slot into a retired fragment.
        cache.retire(plain);
        let plain_record = record(&cache, plain, 0x1000);
        cache.slots_all[ibtc_lookup_slots(0x1000).0[0]] = plain_record;'''),
('''        assert!(cache.slot_target(false, 0x1000).is_some());
        // The same target again resolves without translating.''','''        assert!(cache.lookup(false, 0x1000).is_some());
        // The same target again resolves without translating.'''),
('''    use crate::runtime::DEFAULT_CACHE_LAYOUT;''','''    use crate::runtime::default_cache_layout;
    use crate::shared::abi::{ibtc_variant, IbtcVariant};'''),
('''            DEFAULT_CACHE_LAYOUT,
            Some(MockCodeProvider::new(TEXT_BASE, text)),''','''            default_cache_layout(),
            Some(MockCodeProvider::new(TEXT_BASE, text)),'''),
])
