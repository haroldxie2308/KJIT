//! Dispatch-table slot planning (A11c, docs/pipeline.md "In-fragment branch dispatch
//! (A11)"). Pure functions over table word indices (main part `0..IBTC_SLOTS`, victim
//! part `IBTC_SLOTS..IBTC_TABLE_WORDS`), called by the kernel runtime (through
//! `kjit_glue.c`, under `kmm->lock`) and by the harness code cache, so the harness
//! mirrors the kernel by construction. The template that reads the tables is
//! `KJIT_DISPATCH_TEMPLATE` (`wrapper.rs`); the two must agree on `ibtc_lookup_slots`.

use super::{ibtc_slot_index, ibtc_victim_index};

/// The slots (table word indices) the template probes for `pc`, in probe order: its
/// main slot, then its victim slot. Retire clears the ones that still hold a label's
/// record.
pub fn ibtc_lookup_slots(pc: u64) -> [usize; 2] {
    [ibtc_slot_index(pc), ibtc_victim_index(pc)]
}

/// What a planned store writes: the record being published, or the record that is
/// currently in another slot (a move).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IbtcSource {
    New,
    Slot(usize),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IbtcStore {
    pub dst: usize,
    pub src: IbtcSource,
}

/// The stores that publish a record, in the order they must be performed, each a
/// single 8-byte release store: a moved record is stored at its victim slot before the
/// new record replaces it in the main slot, so every slot always holds 0 or a live
/// record and a concurrent probe of the moved record's pc finds it in one of the two.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IbtcPlan {
    stores: [IbtcStore; 2],
    len: usize,
}

impl IbtcPlan {
    const NONE: Self = Self {
        stores: [IbtcStore { dst: 0, src: IbtcSource::New }; 2],
        len: 0,
    };

    pub fn stores(&self) -> &[IbtcStore] {
        &self.stores[..self.len]
    }
}

/// The publish plan for a record of `pc`, for one table. `resident(slot)` is the pc of
/// the record in table word `slot`, if any.
///
/// - Nothing if `pc`'s main slot or victim slot already holds a record for `pc`: any
///   fragment's record is a translation of the same text, and replacing it would only
///   make two fragments take turns in the slot.
/// - Else, if the main slot is empty: the new record goes there.
/// - Else the main slot holds a record R for another pc P: R is stored into P's victim
///   slot (dropping whatever it held), then the new record into `pc`'s main slot.
pub fn ibtc_plan_publish(pc: u64, resident: &dyn Fn(usize) -> Option<u64>) -> IbtcPlan {
    let [main, victim] = ibtc_lookup_slots(pc);
    if resident(main) == Some(pc) || resident(victim) == Some(pc) {
        return IbtcPlan::NONE;
    }
    let new = IbtcStore { dst: main, src: IbtcSource::New };
    match resident(main) {
        None => IbtcPlan { stores: [new, new], len: 1 },
        Some(evicted_pc) => IbtcPlan {
            stores: [
                IbtcStore {
                    dst: ibtc_victim_index(evicted_pc),
                    src: IbtcSource::Slot(main),
                },
                new,
            ],
            len: 2,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::abi::{IBTC_SLOTS, IBTC_TABLE_WORDS};
    use std::cell::RefCell;
    use std::collections::BTreeMap;

    /// A table of pcs (the record identity is its pc) and the executed plans.
    struct Table(RefCell<BTreeMap<usize, u64>>);

    impl Table {
        fn new() -> Self {
            Self(RefCell::new(BTreeMap::new()))
        }

        fn publish(&self, pc: u64) -> Vec<IbtcStore> {
            let plan = ibtc_plan_publish(pc, &|slot| self.0.borrow().get(&slot).copied());
            for store in plan.stores() {
                let value = match store.src {
                    IbtcSource::New => pc,
                    IbtcSource::Slot(slot) => self.0.borrow()[&slot],
                };
                self.0.borrow_mut().insert(store.dst, value);
            }
            plan.stores().to_vec()
        }

        fn at(&self, slot: usize) -> Option<u64> {
            self.0.borrow().get(&slot).copied()
        }

        /// What the template finds for `pc`: the main slot's record if it is `pc`'s,
        /// else the victim slot's.
        fn hit(&self, pc: u64) -> bool {
            ibtc_lookup_slots(pc).iter().any(|&slot| self.at(slot) == Some(pc))
        }
    }

    #[test]
    fn the_indices_are_the_contracts() {
        // Main: pc[13:2]; victim: pc[9:2] ^ pc[21:14], in the part at IBTC_SLOTS.
        let pc = 0x0000_ffff_8123_4568_u64;
        assert_eq!(ibtc_slot_index(pc), ((pc >> 2) & 0xfff) as usize);
        assert_eq!(
            ibtc_victim_index(pc),
            IBTC_SLOTS + ((((pc >> 2) & 0xff) ^ ((pc >> 14) & 0xff)) as usize)
        );
        for pc in [0u64, 4, 0x1000, 0x4000, 0xffff_ffff_fffc, 0xaaaa_bbbb_cccc, u64::MAX & !3] {
            let [main, victim] = ibtc_lookup_slots(pc);
            assert!(main < IBTC_SLOTS, "pc {pc:#x}");
            assert!((IBTC_SLOTS..IBTC_TABLE_WORDS).contains(&victim), "pc {pc:#x}");
        }
        // Two pcs 16 KiB apart share their main slot and differ in the victim slot.
        assert_eq!(ibtc_slot_index(0x10000), ibtc_slot_index(0x14000));
        assert_ne!(ibtc_victim_index(0x10000), ibtc_victim_index(0x14000));
    }

    #[test]
    fn publish_fills_an_empty_main_slot_and_keeps_a_resident_pc() {
        let table = Table::new();
        let a = 0x10000;
        assert_eq!(
            table.publish(a),
            [IbtcStore { dst: ibtc_slot_index(a), src: IbtcSource::New }]
        );
        assert!(table.publish(a).is_empty(), "same pc kept");
        assert!(table.hit(a));
    }

    #[test]
    fn a_conflicting_publish_moves_the_old_record_to_its_victim_slot_first() {
        let table = Table::new();
        let (a, b, c) = (0x10000u64, 0x14000u64, 0x18000u64);
        table.publish(a);
        let stores = table.publish(b);
        // Victim store first, then the main store.
        assert_eq!(
            stores,
            [
                IbtcStore { dst: ibtc_victim_index(a), src: IbtcSource::Slot(ibtc_slot_index(b)) },
                IbtcStore { dst: ibtc_slot_index(b), src: IbtcSource::New },
            ]
        );
        assert_eq!(table.at(ibtc_slot_index(b)), Some(b));
        assert_eq!(table.at(ibtc_victim_index(a)), Some(a));
        assert!(table.hit(a) && table.hit(b));
        // a is live in the victim part: not published again, nothing evicted.
        assert!(table.publish(a).is_empty());
        assert_eq!(table.at(ibtc_slot_index(b)), Some(b));
        // A third pc on the same main slot evicts b into its own victim slot; a stays
        // (distinct victim slots).
        table.publish(c);
        assert!(table.hit(a) && table.hit(b) && table.hit(c));
    }

    #[test]
    fn two_evicted_pcs_sharing_a_victim_slot_drop_the_earlier_one() {
        // The known limit of the victim part: x and y have different main slots but
        // the same victim slot; each is evicted by an alias of its own main slot.
        let (x, y) = (0x10000u64, 0x10000u64 + (1 << 2) + (1 << 14));
        assert_ne!(ibtc_slot_index(x), ibtc_slot_index(y));
        assert_eq!(ibtc_victim_index(x), ibtc_victim_index(y));
        let table = Table::new();
        let (x2, y2) = (x + (1 << 16), y + (1 << 16));
        assert_eq!(ibtc_slot_index(x), ibtc_slot_index(x2));
        assert_eq!(ibtc_slot_index(y), ibtc_slot_index(y2));
        for pc in [x, y, x2, y2] {
            table.publish(pc);
        }
        assert!(table.hit(y) && !table.hit(x), "y's eviction replaced x in the shared slot");
        assert!(table.hit(x2) && table.hit(y2));
    }

    /// A pc found in the victim part while its main slot holds another pc is kept
    /// (no store), and one whose main slot holds itself is kept too.
    #[test]
    fn publish_skips_a_pc_held_in_either_slot() {
        let table = Table::new();
        table.0.borrow_mut().insert(ibtc_victim_index(0x20000), 0x20000);
        table.0.borrow_mut().insert(ibtc_slot_index(0x20000), 0x24000);
        assert!(table.publish(0x20000).is_empty());
        assert_eq!(table.at(ibtc_slot_index(0x20000)), Some(0x24000));
    }
}
