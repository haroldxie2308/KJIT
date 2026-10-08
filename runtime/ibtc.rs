// SPDX-License-Identifier: GPL-2.0

//! Dispatch-miss classification (tmp/pipeline.md, "A11 contract"). A fragment
//! looks a branch target up in its run's dispatch table; every `BL`, `BLR`,
//! `BR` and `RET` exit that reaches `run_chain` is a miss. Before the runtime
//! publishes anything it reads the slot the fragment missed in and classifies
//! the miss by what it held:
//!
//! - empty: `ibtc_miss_cold`;
//! - a record for another pc: `ibtc_miss_conflict` (direct mapped: the publish
//!   that follows evicts it);
//! - a record for the same pc: `ibtc_miss_other`. Not a state the runtime can
//!   create: the fragment compares the full pc, so it can only mean another
//!   thread published that pc between the fragment's read and ours.
//!
//! Exits of a non-FP/SIMD run whose target resolves to an FP/SIMD fragment
//! (`ibtc_fpsimd_boundary`) are excluded from all three: `table_nofp` never
//! holds such a target, so the slot state says nothing about capacity or
//! aliasing, and no publish into it follows. Hence for any interval
//!
//! ```text
//! cold + conflict + other + fpsimd_boundary == exit_bl + exit_blr + exit_br + exit_ret
//! ```
//!
//! up to counters read while exits are in flight.
//!
//! Per slot, for each table class (`table_all` is the table of FP/SIMD runs,
//! `table_nofp` of all others), the conflicts are also counted, with the last
//! missing pc and the last resident pc. The counters are global (all mms:
//! tables of different mms are not distinguished) and `/sys/kernel/debug/kjit/
//! ibtc_slots` lists the 32 slots with most conflicts per table; writing
//! `reset` to it zeroes them. The two pcs of a slot are two relaxed stores,
//! racy by design: under concurrent misses in one slot they may come from
//! different misses. "Evictor" is the target that missed; it displaces the
//! resident unless the exit then ends the hook call unresolved (chain budget,
//! run condition, untranslatable target), in which case nothing is published.
//!
//! Cost, on the miss path only (a runtime round trip already costs a full
//! epilogue, a trampoline call and a prologue): two loads (the slot and its
//! record, both just read by the fragment's template, so cache-hot), one atomic
//! add for the class counter and, for a conflict, one more for the slot plus
//! two plain stores. Hits run no runtime code.

use core::fmt::Write;
use core::sync::atomic::{AtomicU64, Ordering};

use kernel::alloc::flags::GFP_KERNEL;
use kernel::prelude::*;

use super::stats::{self, BufWriter, Stat};
use crate::shared::abi::{ibtc_slot_index, IBTC_RECORD_PC_OFFSET, IBTC_SLOTS};

/// `table_all`, `table_nofp`: the order of `DIAG` and of the listing.
const TABLES: usize = 2;
const TABLE_ALL: usize = 0;
const TABLE_NOFP: usize = 1;
const TABLE_NAMES: [&str; TABLES] = ["all", "nofp"];

/// Slots listed per table by `ibtc_slots`.
const TOP_SLOTS: usize = 32;

struct SlotDiag {
    conflicts: AtomicU64,
    /// The target that missed last in this slot with a resident of another pc.
    evictor: AtomicU64,
    /// The pc of the record that was resident then.
    evicted: AtomicU64,
}

#[allow(clippy::declare_interior_mutable_const)]
const ZERO_DIAG: SlotDiag = SlotDiag {
    conflicts: AtomicU64::new(0),
    evictor: AtomicU64::new(0),
    evicted: AtomicU64::new(0),
};
/// `TABLES` consecutive runs of `IBTC_SLOTS`: `DIAG[table * IBTC_SLOTS + slot]`.
static DIAG: [SlotDiag; TABLES * IBTC_SLOTS] = [ZERO_DIAG; TABLES * IBTC_SLOTS];

/// What a run's dispatch table held where a branch exit's target belongs.
#[derive(Clone, Copy)]
pub(super) struct Seen {
    table: usize,
    slot: usize,
    /// The pc of the record in the slot, if there was one.
    resident: Option<u64>,
}

/// Reads the slot of `target` in `table`, the dispatch table of the run that
/// exited (`all`: it is `table_all`, the table of an FP/SIMD run). Call before
/// anything publishes into the table.
pub(super) fn probe(table: u64, all: bool, target: u64) -> Seen {
    let slot = ibtc_slot_index(target);
    // SAFETY: `table` is the run's dispatch table (`kjit_frag_table`):
    // IBTC_SLOTS 8-byte slots, freed only after a hook-SRCU grace period, so
    // valid for this hook call. Fragment code and publishers access slots
    // concurrently: a volatile read is READ_ONCE.
    let record = unsafe { core::ptr::read_volatile((table as *const u64).add(slot)) };
    let resident = (record != 0).then(|| {
        // SAFETY: a non-zero slot holds a record (a `kjit_label`, `pc` at
        // IBTC_RECORD_PC_OFFSET) of a fragment of this mm. It can be retired
        // from now on, but is freed only after a hook-SRCU grace period, which
        // this hook call holds off (the slot is cleared before the grace
        // period starts, so a read that saw it set began before it): the same
        // argument as `kjit_ibtc_publish`'s.
        unsafe { core::ptr::read_volatile((record + u64::from(IBTC_RECORD_PC_OFFSET)) as *const u64) }
    });
    Seen {
        table: if all { TABLE_ALL } else { TABLE_NOFP },
        slot,
        resident,
    }
}

/// Counts the miss on `target` that `probe` classified.
pub(super) fn note_miss(seen: Seen, target: u64) {
    match seen.resident {
        None => stats::inc(Stat::IbtcMissCold),
        Some(pc) if pc == target => stats::inc(Stat::IbtcMissOther),
        Some(pc) => {
            stats::inc(Stat::IbtcMissConflict);
            let diag = &DIAG[seen.table * IBTC_SLOTS + seen.slot];
            diag.conflicts.fetch_add(1, Ordering::Relaxed);
            diag.evictor.store(target, Ordering::Relaxed);
            diag.evicted.store(pc, Ordering::Relaxed);
        }
    }
}

/// Zeroes the per-slot diagnostics (not the `ibtc_miss_*` counters, which are
/// read as deltas of `stats`).
#[no_mangle]
extern "C" fn kjit_rs_ibtc_slots_reset() {
    for diag in DIAG.iter() {
        diag.conflicts.store(0, Ordering::Relaxed);
        diag.evictor.store(0, Ordering::Relaxed);
        diag.evicted.store(0, Ordering::Relaxed);
    }
}

/// Per table: a `# table <name> conflicts <total> slots <n> top<K> <sum>`
/// header, then `<name> <slot> <conflicts> <evictor> <evicted>` for the
/// `TOP_SLOTS` slots with most conflicts (ties: lower slot first). Returns the
/// number of bytes written to `buf`.
#[no_mangle]
extern "C" fn kjit_rs_ibtc_slots_show(buf: *mut u8, len: usize) -> usize {
    // SAFETY: the C caller passes a writable buffer of `len` bytes.
    let buf = unsafe { core::slice::from_raw_parts_mut(buf, len) };
    let mut out = BufWriter { buf, len: 0 };
    // Up to IBTC_SLOTS rows (64 KiB): kvmalloc, not a contiguous kmalloc.
    let mut rows: KVVec<(u64, usize)> = KVVec::new();
    for (table, name) in TABLE_NAMES.iter().enumerate() {
        rows.clear();
        let mut total = 0u64;
        for (slot, diag) in DIAG[table * IBTC_SLOTS..][..IBTC_SLOTS].iter().enumerate() {
            let conflicts = diag.conflicts.load(Ordering::Relaxed);
            if conflicts == 0 {
                continue;
            }
            total += conflicts;
            if rows.push((conflicts, slot), GFP_KERNEL).is_err() {
                let _ = writeln!(out, "error: out of memory");
                return out.len;
            }
        }
        rows.sort_unstable_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
        let top = &rows[..rows.len().min(TOP_SLOTS)];
        let top_sum: u64 = top.iter().map(|row| row.0).sum();
        // `BufWriter` never fails.
        let _ = writeln!(
            out,
            "# table {name} conflicts {total} slots {} top{TOP_SLOTS} {top_sum}",
            rows.len()
        );
        for &(conflicts, slot) in top {
            let diag = &DIAG[table * IBTC_SLOTS + slot];
            let _ = writeln!(
                out,
                "{name} {slot} {conflicts} {:#x} {:#x}",
                diag.evictor.load(Ordering::Relaxed),
                diag.evicted.load(Ordering::Relaxed)
            );
        }
    }
    out.len
}
