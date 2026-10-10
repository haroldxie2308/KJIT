base='/Volumes/CaseSentitiveLocal/KJIT/.claude/worktrees/agent-a4b243dcf4b342be4/'
def edit(path, pairs):
    s=open(base+path).read()
    for old,new in pairs:
        assert s.count(old)==1, (path, s.count(old), old[:80])
        s=s.replace(old,new)
    open(base+path,'w').write(s)

edit('runtime/ibtc.rs', [
('''//! - empty: `ibtc_miss_cold`;
//! - a record for another pc: `ibtc_miss_conflict` (direct mapped: the publish
//!   that follows evicts it);
//! - a record for the same pc: `ibtc_miss_other`. Not a state the runtime can
//!   create: the fragment compares the full pc, so it can only mean another
//!   thread published that pc between the fragment's read and ours.''','''//! - empty: `ibtc_miss_cold`;
//! - a record for another pc: `ibtc_miss_conflict` (the publish that follows
//!   evicts it);
//! - a record for the same pc: `ibtc_miss_other`. Not a state the runtime can
//!   create: the fragment compares the full pc, so it can only mean another
//!   thread published that pc between the fragment's read and ours.
//!
//! "The slot" is the set of slots the selected variant's template probes for the pc
//! (`ibtc_lookup_slots`): one for the direct and hash variants; for the two-way
//! variants cold means a way is empty (the publish fills it) and conflict that both
//! ways hold other pcs (the publish evicts way 1's record); for the victim variants
//! the main slot decides (cold: empty; conflict: another pc, which the publish moves
//! to the victim table, evicting whatever sits there).'''),
('''//! Per slot, for each table class''','''//! Per primary slot (the first probed: the main-table slot, the set index), for each table class'''),
('''use crate::shared::abi::{ibtc_slot_index, IBTC_RECORD_PC_OFFSET, IBTC_SLOTS};''','''use crate::shared::abi::{
    ibtc_lookup_slots, ibtc_plan_publish, ibtc_table_bytes, ibtc_variant, select_ibtc_variant,
    IbtcSource, IbtcVariant, IBTC_BITS, IBTC_MAX_PROBES, IBTC_RECORD_PC_OFFSET,
};'''),
('''/// `TABLES` consecutive runs of `IBTC_SLOTS`: `DIAG[table * IBTC_SLOTS + slot]`.
static DIAG: [SlotDiag; TABLES * IBTC_SLOTS] = [ZERO_DIAG; TABLES * IBTC_SLOTS];

/// What a run's dispatch table held where a branch exit's target belongs.
#[derive(Clone, Copy)]
pub(super) struct Seen {
    table: usize,
    slot: usize,
    /// The pc of the record in the slot, if there was one.
    resident: Option<u64>,
}''','''/// Primary slots are below `1 << IBTC_BITS` in every variant (a main-table index, a
/// set index). `TABLES` consecutive runs of `DIAG_SLOTS`: `DIAG[table * DIAG_SLOTS +
/// slot]`.
const DIAG_SLOTS: usize = 1 << IBTC_BITS;
static DIAG: [SlotDiag; TABLES * DIAG_SLOTS] = [ZERO_DIAG; TABLES * DIAG_SLOTS];

#[derive(Clone, Copy)]
enum Class {
    Cold,
    /// Another pc's record would be evicted: this pc.
    Conflict(u64),
    Other,
}

/// What a run's dispatch table held where a branch exit's target belongs.
#[derive(Clone, Copy)]
pub(super) struct Seen {
    table: usize,
    /// The primary slot of the target.
    slot: usize,
    class: Class,
}

/// Classifies a miss on `target` by the pcs of the records in the slots the
/// template probes (`residents`, in probe order). See the module documentation.
fn classify(
    variant: IbtcVariant,
    target: u64,
    residents: &[Option<u64>; IBTC_MAX_PROBES],
    probes: usize,
) -> Class {
    if residents[..probes].contains(&Some(target)) {
        return Class::Other;
    }
    match variant {
        IbtcVariant::Direct | IbtcVariant::Hash | IbtcVariant::Victim { .. } => {
            match residents[0] {
                None => Class::Cold,
                Some(pc) => Class::Conflict(pc),
            }
        }
        IbtcVariant::TwoWay { .. } => match (residents[0], residents[1]) {
            (Some(_), Some(evicted)) => Class::Conflict(evicted),
            _ => Class::Cold,
        },
    }
}'''),
('''pub(super) fn probe(table: u64, all: bool, target: u64) -> Seen {
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
}''','''pub(super) fn probe(table: u64, all: bool, target: u64) -> Seen {
    let (slots, probes) = ibtc_lookup_slots(target);
    let mut residents = [None; IBTC_MAX_PROBES];
    for (resident, &slot) in residents.iter_mut().zip(&slots[..probes]) {
        *resident = record_pc(table as *const u64, slot);
    }
    Seen {
        table: if all { TABLE_ALL } else { TABLE_NOFP },
        slot: slots[0],
        class: classify(ibtc_variant(), target, &residents, probes),
    }
}

/// The pc of the record in word `slot` of `table`, if any.
fn record_pc(table: *const u64, slot: usize) -> Option<u64> {
    // SAFETY: `table` is the run's dispatch table (`kjit_frag_table`):
    // `ibtc_table_words()` 8-byte slots, freed only after a hook-SRCU grace period,
    // so valid for this hook call; `slot` comes from `ibtc_lookup_slots`, below the
    // table's size. Fragment code and publishers access slots concurrently: a
    // volatile read is READ_ONCE.
    let record = unsafe { core::ptr::read_volatile(table.add(slot)) };
    (record != 0).then(|| {
        // SAFETY: a non-zero slot holds a record (a `kjit_label`, `pc` at
        // IBTC_RECORD_PC_OFFSET) of a fragment of this mm. It can be retired
        // from now on, but is freed only after a hook-SRCU grace period, which
        // this hook call holds off (the slot is cleared before the grace
        // period starts, so a read that saw it set began before it): the same
        // argument as `kjit_ibtc_publish`'s.
        unsafe { core::ptr::read_volatile((record + u64::from(IBTC_RECORD_PC_OFFSET)) as *const u64) }
    })
}

/// Counts the miss on `target` that `probe` classified.
pub(super) fn note_miss(seen: Seen, target: u64) {
    match seen.class {
        Class::Cold => stats::inc(Stat::IbtcMissCold),
        Class::Other => stats::inc(Stat::IbtcMissOther),
        Class::Conflict(pc) => {
            stats::inc(Stat::IbtcMissConflict);
            let diag = &DIAG[seen.table * DIAG_SLOTS + seen.slot];
            diag.conflicts.fetch_add(1, Ordering::Relaxed);
            diag.evictor.store(target, Ordering::Relaxed);
            diag.evicted.store(pc, Ordering::Relaxed);
        }
    }
}

/// `struct kjit_ibtc_store` of `kjit_glue.c`: one planned slot store.
#[repr(C)]
pub(crate) struct IbtcStoreC {
    dst: u32,
    /// `IBTC_SRC_NEW`: the label being published; otherwise the slot whose
    /// current record is moved.
    src: u32,
}
const IBTC_SRC_NEW: u32 = u32::MAX;

/// The selected variant's table size in bytes (for the C side's allocation).
#[no_mangle]
extern "C" fn kjit_rs_ibtc_table_bytes() -> usize {
    ibtc_table_bytes()
}

/// Selects the dispatch variant (`ibtc_variant` module parameter) before any
/// translation, verification or table. Returns 0, or a negative errno-style value
/// for an unknown id.
#[no_mangle]
extern "C" fn kjit_rs_select_ibtc_variant(id: u32) -> i32 {
    match u8::try_from(id) {
        Ok(id) if select_ibtc_variant(id) => 0,
        _ => -22,
    }
}

/// The publish policy (`ibtc_plan_publish`, the function the harness code cache
/// runs) for a record of `pc` against `table`: writes up to two stores to `out`, in
/// the order they must be performed, and returns how many. The caller holds the
/// mm's lock: the records in the table are of live fragments and cannot be retired
/// under it.
///
/// # Safety
///
/// `table` is a dispatch table of the selected variant (`ibtc_table_bytes()`
/// bytes), `out` has room for two stores.
#[no_mangle]
unsafe extern "C" fn kjit_rs_ibtc_plan_publish(
    table: *const u64,
    pc: u64,
    out: *mut IbtcStoreC,
) -> u32 {
    let plan = ibtc_plan_publish(pc, &|slot| record_pc(table, slot));
    for (index, store) in plan.stores().iter().enumerate() {
        let src = match store.src {
            IbtcSource::New => IBTC_SRC_NEW,
            IbtcSource::Slot(slot) => slot as u32,
        };
        // SAFETY: `out` has room for two stores and a plan has at most two.
        unsafe { out.add(index).write(IbtcStoreC { dst: store.dst as u32, src }) };
    }
    plan.len as u32
}

/// The slots a record for `pc` may sit in (`ibtc_lookup_slots`): written to `out`
/// (room for two), returns how many. The retire path clears the ones that hold its
/// labels.
///
/// # Safety
///
/// `out` has room for two words.
#[no_mangle]
unsafe extern "C" fn kjit_rs_ibtc_lookup_slots(pc: u64, out: *mut u32) -> u32 {
    let (slots, probes) = ibtc_lookup_slots(pc);
    for (index, &slot) in slots[..probes].iter().enumerate() {
        // SAFETY: `out` has room for two words and a lookup has at most two slots.
        unsafe { out.add(index).write(slot as u32) };
    }
    probes as u32
}'''),
('''        let mut total = 0u64;
        for (slot, diag) in DIAG[table * IBTC_SLOTS..][..IBTC_SLOTS].iter().enumerate() {''','''        let mut total = 0u64;
        for (slot, diag) in DIAG[table * DIAG_SLOTS..][..DIAG_SLOTS].iter().enumerate() {'''),
('''            let diag = &DIAG[table * IBTC_SLOTS + slot];''','''            let diag = &DIAG[table * DIAG_SLOTS + slot];'''),
])

edit('runtime/ffi.rs', [
('''use crate::shared::abi::{
    IBTC_BITS, IBTC_INDEX_LSB, IBTC_RECORD_BYTES, IBTC_RECORD_HOST_OFFSET, IBTC_RECORD_PC_OFFSET,
    IBTC_SLOT_BYTES,
};

// kjit_glue.c mirrors the dispatch-table layout the template reads
// (`KJIT_IBTC_BITS`, `kjit_ibtc_index`, `struct kjit_label`, 8-byte slots); it
// cannot include the Rust constants, so a change here must change it too.
const _: () = assert!(
    IBTC_BITS == 12
        && IBTC_INDEX_LSB == 2
        && IBTC_SLOT_BYTES == 8
        && IBTC_RECORD_PC_OFFSET == 0
        && IBTC_RECORD_HOST_OFFSET == 8
        && IBTC_RECORD_BYTES == 16
);''','''use crate::shared::abi::{
    IBTC_RECORD_BYTES, IBTC_RECORD_HOST_OFFSET, IBTC_RECORD_PC_OFFSET, IBTC_SLOT_BYTES,
};

// kjit_glue.c mirrors the record layout the template reads (`struct kjit_label`,
// 8-byte slots); it cannot include the Rust constants, so a change here must change
// it too. Which slots a pc lives in, the table size and the publish policy are the
// selected variant's (`shared::abi` dispatch) and reach the C side through
// `kjit_rs_ibtc_*` (runtime/ibtc.rs).
const _: () = assert!(
    IBTC_SLOT_BYTES == 8
        && IBTC_RECORD_PC_OFFSET == 0
        && IBTC_RECORD_HOST_OFFSET == 8
        && IBTC_RECORD_BYTES == 16
);'''),
('''    pub(crate) fn kjit_glue_init() -> c_int;''','''    pub(crate) fn kjit_glue_ibtc_variant() -> u32;
    pub(crate) fn kjit_glue_init() -> c_int;'''),
])
