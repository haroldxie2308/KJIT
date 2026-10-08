// SPDX-License-Identifier: GPL-2.0

//! Global counters, read through `/sys/kernel/debug/kjit/stats`, and the
//! Unsupported-word histogram behind `/sys/kernel/debug/kjit/unsupported_top`.

use core::fmt::Write;
use core::num::NonZeroU32;
use core::sync::atomic::{AtomicU64, Ordering};

use kernel::alloc::flags::GFP_KERNEL;
use kernel::prelude::*;

use super::ffi;
use crate::shared::abi::UNSUPPORTED_WORD_UNREADABLE;

#[derive(Clone, Copy)]
pub(crate) enum Stat {
    /// Syscalls the kernel invoked on a fragment's `Svc` exit (never went to EL0).
    SyscallsInKernel,
    /// Fragment calls (first entries and chained entries): runtime round trips
    /// only since A11; a transfer dispatched inside fragment code is not
    /// counted (no atomics there), nor are the `exit_*` and `chains` of the
    /// runs it continues. Not comparable with A10 numbers.
    FragmentEntries,
    /// Chained entries (branch exits continued in a fragment by the runtime).
    Chains,
    /// Branch exits not chained because the hook call used its `chain_budget`
    /// of fragment entries.
    ChainCap,
    /// Hook calls that ended before their next fragment entry because a run
    /// condition failed (pending exit work such as `need_resched` or a signal,
    /// a traced or compat task): at the hook, for any task's syscall, or at a
    /// branch exit the chain budget allowed to chain.
    RunDeclined,
    ExitSvc,
    ExitBl,
    ExitBlr,
    ExitBr,
    ExitRet,
    ExitMem,
    ExitUnsupported,
    ExitBudget,
    /// Unknown status: WARN, KJIT disabled for the mm.
    ExitInvalid,
    /// `Svc` exits where a run condition failed on the re-check: userspace
    /// re-executes the SVC.
    SvcDeclined,
    TranslateOk,
    /// The entry PC already had a fragment.
    TranslateExists,
    /// The text could not be read: not in an executable, non-writable VMA,
    /// unmapped, or over the per-translation read budget.
    TranslateTextUnreadable,
    /// The entry instruction is not translatable (Unsupported exit at entry):
    /// refused, no fragment.
    TranslateEntryUnsupported,
    TranslateCompileFailed,
    TranslateEncodeFailed,
    TranslateVerifyRejected,
    /// Verifier rejections with rule FallsOffEnd (known translator bug:
    /// a block at the end of readable text falls off the fragment).
    TranslateVerifyFallsOffEnd,
    /// An invalidation raced with a translation attempt (each attempt counts;
    /// the translation is retried a few times, then counted as failed here too).
    TranslateRaced,
    /// Install refused: a per-mm or global fragment cap is reached.
    TranslateCapped,
    /// Install failed (memory, mm gone).
    TranslateInstallFailed,
    /// Fragments removed by an mmu_notifier range invalidation.
    Invalidated,
    /// Fragments removed at mm release, module unload, or after a runtime bug
    /// disabled the mm.
    Released,
    /// SVC words found by `translate_svc_sites`.
    SvcSitesScanned,
    // Auto mode (kjit_glue.c, "Auto mode"), bumped through `kjit_rs_note`.
    MmCreated,
    MmSetupFailed,
    ProfFull,
    HotNegative,
    HotCapped,
    HotQueueFull,
    ReqSvcResume,
    ReqExitTarget,
    ReqDropped,
    ReqStale,
    NegAdded,
    NegEvicted,
    TranslateNs,
    /// Unsupported exits whose word did not fit in `unsupported_top`.
    UnsupportedTopDropped,
    /// Unsupported exits whose x10 was neither a word nor the unreadable
    /// sentinel (a translator bug; not recorded in `unsupported_top`).
    UnsupportedBadWord,
    /// Fragment entries (chained ones included) of fragments that use FP/SIMD,
    /// each inside the FP/SIMD bracket (kjit_glue.c).
    FpsimdEntries,
    /// ... of which found TIF_FOREIGN_FPSTATE set and reloaded the user's
    /// FP/SIMD state first (bumped through `kjit_rs_note`).
    FpsimdRestores,
    /// `Mem` exits of those runs (page faults disabled: every user-access
    /// fault ends the run).
    FpsimdExitMem,
    /// Translations refused because they use FP/SIMD on a CPU with SVE/SME
    /// (or without FP/SIMD).
    FpsimdRefusedSveSme,
    /// Dispatch-table slot stores (A11), per table: one resolution of a branch
    /// target may store into `table_all` and `table_nofp`. Bumped through
    /// `kjit_rs_note`.
    IbtcInsert,
    /// ... of which the slot held another record.
    IbtcReplace,
    /// Slots cleared by the retirement of the fragment they pointed into.
    IbtcClear,
    /// Branch exits of a non-FP/SIMD run whose target resolved to an FP/SIMD
    /// fragment: the run continues through the runtime, never in fragment code.
    IbtcFpsimdBoundary,
    /// Branch exits (BL/BLR/BR/RET reaching `run_chain`) whose slot in the
    /// run's own dispatch table was empty. With the next two and
    /// `ibtc_fpsimd_boundary` they partition `exit_bl + exit_blr + exit_br +
    /// exit_ret`. Classified by `runtime/ibtc.rs` before anything is published.
    IbtcMissCold,
    /// ... whose slot held a record for another pc (the publish evicts it).
    IbtcMissConflict,
    /// ... whose slot held a record for the same pc: only through a race (a
    /// publish by another thread between the fragment's read and the
    /// runtime's).
    IbtcMissOther,
}

const COUNT: usize = Stat::IbtcMissOther as usize + 1;

const NAMES: [&str; COUNT] = [
    "syscalls_in_kernel",
    "fragment_entries",
    "chains",
    "chain_cap",
    "run_declined",
    "exit_svc",
    "exit_bl",
    "exit_blr",
    "exit_br",
    "exit_ret",
    "exit_mem",
    "exit_unsupported",
    "exit_budget",
    "exit_invalid",
    "svc_declined",
    "translate_ok",
    "translate_exists",
    "translate_text_unreadable",
    "translate_entry_unsupported",
    "translate_compile_failed",
    "translate_encode_failed",
    "translate_verify_rejected",
    "translate_verify_falls_off_end",
    "translate_raced",
    "translate_capped",
    "translate_install_failed",
    "invalidated_fragments",
    "released_fragments",
    "svc_sites_scanned",
    "auto_mm_created",
    "auto_mm_setup_failed",
    "auto_prof_full",
    "auto_hot_negative",
    "auto_hot_capped",
    "auto_hot_queue_full",
    "auto_req_svc_resume",
    "auto_req_exit_target",
    "auto_req_dropped",
    "auto_req_stale",
    "auto_neg_added",
    "auto_neg_evicted",
    "auto_translate_ns",
    "unsupported_top_dropped",
    "unsupported_bad_word",
    "fpsimd_entries",
    "fpsimd_restores",
    "fpsimd_exit_mem",
    "fpsimd_refused_sve_sme",
    "ibtc_insert",
    "ibtc_replace",
    "ibtc_clear",
    "ibtc_fpsimd_boundary",
    "ibtc_miss_cold",
    "ibtc_miss_conflict",
    "ibtc_miss_other",
];

#[allow(clippy::declare_interior_mutable_const)]
const ZERO: AtomicU64 = AtomicU64::new(0);
static STATS: [AtomicU64; COUNT] = [ZERO; COUNT];

/// Fragment entries per hook call that ran a fragment (chained entries plus
/// the first): the most seen, and a log2 histogram. Bucket `b` counts calls
/// with `2^b <= entries < 2^(b+1)`, one bucket per bit of a `u32`.
static CHAIN_MAX: AtomicU64 = ZERO;
const CHAIN_BUCKETS: usize = u32::BITS as usize;
static CHAIN_HIST: [AtomicU64; CHAIN_BUCKETS] = [ZERO; CHAIN_BUCKETS];

/// Records one hook call's fragment entries.
pub(crate) fn note_chain(entries: NonZeroU32) {
    CHAIN_MAX.fetch_max(u64::from(entries.get()), Ordering::Relaxed);
    CHAIN_HIST[entries.ilog2() as usize].fetch_add(1, Ordering::Relaxed);
}

pub(crate) fn add(stat: Stat, n: u64) {
    STATS[stat as usize].fetch_add(n, Ordering::Relaxed);
}

pub(crate) fn inc(stat: Stat) {
    add(stat, 1);
}

/// The counters `kjit_glue.c` bumps: `enum kjit_note` there, same values.
fn note_stat(note: u32) -> Option<Stat> {
    Some(match note {
        0 => Stat::Invalidated,
        1 => Stat::Released,
        2 => Stat::SvcSitesScanned,
        3 => Stat::MmCreated,
        4 => Stat::MmSetupFailed,
        5 => Stat::ProfFull,
        6 => Stat::HotNegative,
        7 => Stat::HotCapped,
        8 => Stat::HotQueueFull,
        9 => Stat::ReqSvcResume,
        10 => Stat::ReqExitTarget,
        11 => Stat::ReqDropped,
        12 => Stat::ReqStale,
        13 => Stat::NegAdded,
        14 => Stat::NegEvicted,
        15 => Stat::TranslateNs,
        16 => Stat::FpsimdRestores,
        17 => Stat::IbtcInsert,
        18 => Stat::IbtcReplace,
        19 => Stat::IbtcClear,
        _ => return None,
    })
}

#[no_mangle]
extern "C" fn kjit_rs_note(note: u32, n: u64) {
    match note_stat(note) {
        Some(stat) => add(stat, n),
        // A C/Rust mismatch of `enum kjit_note`: a build bug, not user input.
        None => pr_warn!("kjit: unknown note {note}\n"),
    }
}

/// `unsupported_top` slots: open addressing, a word may sit in any of the
/// `UNSUPPORTED_PROBE` slots from its hash slot. Lock-free: a slot's key is
/// claimed once (compare-exchange from empty) and never changes afterwards,
/// so a count is never attributed to another word.
const UNSUPPORTED_SLOTS: usize = 1024;
const UNSUPPORTED_PROBE: usize = 16;
/// Key of a slot: 0 = empty, else the word with bit 63 set (words are
/// <= u32::MAX), or `UNSUPPORTED_WORD_UNREADABLE` (u64::MAX) itself.
const WORD_TAG: u64 = 1 << 63;

#[allow(clippy::declare_interior_mutable_const)]
static UNSUPPORTED_KEYS: [AtomicU64; UNSUPPORTED_SLOTS] = [ZERO; UNSUPPORTED_SLOTS];
/// Unsupported exits at the word.
static UNSUPPORTED_EXITS: [AtomicU64; UNSUPPORTED_SLOTS] = [ZERO; UNSUPPORTED_SLOTS];
/// Branch exits to (or syscall returns at) a PC whose first word it is: no
/// fragment can start there, so the in-kernel path stops (kjit_glue.c,
/// `stop_word`; counted once the PC is in the negative cache).
static UNSUPPORTED_ENTRY_STOPS: [AtomicU64; UNSUPPORTED_SLOTS] = [ZERO; UNSUPPORTED_SLOTS];

/// Counts one Unsupported exit with x10 = `word`.
pub(crate) fn note_unsupported(word: u64) {
    note_word(word, &UNSUPPORTED_EXITS);
}

/// Counts one path stop at an untranslatable entry word.
#[no_mangle]
extern "C" fn kjit_rs_note_entry_stop(word: u32) {
    note_word(u64::from(word), &UNSUPPORTED_ENTRY_STOPS);
}

fn note_word(word: u64, counts: &[AtomicU64; UNSUPPORTED_SLOTS]) {
    let key = if word == UNSUPPORTED_WORD_UNREADABLE {
        word
    } else if word <= u64::from(u32::MAX) {
        word | WORD_TAG
    } else {
        inc(Stat::UnsupportedBadWord);
        return;
    };
    // Fibonacci hashing of the word.
    let hash = (word.wrapping_mul(0x9e37_79b9_7f4a_7c15) >> 54) as usize;
    for i in 0..UNSUPPORTED_PROBE {
        let slot = (hash + i) % UNSUPPORTED_SLOTS;
        let current = UNSUPPORTED_KEYS[slot].load(Ordering::Relaxed);
        let owned = current == key
            || (current == 0
                && match UNSUPPORTED_KEYS[slot].compare_exchange(
                    0,
                    key,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => true,
                    Err(actual) => actual == key,
                });
        if owned {
            counts[slot].fetch_add(1, Ordering::Relaxed);
            return;
        }
    }
    inc(Stat::UnsupportedTopDropped);
}

/// `word exits entry_stops` per line (`unreadable ...` for the sentinel),
/// highest `exits + entry_stops` first. Returns the number of bytes written to
/// `buf`.
#[no_mangle]
extern "C" fn kjit_rs_unsupported_show(buf: *mut u8, len: usize) -> usize {
    // SAFETY: the C caller passes a writable buffer of `len` bytes.
    let buf = unsafe { core::slice::from_raw_parts_mut(buf, len) };
    let mut out = BufWriter { buf, len: 0 };
    let mut rows: KVec<(u64, u64, u64)> = KVec::new();
    for slot in 0..UNSUPPORTED_SLOTS {
        let key = UNSUPPORTED_KEYS[slot].load(Ordering::Relaxed);
        let exits = UNSUPPORTED_EXITS[slot].load(Ordering::Relaxed);
        let stops = UNSUPPORTED_ENTRY_STOPS[slot].load(Ordering::Relaxed);
        if key != 0 && exits + stops != 0 && rows.push((key, exits, stops), GFP_KERNEL).is_err() {
            let _ = writeln!(out, "error: out of memory");
            return out.len;
        }
    }
    rows.sort_unstable_by(|a, b| (b.1 + b.2).cmp(&(a.1 + a.2)).then(a.0.cmp(&b.0)));
    for &(key, exits, stops) in rows.iter() {
        // Whole lines only: the longest is well under 64 bytes.
        if out.buf.len() - out.len < 64 {
            break;
        }
        // `BufWriter` never fails.
        let _ = if key == UNSUPPORTED_WORD_UNREADABLE {
            writeln!(out, "unreadable {exits} {stops}")
        } else {
            writeln!(out, "{:#010x} {exits} {stops}", key & !WORD_TAG)
        };
    }
    out.len
}

/// Writes into a byte buffer, silently stopping at its end (the caller sized
/// it for the whole table; a short read is still well-formed lines).
pub(super) struct BufWriter<'a> {
    pub(super) buf: &'a mut [u8],
    pub(super) len: usize,
}

impl Write for BufWriter<'_> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let room = self.buf.len() - self.len;
        let n = s.len().min(room);
        self.buf[self.len..self.len + n].copy_from_slice(&s.as_bytes()[..n]);
        self.len += n;
        Ok(())
    }
}

/// `name value` per line. Returns the number of bytes written to `buf`.
#[no_mangle]
extern "C" fn kjit_rs_stats_show(buf: *mut u8, len: usize) -> usize {
    // SAFETY: the C caller passes a writable buffer of `len` bytes.
    let buf = unsafe { core::slice::from_raw_parts_mut(buf, len) };
    let mut out = BufWriter { buf, len: 0 };
    for (name, value) in NAMES.iter().zip(STATS.iter()) {
        // `BufWriter` never fails.
        let _ = writeln!(out, "{name} {}", value.load(Ordering::Relaxed));
    }
    // SAFETY: plain read of per-CPU counters.
    let hook_calls = unsafe { ffi::kjit_hook_calls() };
    let _ = writeln!(out, "hook_calls {hook_calls}");
    // SAFETY: plain read of per-CPU maxima.
    let fpsimd_max = unsafe { ffi::kjit_fpsimd_run_max_ns() };
    let _ = writeln!(out, "fpsimd_run_max_ns {fpsimd_max}");
    let _ = writeln!(out, "chain_max {}", CHAIN_MAX.load(Ordering::Relaxed));
    // `chain_hist_<lo>_<hi> n`: hook calls with lo <= entries <= hi, the
    // non-empty buckets only (entries never exceed chain_budget <= 65536).
    for (bucket, count) in CHAIN_HIST.iter().enumerate() {
        let count = count.load(Ordering::Relaxed);
        if count != 0 {
            let lo = 1u64 << bucket;
            let _ = writeln!(out, "chain_hist_{lo}_{} {count}", 2 * lo - 1);
        }
    }
    out.len
}
