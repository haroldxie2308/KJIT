// SPDX-License-Identifier: GPL-2.0

//! Global counters, read through `/sys/kernel/debug/kjit/stats`.

use core::fmt::Write;
use core::sync::atomic::{AtomicU64, Ordering};

#[derive(Clone, Copy)]
pub(crate) enum Stat {
    /// Syscalls the kernel invoked on a fragment's `Svc` exit (never went to EL0).
    SyscallsInKernel,
    /// Fragment calls (first entries and chained entries).
    FragmentEntries,
    /// Chained entries (branch exits continued in a fragment).
    Chains,
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
    TranslateCompileFailed,
    TranslateEncodeFailed,
    TranslateVerifyRejected,
    /// Verifier rejections with rule FallsOffEnd (known translator bug:
    /// a block at the end of readable text falls off the fragment).
    TranslateVerifyFallsOffEnd,
    /// An invalidation raced with a translation attempt (each attempt counts;
    /// the translation is retried a few times, then counted as failed here too).
    TranslateRaced,
    /// Install failed (memory, mm gone).
    TranslateInstallFailed,
    /// Fragments removed by an mmu_notifier range invalidation.
    Invalidated,
    /// Fragments removed at mm release, module unload, or after a runtime bug
    /// disabled the mm.
    Released,
    /// SVC words found by `translate_svc_sites`.
    SvcSitesScanned,
}

const COUNT: usize = Stat::SvcSitesScanned as usize + 1;

const NAMES: [&str; COUNT] = [
    "syscalls_in_kernel",
    "fragment_entries",
    "chains",
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
    "translate_compile_failed",
    "translate_encode_failed",
    "translate_verify_rejected",
    "translate_verify_falls_off_end",
    "translate_raced",
    "translate_install_failed",
    "invalidated_fragments",
    "released_fragments",
    "svc_sites_scanned",
];

#[allow(clippy::declare_interior_mutable_const)]
const ZERO: AtomicU64 = AtomicU64::new(0);
static STATS: [AtomicU64; COUNT] = [ZERO; COUNT];

pub(crate) fn add(stat: Stat, n: u64) {
    STATS[stat as usize].fetch_add(n, Ordering::Relaxed);
}

pub(crate) fn inc(stat: Stat) {
    add(stat, 1);
}

#[no_mangle]
extern "C" fn kjit_rs_note_invalidated(fragments: u64) {
    add(Stat::Invalidated, fragments);
}

#[no_mangle]
extern "C" fn kjit_rs_note_released(fragments: u64) {
    add(Stat::Released, fragments);
}

#[no_mangle]
extern "C" fn kjit_rs_note_svc_scan(sites: u64) {
    add(Stat::SvcSitesScanned, sites);
}

/// Writes into a byte buffer, silently stopping at its end (the caller sized
/// it for the whole table; a short read is still well-formed lines).
struct BufWriter<'a> {
    buf: &'a mut [u8],
    len: usize,
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
    out.len
}
