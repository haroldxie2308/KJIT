// SPDX-License-Identifier: GPL-2.0

//! The C side of the runtime (`kjit_glue.c`). Types here mirror the C
//! definitions; the C file asserts the `pt_regs` offsets.

use kernel::ffi::c_int;

use crate::shared::abi::{
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
);

/// `struct kjit_mm`: per-mm code cache (opaque).
#[repr(C)]
pub(crate) struct KjitMm {
    _opaque: [u8; 0],
}

/// `struct kjit_frag`: one installed fragment (opaque).
#[repr(C)]
pub(crate) struct KjitFrag {
    _opaque: [u8; 0],
}

/// Prefix of arm64 `struct pt_regs` (`user_pt_regs`).
#[repr(C)]
pub(crate) struct PtRegs {
    pub(crate) regs: [u64; 31],
    pub(crate) sp: u64,
    pub(crate) pc: u64,
    pub(crate) pstate: u64,
}

/// `struct kjit_site`: a user access at code offset `access` resumes at `stub`.
#[repr(C)]
pub(crate) struct KjitSite {
    pub(crate) access: u32,
    pub(crate) stub: u32,
}

/// `struct kjit_entry`: a verified entry as `kjit_install` takes it, original
/// PC -> code offset (the C side turns it into a `kjit_label`: PC -> host).
#[repr(C)]
pub(crate) struct KjitEntry {
    pub(crate) pc: u64,
    pub(crate) offset: u32,
    pub(crate) pad: u32,
}

extern "C" {
    pub(crate) fn kjit_glue_init() -> c_int;
    pub(crate) fn kjit_glue_exit();

    pub(crate) fn kjit_mm_seq(kmm: *mut KjitMm) -> u64;
    pub(crate) fn kjit_read_text_page(kmm: *mut KjitMm, addr: u64, buf: *mut u8) -> c_int;
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn kjit_install(
        kmm: *mut KjitMm,
        seq: u64,
        entry_pc: u64,
        code: *const u8,
        code_len: u32,
        entry_offset: u32,
        sites: *const KjitSite,
        n_sites: u32,
        entries: *const KjitEntry,
        n_entries: u32,
        src_start: u64,
        src_end: u64,
        uses_fpsimd: bool,
    ) -> c_int;
    pub(crate) fn kjit_fpsimd_supported() -> bool;

    pub(crate) fn kjit_can_run(regs: *const PtRegs) -> bool;
    pub(crate) fn kjit_lookup(pc: u64, link: bool, entry: *mut u64) -> *mut KjitFrag;
    pub(crate) fn kjit_frag_base(frag: *const KjitFrag) -> u64;
    pub(crate) fn kjit_frag_link(frag: *mut KjitFrag, pc: u64) -> u64;
    pub(crate) fn kjit_frag_table(frag: *const KjitFrag) -> u64;
    pub(crate) fn kjit_frag_uses_fpsimd(frag: *const KjitFrag) -> bool;
    pub(crate) fn kjit_bad_status(status: u64, pc: u64);
    pub(crate) fn kjit_call_fragment(regs: *mut PtRegs, extra: *mut u64, entry: u64, base: u64)
        -> u64;
    pub(crate) fn kjit_call_fragment_fpsimd(
        regs: *mut PtRegs,
        extra: *mut u64,
        entry: u64,
        base: u64,
    ) -> u64;
    pub(crate) fn kjit_fpsimd_run_max_ns() -> u64;
    pub(crate) fn kjit_profile(pc: u64, kind: u32);
    pub(crate) fn kjit_hook_calls() -> u64;
    pub(crate) fn kjit_chain_budget() -> u32;
}
