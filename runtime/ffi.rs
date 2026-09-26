// SPDX-License-Identifier: GPL-2.0

//! The C side of the runtime (`kjit_glue.c`). Types here mirror the C
//! definitions; the C file asserts the `pt_regs` offsets.

use kernel::ffi::c_int;

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

/// `struct kjit_label`: verified entry, original PC -> code offset.
#[repr(C)]
pub(crate) struct KjitLabel {
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
        labels: *const KjitLabel,
        n_labels: u32,
        src_start: u64,
        src_end: u64,
    ) -> c_int;

    pub(crate) fn kjit_can_run(regs: *const PtRegs) -> bool;
    pub(crate) fn kjit_lookup(pc: u64, entry: *mut u64) -> *mut KjitFrag;
    pub(crate) fn kjit_frag_put(frag: *mut KjitFrag);
    pub(crate) fn kjit_frag_base(frag: *const KjitFrag) -> u64;
    pub(crate) fn kjit_frag_offset_for_pc(frag: *const KjitFrag, pc: u64) -> i64;
    pub(crate) fn kjit_bad_status(status: u64, pc: u64);
    pub(crate) fn kjit_call_fragment(regs: *mut PtRegs, extra: *mut u64, entry: u64, base: u64)
        -> u64;
}
