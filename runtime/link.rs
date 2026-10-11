// SPDX-License-Identifier: GPL-2.0

//! The C glue's access to the shared link-slot encoder (docs/pipeline.md, "Direct BL
//! links (A16)"): the word `kjit_glue.c` patches into a slot is
//! `shared::abi::link_branch_word`'s, the function the harness code cache uses.

use crate::shared::abi::link_branch_word;

/// Writes `b <host>` for a link slot at `slot_addr` to `word` and returns true, or
/// returns false (writing nothing) if `host` is outside `b`'s +-128 MiB: the slot
/// stays a `nop`.
///
/// # Safety
///
/// `word` is valid for a write of a `u32`.
#[no_mangle]
unsafe extern "C" fn kjit_rs_link_branch_word(slot_addr: u64, host: u64, word: *mut u32) -> bool {
    match link_branch_word(slot_addr, host) {
        Some(value) => {
            // SAFETY: the caller passes a valid `word`.
            unsafe { word.write(value) };
            true
        }
        None => false,
    }
}
