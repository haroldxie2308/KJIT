// SPDX-License-Identifier: GPL-2.0

//! K2 kernel runtime: translate on request, run on the syscall return path.
//!
//! - `translate`: user text -> `compile_request` -> encode -> `verify_fragment`
//!   -> install (C: execmem + extable + code cache).
//! - `exec`: the `kjit_after_syscall` decision table (docs/pipeline.md,
//!   "kjit_after_syscall decision").
//! - `stats`: counters behind `/sys/kernel/debug/kjit/stats`.
//! - `ffi`: the C glue (`kjit_glue.c`): hook registration, code cache,
//!   mmu_notifier, fragment memory, trampoline, debugfs.

mod exec;
mod ffi;
mod stats;
mod translate;

use kernel::prelude::*;

/// Registers the syscall hook and creates `/sys/kernel/debug/kjit/`.
pub(crate) fn init() -> Result {
    // SAFETY: called once from module init.
    kernel::error::to_result(unsafe { ffi::kjit_glue_init() })
}

/// Unregisters the hook (waiting for calls in flight) and frees every fragment.
pub(crate) fn exit() {
    // SAFETY: called once from module exit, after a successful `init`.
    unsafe { ffi::kjit_glue_exit() }
}
