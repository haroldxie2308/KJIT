// SPDX-License-Identifier: GPL-2.0

//! `kjit_after_syscall(regs)`: the decision table of tmp/pipeline.md, "K2
//! contract: kernel runtime". The kernel-side mirror of the harness's
//! `decide_runtime_return` (harness/src/runtime.rs), with the kernel's run
//! conditions re-checked before every entry and every in-kernel syscall.

use core::num::NonZeroU32;

use kernel::ffi::c_long;

use super::ffi::{self, KjitFrag, PtRegs};
use super::stats::{self, Stat};
use crate::shared::abi::RetStatus;

/// `kjit_profile` kinds (`enum kjit_hot_kind` in kjit_glue.c).
const HOT_SVC_RESUME: u32 = 0;
const HOT_EXIT_TARGET: u32 = 1;

/// "Return to userspace at regs->pc."
const TO_USER: c_long = -1;

const SVC: u64 = RetStatus::Svc.as_reg();
const BL: u64 = RetStatus::Bl.as_reg();
const BLR: u64 = RetStatus::Blr.as_reg();
const BR: u64 = RetStatus::Br.as_reg();
const RET: u64 = RetStatus::Ret.as_reg();
const MEM: u64 = RetStatus::Mem.as_reg();
const UNSUPPORTED: u64 = RetStatus::Unsupported.as_reg();
const BUDGET: u64 = RetStatus::Budget.as_reg();

/// A fragment reference taken by `kjit_lookup`, dropped on every path.
struct Running {
    frag: *mut KjitFrag,
    base: u64,
    /// Installed with the verifier's `uses_fpsimd`: every entry (chained ones
    /// included) runs inside the FP/SIMD bracket.
    fpsimd: bool,
}

impl Running {
    fn lookup(pc: u64, entry: &mut u64) -> Option<Self> {
        // SAFETY: called on the syscall path of the current task.
        let frag = unsafe { ffi::kjit_lookup(pc, entry) };
        if frag.is_null() {
            return None;
        }
        // SAFETY: `frag` is referenced until `Drop`.
        let (base, fpsimd) =
            unsafe { (ffi::kjit_frag_base(frag), ffi::kjit_frag_uses_fpsimd(frag)) };
        Some(Self { frag, base, fpsimd })
    }

    /// Runs the fragment from `entry` (`base` + one of its verified entry
    /// offsets); `extra` receives x10/x11. Returns the status in x0.
    fn call(&self, regs: *mut PtRegs, extra: &mut [u64; 2], entry: u64) -> u64 {
        stats::inc(Stat::FragmentEntries);
        // SAFETY (both calls): `entry` is `base` + a verified entry offset of
        // the referenced fragment; `extra` receives x10/x11 (epilogue `stp x10,
        // x11, [x1]`). A fragment the verifier found to use FP/SIMD only runs
        // inside the FP/SIMD bracket (kjit_glue.c), which makes the user's
        // FP/SIMD state live in the registers for the run.
        if self.fpsimd {
            stats::inc(Stat::FpsimdEntries);
            unsafe { ffi::kjit_call_fragment_fpsimd(regs, extra.as_mut_ptr(), entry, self.base) }
        } else {
            unsafe { ffi::kjit_call_fragment(regs, extra.as_mut_ptr(), entry, self.base) }
        }
    }

    /// The entry address for `pc` inside this fragment (one of its verified
    /// entry offsets), if it has one.
    fn entry_for(&self, pc: u64) -> Option<u64> {
        // SAFETY: `frag` is referenced.
        let offset = unsafe { ffi::kjit_frag_offset_for_pc(self.frag, pc) };
        u64::try_from(offset)
            .ok()
            .map(|offset| self.base.wrapping_add(offset))
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        // SAFETY: drops the reference `kjit_lookup` took.
        unsafe { ffi::kjit_frag_put(self.frag) }
    }
}

fn can_run(regs: *mut PtRegs) -> bool {
    // SAFETY: `regs` is the current task's pt_regs.
    unsafe { ffi::kjit_can_run(regs) }
}

/// Auto mode: one more hit of `pc`, where userspace resumes and current's mm
/// has no fragment. A no-op unless auto mode is on.
fn profile(pc: u64, kind: u32) {
    // SAFETY: called on the syscall path of the current task.
    unsafe { ffi::kjit_profile(pc, kind) }
}

/// Called by the kernel after a syscall without syscall work (0001's hook).
/// Returns a syscall number for the kernel to invoke next, or -1 to return to
/// userspace at `regs->pc`. Any user state the fragment produced is already in
/// `regs` (epilogue), so either way is exact.
#[no_mangle]
extern "C" fn kjit_rs_after_syscall(regs: *mut PtRegs) -> c_long {
    // SAFETY: the kernel passes the current task's pt_regs; nothing else
    // accesses them while this task runs this function.
    let pc = unsafe { (*regs).pc };
    if !can_run(regs) {
        return TO_USER;
    }
    let mut entry = 0u64;
    let Some(run) = Running::lookup(pc, &mut entry) else {
        profile(pc, HOT_SVC_RESUME);
        return TO_USER;
    };
    // SAFETY: reads a module parameter.
    let budget = unsafe { ffi::kjit_chain_budget() };
    let (ret, entries) = run_chain(regs, run, entry, budget);
    stats::note_chain(entries);
    ret
}

/// Runs `run` from `entry` and chains through branch exits while the run
/// conditions hold, for at most `budget` fragment entries (the first one
/// always runs): the `chain_budget` of tmp/pipeline.md, "K3", chaining rules.
/// Returns the hook's result and the number of entries made.
fn run_chain(
    regs: *mut PtRegs,
    mut run: Running,
    mut entry: u64,
    budget: u32,
) -> (c_long, NonZeroU32) {
    // SAFETY: as in `kjit_rs_after_syscall`.
    let pc = unsafe { (*regs).pc };
    let mut entries = NonZeroU32::MIN;

    loop {
        let mut extra = [0u64; 2];
        let status = run.call(regs, &mut extra, entry);
        let [param0, param1] = extra;

        match status {
            SVC => {
                // x11 = PC after the SVC; x8 holds the syscall number.
                stats::inc(Stat::ExitSvc);
                drop(run);
                // SAFETY: as above.
                let scno = unsafe { (*regs).regs[8] } as i32;
                // The kernel's own entry uses the low 32 bits of x8 as a signed
                // int; a negative one is left to the native SVC so its handling
                // stays the kernel's.
                if can_run(regs) && scno >= 0 {
                    // SAFETY: as above.
                    unsafe { (*regs).pc = param1 };
                    stats::inc(Stat::SyscallsInKernel);
                    return (scno as c_long, entries);
                }
                stats::inc(Stat::SvcDeclined);
                // SAFETY: as above. Userspace re-executes the SVC itself.
                unsafe { (*regs).pc = param1.wrapping_sub(4) };
                return (TO_USER, entries);
            }
            BL | BLR | BR | RET => {
                stats::inc(match status {
                    BL => Stat::ExitBl,
                    BLR => Stat::ExitBlr,
                    BR => Stat::ExitBr,
                    _ => Stat::ExitRet,
                });
                // x10 = branch target; BL/BLR already wrote x30.
                let target = param0;
                if entries.get() >= budget {
                    stats::inc(Stat::ChainCap);
                } else if can_run(regs) {
                    if let Some(next) = run.entry_for(target) {
                        entry = next;
                        entries = entries.saturating_add(1);
                        stats::inc(Stat::Chains);
                        continue;
                    }
                    if let Some(next) = Running::lookup(target, &mut entry) {
                        run = next;
                        entries = entries.saturating_add(1);
                        stats::inc(Stat::Chains);
                        continue;
                    }
                    // Exit-target learning: userspace resumes at `target`.
                    drop(run);
                    profile(target, HOT_EXIT_TARGET);
                }
                // SAFETY: as above.
                unsafe { (*regs).pc = target };
                return (TO_USER, entries);
            }
            // Never re-entered at x11: userspace executes that instruction (and
            // takes its fault, or runs the back-edge) natively.
            MEM | UNSUPPORTED | BUDGET => {
                stats::inc(match status {
                    MEM => Stat::ExitMem,
                    UNSUPPORTED => Stat::ExitUnsupported,
                    _ => Stat::ExitBudget,
                });
                if status == MEM && run.fpsimd {
                    // Taken under pagefault_disable(): includes faults that a
                    // fragment without FP/SIMD would have resolved in place.
                    stats::inc(Stat::FpsimdExitMem);
                }
                if status == UNSUPPORTED {
                    // x10 = the word (or UNSUPPORTED_WORD_UNREADABLE).
                    stats::note_unsupported(param0);
                }
                // SAFETY: as above.
                unsafe { (*regs).pc = param1 };
                return (TO_USER, entries);
            }
            _ => {
                stats::inc(Stat::ExitInvalid);
                drop(run);
                // SAFETY: current task context; WARN_ONCE + disable this mm.
                unsafe { ffi::kjit_bad_status(status, pc) };
                // SAFETY: as above.
                unsafe { (*regs).pc = param1 };
                return (TO_USER, entries);
            }
        }
    }
}
