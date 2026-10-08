// SPDX-License-Identifier: GPL-2.0

//! `kjit_after_syscall(regs)`: the decision table of docs/pipeline.md, "Kernel
//! runtime (K2)". The kernel-side mirror of the harness's
//! `decide_runtime_return` (harness/src/runtime.rs), with the kernel's run
//! conditions re-checked before every entry and every in-kernel syscall.

use core::num::NonZeroU32;

use kernel::ffi::c_long;

use super::ffi::{self, KjitFrag, PtRegs};
use super::stats::{self, Stat};
use crate::shared::abi::{RetStatus, EXTRA_PARAMS_WORDS, EXTRA_PARAM_IBTC_TABLE_INDEX};

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

/// A fragment found by `kjit_lookup`. No reference is held: the fragment stays
/// allocated until this hook call returns (it is freed a hook-SRCU grace
/// period after it is retired, kernel-patches/0007), also if it is retired
/// meanwhile. So a `Running` must not outlive the call that made it.
#[derive(Clone, Copy)]
struct Running {
    frag: *mut KjitFrag,
    base: u64,
    /// Installed with the verifier's `uses_fpsimd`: every entry (chained ones
    /// included) runs inside the FP/SIMD bracket.
    fpsimd: bool,
    /// The dispatch table of runs of this fragment (`kjit_frag_table`).
    table: u64,
}

impl Running {
    /// The fragment for `pc` and its entry address in `entry`. `link`: `pc` is
    /// a branch exit's target, resolved here, so its entry is also published in
    /// the dispatch tables.
    fn lookup(pc: u64, link: bool, entry: &mut u64) -> Option<Self> {
        // SAFETY: called on the syscall path of the current task, inside the
        // hook call.
        let frag = unsafe { ffi::kjit_lookup(pc, link, entry) };
        if frag.is_null() {
            return None;
        }
        // SAFETY: `frag` stays allocated for this hook call.
        let (base, fpsimd, table) = unsafe {
            (
                ffi::kjit_frag_base(frag),
                ffi::kjit_frag_uses_fpsimd(frag),
                ffi::kjit_frag_table(frag),
            )
        };
        Some(Self {
            frag,
            base,
            fpsimd,
            table,
        })
    }

    /// Runs the fragment from `entry` (the host address of one of its verified
    /// entries); `extra` receives x10/x11 and gets the dispatch table. Returns
    /// the status in x0.
    fn call(&self, regs: *mut PtRegs, extra: &mut [u64; EXTRA_PARAMS_WORDS], entry: u64) -> u64 {
        stats::inc(Stat::FragmentEntries);
        extra[EXTRA_PARAM_IBTC_TABLE_INDEX] = self.table;
        // SAFETY (both calls): `entry` is the host of a label of this
        // fragment; `extra` receives x10/x11 (epilogue `stp x10, x11, [x1]`)
        // and holds this run's dispatch table. A fragment the verifier found to
        // use FP/SIMD only runs inside the FP/SIMD bracket (kjit_glue.c), which
        // makes the user's FP/SIMD state live in the registers for the run.
        if self.fpsimd {
            stats::inc(Stat::FpsimdEntries);
            unsafe { ffi::kjit_call_fragment_fpsimd(regs, extra.as_mut_ptr(), entry, self.base) }
        } else {
            unsafe { ffi::kjit_call_fragment(regs, extra.as_mut_ptr(), entry, self.base) }
        }
    }

    /// A branch exit's target `pc` resolved inside this fragment: its verified
    /// entry address, if it has one, also published in the dispatch tables.
    fn link(&self, pc: u64) -> Option<u64> {
        // SAFETY: `frag` stays allocated for this hook call.
        let host = unsafe { ffi::kjit_frag_link(self.frag, pc) };
        (host != 0).then_some(host)
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
        stats::inc(Stat::RunDeclined);
        return TO_USER;
    }
    let mut entry = 0u64;
    let Some(run) = Running::lookup(pc, false, &mut entry) else {
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
/// always runs): the `chain_budget` of docs/pipeline.md, "Chaining rules".
/// Returns the hook's result and the number of entries made.
///
/// Since A11 an "entry" is a runtime round trip: a branch whose target is in
/// the run's dispatch table continues inside the fragment code and is neither
/// counted here nor preceded by the run-condition check. Between two checks a
/// run spends at most `KJIT_BACKEDGE_BUDGET` units (docs/pipeline.md, "Run
/// conditions (kjit_can_run)", bounds).
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
        let mut extra = [0u64; EXTRA_PARAMS_WORDS];
        let status = run.call(regs, &mut extra, entry);
        let (param0, param1) = (extra[0], extra[1]);

        match status {
            SVC => {
                // x11 = PC after the SVC; x8 holds the syscall number.
                stats::inc(Stat::ExitSvc);
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
                    if let Some(next) = run.link(target) {
                        entry = next;
                        entries = entries.saturating_add(1);
                        stats::inc(Stat::Chains);
                        continue;
                    }
                    if let Some(next) = Running::lookup(target, true, &mut entry) {
                        if next.fpsimd && !run.fpsimd {
                            // Published in table_all only: this run's table
                            // (table_nofp) never holds an FP/SIMD fragment.
                            stats::inc(Stat::IbtcFpsimdBoundary);
                        }
                        run = next;
                        entries = entries.saturating_add(1);
                        stats::inc(Stat::Chains);
                        continue;
                    }
                    // Exit-target learning: userspace resumes at `target`.
                    profile(target, HOT_EXIT_TARGET);
                } else {
                    stats::inc(Stat::RunDeclined);
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
                // SAFETY: current task context; WARN_ONCE + disable this mm.
                unsafe { ffi::kjit_bad_status(status, pc) };
                // SAFETY: as above.
                unsafe { (*regs).pc = param1 };
                return (TO_USER, entries);
            }
        }
    }
}
