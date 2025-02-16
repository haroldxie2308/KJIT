//! Module `svc_profiler`
//! 
//! NOTICE: This module is part of the UCA project.
//!
//! This module profiles incoming SVC operations and select intensive ones for translation and lift
//! by module `code_lifter`.

use core::sync::atomic::{AtomicPtr, Ordering};
use kernel::prelude::*;
use kernel::sync::Arc;
use kernel::task::pt_regs;
use super::code_lifter::*;
use super::ez_hash;

const NR_ONLINE_CPUS: usize = 6;
const NR_SVC_INFOS: usize = 32;
const LIFT_INTERVAL: usize = 100000;
// Each CPU has its own CpuInfo, so we should be good without synchronization primitives.
pub(crate) static GLOBAL_PROFILER: AtomicPtr<SvcProfiler> = AtomicPtr::new(core::ptr::null_mut());

fn get_cpu() -> u32 {
    // ! PENDING: another implementation might be simply read from system register with inline asm.
    // Safety: get the CPU of the current thread, this number is copied and should always be a safe operation.
    unsafe { (*kernel::task::Task::current_raw()).thread_info.cpu }
}

#[derive(Default)]
pub(crate) struct SvcInfo {
    pub(crate) pc: u64,
    pub(crate) pid: i32,
    pub(crate) count: usize,
}

impl SvcInfo {
    fn reset(&mut self) {
        self.pc = 0;
        self.pid = 0;
        self.count = 0;
    }
}

#[derive(Default)]
pub(crate) struct CpuInfo {
    pub(crate) count: usize,
    pub(crate) prev_ts: usize,
    pub(crate) svc_infos: Vec<SvcInfo>
}

impl CpuInfo {
    fn reset(&mut self, new_ts: usize) {
        self.count = 0;
        self.prev_ts = new_ts;
        let info_ptr = self.svc_infos.as_mut_ptr();
        for i in 0..self.svc_infos.len() {
            unsafe {
                let curr_info_ptr = info_ptr.add(i);
                (*curr_info_ptr).reset();
            }
        }
    } 
}

pub(crate) struct SvcProfiler {
    milestone: usize,
    intvl_thres: usize,
    svc_cnt_thres: usize,
    infos: Vec<CpuInfo>,
    // ! TEST
    count: usize,
    prev_pid: i32,
}

impl SvcProfiler {
    pub(crate) fn new() -> Self {
        let mut infos = Vec::new();
        for _ in 0..NR_ONLINE_CPUS {
            let mut svc_infos = Vec::new();
            for _ in 0..NR_SVC_INFOS {
                svc_infos.push(SvcInfo::default(), GFP_ATOMIC).unwrap();
            }
            infos.push(CpuInfo { count: 0, prev_ts: 0, svc_infos }, GFP_ATOMIC).unwrap();
        }
        Self {
            milestone: 1 << 13,     /* every 2^14 SVCs for one profiling */
            intvl_thres: 1 << 23,   /* time interval 16 */
            svc_cnt_thres: 1 << 7,  /* svc interval threshold 8 */
            infos,
            count: 0,
            prev_pid: 0,
        }
    }

    pub(crate) fn called(&mut self, regs: *mut pt_regs, ts: usize) {
        // if self.count > COUNT_LIMIT {
        //     return;
        // }

        let pid = current!().pid();
        let pc = unsafe { (*regs).__bindgen_anon_1.user_regs.pc };
        if pid == 0 || pc == 0 {
            return;
        }
        
        let cpu = get_cpu() as usize;
        let cpu_info: &mut CpuInfo = &mut self.infos[cpu];
        cpu_info.count += 1;

        if unsafe { send_lift(pc, pid, cpu, regs).is_ok() } {
            // If this entry point can be lifted, we simply returns.
            // ! PENDING: keep profiling to keep `ExecInfo`s fresh. (delete outdated ones)
            return;
        }
        
        let pos = ez_hash(pc, pid) % NR_SVC_INFOS;
        let curr_info: &mut SvcInfo = unsafe {
            &mut *cpu_info.svc_infos
                          .as_mut_ptr()
                          .add(pos)
        };

        if curr_info.pc == pc && curr_info.pid == pid {
            curr_info.count += 1;
        } else {
            curr_info.pc = pc;
            curr_info.pid = pid;
            curr_info.count = 1;
        }

        // ! PENDING: We want a better profiler than this!!!
        // If current CPU has encountered `milestone` SVCs, we do a profile for this particular CPU.
        if cpu_info.count > self.milestone {
            if ts - cpu_info.prev_ts < self.intvl_thres  {
                if curr_info.count > self.svc_cnt_thres {
                    // This particular `(pc, pid)` pair will no longer reach this line again as it will be lifted beforehand.
                    // So every time `milestone` SVCs are executed on some CPU, it will either capture a NEW hot SVC or not.

                    // ! PENDING: But we may be able to continue profiling and send a `del` signal to `code_lifter` to delete this info if it's no longer hot.
                    // Safety: We can send hot SVC with this particular `pid` (only).
                    unsafe { send_svc(pc, pid, cpu); }
                }
            }
            
            // Reset `CpuInfo` for a new round of profiling
            cpu_info.reset(ts);
        }
    }
}

/// Sends svc to `code_lifter` to prepare for lifted execution.
/// 
/// ## Safety
/// 
/// `pid` must corresponding to the current execution context, or UB is expected.
unsafe fn send_svc(pc: u64, pid: i32, cpu: usize) {
    unsafe {
        let lifter = *GLOBAL_LIFTER.as_ptr();
        (*lifter).prepare(pc, pid, cpu);
    }
}

/// Try lifting the code starting at `pc`. 
/// 
/// ## Safety
/// 
/// `pid`, `pc` and `regs` must correspond to the current execution context.
unsafe fn send_lift(pc: u64, pid: i32, cpu: usize, regs: *mut pt_regs) -> Result<()> {
    unsafe {
        let lifter = *GLOBAL_LIFTER.as_ptr();
        (*lifter).try_lift(pc, pid, cpu, regs)
    }
}

/// Initializes `svc_profiler` for `rust_uca`
pub(crate) fn up() {
    let profiler = Arc::new(SvcProfiler::new(), GFP_ATOMIC).unwrap();
    let profiler_ptr = Arc::into_raw(profiler) as *mut SvcProfiler;
    GLOBAL_PROFILER.store(profiler_ptr, Ordering::SeqCst);
}

pub(crate) fn down() {
    let profiler_ptr = GLOBAL_PROFILER.swap(core::ptr::null_mut(), Ordering::SeqCst);
    unsafe { Arc::from_raw(profiler_ptr); }
}
