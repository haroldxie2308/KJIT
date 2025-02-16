use kernel::prelude::*;
use kernel::task::pt_regs;

mod svc_profiler;
mod code_lifter;

/// This function binds to `svc_bridge` function pointer during module initialization
#[no_mangle]
extern "C" fn svc_bridge_rust(regs: *mut pt_regs, ts: usize) {
    unsafe {
        let profiler = *svc_profiler::GLOBAL_PROFILER.as_ptr();
        (*profiler).called(regs, ts);
    }
}

extern "C" {
    // Declaration of `svc_bridge` function pointer in C
    // at entry_common.c under arch/arm64/kernel/
    static mut svc_bridge: Option<extern "C" fn(*mut pt_regs, usize)>;
}

pub(crate) fn up() {
	svc_profiler::up();
	code_lifter::up();
	unsafe { svc_bridge = Some(svc_bridge_rust); }
	pr_info!("UCA online\n");
}

pub(crate) fn down() {
	svc_profiler::down();
	code_lifter::down();
	unsafe { svc_bridge = None; }
	pr_info!("UCA offline\n");
}

/// Hash function for UCA
fn ez_hash(pc: u64, pid: i32) -> usize {
    (pc ^ 0x63CFDDB3 + pid as u64 ^ 0x8B1D1) as usize
}