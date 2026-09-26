//! Native hardware oracle (Linux arm64 only).
//!
//! The interpreter in `arm64.rs` runs both the original code and the translated
//! fragment, so an interpreter semantics bug cancels out of the differential
//! check. This module runs both on the CPU instead:
//!
//! - **Original:** the fixture text is mapped at its text base with every SVC and
//!   every interpreter halt point replaced by a BRK. SVC traps apply the same mock
//!   as `execute_original_with_mocked_svc` (no state change, resume after it).
//!   A branch exit (RET/BR/BL/BLR) is then executed by the hardware alone in a
//!   copy of the text where every other word is a BRK, so the stop state includes
//!   the hardware's own link-register write and the branch target it took.
//! - **Fragment:** the encoded fragment is mapped RX and called like the kernel
//!   will call it (x0 = pt_regs, x1 = extra params, x2 = entry address, lr =
//!   return), driven by the same `decide_runtime_return` loop as `URuntime`.
//!
//! Register state enters and leaves user code through the signal frame: a BRK
//! in `kjit_native_enter_user` lets the SIGTRAP handler load every register from
//! the requested state, and every later trap or fault snapshots the registers
//! and resumes at `kjit_native_landing`, which restores the host's callee-saved
//! registers and returns to Rust. SIGSEGV/SIGBUS/SIGILL are reported as events,
//! never as a crash.
//!
//! TPIDR_EL0 is the host thread's TLS pointer, but user code and fragments read
//! the fixture's (`MachineState::tpidr_el0`, via `MRS`). It is switched to the
//! fixture value only while user code or a fragment runs; `kjit_native_signal_entry`
//! switches it back before any Rust (and so any TLS access) runs in the handler.

use core::arch::{asm, global_asm};
use core::cell::Cell;
use core::ffi::c_void;
use core::mem::{offset_of, size_of};
use core::ptr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard};

use crate::model::{ExecutionResult, Flags, HaltReason, MachineState, PagePerm, PAGE_SIZE};
use crate::runtime::{
    decide_runtime_return, validate_entry_offset, RuntimeAction, URuntimeHalt, PT_REGS_BYTES,
    PT_REGS_SP_OFFSET,
};
use crate::shared::abi::pt_regs_x_slot_offset;
use crate::shared::emit::layout::ExecutionFragment;
use crate::shared::trans::cfg::admit_word;
use crate::shared::trans::cfg::RuntimeExitReason;

/// Same continuation bound as `execute_original_with_mocked_svc` / `URuntime`.
const MAX_RUNTIME_EXITS: usize = 10_000;

const BRK_ENTER_IMM: u16 = 0x4b01;
const BRK_SVC_IMM: u16 = 0x4b02;
const BRK_STOP_IMM: u16 = 0x4b03;
const BRK_FILL_IMM: u16 = 0x4b04;
const BRK_SVC: u32 = brk(BRK_SVC_IMM);
const BRK_STOP: u32 = brk(BRK_STOP_IMM);
const BRK_FILL: u32 = brk(BRK_FILL_IMM);

const NZCV_MASK: u64 = 0xf000_0000;
const ALT_STACK_BYTES: usize = 256 * 1024;

const fn brk(imm16: u16) -> u32 {
    0xd420_0000 | ((imm16 as u32) << 5)
}

// ---------------------------------------------------------------------------
// libc FFI (Linux aarch64, glibc layouts)
// ---------------------------------------------------------------------------

const PROT_READ: i32 = 1;
const PROT_WRITE: i32 = 2;
const PROT_EXEC: i32 = 4;
const MAP_PRIVATE: i32 = 0x02;
const MAP_ANONYMOUS: i32 = 0x20;
const MAP_FIXED_NOREPLACE: i32 = 0x10_0000;
const SC_PAGESIZE: i32 = 30;
const SIGILL: i32 = 4;
const SIGTRAP: i32 = 5;
const SIGBUS: i32 = 7;
const SIGSEGV: i32 = 11;
const SA_SIGINFO: i32 = 4;
const SA_ONSTACK: i32 = 0x0800_0000;
const SS_DISABLE: i32 = 2;
const TRAP_BRKPT: i32 = 1;
const HANDLED_SIGNALS: [i32; 4] = [SIGILL, SIGTRAP, SIGBUS, SIGSEGV];

#[repr(C)]
#[derive(Clone, Copy)]
struct SigAction {
    sa_sigaction: usize,
    sa_mask: [u64; 16],
    sa_flags: i32,
    sa_restorer: usize,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct StackT {
    ss_sp: *mut c_void,
    ss_flags: i32,
    ss_size: usize,
}

#[repr(C)]
struct SigInfo {
    si_signo: i32,
    si_errno: i32,
    si_code: i32,
    _pad: i32,
    si_addr: u64,
}

#[repr(C, align(16))]
struct MContext {
    fault_address: u64,
    regs: [u64; 31],
    sp: u64,
    pc: u64,
    pstate: u64,
    // `__reserved` (FP/SIMD and ESR records) follows; never touched here.
}

#[repr(C)]
struct UContext {
    uc_flags: u64,
    uc_link: usize,
    uc_stack: StackT,
    uc_sigmask: [u64; 16],
    uc_mcontext: MContext,
}

const _: () = assert!(size_of::<SigAction>() == 152);
const _: () = assert!(offset_of!(SigInfo, si_addr) == 16);
const _: () = assert!(offset_of!(UContext, uc_mcontext) == 176);
const _: () = assert!(offset_of!(MContext, pc) == 264);

extern "C" {
    fn mmap(addr: *mut c_void, len: usize, prot: i32, flags: i32, fd: i32, off: i64)
        -> *mut c_void;
    fn mprotect(addr: *mut c_void, len: usize, prot: i32) -> i32;
    fn munmap(addr: *mut c_void, len: usize) -> i32;
    fn sysconf(name: i32) -> i64;
    fn sigaction(sig: i32, act: *const SigAction, old: *mut SigAction) -> i32;
    fn sigaltstack(ss: *const StackT, old: *mut StackT) -> i32;
}

fn os_error(what: &str) -> String {
    format!("{what}: {}", std::io::Error::last_os_error())
}

fn page_size() -> Result<usize, String> {
    let size = unsafe { sysconf(SC_PAGESIZE) };
    usize::try_from(size)
        .ok()
        .filter(|size| size.is_power_of_two())
        .ok_or_else(|| format!("sysconf(_SC_PAGESIZE) returned {size}"))
}

fn round_up(len: usize, page: usize) -> usize {
    (len + page - 1) & !(page - 1)
}

// ---------------------------------------------------------------------------
// Entry / landing trampolines
// ---------------------------------------------------------------------------

/// Shared with the asm below; every offset it uses is asserted.
#[repr(C)]
struct NativeCtx {
    /// Host x18, x19..x28, x29, x30, sp, d8..d15, saved on entry and restored by
    /// `kjit_native_landing`.
    host: [u64; 22],
    /// x18..x29 and sp right after the fragment returned, for the C ABI check.
    after_call: [u64; 13],
    /// Fragment return value (x0 = RetStatus) and NZCV after the call.
    status: u64,
    nzcv: u64,
    /// In: user state to start (enter_user). Out: register snapshot at the event.
    user: UserRegs,
    event: Event,
    /// In: the fragment's fault-site redirects while a fragment call runs.
    fault_fixup: FaultFixup,
    /// Out: data aborts redirected to a fault stub during the call.
    fault_redirects: u64,
}

/// The kernel's user-access fixup (tmp/pipeline.md, "Fault sites (A5)"): a data
/// abort at `base + access_offset` resumes at `base + stub_offset`, nothing else
/// changes. `sites` is sorted by access offset. Empty outside fragment calls.
#[repr(C)]
#[derive(Clone, Copy)]
struct FaultFixup {
    base: u64,
    len: u64,
    sites: *const FixupSite,
    sites_len: usize,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct FixupSite {
    access_offset: u64,
    stub_offset: u64,
}

impl FaultFixup {
    const NONE: Self = Self {
        base: 0,
        len: 0,
        sites: ptr::null(),
        sites_len: 0,
    };

    /// Async-signal-safe: reads only the caller-owned site slice.
    unsafe fn stub_for(&self, pc: u64) -> Option<u64> {
        let offset = pc
            .checked_sub(self.base)
            .filter(|offset| *offset < self.len)?;
        let sites = core::slice::from_raw_parts(self.sites, self.sites_len);
        sites
            .binary_search_by_key(&offset, |site| site.access_offset)
            .ok()
            .map(|index| self.base + sites[index].stub_offset)
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct UserRegs {
    x: [u64; 31],
    sp: u64,
    pc: u64,
    pstate: u64,
}

/// `signal == 0`: the fragment returned normally.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct Event {
    signal: i32,
    pc: u64,
    fault_addr: u64,
    /// The trapping BRK word for a SIGTRAP from a BRK, else 0 (never a BRK).
    brk_word: u32,
}

impl Event {
    fn brk(&self) -> Option<u32> {
        (self.brk_word != 0).then_some(self.brk_word)
    }
}

const HOST_SP_INDEX: usize = 13;
const _: () = assert!(offset_of!(NativeCtx, host) == 0);
const _: () = assert!(offset_of!(NativeCtx, after_call) == 176);
const _: () = assert!(offset_of!(NativeCtx, status) == 280);
const _: () = assert!(offset_of!(NativeCtx, nzcv) == 288);

impl NativeCtx {
    fn new(user: UserRegs) -> Self {
        Self {
            host: [0; 22],
            after_call: [0; 13],
            status: 0,
            nzcv: 0,
            user,
            event: Event::default(),
            fault_fixup: FaultFixup::NONE,
            fault_redirects: 0,
        }
    }
}

global_asm!(
    ".macro KJIT_NATIVE_SAVE_HOST",
    "    str x18, [x0, #0]",
    "    stp x19, x20, [x0, #8]",
    "    stp x21, x22, [x0, #24]",
    "    stp x23, x24, [x0, #40]",
    "    stp x25, x26, [x0, #56]",
    "    stp x27, x28, [x0, #72]",
    "    stp x29, x30, [x0, #88]",
    "    mov x9, sp",
    "    str x9, [x0, #104]",
    "    stp d8, d9, [x0, #112]",
    "    stp d10, d11, [x0, #128]",
    "    stp d12, d13, [x0, #144]",
    "    stp d14, d15, [x0, #160]",
    ".endm",
    "",
    ".text",
    ".balign 4",
    // void kjit_native_enter_user(NativeCtx *ctx)
    // Saves the host, then traps; the SIGTRAP handler loads ctx->user.
    ".globl kjit_native_enter_user",
    ".type kjit_native_enter_user, %function",
    "kjit_native_enter_user:",
    "    KJIT_NATIVE_SAVE_HOST",
    ".globl kjit_native_enter_user_brk",
    "kjit_native_enter_user_brk:",
    "    brk #{enter}",
    ".size kjit_native_enter_user, . - kjit_native_enter_user",
    "",
    // void kjit_native_call_fragment(NativeCtx *ctx, u64 *pt_regs, u64 *extra,
    //                                u64 entry_addr, u64 fragment_base, u64 nzcv)
    ".globl kjit_native_call_fragment",
    ".type kjit_native_call_fragment, %function",
    "kjit_native_call_fragment:",
    "    KJIT_NATIVE_SAVE_HOST",
    "    sub sp, sp, #16",
    "    str x0, [sp]",
    "    msr nzcv, x5",
    "    adrp x10, {user_tpidr}",
    "    ldr x10, [x10, :lo12:{user_tpidr}]",
    "    msr tpidr_el0, x10",
    "    mov x9, x4",
    "    mov x0, x1",
    "    mov x1, x2",
    "    mov x2, x3",
    "    blr x9",
    "    mrs x10, nzcv",
    "    adrp x11, {host_tpidr}",
    "    ldr x11, [x11, :lo12:{host_tpidr}]",
    "    msr tpidr_el0, x11",
    "    ldr x9, [sp]",
    "    add sp, sp, #16",
    "    str x18, [x9, #176]",
    "    stp x19, x20, [x9, #184]",
    "    stp x21, x22, [x9, #200]",
    "    stp x23, x24, [x9, #216]",
    "    stp x25, x26, [x9, #232]",
    "    stp x27, x28, [x9, #248]",
    "    str x29, [x9, #264]",
    "    mov x11, sp",
    "    str x11, [x9, #272]",
    "    str x0, [x9, #280]",
    "    str x10, [x9, #288]",
    // Falls through: restore the host and return.
    // Also the signal handler's resume point, with x9 = ctx.
    ".globl kjit_native_landing",
    "kjit_native_landing:",
    "    ldr x18, [x9, #0]",
    "    ldp x19, x20, [x9, #8]",
    "    ldp x21, x22, [x9, #24]",
    "    ldp x23, x24, [x9, #40]",
    "    ldp x25, x26, [x9, #56]",
    "    ldp x27, x28, [x9, #72]",
    "    ldp x29, x30, [x9, #88]",
    "    ldr x10, [x9, #104]",
    "    mov sp, x10",
    "    ldp d8, d9, [x9, #112]",
    "    ldp d10, d11, [x9, #128]",
    "    ldp d12, d13, [x9, #144]",
    "    ldp d14, d15, [x9, #160]",
    "    ret",
    ".size kjit_native_call_fragment, . - kjit_native_call_fragment",
    "",
    // The installed sa_sigaction. If TPIDR_EL0 holds the fixture value of the
    // run in progress, restores the host's before `on_signal` touches TLS. Any
    // other thread's TPIDR_EL0 is a real TLS pointer and never that value: the
    // fixture value lies in the fixture data window, which the run maps fixed.
    ".globl kjit_native_signal_entry",
    ".type kjit_native_signal_entry, %function",
    "kjit_native_signal_entry:",
    "    adrp x9, {user_tpidr}",
    "    ldr x9, [x9, :lo12:{user_tpidr}]",
    "    cbz x9, 1f",
    "    mrs x10, tpidr_el0",
    "    cmp x9, x10",
    "    b.ne 1f",
    "    adrp x10, {host_tpidr}",
    "    ldr x10, [x10, :lo12:{host_tpidr}]",
    "    msr tpidr_el0, x10",
    "1:",
    "    b {on_signal}",
    ".size kjit_native_signal_entry, . - kjit_native_signal_entry",
    enter = const BRK_ENTER_IMM,
    user_tpidr = sym USER_TPIDR,
    host_tpidr = sym HOST_TPIDR,
    on_signal = sym on_signal,
);

/// TPIDR_EL0 of the native run in progress, or 0 when none is (read by the asm).
static USER_TPIDR: AtomicU64 = AtomicU64::new(0);
/// The session thread's own TPIDR_EL0, restored whenever Rust runs again.
static HOST_TPIDR: AtomicU64 = AtomicU64::new(0);

fn read_tpidr_el0() -> u64 {
    let value: u64;
    unsafe { asm!("mrs {}, tpidr_el0", out(reg) value, options(nomem, nostack)) };
    value
}

/// Publishes the fixture TPIDR_EL0 for one native run; cleared on drop.
struct UserTpidr;

impl UserTpidr {
    fn set(user: u64) -> Result<Self, String> {
        let host = read_tpidr_el0();
        if user == 0 || user == host {
            return Err(format!(
                "fixture TPIDR_EL0 {user:#x} must be nonzero and differ from the host's {host:#x}"
            ));
        }
        HOST_TPIDR.store(host, Ordering::SeqCst);
        USER_TPIDR.store(user, Ordering::SeqCst);
        Ok(Self)
    }
}

impl Drop for UserTpidr {
    fn drop(&mut self) {
        USER_TPIDR.store(0, Ordering::SeqCst);
    }
}

extern "C" {
    fn kjit_native_enter_user(ctx: *mut NativeCtx);
    fn kjit_native_enter_user_brk();
    fn kjit_native_call_fragment(
        ctx: *mut NativeCtx,
        pt_regs: *mut u64,
        extra_params: *mut u64,
        entry_addr: u64,
        fragment_base: u64,
        nzcv: u64,
    );
    fn kjit_native_landing();
    fn kjit_native_signal_entry();
}

// ---------------------------------------------------------------------------
// Signal handling
// ---------------------------------------------------------------------------

thread_local! {
    /// Context of the native run in progress on this thread, or null.
    static ACTIVE_CTX: Cell<*mut NativeCtx> = const { Cell::new(ptr::null_mut()) };
}

/// Handlers replaced by the live `NativeSession`, indexed like `HANDLED_SIGNALS`.
/// Written only while `SESSION_LOCK` is held and no handler of ours is installed.
static mut PREVIOUS_ACTIONS: [SigAction; 4] = [SigAction {
    sa_sigaction: 0,
    sa_mask: [0; 16],
    sa_flags: 0,
    sa_restorer: 0,
}; 4];

static SESSION_LOCK: Mutex<()> = Mutex::new(());

extern "C" fn on_signal(sig: i32, info: *mut SigInfo, uc: *mut c_void) {
    let ctx = ACTIVE_CTX.with(Cell::get);
    unsafe {
        if ctx.is_null() {
            // Not raised by a native run on this thread (e.g. a stack overflow in
            // another test): reinstall the previous handler and return, so the
            // faulting instruction re-executes and faults under it.
            if let Some(index) = HANDLED_SIGNALS.iter().position(|s| *s == sig) {
                let previous = ptr::addr_of!(PREVIOUS_ACTIONS[index]);
                sigaction(sig, previous, ptr::null_mut());
            }
            return;
        }

        let mc = &mut (*(uc as *mut UContext)).uc_mcontext;
        if sig == SIGTRAP && mc.pc == kjit_native_enter_user_brk as usize as u64 {
            let user = (*ctx).user;
            mc.regs = user.x;
            mc.sp = user.sp;
            mc.pc = user.pc;
            mc.pstate = (mc.pstate & !NZCV_MASK) | (user.pstate & NZCV_MASK);
            // Last: no TLS access may follow until the next signal switches back.
            asm!(
                "msr tpidr_el0, {}",
                in(reg) USER_TPIDR.load(Ordering::SeqCst),
                options(nostack)
            );
            return;
        }

        // A user access of the fragment faulted: exactly the kernel's fixup. Only
        // the PC changes; then the fragment's own TPIDR_EL0 (a fragment never
        // writes it, so it is still the run's value) goes back, last.
        if sig == SIGSEGV || sig == SIGBUS {
            if let Some(stub) = (*ctx).fault_fixup.stub_for(mc.pc) {
                mc.pc = stub;
                (*ctx).fault_redirects += 1;
                asm!(
                    "msr tpidr_el0, {}",
                    in(reg) USER_TPIDR.load(Ordering::SeqCst),
                    options(nostack)
                );
                return;
            }
        }

        // A BRK was fetched from pc, so the word is readable.
        let brk_word = if sig == SIGTRAP && (*info).si_code == TRAP_BRKPT {
            ptr::read_volatile(mc.pc as *const u32)
        } else {
            0
        };
        (*ctx).event = Event {
            signal: sig,
            pc: mc.pc,
            fault_addr: (*info).si_addr,
            brk_word,
        };
        (*ctx).user = UserRegs {
            x: mc.regs,
            sp: mc.sp,
            pc: mc.pc,
            pstate: mc.pstate,
        };
        mc.regs[9] = ctx as u64;
        mc.sp = (*ctx).host[HOST_SP_INDEX];
        mc.pc = kjit_native_landing as usize as u64;
    }
}

/// Owns the process-wide native-run setup: our handlers for SIGILL/SIGTRAP/
/// SIGBUS/SIGSEGV and an alternate signal stack on the current thread (user SP
/// is arbitrary while fixture code runs). One session at a time per process;
/// every native run must happen on the thread that created it.
pub struct NativeSession {
    _lock: MutexGuard<'static, ()>,
    /// Registered with sigaltstack until Drop; unmapped after.
    _alt_stack: Mapping,
    previous_alt_stack: StackT,
    page: usize,
}

impl NativeSession {
    pub fn new() -> Result<Self, String> {
        // A poisoned lock only records that an earlier session's thread panicked;
        // its Drop still restored the handlers, so the lock state is valid.
        let lock = SESSION_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let page = page_size()?;
        let alt_stack = Mapping::anywhere(ALT_STACK_BYTES, PROT_READ | PROT_WRITE)?;
        let stack = StackT {
            ss_sp: alt_stack.addr as *mut c_void,
            ss_flags: 0,
            ss_size: alt_stack.len,
        };
        let mut previous_alt_stack = StackT {
            ss_sp: ptr::null_mut(),
            ss_flags: SS_DISABLE,
            ss_size: 0,
        };
        if unsafe { sigaltstack(&stack, &mut previous_alt_stack) } != 0 {
            return Err(os_error("sigaltstack"));
        }

        let action = SigAction {
            sa_sigaction: kjit_native_signal_entry as usize,
            sa_mask: [0; 16],
            sa_flags: SA_SIGINFO | SA_ONSTACK,
            sa_restorer: 0,
        };
        for (index, sig) in HANDLED_SIGNALS.iter().enumerate() {
            let previous = unsafe { ptr::addr_of_mut!(PREVIOUS_ACTIONS[index]) };
            if unsafe { sigaction(*sig, &action, previous) } != 0 {
                let err = os_error("sigaction");
                restore_handlers(index);
                unsafe { sigaltstack(&previous_alt_stack, ptr::null_mut()) };
                return Err(err);
            }
        }

        Ok(Self {
            _lock: lock,
            _alt_stack: alt_stack,
            previous_alt_stack,
            page,
        })
    }

    /// Starts user code at `regs.pc` with every register from `regs` and runs it
    /// until the first trap or fault.
    fn enter_user(&self, regs: UserRegs, tpidr: u64) -> Result<(Event, UserRegs), String> {
        let mut ctx = NativeCtx::new(regs);
        let _tpidr = UserTpidr::set(tpidr)?;
        let _active = ActiveCtx::set(&mut ctx);
        unsafe { kjit_native_enter_user(&mut ctx) };
        Ok((ctx.event, ctx.user))
    }

    fn call_fragment(
        &self,
        pt_regs: &mut [u64],
        extra_params: &mut [u64; 2],
        entry_addr: u64,
        fragment_base: u64,
        fragment_len: u64,
        fault_sites: &[FixupSite],
        nzcv: u64,
        tpidr: u64,
    ) -> Result<Box<NativeCtx>, String> {
        let mut ctx = Box::new(NativeCtx::new(UserRegs::default()));
        ctx.fault_fixup = FaultFixup {
            base: fragment_base,
            len: fragment_len,
            sites: fault_sites.as_ptr(),
            sites_len: fault_sites.len(),
        };
        let _tpidr = UserTpidr::set(tpidr)?;
        let _active = ActiveCtx::set(&mut ctx);
        unsafe {
            kjit_native_call_fragment(
                &mut *ctx,
                pt_regs.as_mut_ptr(),
                extra_params.as_mut_ptr(),
                entry_addr,
                fragment_base,
                nzcv,
            )
        };
        Ok(ctx)
    }
}

impl Drop for NativeSession {
    fn drop(&mut self) {
        restore_handlers(HANDLED_SIGNALS.len());
        // `_alt_stack` is unmapped after this, once it is no longer registered.
        unsafe { sigaltstack(&self.previous_alt_stack, ptr::null_mut()) };
    }
}

fn restore_handlers(count: usize) {
    for (index, sig) in HANDLED_SIGNALS.iter().take(count).enumerate() {
        unsafe {
            sigaction(
                *sig,
                ptr::addr_of!(PREVIOUS_ACTIONS[index]),
                ptr::null_mut(),
            )
        };
    }
}

struct ActiveCtx;

impl ActiveCtx {
    fn set(ctx: &mut NativeCtx) -> Self {
        ACTIVE_CTX.with(|cell| cell.set(ctx));
        Self
    }
}

impl Drop for ActiveCtx {
    fn drop(&mut self) {
        ACTIVE_CTX.with(|cell| cell.set(ptr::null_mut()));
    }
}

// ---------------------------------------------------------------------------
// Memory mappings
// ---------------------------------------------------------------------------

struct Mapping {
    addr: *mut u8,
    len: usize,
}

impl Mapping {
    /// Maps exactly at `addr`; fails if anything is already mapped there.
    fn fixed(addr: u64, len: usize, prot: i32) -> Result<Self, String> {
        let got = unsafe {
            mmap(
                addr as *mut c_void,
                len,
                prot,
                MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
                -1,
                0,
            )
        };
        if got as isize == -1 {
            return Err(os_error(&format!("mmap fixed {addr:#x}+{len:#x}")));
        }
        let mapping = Self {
            addr: got as *mut u8,
            len,
        };
        // Kernels before 4.17 ignore MAP_FIXED_NOREPLACE and treat addr as a hint.
        if got as u64 != addr {
            return Err(format!(
                "mmap fixed {addr:#x} landed at {got:p}; is vm.mmap_min_addr above it?"
            ));
        }
        Ok(mapping)
    }

    fn anywhere(len: usize, prot: i32) -> Result<Self, String> {
        let got = unsafe {
            mmap(
                ptr::null_mut(),
                len,
                prot,
                MAP_PRIVATE | MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if got as isize == -1 {
            return Err(os_error(&format!("mmap {len:#x}")));
        }
        Ok(Self {
            addr: got as *mut u8,
            len,
        })
    }

    fn base(&self) -> u64 {
        self.addr as u64
    }

    fn contains(&self, addr: u64) -> bool {
        addr >= self.base() && addr - self.base() < self.len as u64
    }

    fn protect(&self, prot: i32) -> Result<(), String> {
        if unsafe { mprotect(self.addr as *mut c_void, self.len, prot) } != 0 {
            return Err(os_error("mprotect"));
        }
        Ok(())
    }

    /// Replaces the mapping's contents with `words`, BRK-filled to the end, and
    /// makes it RX with the instruction cache synchronized.
    fn install_code(&self, words: &[u32]) -> Result<(), String> {
        if words.len() * 4 > self.len {
            return Err("code does not fit its mapping".to_string());
        }
        self.protect(PROT_READ | PROT_WRITE)?;
        let slots = unsafe { core::slice::from_raw_parts_mut(self.addr as *mut u32, self.len / 4) };
        for (index, slot) in slots.iter_mut().enumerate() {
            *slot = words.get(index).copied().unwrap_or(BRK_FILL);
        }
        self.protect(PROT_READ | PROT_EXEC)?;
        sync_icache(self.base(), self.len);
        Ok(())
    }

    fn read_u64(&self, offset: usize) -> u64 {
        assert!(offset + 8 <= self.len);
        unsafe { ptr::read_volatile(self.addr.add(offset) as *const u64) }
    }
}

impl Drop for Mapping {
    fn drop(&mut self) {
        unsafe { munmap(self.addr as *mut c_void, self.len) };
    }
}

/// Makes freshly written code visible to instruction fetch (Arm ARM D7.5.2).
fn sync_icache(start: u64, len: usize) {
    let ctr: u64;
    unsafe { asm!("mrs {}, ctr_el0", out(reg) ctr) };
    let dline = 4u64 << ((ctr >> 16) & 0xf);
    let iline = 4u64 << (ctr & 0xf);
    let end = start + len as u64;
    let mut addr = start & !(dline - 1);
    while addr < end {
        unsafe { asm!("dc cvau, {}", in(reg) addr) };
        addr += dline;
    }
    unsafe { asm!("dsb ish") };
    addr = start & !(iline - 1);
    while addr < end {
        unsafe { asm!("ic ivau, {}", in(reg) addr) };
        addr += iline;
    }
    unsafe { asm!("dsb ish", "isb") };
}

/// The interpreter's user page map, mapped natively at the same addresses with
/// the same permissions (read-only -> PROT_READ, read-write -> PROT_READ |
/// PROT_WRITE) and seeded from the initial memory.
struct UserMemory {
    pages: Vec<(Mapping, PagePerm)>,
}

impl UserMemory {
    fn map(initial: &MachineState, host_page: usize) -> Result<Self, String> {
        // One mapping per interpreter page, so permissions must be per 4 KiB.
        if host_page as u64 != PAGE_SIZE {
            return Err(format!(
                "host page size {host_page:#x} differs from the interpreter's {PAGE_SIZE:#x}"
            ));
        }
        let mut pages = Vec::new();
        for (base, perm) in initial.user_pages() {
            let page = Mapping::fixed(base, PAGE_SIZE as usize, PROT_READ | PROT_WRITE)?;
            pages.push((page, perm));
        }
        let memory = Self { pages };
        for (&addr, &byte) in initial.memory() {
            let Some((page, _)) = memory.pages.iter().find(|(page, _)| page.contains(addr)) else {
                return Err(format!(
                    "initial memory byte at {addr:#x} is not in a mapped user page"
                ));
            };
            unsafe { *page.addr.add((addr - page.base()) as usize) = byte };
        }
        for (page, perm) in &memory.pages {
            page.protect(match perm {
                PagePerm::ReadOnly => PROT_READ,
                PagePerm::ReadWrite => PROT_READ | PROT_WRITE,
            })?;
        }
        Ok(memory)
    }
}

/// `base` with its registers, SP, NZCV and every mapped user page replaced by
/// the native values. Zero bytes are dropped by `write_u64`, matching the
/// interpreter's sparse memory.
fn native_state(base: &MachineState, regs: &UserRegs, memory: &UserMemory) -> MachineState {
    let mut state = base.clone();
    for reg in 0..31u8 {
        state.write_x(reg, regs.x[reg as usize]);
    }
    state.set_sp(regs.sp);
    state.flags = nzcv_to_flags(regs.pstate);
    for (page, _) in &memory.pages {
        for offset in (0..page.len).step_by(8) {
            state.write_u64(page.base() + offset as u64, page.read_u64(offset));
        }
    }
    state
}

fn flags_to_nzcv(flags: Flags) -> u64 {
    (flags.n as u64) << 31
        | (flags.z as u64) << 30
        | (flags.c as u64) << 29
        | (flags.v as u64) << 28
}

fn nzcv_to_flags(nzcv: u64) -> Flags {
    Flags {
        n: nzcv & (1 << 31) != 0,
        z: nzcv & (1 << 30) != 0,
        c: nzcv & (1 << 29) != 0,
        v: nzcv & (1 << 28) != 0,
    }
}

fn user_regs(state: &MachineState, pc: u64) -> UserRegs {
    let mut x = [0u64; 31];
    for (reg, value) in x.iter_mut().enumerate() {
        *value = state.read_x(reg as u8);
    }
    UserRegs {
        x,
        sp: state.sp(),
        pc,
        pstate: flags_to_nzcv(state.flags),
    }
}

fn describe_event(event: &Event) -> String {
    let name = match event.signal {
        SIGILL => "SIGILL",
        SIGTRAP => "SIGTRAP",
        SIGBUS => "SIGBUS",
        SIGSEGV => "SIGSEGV",
        _ => "signal",
    };
    match event.brk() {
        Some(word) => format!("{name} (brk word {word:#010x}) at pc {:#x}", event.pc),
        None => format!(
            "{name} ({}) at pc {:#x}, fault address {:#x}",
            event.signal, event.pc, event.fault_addr
        ),
    }
}

// ---------------------------------------------------------------------------
// Native original run
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeStop {
    /// The hardware executed the branch exit at `pc` and arrived at `target_pc`.
    Branch { pc: u64, target_pc: u64 },
    /// Stopped before the word at `pc` that `admit_word` rejects.
    Unsupported { pc: u64 },
    /// Execution reached the first word past the text.
    FellOffEnd { pc: u64 },
    /// The instruction at `pc` took a data abort at `addr` and did not retire.
    Fault { pc: u64, addr: u64 },
}

#[derive(Clone, Debug)]
pub struct NativeOriginal {
    pub state: MachineState,
    pub stop: NativeStop,
}

/// Applies the interpreter's own halting rule (`OriginalStepper::step`, via
/// `admit_word`) to every word: SVCs become `BRK_SVC`, rejected words and
/// non-SVC runtime exits become `BRK_STOP`. The interpreter halts nowhere else
/// inside the text, apart from user-access faults, which trap natively too.
fn stop_point_words(words: &[u32], text_base: u64) -> Vec<u32> {
    words
        .iter()
        .enumerate()
        .map(|(index, &word)| {
            let pc = text_base + index as u64 * 4;
            match admit_word(word, pc) {
                Ok(Ok(insn)) => match insn.inner.runtime_exit_reason(pc) {
                    Some(RuntimeExitReason::Svc { .. }) => BRK_SVC,
                    Some(_) => BRK_STOP,
                    None => word,
                },
                Ok(Err(_unsupported)) => BRK_STOP,
                // The interpreter reports an error if it reaches this word, so the
                // case fails before any native run; unreached, it is irrelevant.
                Err(_) => word,
            }
        })
        .collect()
}

fn is_unsupported(word: u32, pc: u64) -> bool {
    matches!(admit_word(word, pc), Ok(Err(_)))
}

pub fn run_original(
    session: &NativeSession,
    text_base: u64,
    text: &[u8],
    entry_pc: u64,
    initial: &MachineState,
) -> Result<NativeOriginal, String> {
    if text.len() % 4 != 0 {
        return Err("fixture text length must be a multiple of 4 bytes".to_string());
    }
    let words = text
        .chunks_exact(4)
        .map(|chunk| u32::from_le_bytes(chunk.try_into().expect("chunks_exact(4)")))
        .collect::<Vec<_>>();
    let text_end = text_base + text.len() as u64;
    // At least one BRK_FILL word past the text catches falling off the end.
    let text_map = Mapping::fixed(
        text_base,
        round_up(text.len() + 4, session.page),
        PROT_READ | PROT_WRITE,
    )?;
    text_map.install_code(&stop_point_words(&words, text_base))?;
    let memory = UserMemory::map(initial, session.page)?;

    let mut regs = user_regs(initial, entry_pc);
    for _ in 0..MAX_RUNTIME_EXITS {
        let (event, snapshot) = session.enter_user(regs, initial.tpidr_el0)?;
        let pc = event.pc;
        match (event.signal, event.brk()) {
            (SIGTRAP, Some(BRK_SVC)) => {
                // The mocked SVC of `execute_original_with_mocked_svc`: no state
                // change, resume at the next instruction.
                regs = snapshot;
                regs.pc = pc + 4;
            }
            (SIGTRAP, Some(BRK_STOP)) => {
                let word = words[((pc - text_base) / 4) as usize];
                if is_unsupported(word, pc) {
                    return Ok(NativeOriginal {
                        state: native_state(initial, &snapshot, &memory),
                        stop: NativeStop::Unsupported { pc },
                    });
                }
                return execute_branch_exit(
                    session, &text_map, &words, text_base, snapshot, initial, &memory,
                );
            }
            (SIGTRAP, Some(BRK_FILL)) if pc == text_end => {
                return Ok(NativeOriginal {
                    state: native_state(initial, &snapshot, &memory),
                    stop: NativeStop::FellOffEnd { pc },
                });
            }
            // A data abort from an instruction in the text: precise, so the
            // snapshot is the state before it, as in the interpreter's fault halt.
            (SIGSEGV | SIGBUS, None) if text_map.contains(pc) && pc != event.fault_addr => {
                return Ok(NativeOriginal {
                    state: native_state(initial, &snapshot, &memory),
                    stop: NativeStop::Fault {
                        pc,
                        addr: event.fault_addr,
                    },
                });
            }
            _ => {
                return Err(format!(
                    "native original run: unexpected {}",
                    describe_event(&event)
                ))
            }
        }
    }
    Err("native original run exceeded the runtime-exit continuation limit".to_string())
}

/// Lets the hardware execute the branch exit at `at.pc` in a text copy where
/// every other word traps, and records where it went.
fn execute_branch_exit(
    session: &NativeSession,
    text_map: &Mapping,
    words: &[u32],
    text_base: u64,
    at: UserRegs,
    initial: &MachineState,
    memory: &UserMemory,
) -> Result<NativeOriginal, String> {
    let index = ((at.pc - text_base) / 4) as usize;
    let mut solo = vec![BRK_FILL; words.len()];
    solo[index] = words[index];
    text_map.install_code(&solo)?;

    let (event, snapshot) = session.enter_user(at, initial.tpidr_el0)?;
    let target_pc = match (event.signal, event.brk()) {
        (SIGTRAP, Some(BRK_FILL)) if text_map.contains(event.pc) => event.pc,
        // Instruction abort: the branch left every executable mapping.
        (SIGSEGV, None) if event.pc == event.fault_addr => event.pc,
        _ => {
            return Err(format!(
                "native branch exit at {:#x}: unexpected {}",
                at.pc,
                describe_event(&event)
            ))
        }
    };
    Ok(NativeOriginal {
        state: native_state(initial, &snapshot, memory),
        stop: NativeStop::Branch {
            pc: at.pc,
            target_pc,
        },
    })
}

/// The interpreter's halt and the native stop describe the same exit.
pub fn original_halt_matches(
    original: &ExecutionResult,
    text_base: u64,
    text: &[u8],
    native: &NativeStop,
) -> Result<(), String> {
    let mismatch = || {
        format!(
            "halt mismatch: interpreter {:?}, native {native:?}",
            original.halt_reason
        )
    };
    match (original.halt_reason, *native) {
        (HaltReason::FellOffEnd, NativeStop::FellOffEnd { .. }) => Ok(()),
        (
            HaltReason::RuntimeExit {
                reason: RuntimeExitReason::Unsupported { pc, .. },
            },
            NativeStop::Unsupported { pc: native_pc },
        ) if pc == native_pc => Ok(()),
        // The CPU reports the first faulting byte, which may lie past the start
        // of an access that crosses into a bad page.
        (HaltReason::Fault(fault), NativeStop::Fault { pc, addr })
            if fault.pc == pc
                && addr >= fault.access.addr
                && addr - fault.access.addr < fault.access.size as u64 =>
        {
            Ok(())
        }
        (HaltReason::RuntimeExit { reason }, NativeStop::Branch { pc, target_pc }) => {
            let offset = (pc - text_base) as usize;
            let word = u32::from_le_bytes(
                text[offset..offset + 4]
                    .try_into()
                    .expect("stop pc is inside the text"),
            );
            let native_reason = match admit_word(word, pc) {
                Ok(Ok(insn)) => insn.inner.runtime_exit_reason(pc),
                _ => None,
            };
            if native_reason != Some(reason) {
                return Err(mismatch());
            }
            let expected_target = match reason {
                RuntimeExitReason::Ret { lr_reg: reg }
                | RuntimeExitReason::Br { target_reg: reg } => Some(original.state.read_x(reg)),
                RuntimeExitReason::Bl { target_pc, .. } => Some(target_pc),
                // BLR x30 overwrote its own target with the link value; the halt
                // state no longer holds it (same limit as runtime_halt_matches_original).
                RuntimeExitReason::Blr { target_reg, .. } if target_reg == 30 => None,
                RuntimeExitReason::Blr { target_reg, .. } => {
                    Some(original.state.read_x(target_reg))
                }
                RuntimeExitReason::Svc { .. } | RuntimeExitReason::Unsupported { .. } => {
                    return Err(mismatch())
                }
            };
            match expected_target {
                Some(expected) if expected != target_pc => Err(mismatch()),
                _ => Ok(()),
            }
        }
        _ => Err(mismatch()),
    }
}

// ---------------------------------------------------------------------------
// Native fragment run
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct NativeFragment {
    pub state: MachineState,
    pub halt: URuntimeHalt,
    pub calls: usize,
    /// Hardware data aborts redirected to a fault stub.
    pub fault_redirects: usize,
}

/// Calls the encoded fragment through the ABI boundary until the shared runtime
/// decision stops, exactly as `URuntime::run` does in the interpreter.
pub fn run_fragment(
    session: &NativeSession,
    fragment: &ExecutionFragment,
    encoded: &[u8],
    initial: &MachineState,
) -> Result<NativeFragment, String> {
    if encoded.len() != fragment.len_bytes() {
        return Err(format!(
            "encoded fragment is {:#x} bytes, fragment layout says {:#x}",
            encoded.len(),
            fragment.len_bytes()
        ));
    }
    let words = encoded
        .chunks_exact(4)
        .map(|chunk| u32::from_le_bytes(chunk.try_into().expect("chunks_exact(4)")))
        .collect::<Vec<_>>();
    let code = Mapping::anywhere(
        round_up(encoded.len() + 4, session.page),
        PROT_READ | PROT_WRITE,
    )?;
    code.install_code(&words)?;
    let fragment_base = code.base();
    let fragment_end = fragment_base + encoded.len() as u64;
    let memory = UserMemory::map(initial, session.page)?;

    let mut pt_regs = vec![0u64; PT_REGS_BYTES as usize / 8];
    for reg in 0..31u8 {
        let slot = pt_regs_x_slot_offset(reg).expect("x0..x30 have pt_regs slots") as usize / 8;
        pt_regs[slot] = initial.read_x(reg);
    }
    pt_regs[PT_REGS_SP_OFFSET as usize / 8] = initial.sp();
    let mut extra_params = [0u64; 2];
    let mut nzcv = flags_to_nzcv(initial.flags);
    let mut offset = fragment.entry_offset;
    let fault_sites = fragment
        .fault_sites
        .iter()
        .map(|site| FixupSite {
            access_offset: site.access_offset as u64,
            stub_offset: site.stub_offset as u64,
        })
        .collect::<Vec<_>>();
    let mut fault_redirects = 0;

    for calls in 1..=MAX_RUNTIME_EXITS {
        validate_entry_offset(fragment, offset)?;
        let ctx = session.call_fragment(
            &mut pt_regs,
            &mut extra_params,
            fragment_base + offset as u64,
            fragment_base,
            encoded.len() as u64,
            &fault_sites,
            nzcv,
            initial.tpidr_el0,
        )?;
        fault_redirects += ctx.fault_redirects as usize;

        let user_state = |nzcv: u64| {
            let mut regs = UserRegs {
                sp: pt_regs[PT_REGS_SP_OFFSET as usize / 8],
                pstate: nzcv,
                ..UserRegs::default()
            };
            for reg in 0..31u8 {
                let slot = pt_regs_x_slot_offset(reg).expect("x0..x30 have pt_regs slots");
                regs.x[reg as usize] = pt_regs[slot as usize / 8];
            }
            native_state(initial, &regs, &memory)
        };

        let event = ctx.event;
        if event.signal != 0 {
            if event.brk() == Some(BRK_FILL) && event.pc == fragment_end {
                return Ok(NativeFragment {
                    state: user_state(ctx.user.pstate & NZCV_MASK),
                    halt: URuntimeHalt::FellOffFragment { pc: event.pc },
                    calls,
                    fault_redirects,
                });
            }
            // A data abort in the fragment reaches here only without a fault-site
            // entry: a runtime access or an untagged user access. Hard failure.
            let at = if code.contains(event.pc) {
                format!(
                    " (fragment offset {:#x}, no fault-site entry)",
                    event.pc - fragment_base
                )
            } else {
                String::new()
            };
            return Err(format!(
                "native fragment call {calls}: {}{at}",
                describe_event(&event)
            ));
        }
        check_callee_saved(&ctx)?;

        // Epilogue contract (shared/abi KJIT_EPILOGUE): x0 = RetStatus, extra
        // params [0] = RET_PARAM0, [1] = RET_PARAM1.
        nzcv = ctx.nzcv & NZCV_MASK;
        match decide_runtime_return(fragment, ctx.status, extra_params[0], extra_params[1]) {
            RuntimeAction::ContinueAt(next) => offset = next,
            RuntimeAction::Stop(halt) => {
                return Ok(NativeFragment {
                    state: user_state(nzcv),
                    halt,
                    calls,
                    fault_redirects,
                })
            }
        }
    }
    Err("native fragment run exceeded the runtime-exit continuation limit".to_string())
}

/// The kernel calls a fragment as a C function: x18..x29 and sp must survive.
fn check_callee_saved(ctx: &NativeCtx) -> Result<(), String> {
    let mut broken = Vec::new();
    for (index, reg) in (18..=29).enumerate() {
        if ctx.after_call[index] != ctx.host[index] {
            broken.push(format!(
                "x{reg} {:#x} -> {:#x}",
                ctx.host[index], ctx.after_call[index]
            ));
        }
    }
    if ctx.after_call[12] != ctx.host[HOST_SP_INDEX] {
        broken.push(format!(
            "sp {:#x} -> {:#x}",
            ctx.host[HOST_SP_INDEX], ctx.after_call[12]
        ));
    }
    if broken.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "native fragment broke the C calling convention: {}",
            broken.join(", ")
        ))
    }
}

// ---------------------------------------------------------------------------
// State diff
// ---------------------------------------------------------------------------

/// Differences in user registers, SP, NZCV and memory; empty when equal.
pub fn diff_states(
    left_name: &str,
    left: &MachineState,
    right_name: &str,
    right: &MachineState,
) -> Vec<String> {
    let mut diffs = Vec::new();
    for reg in 0..31u8 {
        let (l, r) = (left.read_x(reg), right.read_x(reg));
        if l != r {
            diffs.push(format!("x{reg}: {left_name}={l:#x} {right_name}={r:#x}"));
        }
    }
    if left.sp() != right.sp() {
        diffs.push(format!(
            "sp: {left_name}={:#x} {right_name}={:#x}",
            left.sp(),
            right.sp()
        ));
    }
    if left.flags != right.flags {
        diffs.push(format!(
            "nzcv: {left_name}={:?} {right_name}={:?}",
            left.flags, right.flags
        ));
    }
    let addrs = left
        .memory()
        .keys()
        .chain(right.memory().keys())
        .copied()
        .collect::<std::collections::BTreeSet<_>>();
    for addr in addrs {
        let l = left.memory().get(&addr).copied().unwrap_or(0);
        let r = right.memory().get(&addr).copied().unwrap_or(0);
        if l != r {
            diffs.push(format!(
                "mem[{addr:#x}]: {left_name}={l:#04x} {right_name}={r:#04x}"
            ));
        }
    }
    if diffs.is_empty() && left != right {
        diffs.push(format!(
            "{left_name} and {right_name} differ outside registers, SP, NZCV and memory bytes"
        ));
    }
    diffs
}

// ---------------------------------------------------------------------------
// Three-way case check
// ---------------------------------------------------------------------------

/// interpreter original == native original == native fragment, for state and
/// halt. `run_entry_fixture` additionally holds the interpreter's own fragment
/// run to the interpreter original. Returns a one-line summary on success.
pub fn check_case(
    session: &NativeSession,
    text_base: u64,
    text: &[u8],
    entry_pc: u64,
    initial: &MachineState,
) -> Result<String, String> {
    let report = crate::run_entry_fixture(
        "native-fixture",
        text_base,
        text.to_vec(),
        entry_pc,
        initial,
    )?;
    let original = run_original(session, text_base, text, entry_pc, initial)?;
    let fragment = run_fragment(session, &report.fragment, &report.encoded_fragment, initial)?;

    let mut problems = diff_states(
        "interp-original",
        &report.original.state,
        "native-original",
        &original.state,
    );
    problems.extend(diff_states(
        "interp-original",
        &report.original.state,
        "native-fragment",
        &fragment.state,
    ));
    if let Err(message) = original_halt_matches(&report.original, text_base, text, &original.stop) {
        problems.push(format!("native-original {message}"));
    }
    if !crate::runtime_halt_matches_original(&report.original, &fragment.halt) {
        problems.push(format!(
            "native-fragment halt mismatch: interpreter {:?}, native {:?}",
            report.original.halt_reason, fragment.halt
        ));
    }

    if problems.is_empty() {
        Ok(format!(
            "halt={:?} native-original={:?} native-fragment={:?} fragment-calls={} \
             fault-redirects={}",
            report.original.halt_reason,
            original.stop,
            fragment.halt,
            fragment.calls,
            fragment.fault_redirects
        ))
    } else {
        Err(problems.join("\n"))
    }
}
