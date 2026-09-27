//! Rule 9 (confidentiality): which general registers hold kernel values. One
//! forward analysis serves rule 3 (a base proven to hold the pt_regs pointer) and
//! rule 9 (no kernel value reaches user-visible state). tmp/pipeline.md,
//! "Verifier (V3)", "Confidentiality (rule 9)".

use crate::shared::abi::KJIT_PROLOGUE;
use crate::shared::arm64::{A64Insn, A64Mem};

use super::rules::{self, classify, reads, writes, Form};

/// Bit n: x_n (n < 31). `pt_regs` is a subset of `kernel`: registers whose kernel
/// value is known to be the pt_regs pointer. SP is kernel-valued at all times and
/// is not tracked here: every read of it other than as a frame-access base is
/// rejected on its own.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Taint {
    pub(super) kernel: u32,
    pub(super) pt_regs: u32,
}

const ALL_GPRS: u32 = (1 << 31) - 1;

impl Taint {
    /// Kernel-valued registers at every body entry, derived by running `step` over
    /// the byte-exact prologue from "every register is a kernel value" (the
    /// trampoline's state): x29 (`add x29, sp, #0`) and the entry scratch (it
    /// holds the entry address the prologue's `br` goes through). `None` when the
    /// prologue's operand metadata is incomplete: fail closed.
    pub(super) fn at_entry() -> Option<Self> {
        let mut state = Self {
            kernel: ALL_GPRS,
            pt_regs: 0,
        };
        for insn in KJIT_PROLOGUE {
            state = step(insn, classify(*insn), state)?;
        }
        // The body starts with no pt_regs fact: a join point.
        state.pt_regs = 0;
        Some(state)
    }

    pub(super) const fn is_kernel(self, reg: u8) -> bool {
        reg < 31 && self.kernel & (1 << reg) != 0
    }

    pub(super) const fn is_pt_regs(self, reg: u8) -> bool {
        reg < 31 && self.pt_regs & (1 << reg) != 0
    }
}

/// What a written register holds after `insn`.
enum Value {
    User,
    Kernel,
    PtRegs,
}

/// Transfer function. It does not check anything (the main pass does, before
/// calling it): it only says what the written registers hold.
///
/// - A load from the runtime frame (SP base) is user state in the user-state
///   slots, a counter in the budget slot, the pt_regs pointer for
///   `rules::pt_regs_pointer_load`, and a kernel value in every other slot.
/// - Any other load reads user state: `LDTR*` and window atomics read user memory,
///   and a runtime access with a non-SP base reads `pt_regs` (the body: rule 3's
///   proven pointer; the prologue: x16 = the pt_regs argument).
/// - Any other write is a kernel value if the instruction reads SP or a
///   kernel-valued register as data, and user state otherwise.
/// - A written base (writeback) keeps a kernel value if it held one.
pub(super) fn step(insn: &A64Insn, form: Form, state: Taint) -> Option<Taint> {
    let read = reads(insn)?;
    let written = writes(insn)?.gprs;
    let value = match form {
        Form::RuntimeAccess {
            mem,
            bytes,
            store: false,
        } => frame_load_value(insn, mem, bytes),
        Form::RuntimeAccess { store: true, .. }
        | Form::UserAccess { .. }
        | Form::WindowAtomic { .. } => Value::User,
        _ if read.sp || read.gprs & state.kernel != 0 => Value::Kernel,
        _ => Value::User,
    };
    let mut next = Taint {
        kernel: state.kernel & !written,
        pt_regs: state.pt_regs & !written,
    };
    match value {
        Value::User => {}
        Value::Kernel => next.kernel |= written,
        Value::PtRegs => {
            next.kernel |= written;
            next.pt_regs |= written;
        }
    }
    if let Some(base) = read.base {
        let bit = if base.enc() < 31 { 1 << base.enc() } else { 0 };
        if written & bit != 0 && state.kernel & bit != 0 {
            next.kernel |= bit;
            next.pt_regs &= !bit;
        }
    }
    Some(next)
}

fn frame_load_value(insn: &A64Insn, mem: A64Mem, bytes: u32) -> Value {
    if !rules::is_sp(mem.base()) {
        return Value::User;
    }
    if rules::pt_regs_pointer_load(insn).is_some() {
        return Value::PtRegs;
    }
    let A64Mem::Offset { offset, .. } = mem else {
        return Value::Kernel;
    };
    let start = offset.value();
    let user_slots = start >= rules::FRAME_USER_START as i64
        && start + bytes as i64 <= rules::FRAME_USER_END as i64;
    // The back-edge counter is not secret: the user can count its own back-edges.
    let budget = start == rules::BUDGET_SLOT_OFFSET as i64 && bytes == 8;
    if user_slots || budget {
        Value::User
    } else {
        Value::Kernel
    }
}
