use super::{REG_VIRT_STACK_BACKED_REG_END, REG_VIRT_STACK_BACKED_REG_START};

// Runtime frame, sp-relative after the prologue's `stp x29, x30, [sp, #-208]!`:
//   0..16    caller x29, x30
//   16..64   stack-backed user x12..x17
//   64..80   user x29, user sp (loaded into their stable mappings x16/x17)
//   80..88   entry address (ABI_ENTRY_ARG_REG), consumed by the prologue's `br`
//   88..96   caller x18
//   96..176  caller x19..x28
//   176..192 pt_regs pointer, extra-params pointer
//   192..200 back-edge budget counter (KJIT_BACKEDGE_BUDGET at every entry)
//   200..208 padding: sp stays 16-byte aligned
pub const RUNTIME_FRAME_SIZE_BYTES: u32 = 208;
pub const RUNTIME_FRAME_ENTRY_ADDR_OFFSET: u32 = 80;
pub const RUNTIME_FRAME_PT_REGS_PTR_OFFSET: u32 = 176;
pub const RUNTIME_FRAME_BUDGET_OFFSET: u32 = 192;

/// Back-edge executions a fragment may perform per entry. The prologue stores it in
/// `RUNTIME_FRAME_BUDGET_OFFSET`; every back-edge first decrements the counter and
/// leaves with `RetStatus::Budget` when it reaches zero, so the N-th back-edge
/// execution of one entry exits (before the branch runs).
///
/// Why 4096: every path through a fragment without a back-edge is acyclic, so one
/// entry runs at most `KJIT_BACKEDGE_BUDGET` times the fragment's longest acyclic
/// path before control returns to the runtime, which re-checks signals and
/// `need_resched`. For fragments of tens to hundreds of instructions that bounds an
/// in-kernel run to the order of 10^5-10^6 instructions (tens to hundreds of
/// microseconds), while a loop shorter than 4096 iterations -- the common
/// syscall-adjacent case -- never pays a runtime round trip.
pub const KJIT_BACKEDGE_BUDGET: u64 = 4096;

// The prologue loads it with one `MOVZ` (16-bit immediate); zero would exit on the
// first back-edge after wrapping, which is never intended.
const _: () = assert!(KJIT_BACKEDGE_BUDGET > 0 && KJIT_BACKEDGE_BUDGET <= 0xFFFF);
const _: () = assert!(RUNTIME_FRAME_SIZE_BYTES % 16 == 0);
const _: () = assert!(RUNTIME_FRAME_BUDGET_OFFSET + 8 <= RUNTIME_FRAME_SIZE_BYTES);
const REG_VIRT_STACK_BACKED_FRAME_OFFSET_START: u32 = 16;
const REG_VIRT_STACK_BACKED_FRAME_SLOT_SIZE: u32 = 8;
const PT_REGS_GPR_SLOT_SIZE: u32 = 8;

pub const fn reg_virt_stack_backed_slot_offset(reg: u8) -> Option<u32> {
    if reg < REG_VIRT_STACK_BACKED_REG_START || reg > REG_VIRT_STACK_BACKED_REG_END {
        return None;
    }

    Some(
        REG_VIRT_STACK_BACKED_FRAME_OFFSET_START
            + ((reg - REG_VIRT_STACK_BACKED_REG_START) as u32)
                * REG_VIRT_STACK_BACKED_FRAME_SLOT_SIZE,
    )
}

pub const fn pt_regs_x_slot_offset(reg: u8) -> Option<u32> {
    if reg >= 31 {
        return None;
    }

    Some((reg as u32) * PT_REGS_GPR_SLOT_SIZE)
}
