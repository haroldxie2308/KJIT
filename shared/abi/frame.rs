use super::{REG_VIRT_STACK_BACKED_REG_END, REG_VIRT_STACK_BACKED_REG_START};

// Runtime frame, sp-relative after the prologue's `stp x29, x30, [sp, #-208]!`:
//   0..16    caller x29, x30
//   16..64   stack-backed user x12..x17
//   64..80   user x29, user sp (loaded into their stable mappings x16/x17)
//   80..88   entry address (ABI_ENTRY_ARG_REG), consumed by the prologue's `br`
//   88..96   caller x18
//   96..176  caller x19..x28
//   176..192 pt_regs pointer, extra-params pointer
//   192..200 back-edge/dispatch budget counter (KJIT_BACKEDGE_BUDGET at every entry)
//   200..208 dispatch table pointer (extra params [2], stored by the prologue);
//            also keeps sp 16-byte aligned
pub const RUNTIME_FRAME_SIZE_BYTES: u32 = 208;
pub const RUNTIME_FRAME_ENTRY_ADDR_OFFSET: u32 = 80;
pub const RUNTIME_FRAME_PT_REGS_PTR_OFFSET: u32 = 176;
pub const RUNTIME_FRAME_BUDGET_OFFSET: u32 = 192;
/// The run's dispatch table (IBTC, docs/pipeline.md "In-fragment branch dispatch
/// (A11)"). The prologue
/// stores `extra params[EXTRA_PARAM_IBTC_TABLE_INDEX]` here; only a dispatch
/// template's table loads (words 0 and 9) read it, and nothing in a body writes it.
pub const RUNTIME_FRAME_IBTC_OFFSET: u32 = 200;

/// Extra params block (`ABI_EXTRA_PARAMS_ARG_REG` points at it): `[0]`, `[1]` are
/// RET_PARAM0/1 (out, written by the epilogue), `[2]` is the run's dispatch table
/// (in, read by the prologue).
pub const EXTRA_PARAMS_WORDS: usize = 3;
pub const EXTRA_PARAM_IBTC_TABLE_INDEX: usize = 2;
pub const EXTRA_PARAM_IBTC_TABLE_OFFSET: u32 = (EXTRA_PARAM_IBTC_TABLE_INDEX * 8) as u32;
pub const EXTRA_PARAMS_BYTES: usize = EXTRA_PARAMS_WORDS * 8;

/// Dispatch tables (A11, A11c): one array of `IBTC_SLOT_BYTES` slots, a direct-mapped
/// main part of `IBTC_SLOTS` slots followed by a victim part of `IBTC_VICTIM_SLOTS`
/// slots at byte offset `IBTC_VICTIM_OFFSET`. A slot is 0 or the address of a record
/// `{ u64 pc @IBTC_RECORD_PC_OFFSET; u64 host @IBTC_RECORD_HOST_OFFSET }` (a user PC and
/// the absolute address of a verified entry of a live fragment translated for exactly
/// that PC). A pc's main slot is `pc[IBTC_INDEX_LSB + IBTC_BITS - 1 : IBTC_INDEX_LSB]`
/// (`ibtc_slot_index`), its victim slot `((pc ^ (pc >> IBTC_VICTIM_FOLD_SHIFT)) >> 2) &
/// 0xff` in the victim part (`ibtc_victim_index`), i.e. `pc[9:2] ^ pc[21:14]`.
pub const IBTC_BITS: u32 = 12;
pub const IBTC_INDEX_LSB: u32 = 2;
pub const IBTC_SLOT_SHIFT: u32 = 3;
pub const IBTC_SLOT_BYTES: u32 = 1 << IBTC_SLOT_SHIFT;
pub const IBTC_SLOTS: usize = 1 << IBTC_BITS;
pub const IBTC_VICTIM_BITS: u32 = 8;
pub const IBTC_VICTIM_SLOTS: usize = 1 << IBTC_VICTIM_BITS;
pub const IBTC_VICTIM_FOLD_SHIFT: u32 = 12;
/// Byte offset of the victim part: the template adds it to the table pointer.
pub const IBTC_VICTIM_OFFSET: usize = IBTC_SLOTS * IBTC_SLOT_BYTES as usize;
pub const IBTC_TABLE_WORDS: usize = IBTC_SLOTS + IBTC_VICTIM_SLOTS;
pub const IBTC_TABLE_BYTES: usize = IBTC_TABLE_WORDS * IBTC_SLOT_BYTES as usize;
pub const IBTC_RECORD_PC_OFFSET: u32 = 0;
pub const IBTC_RECORD_HOST_OFFSET: u32 = 8;
pub const IBTC_RECORD_BYTES: usize = 16;

/// Index of `pc`'s slot in the main part (a table word index).
pub const fn ibtc_slot_index(pc: u64) -> usize {
    ((pc >> IBTC_INDEX_LSB) & ((1 << IBTC_BITS) - 1)) as usize
}

/// Index of `pc`'s slot in the victim part, as a table word index (it starts at
/// `IBTC_SLOTS`).
pub const fn ibtc_victim_index(pc: u64) -> usize {
    IBTC_SLOTS
        + (((pc ^ (pc >> IBTC_VICTIM_FOLD_SHIFT)) >> IBTC_INDEX_LSB) & ((1 << IBTC_VICTIM_BITS) - 1))
            as usize
}

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
const _: () = assert!(RUNTIME_FRAME_BUDGET_OFFSET + 8 <= RUNTIME_FRAME_IBTC_OFFSET);
const _: () = assert!(RUNTIME_FRAME_IBTC_OFFSET + 8 == RUNTIME_FRAME_SIZE_BYTES);
// `ldr x12, [sp, #200]` and `ldr x12, [x1, #16]` take a scaled 12-bit offset.
const _: () = assert!(RUNTIME_FRAME_IBTC_OFFSET % 8 == 0 && RUNTIME_FRAME_IBTC_OFFSET / 8 < 4096);
const _: () = assert!(IBTC_RECORD_HOST_OFFSET as usize + 8 == IBTC_RECORD_BYTES);
const _: () = assert!(IBTC_RECORD_PC_OFFSET == 0);
const _: () = assert!(IBTC_SLOT_BYTES == 8);
// The template adds the victim part's byte offset with one `add ..., #imm12, lsl #12`.
const _: () = assert!(IBTC_VICTIM_OFFSET % 4096 == 0 && IBTC_VICTIM_OFFSET >> 12 < 4096);
const _: () = assert!(IBTC_TABLE_BYTES == (4096 + 256) * 8);
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
