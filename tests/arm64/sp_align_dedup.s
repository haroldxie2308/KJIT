// A20 SP alignment check deduplication fixture (docs/pipeline.md, "SP alignment
// check deduplication (A20)"). Within a block, reg-virt checks the first SP-based
// access only, while user SP is known 16-byte aligned: after a check that did not
// fire, and across `add`/`sub sp, sp, #imm` with imm % 16 == 0. Every other write
// to SP drops the fact, and so does the start of a block (a loop head or any
// branch target).
//
// The cases that end in a fault are the point: SP misaligned by one of the writes
// below must still SIGBUS at the next SP-based access, exactly as natively. The
// differential models the fault (`FaultCause::SpAlignment`, before any access),
// the native runner takes it at the SP value Linux reports (`el0_sp`).
//
//   make harness-test-asm ASM=tests/arm64/sp_align_dedup.s HOT_SVC_SYMBOL=sp_multi_access_mark
//
// Initial fixture state: x12 = FIXTURE_DATA_BASE (16 KiB aligned), a 16 KiB RW
// window (all zero); SP and x30 are 0, so every case builds its stack in the window
// and ends in a `ret` to 0 (an unreadable target) or in a fault.

.text
.global sp_align_dedup_entry
sp_align_dedup_entry:

// Many SP-based accesses in one block: every form, only the first is checked.
.global sp_multi_access_mark
sp_multi_access_mark:
    svc #0
    add sp, x12, #0x2000
    movz x0, #0x11
    movz x1, #0x22
    stp x0, x1, [sp, #-32]!
    str x0, [sp, #16]
    ldr x2, [sp, #16]
    ldp x3, x4, [sp]
    ldrb w5, [sp, #3]
    strh w5, [sp, #6]
    movz x6, #8
    ldr x7, [sp, x6]
    str q0, [sp, #16]
    ldr q1, [sp, #16]
    stp x3, x4, [sp, #-16]!
    ldp x8, x9, [sp], #16
    add sp, sp, #32
    ret

// Adjusts by multiples of 16 keep the fact; the accesses between them run on
// whatever stack the adjusts built.
.global sp_adjust16_mark
sp_adjust16_mark:
    svc #0
    add sp, x12, #0x3000
    ldr x0, [sp]
    sub sp, sp, #16
    str x0, [sp, #8]
    sub sp, sp, #0x40
    ldr x1, [sp, #8]
    add sp, sp, #0x30
    stp x0, x1, [sp, #-16]!
    sub sp, sp, #1, lsl #12
    str x1, [sp]
    add sp, sp, #1, lsl #12
    ldr x2, [sp]
    ret

// SP misaligned mid-block by `sub sp, sp, #8`: the block's first access checked and
// passed, the one after the misalignment must fault.
.global sp_sub8_fault_mark
sp_sub8_fault_mark:
    svc #0
    add sp, x12, #0x2000
    movz x0, #0x77
    ldr x1, [sp]
    ldr x2, [sp, #8]
    sub sp, sp, #8
    ldr x3, [sp]
    movz x0, #0x78
    ret

// Same, with a store, and a SIMD access (a window access carries the same check).
.global sp_sub8_fault_store_mark
sp_sub8_fault_store_mark:
    svc #0
    add sp, x12, #0x2000
    movz x0, #0x55
    ldr x1, [sp]
    sub sp, sp, #8
    str x0, [sp, #-16]
    movz x0, #0x56
    ret

.global sp_sub8_fault_simd_mark
sp_sub8_fault_simd_mark:
    svc #0
    add sp, x12, #0x2000
    movi v3.16b, #0x5a
    ldr q4, [sp]
    sub sp, sp, #8
    ldr q3, [sp]
    ret

// Odd adjusts of both signs, 1 byte and 15 bytes, each followed by an access.
.global sp_sub1_fault_mark
sp_sub1_fault_mark:
    svc #0
    add sp, x12, #0x2000
    ldr x0, [sp]
    sub sp, sp, #1
    ldrb w1, [sp]
    ret

.global sp_add15_fault_mark
sp_add15_fault_mark:
    svc #0
    add sp, x12, #0x2000
    ldr x0, [sp]
    add sp, sp, #15
    ldrb w1, [sp, #-1]
    ret

// Realigned: `sub sp, sp, #8; add sp, sp, #8` is not provably aligned, so the next
// access is checked again, and passes. The pair of 8s misaligns and realigns at runtime
// only.
.global sp_realign_mark
sp_realign_mark:
    svc #0
    add sp, x12, #0x2000
    ldr x0, [sp]
    sub sp, sp, #8
    add sp, sp, #8
    ldr x1, [sp]
    ldr x2, [sp, #8]
    sub sp, sp, #24
    add sp, sp, #8
    add sp, sp, #16
    ldr x3, [sp]
    ret

// Realigned, then misaligned again by a multiple of 16 plus 8: faults at the access
// after the last adjust.
.global sp_realign_then_fault_mark
sp_realign_then_fault_mark:
    svc #0
    add sp, x12, #0x2000
    ldr x0, [sp]
    sub sp, sp, #8
    add sp, sp, #8
    ldr x1, [sp]
    sub sp, sp, #24
    ldr x2, [sp]
    ret

// `mov sp, x0` with an odd x0: SP written from a register, the fact is dropped.
.global sp_mov_odd_fault_mark
sp_mov_odd_fault_mark:
    svc #0
    add sp, x12, #0x2000
    ldr x1, [sp]
    add x0, x12, #0x2000
    add x0, x0, #8
    mov sp, x0
    ldr x2, [sp]
    ret

// `mov sp, x0` with an even x0 (and `add sp, x0, #16`): accesses pass.
.global sp_mov_even_mark
sp_mov_even_mark:
    svc #0
    add sp, x12, #0x2000
    ldr x1, [sp]
    add x0, x12, #0x2000
    add x0, x0, #0x400
    mov sp, x0
    ldr x2, [sp]
    add sp, x0, #16
    str x2, [sp]
    ret

// SP from a register sum, misaligned by x3.
.global sp_add_reg_fault_mark
sp_add_reg_fault_mark:
    svc #0
    add sp, x12, #0x2000
    ldr x1, [sp]
    movz x3, #4
    add sp, sp, x3, uxtx
    ldr x2, [sp]
    ret

// Writeback by 16 keeps the fact (pre and post index, single and pair).
.global sp_writeback16_mark
sp_writeback16_mark:
    svc #0
    add sp, x12, #0x2000
    movz x0, #0xa0
    movz x1, #0xa1
    stp x0, x1, [sp, #-16]!
    str x0, [sp, #-16]!
    str x1, [sp, #-32]!
    ldr x2, [sp], #32
    ldr x3, [sp], #16
    ldp x4, x5, [sp], #16
    ldr x6, [sp, #-8]
    ret

// Writeback by 8 (pre-index): the access after it faults.
.global sp_writeback8_pre_fault_mark
sp_writeback8_pre_fault_mark:
    svc #0
    add sp, x12, #0x2000
    movz x0, #0xb0
    str x0, [sp, #-8]!
    ldr x1, [sp, #8]
    ret

// Writeback by 8 (post-index): the access after it faults.
.global sp_writeback8_post_fault_mark
sp_writeback8_post_fault_mark:
    svc #0
    add sp, x12, #0x2000
    ldr x0, [sp], #8
    ldr x1, [sp]
    ret

// Two writebacks by 8 and an `add sp, sp, #16` in between: the SP at each access is
// aligned or not by the arithmetic alone, so each is checked after a drop.
.global sp_writeback8_pair_mark
sp_writeback8_pair_mark:
    svc #0
    add sp, x12, #0x2000
    movz x0, #0xc0
    str x0, [sp, #-8]!
    add sp, sp, #8
    ldr x1, [sp]
    ldr x2, [sp], #8
    add sp, sp, #8
    ldr x3, [sp]
    ret

// Pair writeback by 8 is encodable (stp pre-index with a multiple of 8): misaligns.
.global sp_writeback_pair8_fault_mark
sp_writeback_pair8_fault_mark:
    svc #0
    add sp, x12, #0x2000
    movz x0, #0xd0
    movz x1, #0xd1
    stp x0, x1, [sp, #-24]!
    ldp x2, x3, [sp]
    ret

// A loop whose head is a join point: every iteration's first access is checked
// (the loop-carried SP is aligned all the way), the body keeps SP aligned.
.global sp_loop_aligned_mark
sp_loop_aligned_mark:
    svc #0
    add sp, x12, #0x3000
    movz x3, #4
1:
    ldr x0, [sp]
    ldr x1, [sp, #8]
    sub sp, sp, #16
    subs x3, x3, #1
    b.ne 1b
    ret

// The head's access is checked on the first entry (SP aligned) and the back-edge
// carries a misaligned SP: the second iteration must fault at the head, which an
// elided check (the fact carried over the join point) would not.
.global sp_loop_misaligns_fault_mark
sp_loop_misaligns_fault_mark:
    svc #0
    add sp, x12, #0x3000
    movz x3, #3
1:
    ldr x0, [sp]
    sub sp, sp, #8
    subs x3, x3, #1
    b.ne 1b
    ret

// A forward join point: one predecessor misaligns SP, the other does not. The
// fall-through path arrives misaligned and faults at the target's access.
.global sp_join_misaligned_fault_mark
sp_join_misaligned_fault_mark:
    svc #0
    add sp, x12, #0x2000
    ldr x0, [sp]
    cbnz x0, 2f
    sub sp, sp, #8
2:
    ldr x1, [sp]
    ret

// The branch is taken (x0 != 0): the aligned path reaches the join and passes.
.global sp_join_aligned_mark
sp_join_aligned_mark:
    svc #0
    add sp, x12, #0x2000
    movz x0, #1
    cbnz x0, 2f
    sub sp, sp, #8
2:
    ldr x1, [sp]
    str x1, [sp, #8]
    ret

// Entry labels (A20): a fragment is entered only at a block start, so a transfer to the middle of a
// block misses and the target is translated as its own fragment, whose first access is checked. Before
// the entry-label restriction the transfer resumed after the elided check of the first fragment and
// the fault was lost. `br x9` into the middle of the block that sets x9 (SP misaligned by the `sub`
// before the `br`: the second pass over label 1 must fault).
.global sp_midblock_br_fault_mark
sp_midblock_br_fault_mark:
    svc #0
    add sp, x12, #0x2000
    adr x9, 1f
    ldr x0, [sp]
1:
    ldr x1, [sp, #8]
    sub sp, sp, #8
    br x9

// Same through a static `bl` into the middle of a callee already translated from its start (the link
// slot may not bind to a mid-block label either): the second call, with SP misaligned, faults at the
// callee's second access.
.global sp_midblock_bl_fault_mark
sp_midblock_bl_fault_mark:
    svc #0
    add sp, x12, #0x2000
    mov x20, x30
    bl mid_callee
    sub sp, sp, #8
    bl mid_callee_inner
    mov x30, x20
    ret

// The same calls with SP aligned: the mid-block entry runs (as its own fragment) and returns.
.global sp_midblock_bl_ok_mark
sp_midblock_bl_ok_mark:
    svc #0
    add sp, x12, #0x2000
    mov x20, x30
    bl mid_callee
    bl mid_callee_inner
    bl mid_callee
    mov x30, x20
    ret

mid_callee:
    ldr x0, [sp]
mid_callee_inner:
    ldr x1, [sp, #8]
    ret
