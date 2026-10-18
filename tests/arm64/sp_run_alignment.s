// A22 run-wide SP alignment fixture (docs/pipeline.md, "User SP is 16-byte aligned
// for a whole run"). A run starts only at a 16-byte aligned user SP, and no write to
// SP inside it leaves SP misaligned: a fragment computes the new SP into a scratch,
// checks it (`and xT, xS, #15; cbnz xT, <Mem stub>`) and only then commits it to x17,
// so a write that would misalign SP exits through the `Mem` stub of its instruction,
// with nothing of it done, and userspace executes it natively. Writes that provably
// keep SP aligned (`add`/`sub sp, sp, #imm` with imm % 16 == 0, writeback by a
// multiple of 16, `and sp, xN, #mask` with the low four bits of the mask clear) carry
// no code. No SP-based access carries an alignment check.
//
// The differential models that: the original stops right before an instruction that
// would leave an aligned SP misaligned (`HaltReason::SpMisaligned`), the fragment must
// leave through `Mem` at that instruction with the state before it. The `_exit_` cases
// end that way, the others run to their `ret`. `asm_fixture_tests.rs`
// (`sp_run_alignment_cases_exit_where_documented`) pins which is which.
//
//   make harness-test-asm ASM=tests/arm64/sp_run_alignment.s HOT_SVC_SYMBOL=sp_multi_access_mark
//
// Initial fixture state: x12 = FIXTURE_DATA_BASE (16 KiB aligned), a 16 KiB RW
// window (all zero); SP and x30 are 0, so every case builds its stack in the window
// and ends in a `ret` to 0 (an unreadable target) or at an SP exit.

.text
.global sp_run_alignment_entry
sp_run_alignment_entry:

// Many SP-based accesses: every form, none carries a check.
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

// Adjusts by multiples of 16: no code, the accesses between them run on whatever
// stack the adjusts built.
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

// `sub sp, sp, #8` misaligns: the run ends at it, the accesses and the `movz` after
// it never run in the fragment. The two loads before it do.
.global sp_sub8_exit_mark
sp_sub8_exit_mark:
    svc #0
    add sp, x12, #0x2000
    movz x0, #0x77
    ldr x1, [sp]
    ldr x2, [sp, #8]
    sub sp, sp, #8
    ldr x3, [sp]
    movz x0, #0x78
    ret

// Odd adjusts of both signs, 1 byte and 15 bytes.
.global sp_sub1_exit_mark
sp_sub1_exit_mark:
    svc #0
    add sp, x12, #0x2000
    ldr x0, [sp]
    sub sp, sp, #1
    ldrb w1, [sp]
    ret

.global sp_add15_exit_mark
sp_add15_exit_mark:
    svc #0
    add sp, x12, #0x2000
    ldr x0, [sp]
    add sp, sp, #15
    ldrb w1, [sp, #-1]
    ret

// 32-bit form: `add wsp, wsp, #16` keeps SP aligned (a guard that passes, SP is below
// 4 GiB here), `add wsp, wsp, #4` does not.
.global sp_wsp_mark
sp_wsp_mark:
    svc #0
    add sp, x12, #0x2000
    add wsp, wsp, #16
    ldr x0, [sp]
    sub wsp, wsp, #32
    str x0, [sp]
    ret

.global sp_wsp_exit_mark
sp_wsp_exit_mark:
    svc #0
    add sp, x12, #0x2000
    ldr x0, [sp]
    add wsp, wsp, #4
    ret

// `mov sp, x0` with an odd x0: exits at the mov.
.global sp_mov_odd_exit_mark
sp_mov_odd_exit_mark:
    svc #0
    add sp, x12, #0x2000
    ldr x1, [sp]
    add x0, x12, #0x2000
    add x0, x0, #8
    mov sp, x0
    ldr x2, [sp]
    ret

// `mov sp, x0` with an even x0 (and `add sp, x0, #16`): the guards pass, the accesses
// right after each write run on the new SP.
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

// SP from a register sum, misaligned by x3: exits at the add.
.global sp_add_reg_exit_mark
sp_add_reg_exit_mark:
    svc #0
    add sp, x12, #0x2000
    ldr x1, [sp]
    movz x3, #4
    add sp, sp, x3, uxtx
    ldr x2, [sp]
    ret

// SP from a register sum that keeps it aligned, then an access through the committed
// SP, a register-offset SP access and a writeback access.
.global sp_guarded_then_access_mark
sp_guarded_then_access_mark:
    svc #0
    add sp, x12, #0x3000
    movz x3, #0x40
    movz x4, #0x77
    sub sp, sp, x3
    str x4, [sp]
    ldr x5, [sp]
    movz x6, #8
    ldr x7, [sp, x6]
    sub sp, sp, x3, uxtx
    stp x4, x5, [sp, #-16]!
    ldp x8, x9, [sp], #16
    add sp, sp, x3
    ldr x10, [sp, #-8]
    ret

// Stack-backed registers (x12..x18) as the sources: the whole scratch pool.
.global sp_guarded_stack_backed_mark
sp_guarded_stack_backed_mark:
    svc #0
    mov x13, x12
    add x14, x12, #0x3000
    movz x15, #0x20
    sub sp, x14, x15, uxtx
    str x13, [sp]
    ldr x0, [sp]
    ret

// `and sp, xN, #~15` realigns an odd x0 and keeps an even one: never an exit.
.global sp_and_mask_mark
sp_and_mask_mark:
    svc #0
    add x0, x12, #0x2000
    add x0, x0, #8
    and sp, x0, #~15
    movz x1, #0x31
    str x1, [sp]
    ldr x2, [sp, #-8]
    add x0, x12, #0x3000
    and sp, x0, #~15
    ldr x3, [sp]
    ret

// A mask whose low four bits are not all clear is guarded: `~7` keeps bit 3, so an x0
// with bit 3 set leaves SP misaligned and exits at the `and`.
.global sp_and_mask7_exit_mark
sp_and_mask7_exit_mark:
    svc #0
    add x0, x12, #0x2000
    add x0, x0, #8
    and sp, x0, #~7
    ldr x1, [sp]
    ret

// The same mask with an x0 that has bit 3 clear: the guard passes.
.global sp_and_mask7_mark
sp_and_mask7_mark:
    svc #0
    add x0, x12, #0x2000
    add x0, x0, #7
    and sp, x0, #~7
    ldr x1, [sp]
    ret

// `orr`/`eor` immediates write SP: guarded. The `orr` (an aligned result) passes, the
// `eor` (x0 ^ 8) exits.
.global sp_orr_eor_exit_mark
sp_orr_eor_exit_mark:
    svc #0
    add x0, x12, #0x2000
    orr sp, x0, #0x20
    ldr x1, [sp]
    eor sp, x0, #8
    ldr x2, [sp]
    ret

// Writeback by 16 (pre and post index, single and pair): no code, no exit.
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

// Writeback by 8, pre-index: exits at the store, which must not happen.
.global sp_writeback8_pre_exit_mark
sp_writeback8_pre_exit_mark:
    svc #0
    add sp, x12, #0x2000
    movz x0, #0xb0
    str x0, [sp, #-8]!
    ldr x1, [sp, #8]
    ret

// Writeback by 8, post-index: exits at the load, which must not write its register.
.global sp_writeback8_post_exit_mark
sp_writeback8_post_exit_mark:
    svc #0
    add sp, x12, #0x2000
    movz x1, #0xb1
    ldr x1, [sp], #8
    ldr x2, [sp]
    ret

// Pair writeback by 24 (encodable: stp pre-index with a multiple of 8) and by 24 on a
// pair load into stack-backed registers: both exit.
.global sp_writeback_pair24_exit_mark
sp_writeback_pair24_exit_mark:
    svc #0
    add sp, x12, #0x2000
    movz x0, #0xd0
    movz x1, #0xd1
    stp x0, x1, [sp, #-24]!
    ldp x2, x3, [sp]
    ret

.global sp_writeback_ldp_stack_backed_exit_mark
sp_writeback_ldp_stack_backed_exit_mark:
    svc #0
    add sp, x12, #0x2000
    movz x13, #0xe0
    movz x14, #0xe1
    ldp x13, x14, [sp], #24
    ret

// A pair writeback with an offset outside simm9 needs an address scratch; by 512 it
// is a multiple of 16 and passes.
.global sp_writeback_pair_far_mark
sp_writeback_pair_far_mark:
    svc #0
    add sp, x12, #0x3000
    movz x13, #0xe2
    movz x14, #0xe3
    stp x13, x14, [sp, #-512]!
    ldp x15, x16, [sp]
    add sp, sp, #512
    ret

// SIMD&FP writeback: by 16 and by a register that is a multiple of 16 pass; `str d0,
// [sp, #-8]!` and an `ld1` post-indexed by 8 exit.
.global sp_simd_writeback_mark
sp_simd_writeback_mark:
    svc #0
    add sp, x12, #0x3000
    movi v0.16b, #0x5a
    str q0, [sp, #-16]!
    ldr q1, [sp]
    movz x3, #0x20
    ld1 {v2.16b}, [sp], x3
    ld1 {v3.16b}, [sp], #16
    ret

.global sp_simd_writeback8_exit_mark
sp_simd_writeback8_exit_mark:
    svc #0
    add sp, x12, #0x3000
    movi v0.16b, #0x5a
    str d0, [sp, #-8]!
    ret

.global sp_simd_post8_exit_mark
sp_simd_post8_exit_mark:
    svc #0
    add sp, x12, #0x3000
    ld1 {v0.8b}, [sp], #8
    ret

.global sp_simd_post_reg_exit_mark
sp_simd_post_reg_exit_mark:
    svc #0
    add sp, x12, #0x3000
    movz x3, #4
    ld1 {v0.16b}, [sp], x3
    ret

// A loop whose body keeps SP aligned all the way.
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

// The loop misaligns SP on its second iteration (x4 is 16, then 8): the run ends at the
// `sub` on that dynamic instance, which the original is stopped at too.
.global sp_loop_misaligns_late_exit_mark
sp_loop_misaligns_late_exit_mark:
    svc #0
    add sp, x12, #0x3000
    movz x3, #3
    movz x4, #16
1:
    ldr x0, [sp]
    sub sp, sp, x4
    subs x3, x3, #1
    movz x4, #8
    b.ne 1b
    ret

// A forward join point: the fall-through path misaligns SP and exits at the `sub`.
.global sp_join_misaligned_exit_mark
sp_join_misaligned_exit_mark:
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

// Entry labels (A20): a fragment is entered only at a block start, so a transfer to the
// middle of a block misses and the target is translated as its own fragment. The same
// calls with SP aligned: the mid-block entry runs (as its own fragment) and returns.
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
