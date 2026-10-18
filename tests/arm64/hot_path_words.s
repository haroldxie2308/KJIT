// A21 hot-path word reduction fixture (docs/pipeline.md, "Hot-path word reduction
// (A21)"). Every case runs through the full-pipeline differential (and the native
// runner on arm64 hosts); a wrong forwarded fill, a deleted spill that a fault or an
// exit could see, a wrong constant chain or a window access on the wrong register is
// a state mismatch.
//
// - Constants: ADR/ADRP results are one word per non-zero halfword (a page address
//   with a zero low halfword, a zero middle halfword, a negative offset), built in the
//   scratch of a stack-backed destination and spilled once.
// - Slot forwarding: chains on stack-backed x13..x17, a loop head and a branch target
//   (join points), a spill that a fault and a conditional branch must still see.
// - SP-based pairs at the edges of a mapped page and a pair whose first access
//   faults or whose second does (the first load stays in scratch there).
// - Window accesses on a base that is not copied: a direct register, SP, x29, the
//   base as its own data register, SIMD&FP base-only forms with and without
//   writeback.
//
//   make harness-test-asm ASM=tests/arm64/hot_path_words.s HOT_SVC_SYMBOL=adrp_stack_backed_mark
//
// Initial fixture state: x12 = FIXTURE_DATA_BASE (16 KiB aligned), a 16 KiB RW window
// (all zero); the page at x12 + 0x4000 is read-only and x12 + 0x5000 is unmapped;
// everything else (SP included) = 0.

.text
.arch_extension lse
.global hot_path_words_entry
hot_path_words_entry:

// ADRP/ADR into stack-backed registers (x13..x17), then their use.
.global adrp_stack_backed_mark
adrp_stack_backed_mark:
    svc #0
    adrp x16, anchor_a
    add x16, x16, :lo12:anchor_a
    adr x0, anchor_a
    sub x1, x16, x0
    adrp x14, #0x40000000
    adrp x15, #0x1000
    adrp x13, anchor_a
    add x13, x13, #8
    mov x2, x13
    adrp x17, #-0x1000
    adrp x3, #0x7ffff000
    adr x4, anchor_a
    adr x15, anchor_b
    sub x5, x15, x4
    adrp x16, anchor_b
    ldr x6, [x16, :lo12:anchor_b]
    ret

// A chain of updates on stack-backed registers: the second fill of a register that
// the previous instruction left is forwarded, and the intermediate spills are dead.
.global fill_forwarding_mark
fill_forwarding_mark:
    svc #0
    movz x14, #5
    movz x15, #7
    add x14, x14, x15
    add x14, x14, x15
    eor x15, x14, x15
    str x14, [x12, #0x40]
    ldr x16, [x12, #0x40]
    add x16, x16, #1
    add x17, x16, x14
    sub x13, x17, x15
    mov x0, x13
    ret

// A loop head and a branch target are join points: the counter's slot is the only
// truth there.
.global join_points_mark
join_points_mark:
    svc #0
    movz x16, #10
    movz x14, #0
1:
    add x14, x14, x16
    sub x16, x16, #1
    cbnz x16, 1b
    movz x15, #3
    cbz x0, 2f
    add x15, x15, #100
2:
    add x15, x15, x14
    mov x1, x15
    ret

// The spills before a faulting user access must land: the Mem exit returns to
// userspace with every register as it was before the faulting instruction.
.global spill_kept_across_fault_mark
spill_kept_across_fault_mark:
    svc #0
    add x14, x14, #1
    add x15, x15, #2
    add x16, x16, #3
    add x14, x14, #4
    ldr x0, [x12, #0x5000]
    add x14, x14, #100
    ret

// ... across a conditional branch, which ends the block: the next block starts from
// the slots (taken and not taken).
.global spill_kept_across_branch_taken_mark
spill_kept_across_branch_taken_mark:
    svc #0
    movz x0, #0
    add x14, x14, #1
    cbz x0, 3f
    add x14, x14, #2
3:
    mov x1, x14
    add x14, x14, #8
    mov x2, x14
    ret

.global spill_kept_across_branch_not_taken_mark
spill_kept_across_branch_not_taken_mark:
    svc #0
    movz x0, #1
    add x14, x14, #1
    cbz x0, 4f
    add x14, x14, #2
4:
    mov x1, x14
    add x14, x14, #8
    mov x2, x14
    ret

// ... across the SP guard of a write that misaligns SP (`and xT, xS, #15; cbnz xT,
// <Mem stub>`, A22): its Mem exit at the `add sp` must see the first update only.
.global spill_kept_across_sp_guard_mark
spill_kept_across_sp_guard_mark:
    svc #0
    add x1, x12, #0x2000
    add x14, x14, #1
    add sp, x1, #8
    add x14, x14, #2
    ldr x0, [sp]
    ret

// SP-based pairs inside the last 16 bytes of a mapped page (the read-only page at
// x12 + 0x4000 ends at x12 + 0x5000, the unmapped one starts there).
.global sp_pair_page_edge_mark
sp_pair_page_edge_mark:
    svc #0
    add x1, x12, #0x5000
    sub sp, x1, #16
    ldp x2, x3, [sp]
    ldp w4, w5, [sp, #8]
    ldpsw x6, x7, [sp, #8]
    ldp x8, x9, [sp], #0
    ldpsw x10, x11, [sp]
    ret

// A pair at the page edge whose first access faults (SP 16-aligned, both accesses
// unmapped) and one whose second does (the pair straddles the edge).
.global sp_pair_first_fault_mark
sp_pair_first_fault_mark:
    svc #0
    movz x2, #0x22
    movz x3, #0x33
    add sp, x12, #0x5000
    ldp x2, x3, [sp]
    ret

.global sp_pair_second_fault_mark
sp_pair_second_fault_mark:
    svc #0
    movz x2, #0x22
    movz x3, #0x33
    add sp, x12, #0x5000
    ldp x2, x3, [sp, #-8]
    ret

// LSE atomics based on a register that is used as it is: direct (x1, x9..x11 in the
// runtime-reserved range, x20), SP, x29, and the base as its own data register.
.global window_direct_base_mark
window_direct_base_mark:
    svc #0
    add x1, x12, #0x100
    movz x0, #0x10
    ldadd x0, x2, [x1]
    ldaddal x0, x3, [x1]
    add x9, x12, #0x110
    swp x0, x4, [x9]
    add x20, x12, #0x120
    ldset x0, x5, [x20]
    stadd x0, [x20]
    casal x2, x3, [x1]
    ldadd x1, x1, [x1]
    ldr x6, [x12, #0x100]
    ret

.global window_sp_base_mark
window_sp_base_mark:
    svc #0
    add sp, x12, #0x200
    movz x0, #0x10
    ldadd x0, x2, [sp]
    swpal x0, x3, [sp]
    ldsetb w0, w4, [sp]
    ldr x5, [x12, #0x200]
    ret

.global window_x29_base_mark
window_x29_base_mark:
    svc #0
    add x29, x12, #0x300
    movz x0, #0x10
    ldadd x0, x2, [x29]
    swpal x0, x3, [x29]
    stclr x0, [x29]
    ldr x5, [x12, #0x300]
    ret

// SIMD&FP base-only window accesses on the same registers, with and without
// writeback (the writeback is a separate add after the access).
.global window_simd_base_mark
window_simd_base_mark:
    svc #0
    add x1, x12, #0x400
    add sp, x12, #0x500
    add x29, x12, #0x600
    movz x0, #0x77
    stp x0, x0, [x1]
    stp x0, x0, [sp]
    stp x0, x0, [x29]
    ldr q0, [x1]
    ldr q1, [sp]
    ldr q2, [x29]
    str q2, [x1, #0]
    str q1, [sp]
    ld1 {v3.16b}, [x1], #16
    ld1 {v4.16b}, [x29], #16
    st1 {v3.16b}, [sp], #16
    ldr x2, [x12, #0x400]
    ret

// An SP-based window access at a 16-byte aligned SP: no alignment code (A22).
.global window_sp_mark
window_sp_mark:
    svc #0
    add sp, x12, #0x200
    movz x0, #0x10
    ldadd x0, x2, [sp]
    ret

// A window access outside the user half (range check) leaves for userspace.
.global window_direct_kernel_pointer_mark
window_direct_kernel_pointer_mark:
    svc #0
    movz x1, #0x1, lsl #48
    movz x0, #0x10
    ldadd x0, x2, [x1]
    ret

.balign 16
anchor_a:
    .quad 0x1122334455667788
    .quad 0
anchor_b:
    .quad 0x99aabbccddeeff00
    .quad 0
