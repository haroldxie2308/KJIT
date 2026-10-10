// A12 fixture: user x18. Physical x18 is the fragment's budget counter, so user x18
// is stack-backed (frame slot 192, docs/pipeline.md "Runtime frame") and every use
// goes through a fill/spill. Each case runs the same instructions on the original
// and on the fragment and compares the whole state, so the value of user x18 must
// survive the prologue, every runtime exit and the epilogue, and must never be
// confused with the counter.
//
//   make harness-test-asm ASM=tests/arm64/user_x18.s HOT_SVC_SYMBOL=x18_alu_mark
//
// Initial fixture state: x12 = FIXTURE_DATA_BASE, a 16 KiB RW window (all zero);
// every other register is 0.

.text
.global user_x18_entry
user_x18_entry:

// x18 as source, destination and read-write operand of the ALU forms, 64 and 32
// bit, flags, four-operand madd, MRS, and across an SVC exit (the value is written
// back to pt_regs from the slot and reloaded on re-entry).
.global x18_alu_mark
x18_alu_mark:
    svc #0
    movz x18, #0x1234
    movk x18, #0xabcd, lsl #32
    add x0, x18, #1
    sub x18, x18, x0, lsl #3
    mov x1, x18
    movz w18, #0x77
    orr x2, x18, x1
    svc #0
    madd x3, x18, x1, x18
    msub x18, x3, x2, x18
    adds x4, x18, x18
    cinc x5, x18, vs
    csel x18, x4, x5, mi
    ubfx x6, x18, #3, #9
    bfi x18, x6, #40, #9
    mrs x18, tpidr_el0
    sub x7, x18, x18
    rbit x18, x18
    cmp x18, x7
    cset w8, hi
    svc #0
    mov x9, x18
    ret

// x18 as memory base (offset, pre/post-index writeback), index, and pair/single
// data register, through the data window.
.global x18_mem_mark
x18_mem_mark:
    svc #0
    add x18, x12, #0x100
    movz x0, #0x5555
    str x0, [x18]
    str x0, [x18, #8]!
    ldr x1, [x18], #16
    ldr x2, [x18, #-16]
    mov x3, #8
    ldr x4, [x12, x3]
    sub x18, x18, x12
    ldr x5, [x12, x18]
    add x18, x12, #0x200
    stp x18, x0, [x12, #0x40]
    ldp x6, x18, [x12, #0x40]
    stp x18, x18, [x12, #0x60]
    ldr w18, [x12, #0x40]
    strb w18, [x12, #0x70]
    ldrb w7, [x12, #0x70]
    add x18, x12, #0x300
    ldr x8, [x18, w3, uxtw #3]
    ldr x18, [x12, #0x48]
    str x18, [x12, #0x78]
    ret

// A countdown in x18 shorter than the budget: the back-edge is guarded by the
// budget check, whose counter is a different register.
.global x18_loop_mark
x18_loop_mark:
    svc #0
    movz x18, #1000
    movz x1, #0
1:
    add x1, x1, x18
    sub x18, x18, #1
    cbnz x18, 1b
    ret

// A countdown in x18 longer than the budget: the Budget exit at the 4096th
// back-edge leaves user x18 = 10000 - 4096, not the counter.
.global x18_budget_mark
x18_budget_mark:
    svc #0
    movz x18, #10000
    movz x3, #0
1:
    add x3, x3, #2
    sub x18, x18, #1
    cbnz x18, 1b
    ret

// Branches through x18: a call, a jump and a return, each a dispatch site charged
// to the budget, and the first reads x18 into the target move.
.global x18_dispatch_mark
x18_dispatch_mark:
    svc #0
    mov x20, x30
    movz x1, #0
    adr x18, x18_callee
    blr x18
    adr x18, x18_callee
    blr x18
    adr x18, 2f
    br x18
    movz x1, #0xdead
2:
    mov x18, x30
    mov x30, x20
    add x1, x1, #1000
    str x1, [x12, #0x70]
    ret

x18_callee:
    add x1, x1, #1
    mov x2, x18
    ret

// x18 as the compare/branch operand of every conditional form, taken and not.
.global x18_branch_mark
x18_branch_mark:
    svc #0
    movz x18, #0
    movz x1, #0
    cbz x18, 1f
    add x1, x1, #1
1:
    add x18, x18, #5
    cbz x18, 2f
    add x1, x1, #2
2:
    tbz x18, #0, 3f
    add x1, x1, #4
3:
    tbnz x18, #2, 4f
    add x1, x1, #8
4:
    cmp x18, #5
    b.eq 5f
    add x1, x1, #16
5:
    ret
