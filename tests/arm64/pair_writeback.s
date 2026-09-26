// Pair and writeback memory fixture for register virtualization.
// Exercises LDP/STP (offset, pre, post) and LDR/STR pre/post-index with SP,
// x29 (stable-mapped) and x12..x17 (stack-backed) as bases and transfer regs.
//
//   make harness-test-asm ASM=tests/arm64/pair_writeback.s
//
// Initial fixture state: x12 = FIXTURE_DATA_BASE (0x20000), everything else
// (including SP) = 0. All addresses are derived from x12.

.text
.global toy_translate_entry
toy_translate_entry:
.global hot_svc_mark
hot_svc_mark:
    svc #0

    // Give user SP a stack well away from the x12 buffer.
    add sp, x12, #0x800

    // Function-like prologue.
    stp x29, x30, [sp, #-32]!
    mov x29, sp
    stp x12, x13, [sp, #16]

    movz x13, #0x1313
    movz x14, #0x1414
    movz x15, #0x1515
    movz x16, #0x1616
    movz x17, #0x1717

    // Stack-backed base with two stack-backed transfer registers.
    stp x14, x15, [x12], #16
    stp x16, x17, [x12, #16]!

    // Runtime exit while SP/x29 are displaced; epilogue/prologue must preserve them.
    svc #0

    // x29 as a pair base: reload the saved x12/x13 into x16/x17.
    ldp x16, x17, [x29, #16]

    // Post-index pointer walk over the buffer written above.
    sub x13, x12, #32
    ldr x0, [x13], #8
    ldr x1, [x13], #8
    ldr w2, [x13, #8]!
    ldr x3, [x13, #-8]!

    add x14, x12, #0x1000
    str x0, [x14], #8
    str x1, [x14, #8]!
    str w2, [x14], #4
    str x3, [x14, #-4]!
    ldr x15, [x14, #-8]!

    // SP as a single-register writeback base.
    str x15, [sp, #-16]!
    ldr x4, [sp], #16

    // Epilogue.
    ldp x12, x13, [sp, #16]
    ldp x29, x30, [sp], #32
    ret
