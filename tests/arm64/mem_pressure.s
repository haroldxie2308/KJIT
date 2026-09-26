// A5 memory-lowering fixture: register overlaps and scratch pressure.
// Exercises LDP/STP whose second register is the base (no writeback), loads
// into stack-backed x12..x15 from a stack-backed base with an out-of-simm9
// offset (all four scratch registers), SP- and x29-based prologue/epilogue
// pairs, and loads whose first destination is x29 or the base itself.
//
//   make harness-test-asm ASM=tests/arm64/mem_pressure.s
//
// Initial fixture state: x12 = FIXTURE_DATA_BASE, the base of a 16 KiB RW data
// window; everything else (including SP) = 0. All addresses derive from x12.

.text
.global mem_pressure_entry
mem_pressure_entry:
.global hot_svc_mark
hot_svc_mark:
    svc #0

    add sp, x12, #0x3000
    movz x29, #0x2929
    movz x30, #0x3030

    // Function-like prologue.
    stp x29, x30, [sp, #-48]!
    mov x29, sp
    str x12, [sp, #16]

    // Seed a table at x12 + 0x800 through x12 + 0x9f8.
    add x0, x12, #0x800
    movz x1, #0x1001
    movz x2, #0x2002
    stp x1, x2, [x0]
    stp x2, x1, [x0, #496]
    str x0, [x0, #16]

    // Second register is the base, no writeback: the base is read before it
    // is overwritten, for loads and stores.
    add x3, x12, #0x800
    ldp x4, x3, [x3]
    add x5, x12, #0x800
    stp x4, x5, [x5, #24]
    add x6, x12, #0x800
    ldp x6, x7, [x6, #16]

    // Stack-backed destinations and base with a large offset: the base, both
    // targets and the materialized address use all four scratch registers.
    add x14, x12, #0x800
    ldp x12, x13, [x14, #496]
    stp x13, x12, [x14, #-512]!
    ldp x15, x16, [x14], #504
    ldr x17, [x14, #-8]!

    // x29 as a load target (x16 physically) and as a pair base.
    ldp x29, x9, [x29, #16]
    ldr x29, [sp, #0]

    // SP-based single-register writeback, pre and post.
    str x15, [sp, #-16]!
    ldr x10, [sp], #16

    // Epilogue.
    ldr x12, [sp, #16]
    ldp x29, x30, [sp], #48
    ret
