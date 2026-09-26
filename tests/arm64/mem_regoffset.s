// A7b register-offset fixture: array indexing with LSL, UXTW, SXTW and SXTX
// index registers (including negative indices and garbage in the top half of
// a W index), byte/halfword/word/doubleword element sizes, an SP base, and a
// load whose base, index and target are all stack-backed (the whole scratch
// pool).
//
//   make harness-test-asm ASM=tests/arm64/mem_regoffset.s
//
// Initial fixture state: x12 = FIXTURE_DATA_BASE, a 16 KiB RW window (all
// zero); everything else (including SP) = 0. All addresses derive from x12.

.text
.global mem_regoffset_entry
mem_regoffset_entry:
.global hot_svc_mark
hot_svc_mark:
    svc #0

    // a[i] = 3 * i + 1 for i in -8..8, 64-bit elements centred at x12 + 0x800.
    add x0, x12, #0x800
    movn x1, #7                         // i = -8
    movz x8, #172
.Lfill:
    add x2, x1, x1, lsl #1
    add x2, x2, #1
    str x2, [x0, x1, lsl #3]
    add x1, x1, #1
    cmp x1, #8
    b.ne .Lfill

    // sum = sum of a[i] via SXTW indices, SVC inside the loop.
    movz x3, #0
    movn w4, #7                         // w4 = -8; top half of x4 is zero
.Lsum:
    ldr x5, [x0, w4, sxtw #3]
    add x3, x3, x5
    svc #0
    add w4, w4, #1
    cmp w4, #8
    b.ne .Lsum

    // Negative and garbage-topped indices.
    movn x6, #1                         // -2
    ldr x7, [x0, x6, sxtx #3]           // a[-2]
    ldr x9, [x0, x6, lsl #3]            // same address
    movz x10, #3
    movk x10, #0xdead, lsl #48          // uxtw must ignore the top half
    ldr x11, [x0, w10, uxtw #3]         // a[3]
    movz x13, #0xfff8
    movk x13, #0xffff, lsl #16          // w13 = -8, x13 top half zero
    ldr x14, [x0, w13, sxtw]            // byte offset -8: a[-1]

    // 32-bit elements, LDRSW and a W target.
    add x15, x12, #0xc00
    movn w16, #0                        // -1 as a word
    movz x17, #2
    str w16, [x15, x17, lsl #2]
    ldrsw x1, [x15, x17, lsl #2]        // -1 sign-extended
    ldr w2, [x15, w17, uxtw #2]         // 0xffffffff zero-extended
    movn x6, #0
    ldrsw x4, [x15, x6, sxtx #2]        // word at -4: zero

    // Halfwords and bytes.
    movz w5, #0x8001
    strh w5, [x15, x17, lsl #1]         // at +4
    ldrh w7, [x15, x17, lsl #1]
    ldrsh x9, [x15, w17, uxtw #1]
    ldrsh w10, [x15, x17]               // offset 2: zero half
    movz w11, #0x80
    strb w11, [x15, x17]
    ldrb w13, [x15, x17]
    ldrsb x14, [x15, x17, lsl #0]
    ldrsb w16, [x15, w17, sxtw]
    movn x6, #0                         // -1
    ldrb w0, [x15, x6]                  // byte before the array
    strb wzr, [x15, x6]
    str xzr, [x15, xzr]

    // SP as the base.
    add sp, x12, #0x2000
    movz x6, #5
    str x3, [sp, x6, lsl #3]
    ldr x2, [sp, w6, uxtw #3]

    // Stack-backed base, index and target at once.
    add x13, x12, #0x800
    movz x14, #4
    ldr x12, [x13, x14, lsl #3]         // a[4]; x12 itself is overwritten
    ldrh w15, [x13, x14]
    ret
