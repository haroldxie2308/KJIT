// A7b byte/halfword fixture: string-routine style byte loops (memset, strlen,
// memcpy) with an SVC inside the loop, plus every sign/zero-extending narrow
// load at its boundary values, unscaled offsets, unaligned and page-crossing
// halfword/word accesses.
//
//   make harness-test-asm ASM=tests/arm64/mem_bytes.s
//
// Initial fixture state: x12 = FIXTURE_DATA_BASE, a 16 KiB RW window (all
// zero); everything else (including SP) = 0. All addresses derive from x12.

.text
.global mem_bytes_entry
mem_bytes_entry:
.global hot_svc_mark
hot_svc_mark:
    svc #0

    // memset(x12 + 0x100, 0x5a, 37): post-index byte stores, SVC every byte.
    add x0, x12, #0x100
    movz w1, #0x5a
    movz x2, #37
    movz x8, #172
.Lmemset:
    strb w1, [x0], #1
    svc #0
    subs x2, x2, #1
    b.ne .Lmemset

    // A NUL-terminated string at x12 + 0x200: "hello, kjit!" (12 bytes).
    add x3, x12, #0x200
    movz x4, #0x6568
    movk x4, #0x6c6c, lsl #16
    movk x4, #0x2c6f, lsl #32
    movk x4, #0x6b20, lsl #48
    str x4, [x3]
    movz w4, #0x696a
    movk w4, #0x2174, lsl #16
    str w4, [x3, #8]

    // strlen: pre-index byte walk; the SVC sits inside the loop.
    sub x5, x3, #1
.Lstrlen:
    ldrb w6, [x5, #1]!
    svc #0
    cbnz w6, .Lstrlen
    sub x7, x5, x3                      // 12

    // memcpy(x12 + 0x300, x3, x7 + 1) with post-index halfword then byte copies.
    add x9, x12, #0x300
    mov x10, x3
    lsr x11, x7, #1
.Lcopy_half:
    ldrh w13, [x10], #2
    strh w13, [x9], #2
    subs x11, x11, #1
    b.ne .Lcopy_half
    ldrb w13, [x10]
    strb w13, [x9]

    // Boundary values for every signed narrow load.
    add x14, x12, #0x400
    movz w0, #0x807f                    // bytes 7f 80
    strh w0, [x14]
    movz w0, #0x7fff
    strh w0, [x14, #2]
    movz w0, #0x8000
    strh w0, [x14, #4]
    movn w0, #0x8000, lsl #16           // 0x7fffffff
    str w0, [x14, #8]
    movz w0, #0x8000, lsl #16           // 0x80000000
    str w0, [x14, #12]

    movn x15, #0                        // all ones: 32-bit targets must clear it
    mov x16, x15
    mov x17, x15
    ldrsb w15, [x14]                    // 0x7f
    ldrsb w16, [x14, #1]                // 0xffffff80
    ldrsb x17, [x14, #1]                // sign-extended to 64
    ldrsh w0, [x14, #2]                 // 0x7fff
    ldrsh w1, [x14, #4]                 // 0xffff8000
    ldrsh x2, [x14, #4]
    ldrsw x4, [x14, #8]                 // 0x7fffffff
    ldrsw x6, [x14, #12]                // 0xffffffff80000000
    ldrb w11, [x14, #1]                 // 0x80, zero-extended
    ldrh w13, [x14, #4]                 // 0x8000, zero-extended

    // Unscaled forms with negative offsets from a pointer past the data.
    add x14, x14, #16
    ldursb w15, [x14, #-15]
    ldursb x16, [x14, #-15]
    ldursh x17, [x14, #-12]
    ldursw x0, [x14, #-4]
    ldurb w1, [x14, #-16]
    ldurh w2, [x14, #-14]
    ldur w4, [x14, #-8]
    ldur x6, [x14, #-16]
    sturb w1, [x14, #1]
    sturh w2, [x14, #3]
    stur w4, [x14, #5]
    stur x6, [x14, #9]
    stur xzr, [x14, #17]
    sturh wzr, [x14, #25]

    // Unaligned accesses, and halfword/word/doubleword straddling the page
    // boundary at x12 + 0x1000 (both pages mapped).
    add x9, x12, #0x1000
    movz x10, #0xa1b2
    movk x10, #0xc3d4, lsl #16
    movk x10, #0xe5f6, lsl #32
    movk x10, #0x0718, lsl #48
    stur x10, [x9, #-3]
    ldurh w11, [x9, #-1]
    ldursh x13, [x9, #-1]
    ldur w15, [x9, #-2]
    ldursw x16, [x9, #-3]
    ldrh w17, [x9, #-3]!                // pre-index to an odd address
    sturh w17, [x9, #7]
    ldrsb x0, [x9], #3
    strb w0, [x9, #255]
    ret
