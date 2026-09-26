// A5 memory-lowering fixture: offsets LDTR/STTR cannot encode directly.
// Exercises out-of-simm9 immediates (materialized into scratch with ADD/SUB,
// optionally lsl #12), negative pre/post-index writeback, pair offsets up to
// -512, and single and pair accesses that cross a page boundary.
//
//   make harness-test-asm ASM=tests/arm64/mem_offsets.s
//
// Initial fixture state: x12 = FIXTURE_DATA_BASE, the base of a 16 KiB RW data
// window; everything else (including SP) = 0. All addresses derive from x12.

.text
.global mem_offsets_entry
mem_offsets_entry:
.global hot_svc_mark
hot_svc_mark:
    svc #0

    movz x0, #0x1111
    movk x0, #0xaaaa, lsl #48
    movz x2, #0x2222
    movk x2, #0xbbbb, lsl #16

    // Largest scaled unsigned offsets: the base sits far below the window so
    // base + offset lands inside it.
    sub x1, x12, #0x5000
    str x0, [x1, #32760]
    ldr x4, [x1, #32760]
    sub x3, x12, #0x2000
    str w2, [x3, #16380]
    ldr w5, [x3, #16380]

    // Offsets just outside simm9 in both directions.
    add x6, x12, #0x2000
    str x4, [x6, #256]
    ldr x7, [x6, #256]
    str w5, [x6, #260]

    // Negative pre/post-index writeback.
    add x8, x12, #0x2000
    str x0, [x8, #-8]!
    ldr x9, [x8], #-16
    str w2, [x8, #-4]!
    ldr w10, [x8], #-256

    // Pair offsets at the ends of the imm7 range; -512 needs a scratch address.
    add x11, x12, #0x3000
    stp x0, x2, [x11, #-512]!
    ldp x13, x14, [x11], #504
    stp x4, x5, [x11, #504]
    ldp x15, x16, [x11, #-512]

    // Page crossing: an unaligned 8-byte LDR/STR over the page 1/page 2 border
    // (x12 + 0x2000), and pairs whose halves live on different pages.
    add x17, x12, #0x1000
    add x17, x17, #0xff8
    ldr x3, [x17, #4]!
    str x0, [x17], #4
    stp x0, x2, [x17]
    ldp x5, x6, [x17]
    sub x17, x17, #4
    stp x6, x5, [x17, #-8]!
    ret
