// A7c barriers and acquire/release fixture. DMB/DSB/ISB are emitted unchanged;
// every LDAR*/STLR*/LDAPR* becomes `dmb ish; LDTR*/STTR* [xN, #0]; dmb ish`,
// after the SP check (SP base) or the 16-byte-block alignment check (any
// other base, wider than a byte). Cases: a lock-like loop with an SVC in it,
// SP-based and byte/halfword forms, a permission fault on each side of the
// read-only page, and alignment: misaligned inside a 16-byte block runs,
// crossing a block faults (SIGBUS natively; the fragment leaves through the Mem
// stub before touching memory).
//
//   make harness-test-asm ASM=tests/arm64/barriers_acqrel.s
//
// Initial fixture state: x12 = FIXTURE_DATA_BASE, a 16 KiB RW window (all
// zero); the page at x12 + 0x4000 is read-only and x12 + 0x5000 is unmapped;
// everything else (including SP) = 0. All addresses derive from x12.

.text
.arch_extension rcpc
.global barriers_acqrel_entry
barriers_acqrel_entry:
.global hot_svc_mark
hot_svc_mark:
    svc #0

    // Spin lock around a counter: acquire the flag, take it with a release
    // store, bump the counter under a full barrier, release. Five rounds, an
    // SVC inside each.
    add x1, x12, #0x100
    add x2, x12, #0x108
    movz x3, #5
    movz x8, #172
.Llock:
    ldar w4, [x1]
    cbnz w4, .Lbusy
    movz w5, #1
    stlr w5, [x1]
    dmb ish
    ldr x6, [x2]
    add x6, x6, #1
    str x6, [x2]
    dmb ishst
    stlr wzr, [x1]
    dmb ishld
    isb
    svc #0
    subs x3, x3, #1
    b.ne .Llock
    // RCpc read of the result, every DSB/ISB flavour the subset admits.
    ldapr x7, [x2]
    dsb sy
    dsb ish
    dsb nshst
    ssbb
    pssbb
    isb sy
    dmb oshld
    dmb #0
    ret
.Lbusy:
    movz x7, #0xdead
    ret

// SP-based acquire/release: SP 16-byte aligned, so only the SP check applies.
.global sp_acqrel_mark
sp_acqrel_mark:
    svc #0
    add sp, x12, #0x2000
    movz x3, #0x1234
    movk x3, #0x5678, lsl #32
    stlr x3, [sp]
    ldar x4, [sp]
    ldarb w5, [sp]
    ldaprh w6, [sp]
    stlrh w3, [sp]
    ldapr w7, [sp]
    ret

// Byte/halfword/word variants, misaligned but inside one 16-byte block (no
// fault anywhere), plus stack-backed registers x12..x17 and x29.
.global narrow_acqrel_mark
narrow_acqrel_mark:
    svc #0
    add x0, x12, #0x301
    movz w1, #0xa5
    stlrb w1, [x0]
    ldarb w2, [x0]
    ldaprb w3, [x0]
    add x13, x12, #0x305
    movz w14, #0xbeef
    stlrh w14, [x13]
    ldarh w15, [x13]
    ldaprh w16, [x13]
    add x29, x12, #0x344
    movz x17, #0x7777
    stlr w17, [x29]
    ldar w9, [x29]
    add x10, x12, #0x358
    stlr x14, [x10]
    ldapr x11, [x10]
    ret

// Store-release to the read-only page: the load-acquire before it succeeds; the
// store leaves through its Mem stub with nothing stored.
.global stlr_ro_mark
stlr_ro_mark:
    svc #0
    add x0, x12, #0x4000
    movz x1, #0x55
    ldar x2, [x0]
    stlr x1, [x0, #0]
    movz x3, #1
    ret

// Load-acquire from the unmapped page: the destination keeps its value.
.global ldar_unmapped_mark
ldar_unmapped_mark:
    svc #0
    add x4, x12, #0x5000
    movz x5, #0x5555
    ldarh w5, [x4]
    ret

// Crossing a 16-byte boundary: `ldar x` at +12 of a block faults on alignment
// before any access (natively SIGBUS). The misaligned `ldar w` at +4 before it
// runs.
.global ldar_cross_mark
ldar_cross_mark:
    svc #0
    add x6, x12, #0x404
    ldar w7, [x6]
    add x6, x6, #8
    movz x8, #0x88
    ldar x8, [x6]
    ret

// Same for a halfword store-release at the last byte of a block, through a
// stack-backed base; memory stays untouched.
.global stlrh_cross_mark
stlrh_cross_mark:
    svc #0
    add x15, x12, #0x40f
    movz w1, #0xffff
    stlrh w1, [x15]
    ret

// SP-based load-acquire with SP not 16-byte aligned: the SP check fires first.
.global ldar_sp_misaligned_mark
ldar_sp_misaligned_mark:
    svc #0
    add sp, x12, #0x2000
    add sp, sp, #8
    ldar x0, [sp]
    ret
