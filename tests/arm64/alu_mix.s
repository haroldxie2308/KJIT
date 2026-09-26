// ALU mix fixture: a hash loop over a small table with the usual compiler ALU
// set (shifted/extended add, logical immediates, bitfield moves, madd/msub,
// division, multiply-high, rev/rbit/clz, csel family, ccmp/ccmn) and two SVCs
// per iteration. Flag probes branch on all 16 condition codes. The index-driven
// probes (`cmp x5, #3` and the signed-overflow `adds`) make every condition
// except AL/NV go both ways across the 8 iterations; the rest depend on data.
//
// Initial fixture state: x12 = data window base.
//
//   make harness-test-asm ASM=tests/arm64/alu_mix.s

// b.<cond> plus a cinc on the same condition: the not-taken count goes to x21,
// the taken/not-taken history is folded into x20.
.macro probe cond
    b.\cond 1f
    add x21, x21, #1
1:
    cinc x20, x20, \cond
    ror x20, x20, #61
.endm

// AL and NV always branch; cinc does not accept them.
.macro probe_always cond
    b.\cond 1f
    add x21, x21, #0x100
1:
.endm

.text
.global alu_mix_entry
alu_mix_entry:
.global hot_svc_mark
hot_svc_mark:
    svc #0

    // Seed an 8-entry u64 table at x12 with xorshift64 values.
    movz x1, #0x1234
    movk x1, #0x9e37, lsl #48
    movz x2, #8
    mov x3, x12
.Lseed:
    str x1, [x3], #8
    eor x1, x1, x1, lsl #13
    eor x1, x1, x1, lsr #7
    eor x1, x1, x1, lsl #17
    subs x2, x2, #1
    b.ne .Lseed

    // FNV-1a offset basis and prime.
    mov x4, #0x2325
    movk x4, #0x8422, lsl #16
    movk x4, #0x9ce4, lsl #32
    movk x4, #0xcbf2, lsl #48
    mov x6, #0x1b3
    movk x6, #0x100, lsl #32
    mov x5, #0
    mov x20, #0
    mov x21, #0
    mov x22, #0

.Lloop:
    // Hash step.
    add x8, x12, x5, lsl #3
    ldr x7, [x8]
    eor x4, x4, x7
    madd x4, x4, x6, x5
    ubfx x10, x4, #7, #9
    add x4, x4, x10, lsl #2
    rev x11, x4
    eor x4, x4, x11, lsr #3
    extr x19, x4, x7, #17
    eor x4, x4, x19
    svc #0

    // 32-bit and bitfield work, folded into x22.
    eor w13, w4, w7, ror #5
    sbfx x14, x4, #3, #13
    bfi x13, x14, #40, #12
    sxtw x15, w7
    uxth w16, w4
    add x13, x13, w16, uxtw #2
    sub x13, x13, w15, sxtw #1
    and x14, x4, #0x00ff00ff00ff00ff
    orr w15, w7, #0xf0f0f0f0
    eor x16, x13, #0x8000000000000001
    bic x14, x14, x15, lsl #1
    orn w15, w15, w16
    eon x16, x16, x14, asr #9
    movn w17, #0x1234, lsl #16
    add x22, x22, x13
    eor x22, x22, x14
    add x22, x22, x15, lsl #7
    eor x22, x22, x16, ror #11
    add x22, x22, x17

    // Variable shifts, division, multiply-high, bit counts.
    lsl x13, x4, x5
    lsr w14, w4, w7
    asr x15, x7, x4
    ror w16, w7, w5
    udiv x17, x4, x6
    msub x17, x17, x6, x4
    sdiv w23, w4, w5
    umulh x24, x4, x6
    smulh x25, x4, x7
    smull x26, w4, w7
    umaddl x26, w5, w6, x26
    mneg w27, w4, w7
    clz x28, x7
    rbit w3, w4
    rev16 x1, x7
    rev32 x2, x4
    rev w8, w7
    eor x22, x22, x13
    add x22, x22, x14
    eor x22, x22, x15
    add x22, x22, x16
    eor x22, x22, x17
    add x22, x22, x23
    eor x22, x22, x24
    add x22, x22, x25
    eor x22, x22, x26
    add x22, x22, x27
    eor x22, x22, x28
    add x22, x22, x3
    eor x22, x22, x1
    add x22, x22, x2
    eor x22, x22, x8

    svc #0

    // Probes on idx vs 3: idx < 3 -> N, idx == 3 -> Z,C, idx > 3 -> C.
    cmp x5, #3
    probe eq
    probe ne
    probe hs
    probe lo
    probe mi
    probe pl
    probe hi
    probe ls
    probe ge
    probe lt
    probe gt
    probe le
    probe_always al
    probe_always nv

    // Signed overflow: (idx << 61) doubled overflows for idx = 2..5.
    lsl x9, x5, #61
    adds x9, x9, x9
    probe vs
    probe vc

    // csel family on the idx compare.
    cmp x5, #5
    csel x13, x10, x5, hi
    csinc x14, x11, x7, lt
    csinv w15, w4, w7, ge
    csneg x16, x4, x7, ne
    cset w17, ls
    csetm x23, gt
    add x22, x22, x13
    eor x22, x22, x14
    add x22, x22, x15
    eor x22, x22, x16
    add x22, x22, x17
    eor x22, x22, x23

    // ccmp: compares only when idx > 2, else takes nzcv = N.
    cmp x5, #2
    ccmp x7, x4, #0b1000, hi
    probe mi
    probe hs
    // ccmn (register) when idx != 4, else nzcv = Z,C.
    cmp x5, #4
    ccmn x5, x6, #0b0110, ne
    probe eq
    probe hi
    // ccmp (register, 32-bit) and ccmn (immediate).
    tst w5, #1
    ccmp w5, w7, #0b0001, eq
    probe vs
    probe le
    cmp x5, #6
    ccmn x5, #31, #0b0000, lo
    probe pl

    // Data-dependent flags.
    adds x13, x4, x7
    probe hs
    subs w14, w4, w7
    probe lt
    ands x15, x4, x7, lsl #3
    probe eq
    bics w16, w4, w7
    probe mi
    cmn w4, w7, uxtb
    probe hi

    add x5, x5, #1
    cmp x5, #8
    b.lo .Lloop

    stp x4, x20, [x12, #0x100]
    stp x21, x22, [x12, #0x110]
    ret
