// A9a SIMD&FP strlen fixture: glibc's aarch64 strlen (ld1 / cmeq / shrn /
// umaxp / fmov to a general register) with an SVC inside the search loop. The
// strings are built with dup / st1 and a NUL byte store.
//
//   make harness-test-asm ASM=tests/arm64/simd_strlen.s
//
// Initial fixture state: x12 = FIXTURE_DATA_BASE (16 KiB RW, zero); every other
// register (V0-V31 included) is 0. All addresses derive from x12.

.text
.global simd_strlen_entry
simd_strlen_entry:

// A 70-byte string at an unaligned address: the first block has no NUL, the
// loop finds it; x0 = 70.
.global hot_svc_mark
hot_svc_mark:
    svc #0
    add x0, x12, #0x205
    movz w1, #0x61
    dup v5.16b, w1
    mov v6.16b, v5.16b
    mov v7.16b, v5.16b
    mov v8.16b, v5.16b
    sub x1, x0, #5
    st1 {v5.16b, v6.16b, v7.16b, v8.16b}, [x1], #64
    movi v6.16b, #0x62
    st1 {v5.16b, v6.16b}, [x1]
    strb wzr, [x0, #70]
    bic x1, x0, #15
    ld1 {v0.16b}, [x1]
    cmeq v0.16b, v0.16b, #0
    lsl x2, x0, #2
    shrn v1.8b, v0.8h, #4
    fmov x3, d1
    lsr x3, x3, x2
    cbz x3, .Lloop
    rbit x3, x3
    clz x0, x3
    lsr x0, x0, #2
    ret
.Lloop:
    ldr q0, [x1, #16]
    cmeq v0.16b, v0.16b, #0
    umaxp v1.16b, v0.16b, v0.16b
    fmov x3, d1
    cbnz x3, .Lloop_end
    svc #0
    ldr q0, [x1, #32]!
    cmeq v0.16b, v0.16b, #0
    umaxp v1.16b, v0.16b, v0.16b
    fmov x3, d1
    cbz x3, .Lloop
    sub x1, x1, #16
.Lloop_end:
    shrn v1.8b, v0.8h, #4
    sub x0, x1, x0
    fmov x3, d1
    rbit x3, x3
    clz x4, x3
    add x0, x0, x4, lsr #2
    add x0, x0, #16
    ret

// A 5-byte string: the NUL is in the first (aligned-down) block, found through
// the shifted syndrome without entering the loop; x0 = 5.
.global strlen_short_mark
strlen_short_mark:
    svc #0
    add x0, x12, #0x309
    movz x1, #0x6968
    movk x1, #0x6b6a, lsl #16
    movk x1, #0x6c, lsl #32
    str x1, [x0]
    bic x1, x0, #15
    ld1 {v0.16b}, [x1]
    cmeq v0.16b, v0.16b, #0
    lsl x2, x0, #2
    shrn v1.8b, v0.8h, #4
    fmov x3, d1
    lsr x3, x3, x2
    rbit x3, x3
    clz x0, x3
    lsr x0, x0, #2
    ret
