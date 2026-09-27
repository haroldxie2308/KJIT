// A9a SIMD&FP memset fixture: glibc's aarch64 memset shape (dup the byte, stp q
// in a loop, an overlapping stp q at the end) with an SVC in the loop, and the
// movi zeroing path.
//
//   make harness-test-asm ASM=tests/arm64/simd_memset.s
//
// Initial fixture state: x12 = FIXTURE_DATA_BASE (16 KiB RW, zero); every other
// register (V0-V31 included) is 0.

.text
.global simd_memset_entry
simd_memset_entry:

// 200 bytes of 0xa5 at an unaligned destination.
.global hot_svc_mark
hot_svc_mark:
    svc #0
    add x0, x12, #0x303
    movz w1, #0xa5
    movz x2, #200
    dup v0.16b, w1
    add x4, x0, x2
    str q0, [x0]
    bic x3, x0, #15
    sub x5, x4, #64
.Lset:
    stp q0, q0, [x3, #16]
    stp q0, q0, [x3, #48]!
    svc #0
    cmp x3, x5
    b.lo .Lset
    stp q0, q0, [x4, #-64]
    stp q0, q0, [x4, #-32]
    ret

// Zeroing with movi, 128 bytes with st1 (4 registers, post-index by register)
// and a d-register tail; x14 (stack-backed) holds the index.
.global memset_zero_mark
memset_zero_mark:
    svc #0
    add x0, x12, #0x600
    movn x1, #0
    mov x3, x0
    movz x4, #20
.Lones:
    str x1, [x3], #8
    subs x4, x4, #1
    b.ne .Lones
    movi v0.2d, #0
    movi v1.2d, #0
    movi v2.2d, #0
    movi v3.2d, #0
    movz x14, #64
    st1 {v0.16b, v1.16b, v2.16b, v3.16b}, [x0], x14
    st1 {v0.16b, v1.16b, v2.16b, v3.16b}, [x0], x14
    str d0, [x0]
    ret
