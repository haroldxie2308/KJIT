// A9a SIMD&FP memcpy fixture: glibc aarch64 memcpy shapes (ldp/stp q, the
// overlapping ldur/stur q tail) with an SVC inside the copy loop. Every SIMD&FP
// load/store runs in a fragment as the one privileged access of a PAN window:
//
//   [and sB, x17, #15; cbnz sB, <Mem stub>]      SP base only
//   mov/add/sub sA, <base>, #offset               the access address
//   ubfx sB, sA, #48, #8; cbnz sB, <PAN stub>
//   msr pan, #0; <the access, base-only encoding on sA>; msr pan, #1
//   [add/sub <base>, <base>, #imm | add <base>, <base>, Xm]   writeback
//
//   make harness-test-asm ASM=tests/arm64/simd_memcpy.s
//
// Initial fixture state: x12 = FIXTURE_DATA_BASE, a 16 KiB RW window (all
// zero); x12 + 0x4000 is read-only and x12 + 0x5000 unmapped; every other
// register (V0-V31 included) is 0. All addresses derive from x12.

.text
.global simd_memcpy_entry
simd_memcpy_entry:

// 100 bytes, unaligned source and destination: three 32-byte blocks with
// post-indexed ldp/stp q and an SVC per block, then the overlapping tail.
.global hot_svc_mark
hot_svc_mark:
    svc #0
    add x1, x12, #0x101
    add x0, x12, #0x803
    movz x9, #0x1f3d
    movk x9, #0x5b79, lsl #16
    movk x9, #0x97b5, lsl #32
    movk x9, #0xd3f1, lsl #48
    mov x3, x1
    movz x4, #13
.Lfill:
    str x9, [x3], #8
    add x9, x9, x9, lsl #3
    add x9, x9, #0x123
    subs x4, x4, #1
    b.ne .Lfill
    movz x2, #100
    add x4, x1, x2
    add x5, x0, x2
    mov x6, x0
    mov x7, x1
    lsr x8, x2, #5
.Lcopy:
    ldp q0, q1, [x7], #32
    stp q0, q1, [x6], #32
    svc #0
    subs x8, x8, #1
    b.ne .Lcopy
    ldur q2, [x4, #-16]
    stur q2, [x5, #-16]
    ret

// glibc's 33..64-byte path: two 32-byte halves addressed from both ends,
// negative offsets from the end pointers; a stack-backed source (x13) and x29
// destination (user x29 lives in x16 in a fragment).
.global memcpy_medium_mark
memcpy_medium_mark:
    svc #0
    add x13, x12, #0x40
    movz x2, #0x3c1
    movz x3, #50
.Lpattern:
    strh w2, [x13], #2
    add w2, w2, #0x107
    subs x3, x3, #1
    b.ne .Lpattern
    add x13, x12, #0x41
    add x29, x12, #0x900
    movz x2, #59
    add x4, x13, x2
    add x5, x29, x2
    ldp q0, q1, [x13]
    ldp q2, q3, [x4, #-32]
    stp q0, q1, [x29]
    stp q2, q3, [x5, #-32]
    ldr q4, [x29, #16]
    ret

// glibc's long-copy loop: pre-indexed ldp/stp q, 64 bytes per iteration with
// loads running ahead of stores, an SVC every iteration, and d/s-register
// pairs for the tail.
.global memcpy_long_mark
memcpy_long_mark:
    svc #0
    add x1, x12, #0x1000
    movz x3, #0x55aa
    movk x3, #0x1234, lsl #16
    movz x4, #40
    mov x5, x1
.Llfill:
    str x3, [x5], #8
    eor x3, x3, x3, lsr #5
    add x3, x3, #0x31
    subs x4, x4, #1
    b.ne .Llfill
    add x0, x12, #0x1000
    add x0, x0, #0x800
    sub x7, x1, #16
    sub x6, x0, #16
    ldp q0, q1, [x7, #16]
    ldp q2, q3, [x7, #48]!
    movz x8, #4
.Llong:
    stp q0, q1, [x6, #16]
    ldp q0, q1, [x7, #16]
    stp q2, q3, [x6, #48]!
    ldp q2, q3, [x7, #48]!
    svc #0
    subs x8, x8, #1
    b.ne .Llong
    ldp d4, d5, [x7, #16]
    stp d4, d5, [x6, #16]
    ldp s6, s7, [x7, #32]
    stp s6, s7, [x6, #32]
    ret

// SP-based q accesses with SP 16-byte aligned (the SP check passes).
.global memcpy_sp_mark
memcpy_sp_mark:
    svc #0
    add sp, x12, #0x2000
    movi v0.16b, #0x3c
    movi v1.2d, #0xff00ff00ff00ff00
    str q0, [sp, #-32]!
    stp q0, q1, [sp, #32]
    ldr q2, [sp], #16
    ldp q3, q4, [sp, #16]
    ldr d5, [sp, #8]
    ret
