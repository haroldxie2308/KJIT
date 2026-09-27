// A9a SIMD&FP faults: each case ends at a faulting SIMD&FP load/store. In a
// fragment the access faults inside its PAN window and the fault site sends it
// to the window's PAN stub (`msr pan, #1` + Mem exit); the SP alignment check
// and the range check leave before the window. Userspace then re-executes the
// instruction natively and takes the fault itself, so the Mem exit must leave
// the pre-instruction state (up to the store footprint of an earlier element).
//
//   make harness-test-asm ASM=tests/arm64/simd_faults.s
//
// Initial fixture state: x12 = FIXTURE_DATA_BASE, a 16 KiB RW window (zero);
// x12 + 0x4000 is a read-only page, x12 + 0x5000 is unmapped; every other
// register (V0-V31 included) is 0.

.text
.global simd_faults_entry
simd_faults_entry:

// ldp q crossing from the read-only page into the unmapped one: one 32-byte
// access that faults; q0/q1 keep their values.
.global hot_svc_mark
hot_svc_mark:
    svc #0
    movi v0.16b, #0x11
    movi v1.16b, #0x22
    add x0, x12, #0x4000
    add x0, x0, #0xff0
    ldp q0, q1, [x0]
    ret

// stp q from the last 16 bytes of the RW window into the read-only page.
.global stp_q_ro_mark
stp_q_ro_mark:
    svc #0
    movi v0.16b, #0x33
    movi v1.16b, #0x44
    add x0, x12, #0x3000
    add x0, x0, #0xff0
    stp q0, q1, [x0]
    ret

// str q wholly on the read-only page, post-indexed: the base keeps its value.
.global str_q_ro_mark
str_q_ro_mark:
    svc #0
    movi v2.16b, #0x55
    add x13, x12, #0x4000
    add x13, x13, #0x80
    str q2, [x13], #16
    ret

// ld1 of four registers running into the unmapped page (the third register's
// elements fault); every destination keeps its value.
.global ld1_unmapped_mark
ld1_unmapped_mark:
    svc #0
    movi v4.16b, #0x66
    movi v5.16b, #0x77
    movi v6.16b, #0x88
    movi v7.16b, #0x99
    add x1, x12, #0x4000
    add x1, x1, #0xfe0
    ld1 {v4.16b, v5.16b, v6.16b, v7.16b}, [x1], #64
    ret

// st1 of two registers running into the read-only page: element stores before
// the faulting one may already be written (the store footprint).
.global st1_ro_mark
st1_ro_mark:
    svc #0
    movi v8.4s, #0xab
    movi v9.4s, #0xcd
    add x2, x12, #0x3000
    add x2, x2, #0xff8
    movz x3, #32
    st1 {v8.4s, v9.4s}, [x2], x3
    ret

// SP-based ldr q with SP 8 bytes off 16: EL0 SP alignment fault before any
// access; the fragment's check leaves through the plain Mem stub.
.global sp_misaligned_ldr_q_mark
sp_misaligned_ldr_q_mark:
    svc #0
    add x4, x12, #0x1000
    add sp, x4, #8
    movi v3.16b, #0x5a
    ldr q3, [sp]
    ret

// SP-based pre-indexed str q with a misaligned SP: faults, SP unchanged.
.global sp_misaligned_str_q_mark
sp_misaligned_str_q_mark:
    svc #0
    add x4, x12, #0x1000
    add sp, x4, #4
    movi v3.16b, #0x5b
    str q3, [sp, #-16]!
    ret

// A kernel-half pointer: the window's range check leaves through the PAN stub.
.global kernel_half_mark
kernel_half_mark:
    svc #0
    movz x0, #0xffff, lsl #48
    movk x0, #0x1000
    ldr q0, [x0]
    ret

// Beyond 2^48 in the user half (bits 55:48 non-zero): the range check leaves.
.global beyond_va_mark
beyond_va_mark:
    svc #0
    movz x0, #0x1, lsl #48
    add x0, x0, x12
    ld1 {v0.16b}, [x0]
    ret

// A tagged pointer (top byte ignored for data at EL0 and in the window), then
// SIMD&FP LDP with t == t2, which is CONSTRAINED UNPREDICTABLE: translation
// rejects it (Unsupported exit) and the case halts there.
.global tagged_then_unpredictable_mark
tagged_then_unpredictable_mark:
    svc #0
    add x0, x12, #0x700
    movz x5, #0x5a00, lsl #48
    orr x0, x0, x5
    movi v1.16b, #0x42
    str q1, [x0, #16]
    ldr q2, [x0, #16]
    ld1 {v3.2d}, [x0]
    .inst 0xad400000 // ldp q0, q0, [x0]
    ret
