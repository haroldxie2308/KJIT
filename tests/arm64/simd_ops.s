// A9a SIMD&FP register-only forms: every data-movement and integer form of the
// subset on non-trivial lane values, emitted unchanged in a fragment (general
// register operands remapped: stack-backed x12..x17, x29, x9..x11 included).
// The final V0-V31 are compared like every other register.
//
//   make harness-test-asm ASM=tests/arm64/simd_ops.s
//
// Initial fixture state: x12 = FIXTURE_DATA_BASE (16 KiB RW, zero); every other
// register (V0-V31 included) is 0.

.text
.global simd_ops_entry
simd_ops_entry:

// Lane moves: DUP (element, general), INS, UMOV, FMOV (general, register),
// MOVI/MVNI in every cmode class.
.global hot_svc_mark
hot_svc_mark:
    svc #0
    movz x0, #0x8081
    movk x0, #0x7f02, lsl #16
    movk x0, #0xfe03, lsl #32
    movk x0, #0x0104, lsl #48
    fmov d0, x0
    mvn x1, x0
    fmov v0.d[1], x1
    dup v1.16b, v0.b[9]
    dup v2.8h, v0.h[3]
    dup v3.2s, v0.s[3]
    dup v4.2d, v0.d[1]
    dup b5, v0.b[15]
    dup h6, v0.h[5]
    dup d7, v0.d[0]
    dup v8.16b, w0
    dup v9.4h, w1
    movz x13, #0xbeef
    dup v10.4s, w13
    dup v11.2d, x0
    mov v12.16b, v0.16b
    mov v12.b[3], v1.b[0]
    mov v12.h[7], v2.h[1]
    mov v12.s[0], w13
    mov v12.d[1], x0
    umov w14, v0.b[15]
    umov w15, v0.h[2]
    mov w16, v0.s[1]
    mov x17, v0.d[1]
    fmov s13, w0
    fmov w9, s0
    fmov x10, v0.d[1]
    fmov x29, d0
    fmov s14, s0
    fmov d15, d0
    movi v16.16b, #0xa5
    movi v17.4h, #0x81, lsl #8
    movi v18.8h, #0x7e
    movi v19.2s, #0x12, lsl #24
    movi v20.4s, #0x34, lsl #8
    movi v21.4s, #0x56, msl #16
    movi v22.2s, #0x78, msl #8
    movi d23, #0xff0000ffff00ff00
    movi v24.2d, #0x00ffff0000ffff00
    mvni v25.8h, #0x12, lsl #8
    mvni v26.2s, #0x9a
    mvni v27.4s, #0xbc, msl #16
    ret

// Compares (register and zero, signed and unsigned, scalar and vector), logic,
// bit selects and NOT.
.global compare_logic_mark
compare_logic_mark:
    svc #0
    movz x0, #0x8081
    movk x0, #0x7f02, lsl #16
    movk x0, #0xfe03, lsl #32
    movk x0, #0x0100, lsl #48
    fmov d0, x0
    movz x1, #0x0081
    movk x1, #0x8002, lsl #16
    movk x1, #0x0003, lsl #48
    fmov v0.d[1], x1
    movi v1.16b, #0x02
    fmov v1.d[1], x0
    cmeq v2.16b, v0.16b, v1.16b
    cmeq v3.8h, v0.8h, #0
    cmeq d4, d0, d1
    cmeq d5, d0, #0
    cmhi v6.16b, v0.16b, v1.16b
    cmhi d7, d1, d0
    cmhs v8.4s, v0.4s, v1.4s
    cmhs d9, d0, d0
    cmgt v10.8b, v0.8b, v1.8b
    cmgt v11.4h, v0.4h, #0
    cmgt d12, d1, d0
    cmgt d13, d0, #0
    cmge v14.2d, v0.2d, v1.2d
    cmge v15.2s, v0.2s, #0
    cmge d16, d0, d1
    cmge d17, d1, #0
    cmtst v18.16b, v0.16b, v1.16b
    cmtst d19, d0, d1
    and v20.16b, v0.16b, v1.16b
    orr v21.8b, v0.8b, v1.8b
    eor v22.16b, v0.16b, v1.16b
    bic v23.16b, v0.16b, v1.16b
    orn v24.8b, v0.8b, v1.8b
    mov v25.16b, v6.16b
    bit v25.16b, v0.16b, v1.16b
    mov v26.16b, v6.16b
    bif v26.8b, v0.8b, v1.8b
    mov v27.16b, v1.16b
    bsl v27.16b, v0.16b, v22.16b
    not v28.16b, v0.16b
    mvn v29.8b, v1.8b
    ret

// Arithmetic, pairwise and across-lanes reductions.
.global arith_mark
arith_mark:
    svc #0
    movz x0, #0xfff1
    movk x0, #0x7f02, lsl #16
    movk x0, #0x8003, lsl #32
    movk x0, #0x01ff, lsl #48
    fmov d0, x0
    movz x1, #0x0081
    movk x1, #0xffff, lsl #16
    movk x1, #0x1234, lsl #48
    fmov v0.d[1], x1
    dup v1.16b, v0.b[0]
    fmov v1.d[1], x0
    add v2.16b, v0.16b, v1.16b
    add v3.4h, v0.4h, v1.4h
    add v4.4s, v0.4s, v1.4s
    add v5.2d, v0.2d, v1.2d
    add d6, d0, d1
    sub v7.8h, v0.8h, v1.8h
    sub d8, d1, d0
    addp v9.16b, v0.16b, v1.16b
    addp v10.2s, v0.2s, v1.2s
    addp v11.2d, v0.2d, v1.2d
    addp d12, v0.2d
    umaxp v13.8h, v0.8h, v1.8h
    umaxp v14.8b, v0.8b, v1.8b
    uminp v15.4s, v0.4s, v1.4s
    addv b16, v0.16b
    addv h17, v0.8h
    addv s18, v0.4s
    umaxv b19, v0.8b
    umaxv h20, v1.8h
    uminv s21, v0.4s
    uminv b22, v1.16b
    ret

// Shifts, narrowing/widening, EXT, REV, CNT, TBL.
.global shift_permute_mark
shift_permute_mark:
    svc #0
    movz x0, #0xf0e1
    movk x0, #0xd2c3, lsl #16
    movk x0, #0xb4a5, lsl #32
    movk x0, #0x9687, lsl #48
    fmov d0, x0
    movz x1, #0x0102
    movk x1, #0x0304, lsl #16
    movk x1, #0x1005, lsl #32
    movk x1, #0x0f20, lsl #48
    fmov v0.d[1], x1
    movi v1.16b, #0x77
    fmov d1, x1
    shrn v2.8b, v0.8h, #4
    mov v3.16b, v1.16b
    shrn2 v3.16b, v0.8h, #1
    shrn v4.4h, v0.4s, #16
    shrn v5.2s, v0.2d, #32
    ushr v6.16b, v0.16b, #3
    ushr v7.8h, v0.8h, #16
    ushr v8.2d, v0.2d, #64
    ushr d9, d0, #7
    shl v10.4s, v0.4s, #31
    shl v11.8b, v0.8b, #1
    shl d12, d0, #63
    ushll v13.8h, v0.8b, #0
    ushll2 v14.4s, v0.8h, #3
    ushll v15.2d, v0.2s, #31
    xtn v16.8b, v0.8h
    mov v17.16b, v1.16b
    xtn2 v17.4s, v0.2d
    xtn v18.4h, v0.4s
    ext v19.16b, v0.16b, v1.16b, #5
    ext v20.8b, v0.8b, v1.8b, #7
    ext v21.16b, v0.16b, v1.16b, #0
    rev16 v22.16b, v0.16b
    rev32 v23.8h, v0.8h
    rev32 v24.8b, v0.8b
    rev64 v25.4s, v0.4s
    rev64 v26.16b, v0.16b
    cnt v27.16b, v0.16b
    cnt v28.8b, v1.8b
    tbl v29.16b, {v0.16b}, v1.16b
    tbl v30.8b, {v0.16b}, v0.8b
    tbl v31.16b, {v31.16b}, v0.16b
    ret
