// A18 scalar floating point (docs/pipeline.md, "Scalar floating point (A18)"):
// single- and double-precision arithmetic, fused multiply-add, rounding,
// conversions both ways, compares that set NZCV for a following b.cond, FCSEL,
// FCCMP, FMOV (immediate), MRS of FPCR/FPSR, and the register-offset SIMD&FP
// loads/stores (every size and extend), including the exact words of the redis
// event loop and AOF path. The final V0-V31, NZCV, FPSR and memory are compared
// like every other register.
//
//   make harness-test-asm ASM=tests/arm64/fp_scalar.s HOT_SVC_SYMBOL=<case>
//
// Initial fixture state: x12 = FIXTURE_DATA_BASE (16 KiB RW, zero), FPCR = 0 unless
// the case symbol carries `_fpcr<HEX>_` (a fixture cannot write FPCR: `msr fpcr`
// stays an Unsupported exit): bit 25 DN, 24 FZ, 23:22 RMode (00 RN, 01 RP, 10 RM,
// 11 RZ). Every other register (V0-V31 included) is 0.

// movz/movk building blocks: the high 16 bits of a double (fraction bits 47:0 zero),
// the high 16 bits of a single.
.macro dhi dreg, tmp, hi
    movz \tmp, #\hi, lsl #48
    fmov \dreg, \tmp
.endm
.macro shi sreg, tmp, hi
    movz \tmp, #\hi, lsl #16
    fmov \sreg, \tmp
.endm

.text
.global fp_scalar_entry
fp_scalar_entry:

// Arithmetic on ordinary values, double and single: the two-operand forms, the
// fused multiply-adds, FNMUL, FMAX/FMIN and their NM variants, FABS/FNEG/FSQRT.
.global fp_arith_mark
fp_arith_mark:
    svc #0
    dhi d0, x0, 0x4004          // 2.5
    dhi d1, x1, 0xbff8          // -1.5
    dhi d2, x2, 0x4008          // 3.0
    fadd d3, d0, d1
    fsub d4, d0, d1
    fmul d5, d0, d1
    fdiv d6, d0, d1
    fnmul d7, d0, d1
    fmax d8, d0, d1
    fmin d9, d0, d1
    fmaxnm d10, d0, d1
    fminnm d11, d0, d1
    fabs d12, d1
    fneg d13, d0
    fsqrt d14, d2
    fmadd d15, d0, d1, d2
    fmsub d16, d0, d1, d2
    fnmadd d17, d0, d1, d2
    fnmsub d18, d0, d1, d2
    // Destination aliasing a source.
    fadd d0, d0, d0
    fmul d1, d2, d1
    fmadd d2, d2, d2, d2
    ret

// The same on single precision.
.global fp_arith_s_mark
fp_arith_s_mark:
    svc #0
    shi s0, w0, 0x4020         // 2.5
    shi s1, w1, 0xbfc0         // -1.5
    shi s2, w2, 0x4040         // 3.0
    fadd s23, s0, s1
    fsub s24, s0, s1
    fmul s25, s0, s1
    fdiv s26, s0, s1
    fnmul s27, s0, s1
    fmax s28, s0, s1
    fmin s29, s0, s1
    fmaxnm s30, s0, s1
    fminnm s31, s0, s1
    fabs s8, s1
    fneg s9, s0
    fsqrt s10, s2
    fmadd s11, s0, s1, s2
    fmsub s12, s0, s1, s2
    fnmadd s13, s0, s1, s2
    fnmsub s14, s0, s1, s2
    ret

// NaN, infinity, zero and denormal operands through every two-operand form (the
// quiet/signalling NaN rules, FMAX vs FMAXNM, the cumulative IOC/DZC/OFC/UFC/IXC
// flags). Default FPCR: NaNs propagate their payload.
.global fp_special_mark
fp_special_mark:
    svc #0
    dhi d0, x0, 0x7ff8          // quiet NaN
    dhi d1, x1, 0x7ff4          // signalling NaN
    dhi d2, x2, 0x7ff0          // +inf
    dhi d3, x3, 0xfff0          // -inf
    fmov d4, #1.0
    movi d5, #0                 // +0.0
    movz x4, #1
    fmov d6, x4                 // smallest denormal
    fadd d7, d0, d4
    fadd d8, d1, d4
    fadd d9, d2, d3             // inf - inf: invalid
    fmul d10, d2, d5            // inf * 0: invalid
    fdiv d11, d4, d5            // 1 / 0: divide by zero
    fdiv d12, d5, d5            // 0 / 0: invalid
    fmax d13, d0, d4
    fmaxnm d14, d0, d4          // a quiet NaN loses to a number
    fmin d15, d1, d4
    fminnm d16, d1, d4          // a signalling NaN still raises invalid
    fmul d17, d6, d6            // underflow, inexact
    fsqrt d18, d3               // sqrt(-inf): invalid
    fmadd d19, d2, d5, d0
    fneg d20, d0
    fabs d21, d1
    fadd d22, d2, d4
    fsub d23, d2, d2
    ret

// Single-precision NaN, infinity and denormal operands.
.global fp_special_s_mark
fp_special_s_mark:
    svc #0
    movz w5, #0x7fc0, lsl #16
    fmov s0, w5                 // single quiet NaN
    movz w6, #0x7f80, lsl #16
    fmov s1, w6                 // single +inf
    fmov s2, #1.0
    fadd s3, s0, s2
    fsub s4, s1, s1
    fmul s5, s1, s2
    fdiv s6, s2, s5
    movz w7, #0x0001
    fmov s7, w7                 // single denormal
    fmul s8, s7, s7
    fmax s9, s0, s2
    fmaxnm s10, s0, s2
    ret

// The same operations with FPCR.DN set (default NaN) ...
.global fp_special_dn_fpcr2000000_mark
fp_special_dn_fpcr2000000_mark:
    svc #0
    dhi d0, x0, 0x7ff8
    dhi d1, x1, 0x7ff4
    fmov d4, #1.0
    movi d5, #0
    fadd d7, d0, d4
    fadd d8, d1, d4
    fmul d10, d1, d5
    fmax d13, d0, d4
    fmin d15, d1, d4
    fnmul d16, d0, d4
    fsqrt d17, d1
    fmadd d18, d0, d4, d4
    fabs d19, d0
    movz w5, #0x7fc0, lsl #16
    fmov s0, w5
    fmov s2, #1.0
    fadd s3, s0, s2
    fdiv s4, s0, s2
    ret

// ... and with FPCR.FZ set (flush denormal inputs and results to zero; IDC/UFC).
.global fp_denormal_fz_fpcr1000000_mark
fp_denormal_fz_fpcr1000000_mark:
    svc #0
    movz x0, #1
    fmov d0, x0                 // smallest denormal
    fmov d1, #1.0
    fadd d2, d0, d1             // denormal input flushed: exact 1.0, IDC
    fmul d3, d0, d1             // flushed to zero
    fmov d4, #0.5
    fmul d5, d4, d4
    movz x1, #0x0010, lsl #48
    fmov d6, x1                 // smallest normal * 2^4
    fmul d7, d6, d4
    fmul d8, d7, d4             // result below the normal range: flushed, UFC
    fsub d9, d0, d0
    fmax d10, d0, d1
    movz w2, #1
    fmov s0, w2
    fmov s1, #1.0
    fadd s2, s0, s1
    fmul s3, s0, s1
    fabs s4, s0
    ret

// Conversions from integers: SCVTF/UCVTF from W and X to S and D, including values
// that do not fit the destination exactly (inexact, round per FPCR.RMode).
.global fp_int_to_fp_mark
fp_int_to_fp_mark:
    svc #0
    movn x0, #6                 // -7
    movz x1, #0x7fff, lsl #48
    movk x1, #0xffff, lsl #32
    movk x1, #0xffff, lsl #16
    movk x1, #0xffff           // 2^63 - 1
    mov x2, #-1                 // 0xffff_ffff_ffff_ffff
    movz x3, #0x8000, lsl #48   // -2^63 / 2^63
    movz w4, #0x8000, lsl #16   // 0x8000_0000
    movz w5, #0xffff
    movk w5, #0x00ff, lsl #16   // 24-bit integer, exact in a single
    movz x6, #0x1234
    movk x6, #0x5678, lsl #16
    movk x6, #0x9abc, lsl #32
    movk x6, #0x7def, lsl #48
    scvtf d0, w0
    scvtf d1, x0
    scvtf d2, x1
    scvtf d3, x2
    scvtf d4, x3
    scvtf d5, w4
    scvtf s6, w0
    scvtf s7, x0
    scvtf s8, x1
    scvtf s9, w5
    scvtf s10, w4
    scvtf s11, x6
    scvtf d12, x6
    ucvtf d13, w0
    ucvtf d14, x0
    ucvtf d15, x1
    ucvtf d16, x2
    ucvtf d17, x3
    ucvtf d18, w4
    ucvtf s19, w0
    ucvtf s20, x2
    ucvtf s21, w5
    ucvtf s22, x6
    ucvtf d23, x6
    scvtf d24, xzr
    ucvtf s25, wzr
    ret

// The same under each rounding mode, and the redis event loop's conversion.
.macro int_to_fp_rmode
    movz x0, #0x1234
    movk x0, #0x5678, lsl #16
    movk x0, #0x9abc, lsl #32
    movk x0, #0x7def, lsl #48
    mov x1, x0
    neg x2, x0
    movz w3, #0x4321
    movk w3, #0xfedc, lsl #16
    scvtf d0, x0
    scvtf s1, x0
    ucvtf d2, x2
    ucvtf s3, x2
    scvtf d4, x2
    scvtf s5, x2
    scvtf s6, w3
    ucvtf s7, w3
    fmov d8, #1.0
    fadd d9, d0, d8
    fmov d10, #3.0
    fdiv d11, d8, d10
    fmul d12, d11, d10
    fcvt s13, d11
    fcvt d14, s13
    fsub d15, d14, d11
    fmadd d16, d11, d10, d8
    fsqrt d17, d10
    ret
.endm
.global fp_int_to_fp_rn_mark
fp_int_to_fp_rn_mark:
    svc #0
    int_to_fp_rmode
.global fp_int_to_fp_rp_fpcr400000_mark
fp_int_to_fp_rp_fpcr400000_mark:
    svc #0
    int_to_fp_rmode
.global fp_int_to_fp_rm_fpcr800000_mark
fp_int_to_fp_rm_fpcr800000_mark:
    svc #0
    int_to_fp_rmode
.global fp_int_to_fp_rz_fpcrc00000_mark
fp_int_to_fp_rz_fpcrc00000_mark:
    svc #0
    int_to_fp_rmode

// Conversions to integers, all ten rounding flavours, W and X destinations, from S
// and D: the ties of 0.5 .. 2.5 both ways round differently per flavour.
.macro fp_to_int_row dreg, sreg, wd, xd
    fcvtzs \wd, \dreg
    fcvtzu \xd, \dreg
    fcvtns \wd, \dreg
    fcvtnu \xd, \dreg
    fcvtms \wd, \dreg
    fcvtmu \xd, \dreg
    fcvtps \wd, \dreg
    fcvtpu \xd, \dreg
    fcvtas \wd, \dreg
    fcvtau \xd, \dreg
    fcvtzs \xd, \sreg
    fcvtzu \wd, \sreg
    fcvtns \xd, \sreg
    fcvtnu \wd, \sreg
    fcvtms \xd, \sreg
    fcvtmu \wd, \sreg
    fcvtps \xd, \sreg
    fcvtpu \wd, \sreg
    fcvtas \xd, \sreg
    fcvtau \wd, \sreg
.endm
.global fp_to_int_ties_mark
fp_to_int_ties_mark:
    svc #0
    dhi d0, x0, 0x3fe0          // 0.5
    dhi d1, x1, 0x3ff8          // 1.5
    dhi d2, x2, 0x4004          // 2.5
    dhi d3, x3, 0xbfe0          // -0.5
    dhi d4, x4, 0xbff8          // -1.5
    dhi d5, x5, 0xc004          // -2.5
    shi s16, w6, 0x3f00         // 0.5 (single)
    shi s17, w7, 0x3fc0         // 1.5
    shi s18, w8, 0x4020         // 2.5
    shi s19, w9, 0xbf00         // -0.5
    shi s20, w10, 0xbfc0        // -1.5
    shi s21, w11, 0xc020        // -2.5
    fp_to_int_row d0, s16, w20, x21
    fp_to_int_row d1, s17, w22, x23
    fp_to_int_row d2, s18, w24, x25
    fp_to_int_row d3, s19, w26, x27
    fp_to_int_row d4, s20, w28, x29
    fp_to_int_row d5, s21, w15, x16
    ret

// Out-of-range and NaN inputs to every FCVT* (saturation, NaN -> 0, IOC), and
// negative inputs to the unsigned forms.
.global fp_to_int_range_mark
fp_to_int_range_mark:
    svc #0
    dhi d0, x0, 0x43e0          // 2^63
    dhi d1, x1, 0x43f0          // 2^64
    dhi d2, x2, 0xc3e0          // -2^63
    dhi d3, x3, 0xc3f0          // -2^64
    dhi d4, x4, 0x7ff8          // quiet NaN
    dhi d5, x5, 0x7ff0          // +inf
    dhi d6, x6, 0xfff0          // -inf
    dhi d7, x7, 0x41e0          // 2^31
    dhi d8, x8, 0x41f0          // 2^32
    dhi d9, x9, 0xc1e0          // -2^31
    dhi d10, x10, 0xbff0        // -1.0
    shi s16, w0, 0x5f00          // 2^63
    shi s17, w1, 0x5f80          // 2^64
    shi s18, w2, 0xdf00          // -2^63
    shi s19, w3, 0x7fc0          // NaN
    shi s20, w4, 0x7f80          // +inf
    shi s21, w5, 0x4f00          // 2^31
    shi s22, w6, 0x4f80          // 2^32
    shi s23, w7, 0xcf00          // -2^31
    shi s24, w8, 0xbf80          // -1.0
    shi s25, w9, 0xff80          // -inf
    fcvtzs x20, d0
    fcvtzs x21, d1
    fcvtzs x22, d2
    fcvtzs x23, d3
    fcvtzs x24, d4
    fcvtzs x25, d5
    fcvtzs x26, d6
    fcvtzs w27, d7
    fcvtzs w28, d8
    fcvtzs w15, d9
    fcvtzs w16, d4
    fcvtzu x17, d0
    fcvtzu x14, d1
    fcvtzu x13, d2
    fcvtzu x12, d4
    fcvtzu w11, d7
    fcvtzu w10, d8
    fcvtzu w9, d9
    fcvtzu w8, d10
    fcvtzu x7, d10
    fcvtns x6, d1
    fcvtnu x5, d3
    fcvtms w4, d8
    fcvtmu w3, d5
    fcvtps x2, d2
    fcvtpu w1, d6
    fcvtas w0, d5
    fcvtau x29, d4
    fcvtzs x20, s16
    fcvtzs x21, s17
    fcvtzs x22, s18
    fcvtzs x23, s19
    fcvtzs x24, s20
    fcvtzs w25, s21
    fcvtzs w26, s22
    fcvtzs w27, s23
    fcvtzs w28, s19
    fcvtzu x15, s16
    fcvtzu x16, s17
    fcvtzu x17, s18
    fcvtzu w14, s22
    fcvtzu w13, s24
    fcvtzu x12, s24
    fcvtzu w11, s19
    fcvtns w10, s20
    fcvtmu x9, s25
    fcvtpu x8, s23
    fcvtas x7, s21
    fcvtau w6, s22
    ret

// Conversions between precisions: exact, inexact, overflow to infinity, underflow to
// a denormal, NaN payloads, and FPCR-dependent results.
.global fp_fcvt_mark
fp_fcvt_mark:
    svc #0
    fmov d0, #1.5
    fcvt s1, d0
    fcvt d2, s1
    movz x0, #0x3ff0, lsl #48
    movk x0, #0x0000, lsl #32
    movk x0, #0x0000, lsl #16
    movk x0, #0x0001           // 1.0 + 2^-52: not a single
    fmov d3, x0
    fcvt s4, d3
    fcvt d5, s4
    dhi d6, x1, 0x47f0          // 2^127 * 2 = beyond the single range
    fcvt s7, d6
    dhi d8, x2, 0x3800          // 2^-127: a single denormal
    fcvt s9, d8
    dhi d10, x3, 0x3690         // far below the single range
    fcvt s11, d10
    dhi d12, x4, 0x7ff4         // signalling NaN
    fcvt s13, d12
    dhi d14, x5, 0x7ff8         // quiet NaN
    fcvt s15, d14
    shi s16, w6, 0x7fa0         // signalling NaN (single)
    fcvt d17, s16
    shi s18, w7, 0x7f80         // +inf
    fcvt d19, s18
    shi s20, w8, 0x0000
    fcvt d21, s20               // +0
    movz w9, #1
    fmov s22, w9                // single denormal
    fcvt d23, s22               // exact in double
    ret

// Compares set NZCV; b.cond reads it. Ordered less / equal / greater and unordered
// operand pairs through FCMP and FCMPE (register and zero), every condition code
// observed with cset. The loop runs the four pairs.
.global fp_compare_mark
fp_compare_mark:
    svc #0
    fmov d0, #1.0
    fmov d1, #2.0
    dhi d2, x0, 0x7ff8          // quiet NaN
    dhi d3, x1, 0x7ff4          // signalling NaN
    movi d4, #0
    movz x2, #0x8000, lsl #48
    fmov d5, x2                 // -0.0
    // 1.0 < 2.0
    fcmp d0, d1
    cset w3, eq
    cset w4, ne
    cset w5, mi
    cset w6, pl
    cset w7, vs
    cset w8, vc
    cset w9, hi
    cset w10, ls
    cset w11, ge
    cset w13, lt
    cset w14, gt
    cset w15, le
    cset w16, hs
    cset w17, lo
    // 2.0 vs 1.0, equal, unordered
    fcmp d1, d0
    cset w3, gt
    cset w4, hi
    cset w5, ge
    fcmp d0, d0
    cset w6, eq
    cset w7, hs
    cset w8, ls
    fcmp d0, d2
    cset w9, vs
    cset w10, eq
    cset w11, lt
    cset w13, gt
    cset w14, hi
    cset w15, le
    fcmpe d0, d3
    cset w16, vs
    fcmp d3, d0
    cset w17, vs
    fcmp d4, d5                 // +0.0 == -0.0
    cset w20, eq
    fcmp d5, #0.0
    cset w21, eq
    fcmp d2, #0.0
    cset w22, vs
    fcmpe d2, #0.0
    cset w23, vs
    fcmpe d1, #0.0
    cset w24, gt
    fcmpe d0, d1
    cset w25, lt
    // b.cond on the compare flags: a countdown loop with an FP exit condition.
    fmov d6, #1.0
    fmov d7, #31.0
    movz x26, #0
.Lfloop:
    fadd d6, d6, d6
    add x26, x26, #1
    fcmp d6, d7
    b.lt .Lfloop
    fcmpe d6, d7
    b.gt .Lover
    movz x27, #1
    b .Ldone
.Lover:
    movz x27, #2
.Ldone:
    fcmp d6, d2                 // unordered: b.vs
    b.vs .Lunord
    movz x28, #1
    ret
.Lunord:
    movz x28, #2
    ret

// FCCMP/FCCMPE chains (condition false -> the immediate NZCV), FCSEL on every
// condition, FMOV (immediate) across the constant range.
.global fp_cond_mark
fp_cond_mark:
    svc #0
    fmov d0, #1.0
    fmov d1, #2.0
    fmov d2, #-4.0
    fmov s16, #1.0
    fmov s17, #2.0
    dhi d3, x0, 0x7ff8
    // d0 < d1 (lt) and d1 < d2 (false) -> the immediate (nzcv = 4: eq)
    fcmp d0, d1
    fccmp d1, d2, #4, lt
    cset w3, eq
    fcsel d4, d0, d1, lt
    fcsel d5, d0, d1, ge
    fcmp d0, d1
    fccmp d0, d1, #0, ge        // not ge: the immediate 0
    cset w4, mi
    fccmpe d1, d3, #8, lt       // lt holds: compare with a NaN -> unordered, V set
    cset w5, vs
    fcmp s16, s17
    fccmp s16, s17, #2, lt
    cset w6, hs
    fccmpe s17, s16, #15, al
    cset w7, gt
    fcsel s18, s16, s17, mi
    fcsel s19, s16, s17, vs
    fcsel d6, d0, d3, ne        // selecting a NaN is a plain copy
    fcsel d7, d3, d0, eq
    fcmp d0, d0
    fcsel d8, d1, d2, eq
    fcsel d10, d1, d2, al
    fmov s20, #-31.0
    fmov s21, #0.125
    fmov s22, #1.9375
    fmov s23, #0.1328125
    fmov d11, #-31.0
    fmov d12, #0.125
    fmov d13, #1.9375
    fmov d14, #2.0
    fmov d15, #31.0
    fmov d16, #-0.1328125
    ret

// Rounding to integral in floating point under each FPCR.RMode: FRINTN/P/M/Z/A are
// fixed-mode; FRINTX raises inexact; FRINTI uses FPCR. Ties and signs both ways, then
// a huge value (already integral) and a NaN.
.macro frint_body
    fmov d0, #2.5
    dhi d1, x0, 0x3ff8          // 1.5
    dhi d2, x1, 0x3fe0          // 0.5
    dhi d3, x2, 0xbfe0          // -0.5
    dhi d4, x3, 0xbff8          // -1.5
    dhi d5, x4, 0xc004          // -2.5
    dhi d6, x5, 0x4330          // 2^52: integral
    dhi d7, x6, 0x7ff8          // NaN
    dhi d8, x7, 0x3ff4          // 1.25
    frintn d16, d0
    frintp d17, d1
    frintm d18, d2
    frintz d19, d3
    frinta d20, d4
    frintx d21, d5
    frinti d22, d8
    frintn d23, d4
    frintp d24, d4
    frintm d25, d4
    frintz d26, d1
    frinta d27, d2
    frintx d28, d6
    frinti d29, d7
    frinti d30, d0
    frinti d31, d5
    shi s0, w8, 0x4020          // 2.5
    shi s1, w9, 0x3fc0          // 1.5
    shi s2, w10, 0xbf00         // -0.5
    shi s3, w11, 0xbfc0         // -1.5
    shi s4, w13, 0x3fa0         // 1.25
    frintn s8, s0
    frintp s9, s1
    frintm s10, s2
    frintz s11, s3
    frinta s12, s3
    frintx s13, s4
    frinti s14, s0
    frinti s15, s3
    ret
.endm
.global fp_frint_rn_mark
fp_frint_rn_mark:
    svc #0
    frint_body
.global fp_frint_rp_fpcr400000_mark
fp_frint_rp_fpcr400000_mark:
    svc #0
    frint_body
.global fp_frint_rm_fpcr800000_mark
fp_frint_rm_fpcr800000_mark:
    svc #0
    frint_body
.global fp_frint_rz_fpcrc00000_mark
fp_frint_rz_fpcrc00000_mark:
    svc #0
    frint_body

// FCVT* ignore FPCR.RMode except FCVT between precisions; SCVTF and arithmetic
// follow it. FPCR.AHP/FZ/DN with a conversion and an FMA: one case with several bits.
.global fp_mixed_fpcr3400000_mark
fp_mixed_fpcr3400000_mark:
    svc #0
    fmov d0, #1.0
    movz x0, #0x3ff0, lsl #48
    movk x0, #0x0001
    fmov d1, x0                 // 1 + 2^-52
    movz x1, #1
    fmov d2, x1                 // denormal
    fmadd d3, d1, d1, d0
    fadd d4, d1, d2
    fcvt s5, d1
    scvtf d6, x0
    fcvtzs x2, d1
    fcvtms x3, d1
    fmul d7, d2, d0
    dhi d8, x4, 0x7ff4
    fadd d9, d8, d0
    fmax d10, d8, d0
    ret

// MRS FPCR/FPSR read the user's registers: the initial FPCR, and an FPSR that gains
// cumulative flags from the operations in between.
.global fp_mrs_fpcr2400000_mark
fp_mrs_fpcr2400000_mark:
    svc #0
    mrs x0, fpcr
    mrs x1, fpsr
    fmov d0, #1.0
    movz x2, #3
    scvtf d1, x2
    fdiv d2, d0, d1             // inexact: IXC
    mrs x3, fpsr
    movi d3, #0
    fdiv d4, d0, d3             // divide by zero: DZC
    mrs x4, fpsr
    mrs xzr, fpsr
    mrs x5, fpcr
    dhi d5, x6, 0x7ff4
    fadd d6, d5, d0             // invalid: IOC
    mrs x7, fpsr
    ret

// Register-offset SIMD&FP loads and stores, every size and every extend/shift
// option. The data window x12 .. x12 + 0x4000 holds a pattern; stores go to a second
// region and are read back. The index registers carry garbage in the bits an
// extend ignores, and negative values for the signed extends.
.global fp_regoff_mark
fp_regoff_mark:
    svc #0
    mov x15, x12                    // base (x12 itself is stack-backed too)
    // Fill 0x400 bytes with a counting pattern using the GPR stores.
    movz x0, #0
    movz x1, #0x0101
    movk x1, #0x0101, lsl #16
    movk x1, #0x0101, lsl #32
    movk x1, #0x0101, lsl #48
    movz x2, #0x0706
    movk x2, #0x0504, lsl #16
    movk x2, #0x0302, lsl #32
    movk x2, #0x0100, lsl #48
.Lfill_fp:
    str x2, [x15, x0, lsl #3]
    add x2, x2, x1, lsl #3
    add x0, x0, #1
    cmp x0, #128
    b.ne .Lfill_fp
    add x3, x15, #0x200             // 64-bit-element centre
    movn x4, #3                     // -4
    movz x5, #2
    movk x5, #0xdead, lsl #32       // garbage above w5
    movn w7, #1                     // w7 = -2 (x7 = 0x00000000fffffffe)
    // Loads: each size with LSL, UXTW, SXTW, SXTX (scaled and unscaled).
    ldr b0, [x3, x4]                // BL form, S = 0
    ldr b1, [x3, x4, lsl #0]        // BL form, S = 1
    ldr b2, [x3, w5, uxtw]
    ldr b3, [x3, w7, sxtw]
    ldr b4, [x3, x4, sxtx]
    ldr h5, [x3, x4, lsl #1]
    ldr h6, [x3, w5, uxtw #1]
    ldr h7, [x3, w7, sxtw #1]
    ldr h8, [x3, x4, sxtx #1]
    ldr h9, [x3, x4]
    ldr s10, [x3, x4, lsl #2]
    ldr s11, [x3, w5, uxtw #2]
    ldr s12, [x3, w7, sxtw #2]
    ldr s13, [x3, x4, sxtx #2]
    ldr s14, [x3, w5, uxtw]
    ldr d15, [x3, x4, lsl #3]
    ldr d16, [x3, w5, uxtw #3]
    ldr d17, [x3, w7, sxtw #3]
    ldr d18, [x3, x4, sxtx #3]
    ldr d19, [x3, x4]
    ldr q20, [x3, x4, lsl #4]
    ldr q21, [x3, w5, uxtw #4]
    ldr q22, [x3, w7, sxtw #4]
    ldr q23, [x3, x4, sxtx #4]
    ldr q24, [x3, w7, sxtw]
    ldr q25, [x3, x4, lsl #4]
    // Stores into the second half of the window, read back with the same forms.
    add x8, x15, #0x1000
    movn x9, #0                     // -1
    movz x10, #5
    str b0, [x8, x10]
    str b1, [x8, x10, lsl #0]
    str h5, [x8, x10, lsl #1]
    str s10, [x8, w10, uxtw #2]
    str d15, [x8, w10, uxtw #3]
    str q20, [x8, x10, lsl #4]
    str q21, [x8, w9, sxtw #4]
    str d16, [x8, x9, sxtx #3]
    str s11, [x8, w9, sxtw]
    str h6, [x8, w9, sxtw #1]
    str b2, [x8, w9, sxtw]
    str b3, [x8, w10, uxtw #0]
    ldr q26, [x8, x10, lsl #4]
    ldr d27, [x8, w10, uxtw #3]
    ldr s28, [x8, w10, uxtw #2]
    ldr h29, [x8, x10, lsl #1]
    ldr b30, [x8, x10]
    ldr q31, [x8, w9, sxtw #4]
    ret

// The base is SP and/or the registers are the stack-backed x12..x17 (the scratch
// pool: base, index, the address and the range-check result all live at once);
// the index is XZR (the base itself).
.global fp_regoff_regs_mark
fp_regoff_regs_mark:
    svc #0
    movz x0, #0x7700
    str x0, [x12, #8]
    str x0, [x12, #0x80]
    mov x13, x12
    movz x14, #1
    movz x15, #0x8
    movz x16, #2
    ldr d0, [x13, x14, lsl #3]          // x13 + 8: base and index both stack-backed
    ldr q1, [x13, x15, lsl #4]          // x13 + 0x80
    str d0, [x13, x16, lsl #3]
    ldr d2, [x13, x16, lsl #3]
    ldr d3, [x13, xzr]
    ldr s4, [x13, wzr, uxtw #2]
    ldr b5, [x13, x14, lsl #0]
    // SP base: SP must be 16-byte aligned and in the window.
    add sp, x12, #0x1000
    mov x1, #-16
    str q1, [sp, x1]                    // sp - 16
    ldr q6, [sp, x1]
    ldr q7, [sp, w1, sxtw]
    movz w2, #4
    str d0, [sp, w2, uxtw #3]
    ldr d8, [sp, w2, uxtw #3]
    ldr b9, [sp, xzr]
    // SP with a stack-backed index and a destination that is the same V register.
    mov x14, #8
    str d2, [sp, x14]
    ldr d2, [sp, x14]
    ret

// Faults: a store to a read-only page, a load from an unmapped page, an address
// with a bit above bit 47 set (the range check leaves through the Mem stub), a
// wrapping index. The original faults natively; the
// fragment's Mem exit makes the interpreter re-execute it, with the state before it.
.global fp_regoff_fault_ro_mark
fp_regoff_fault_ro_mark:
    svc #0
    fmov d0, #1.5
    movz x1, #0x4000
    str d0, [x12, x1]                   // x12 + 0x4000: read-only page
    ret

.global fp_regoff_fault_unmapped_mark
fp_regoff_fault_unmapped_mark:
    svc #0
    fmov d0, #1.5
    movz x1, #0x5000
    ldr q1, [x12, x1]                   // x12 + 0x5000: unmapped
    ret

.global fp_regoff_fault_high_mark
fp_regoff_fault_high_mark:
    svc #0
    fmov d0, #2.5
    movz x1, #0x0001, lsl #48           // bit 48 set
    ldr d1, [x12, x1]
    ret

.global fp_regoff_fault_kernel_half_mark
fp_regoff_fault_kernel_half_mark:
    svc #0
    fmov d0, #2.5
    movn x1, #0x0fff, lsl #48           // 0xf000_ffff_ffff_ffff
    str s0, [x12, x1]
    ret

.global fp_regoff_fault_wrap_mark
fp_regoff_fault_wrap_mark:
    svc #0
    fmov d0, #2.5
    mov x1, #-8                         // x12 - 8: before the window, unmapped
    str d0, [x12, x1]
    ret

// The redis words: the event loop's integer-to-double conversion and compare, and
// the AOF path's double load by index, in a loop that also makes a syscall (the
// run leaves at each svc and re-enters; V registers, FPSR and NZCV survive).
.global fp_redis_mark
fp_redis_mark:
    svc #0
    mov x14, x12                        // base of a double array
    movz x0, #0
    fmov d1, #4.0                       // threshold
.Lredis_fill:
    ucvtf d2, x0
    str d2, [x14, x0, lsl #3]
    add x0, x0, #1
    cmp x0, #8
    b.ne .Lredis_fill
    movz x12, #0                        // index (x12 is stack-backed as well)
    movz x11, #0
.Lredis_loop:
    ucvtf d0, x11
    fcmpe d1, d0
    b.le .Lredis_done
    ldr d0, [x14, x12, lsl #3]
    fadd d3, d3, d0
    add x12, x12, #1
    add x11, x11, #1
    svc #0
    b .Lredis_loop
.Lredis_done:
    ret

.global fp_redis_words_mark
fp_redis_words_mark:
    svc #0
    mov x14, x12
    movz x12, #3
    movz x11, #7
    movz x0, #0x4010, lsl #48           // 4.0
    str x0, [x14, #24]
    ucvtf d0, x11
    fcmpe d1, d0
    ldr d0, [x14, x12, lsl #3]
    fmov d1, d0
    fcmpe d1, d0
    ret
