// A11 dispatch fixture: a non-FP/SIMD caller of an FP/SIMD callee. A run of a
// non-FP/SIMD fragment dispatches through `table_nofp`, which never holds a record
// of an FP/SIMD fragment (tmp/pipeline.md, "A11 contract", "Mechanism"): the call
// into `fp_func` always misses and goes through the runtime (counted as
// `ibtc_fpsimd_boundary`), which then runs the callee as an FP/SIMD run, whose
// `table_all` may continue into non-FP/SIMD code (its return hits).
//
//   make harness-test-asm ASM=tests/arm64/dispatch_fpsimd.s HOT_SVC_SYMBOL=fp_callee_mark
//
// Initial fixture state: x12 = FIXTURE_DATA_BASE, a 16 KiB RW window (all zero);
// V0-V31 and every other register are 0.

.text
.global dispatch_fpsimd_entry
dispatch_fpsimd_entry:

.global fp_callee_mark
fp_callee_mark:
    svc #0
    mov x20, x30
    add x0, x12, #0x100
    movz x1, #0x1234
    bl fp_func
    add x1, x1, #1
    bl fp_func
    bl plain_func
    str x1, [x12, #0x80]
    mov x30, x20
    ret

// The callee uses SIMD&FP registers; the caller does not.
fp_func:
    dup v0.2d, x1
    add v0.2d, v0.2d, v0.2d
    str q0, [x0]
    ldr q1, [x0]
    umov x1, v1.d[0]
    ret

plain_func:
    add x1, x1, #3
    ret

// An FP/SIMD caller of a plain callee: the FP run's table_all holds the callee.
.global fp_caller_mark
fp_caller_mark:
    svc #0
    mov x20, x30
    add x0, x12, #0x200
    movz x1, #0x77
    dup v2.2d, x1
    str q2, [x0]
    bl plain_func
    bl plain_func
    ldr q3, [x0]
    umov x2, v3.d[1]
    mov x30, x20
    ret
