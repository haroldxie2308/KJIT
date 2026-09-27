// Undecodable-instruction fixture: after a hot SVC loop, execution reaches an
// instruction outside the decoded A64 subset. The translator must end the block
// with an unsupported runtime exit that returns to userspace at that PC, with
// user state (including runtime-reserved x9/x10/x11) intact.
// Base PC used by the fixture scripts: 0x10000

.text
.global unsupported_exit_entry
unsupported_exit_entry:
.global hot_svc_mark
hot_svc_mark:
    svc #0

    movz x0, #5
    movz x1, #0
    movz x8, #172

.Lloop:
    add x1, x1, #1
    svc #0
    subs x0, x0, #1
    cbnz x0, .Lloop

    str x1, [x12, #16]
    movz x9, #0x1234
    movz x10, #0x5678
    movz x11, #0x9abc

.global unsupported_insn
unsupported_insn:
    // Only TPIDR_EL0 is decodable among system-register reads.
    mrs x0, tpidrro_el0
    ret

// A7b: exclusive forms stay outside the subset (A8 admitted the LSE atomics,
// A9a the SIMD&FP loads/stores below), so each ends its block with an
// Unsupported exit at its own PC.
.global ldxr_unsupported_mark
ldxr_unsupported_mark:
    svc #0
    add x0, x12, #0x40
    str x0, [x0]
    ldxr x1, [x0]
    ret

.arch_extension lse
.global ldadd_unsupported_mark
ldadd_unsupported_mark:
    svc #0
    movz x2, #1
    ldadd x2, x3, [x12]
    ret

// A9a: SIMD&FP loads/stores joined the subset except register offset (and
// literal, LD2-4, single structure); FP arithmetic stays out.
.global ldr_q_unsupported_mark
ldr_q_unsupported_mark:
    svc #0
    ldrb w4, [x12, #1]
    ldr q0, [x12]
    ldr q1, [x12, x4]
    ret

.global fadd_unsupported_mark
fadd_unsupported_mark:
    svc #0
    movz x1, #0x4000, lsl #48
    fmov d0, x1
    fadd d1, d0, d0
    ret

// A7c: acquire/release is admitted, but its exclusive and atomic relatives are
// not: each case runs an admitted LDAR/STLR, then ends at the unsupported form.
.global ldaxr_unsupported_mark
ldaxr_unsupported_mark:
    svc #0
    add x0, x12, #0x80
    ldar x1, [x0]
    ldaxr x2, [x0]
    ret

.global stlxr_unsupported_mark
stlxr_unsupported_mark:
    svc #0
    add x0, x12, #0x90
    movz x1, #0x11
    stlr x1, [x0]
    stlxr w2, x1, [x0]
    ret

.global cas_unsupported_mark
cas_unsupported_mark:
    svc #0
    add x0, x12, #0xa0
    movz x1, #0
    movz x2, #0x22
    cas x1, x2, [x0]
    ret

// FEAT_LRCPC2/3 forms beyond the base-register LDAPR stay out.
.arch_extension rcpc3
.global ldapr_writeback_unsupported_mark
ldapr_writeback_unsupported_mark:
    svc #0
    add x0, x12, #0xb0
    ldapr x1, [x0], #8
    ret
