// A7b 32-bit pair fixture: LDP/STP W (offset, pre, post), LDPSW, STP of WZR/XZR,
// pairs at both ends of the imm7 range, pairs whose halves straddle a page
// boundary, and SP/x29/stack-backed bases and transfers.
//
//   make harness-test-asm ASM=tests/arm64/mem_pairs32.s
//
// Initial fixture state: x12 = FIXTURE_DATA_BASE, a 16 KiB RW window (all
// zero); everything else (including SP) = 0. All addresses derive from x12.

.text
.global mem_pairs32_entry
mem_pairs32_entry:
.global hot_svc_mark
hot_svc_mark:
    svc #0

    movn x0, #0                         // all ones: W loads must clear the top
    movz w1, #0x8000, lsl #16           // 0x80000000
    movn w2, #0x8000, lsl #16           // 0x7fffffff
    movz w3, #0x1234

    add x4, x12, #0x400
    stp w1, w2, [x4]
    stp w3, wzr, [x4, #8]
    stp xzr, xzr, [x4, #16]
    ldp w5, w6, [x4]
    ldpsw x7, x9, [x4]                  // sign-extends both
    mov x10, x0
    ldp w10, w11, [x4, #4]              // x10 top half must clear

    // imm7 extremes: -256 and +252 bytes.
    add x13, x12, #0x800
    stp w1, w3, [x13, #-256]!
    ldp w14, w15, [x13], #252
    stp w2, w1, [x13, #252]
    ldpsw x16, x17, [x13, #252]
    ldpsw x0, x1, [x13, #-256]

    // Pre/post-index LDPSW walk with an SVC between.
    add x6, x12, #0x400
    movz x8, #172
    ldpsw x2, x3, [x6], #8
    svc #0
    ldpsw x4, x5, [x6, #-8]!

    // Halves on different pages (x12 + 0x1000 boundary).
    add x9, x12, #0xffc
    stp w3, w1, [x9]
    ldp w10, w11, [x9]
    ldpsw x14, x15, [x9, #-4]!

    // SP and x29 bases. SP stays 16-byte aligned: Linux checks SP alignment for
    // SP-based accesses at EL0, which the interpreter does not model.
    add sp, x12, #0x2000
    mov x29, sp
    stp w2, w3, [sp, #-16]!
    ldp w16, w17, [x29, #-16]
    ldpsw x29, x9, [sp], #16
    ret
