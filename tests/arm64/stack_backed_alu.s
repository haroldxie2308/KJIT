// ALU forms on virtualized registers: stack-backed x12..x17, stable-mapped x29,
// and SP as the register-31 operand of ADD/SUB (immediate and extended), CMP/CMN
// and logical-immediate AND. Up to four stack-backed operands per instruction
// (madd). Runtime exits (svc) happen while SP and x29 are displaced.
//
// Initial fixture state: x12 = data window base, SP = 0.
//
//   make harness-test-asm ASM=tests/arm64/stack_backed_alu.s

.text
.global stack_backed_alu_entry
stack_backed_alu_entry:
.global hot_svc_mark
hot_svc_mark:
    svc #0

    // SP-relative frame in the upper half of the data window.
    add sp, x12, #2, lsl #12
    mov x29, sp
    sub sp, sp, #0x40
    mov x17, #0x40
    sub sp, sp, x17
    and sp, x29, #0xffffffffffffff00
    sub sp, sp, #0x80
    add x13, sp, #0x10
    add x14, sp, w17, uxtw #1
    cmp sp, x13
    cset w15, lo
    cmn sp, #1, lsl #12
    cinc w15, w15, ne
    subs x16, sp, #0x20
    sub x16, x29, x16
    stp x13, x14, [sp, #0x10]
    str x15, [x29, #8]

    svc #0

    // Four stack-backed operands in one instruction, then read-modify-write.
    mov x12, #3
    mov x13, #5
    mov x14, #7
    madd x15, x12, x13, x14
    msub x16, x15, x13, x12
    smull x17, w15, w16
    umulh x12, x17, x15
    add x13, x13, x14, lsl #4
    adds x14, x15, x16, asr #1
    csel x15, x13, x14, pl
    ccmp x16, x17, #0b0100, ne
    csinc x16, x12, x13, eq
    ubfx x17, x15, #2, #5
    bfi x12, x17, #32, #5
    extr x13, x12, x14, #9
    rev x14, x13
    clz x15, x14
    lsl x16, x17, x15
    eor x16, x16, x16, lsr #3
    and w17, w16, #0x7ff
    orr x12, x12, #0x10000
    eon x13, x13, x12
    sdiv x14, x13, x17
    udiv w15, w13, w12

    svc #0

    // x29 (stable-mapped to x16) as source, destination and read-write operand.
    add x29, x29, x12, lsl #1
    sub x29, x29, x12, lsl #1
    bfxil x29, x17, #0, #4
    bic x29, x29, #0xf
    madd x29, x13, x14, x29
    eor x29, x29, x13
    cmp x29, x16
    csneg x17, x29, x15, hi
    mrs x13, tpidr_el0
    sub x13, x13, x29
    rbit x29, x29

    // Store everything through SP and SP-derived bases, then unwind.
    stp x12, x13, [sp, #0x20]
    stp x14, x15, [sp, #0x30]
    stp x16, x17, [sp, #0x40]
    str x29, [sp, #0x50]
    add sp, sp, #0x80
    add sp, sp, w12, uxtb
    sub sp, sp, w12, uxtb
    mov x29, #0
    ret
