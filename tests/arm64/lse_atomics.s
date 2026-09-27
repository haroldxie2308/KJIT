// A8 LSE atomics fixture. Every LD<op>/SWP/CAS (and ST<op>, the Rt = XZR alias)
// runs in a fragment as the one privileged access of a PAN window:
//
//   [mov sA, <base>] [alignment check -> Mem stub]
//   ubfx sB, sA, #48, #8; cbnz sB, <PAN stub>
//   msr pan, #0; <atomic, base sA>; msr pan, #1
//
// and a fault on it (or a range-check failure) leaves through the PAN stub
// (`msr pan, #1` + the Mem exit group). Cases: counters with every operation and
// size, CAS success and failure, a refcount loop with an SVC inside, SP-based,
// stack-backed (x12..x17), x29 and x9..x11 operands, a tagged pointer (top byte
// ignored), faults on the read-only and the unmapped page, a kernel-half
// pointer (range check), and alignment (misaligned inside a 16-byte block runs,
// crossing a block faults natively and leaves through the Mem stub).
//
//   make harness-test-asm ASM=tests/arm64/lse_atomics.s
//
// Initial fixture state: x12 = FIXTURE_DATA_BASE, a 16 KiB RW window (all
// zero); the page at x12 + 0x4000 is read-only and x12 + 0x5000 is unmapped;
// everything else (including SP) = 0. All addresses derive from x12.

.text
.arch_extension lse
.global lse_atomics_entry
lse_atomics_entry:
.global hot_svc_mark
hot_svc_mark:
    svc #0

    // 64-bit counters: every LD<op> and SWP, all four ordering variants.
    add x0, x12, #0x100
    movz x1, #0x10
    ldadd x1, x2, [x0]
    ldadda x1, x3, [x0]
    ldaddal x1, x4, [x0]
    ldaddl x1, x5, [x0]
    movz x6, #0xf0f0
    ldset x6, x7, [x0]
    ldclr x1, x8, [x0]
    ldeor x6, x9, [x0]
    movn x10, #7
    ldsmax x10, x11, [x0]
    ldsmin x10, x13, [x0]
    ldumax x10, x14, [x0]
    ldumin x1, x15, [x0]
    movz x16, #0xabcd
    swp x16, x17, [x0]
    swpal x1, x18, [x0]
    stadd x1, [x0]
    staddl x1, [x0]
    stset x6, [x0]
    ldr x19, [x0]
    ret

// CAS: success (memory holds the expected value) and failure (it does not);
// Rs receives the old value either way. Every size and ordering.
.global cas_mark
cas_mark:
    svc #0
    add x0, x12, #0x200
    movz x1, #0x1111
    str x1, [x0]
    mov x2, x1
    movz x3, #0x2222
    casal x2, x3, [x0]
    movz x4, #0x9999
    cas x4, x1, [x0]
    ldr x5, [x0]
    add x6, x12, #0x210
    movz w7, #0x33
    strb w7, [x6]
    movz w8, #0x33
    movz w9, #0x44
    casab w8, w9, [x6]
    movz w10, #0x55
    caslb w10, w9, [x6]
    add x11, x12, #0x220
    movz w13, #0x7777
    strh w13, [x11]
    movz w14, #0x7777
    movz w15, #0x8888
    cash w14, w15, [x11]
    casalh w14, w15, [x11]
    add x16, x12, #0x230
    movz w17, #0x1234
    str w17, [x16]
    casa w17, wzr, [x16]
    casl w17, w17, [x16]
    ldr w18, [x16]
    ret

// Byte/halfword/word forms of every operation, signed min/max on negative
// values, and the store aliases.
.global narrow_mark
narrow_mark:
    svc #0
    add x0, x12, #0x300
    movz w1, #0xff
    ldaddb w1, w2, [x0]
    ldaddab w1, w3, [x0]
    ldsetb w1, w4, [x0]
    ldclrlb w1, w5, [x0]
    movz w6, #0x80
    ldeoralb w6, w7, [x0]
    ldsmaxb w6, w8, [x0]
    ldsminab w1, w9, [x0]
    ldumaxlb w6, w10, [x0]
    lduminalb w1, w11, [x0]
    swpb w6, w13, [x0]
    staddb w1, [x0]
    add x0, x12, #0x310
    movz w1, #0xffff
    ldaddh w1, w2, [x0]
    ldsetah w1, w3, [x0]
    movz w6, #0x8000
    ldclrh w6, w4, [x0]
    ldeorh w6, w5, [x0]
    ldsmaxh w1, w7, [x0]
    ldsminlh w6, w8, [x0]
    ldumaxah w6, w9, [x0]
    lduminh w1, w10, [x0]
    swpalh w6, w11, [x0]
    steorh w6, [x0]
    add x0, x12, #0x320
    movn w1, #0
    ldadd w1, w2, [x0]
    ldsmax w1, w3, [x0]
    movz w6, #0x7fff, lsl #16
    ldsmin w6, w4, [x0]
    ldumax w6, w5, [x0]
    ldumin w1, w7, [x0]
    ldset w6, w8, [x0]
    ldclr w6, w9, [x0]
    ldeor w1, w10, [x0]
    swpa w6, w11, [x0]
    stumax w1, [x0]
    stsminl w6, [x0]
    ldr x13, [x0]
    ret

// Refcount loop: take a reference, make a syscall, drop it, five times. The
// back-edge carries the budget check; the SVC exits and re-enters the fragment.
.global refcount_mark
refcount_mark:
    svc #0
    add x0, x12, #0x400
    movz w1, #1
    movn w2, #0
    movz x3, #5
    movz x8, #172
.Lref:
    ldaddal w1, w4, [x0]
    svc #0
    ldaddl w2, w5, [x0]
    ldadda w1, w6, [x0]
    subs x3, x3, #1
    b.ne .Lref
    ldr w7, [x0]
    ret

// SP-based atomics (SP 16-byte aligned: the SP check passes, no block check) and
// stack-backed x12..x17 / x29 / x9..x11 operands.
.global mapped_regs_mark
mapped_regs_mark:
    svc #0
    add sp, x12, #0x2000
    movz x1, #3
    ldadd x1, x2, [sp]
    swpal x1, x3, [sp]
    ldsetb w1, w4, [sp]
    add x13, x12, #0x500
    movz x14, #0x21
    ldadd x14, x15, [x13]
    ldaddal x14, x14, [x13]
    movz x16, #0x5
    ldeor x16, x17, [x13]
    ldadd x13, x13, [x13]
    ldclral x12, x16, [x12]
    add x29, x12, #0x510
    ldset x14, x13, [x29]
    add x11, x12, #0x520
    movz x9, #0x99
    swp x9, x10, [x11]
    mov x9, x10
    movz x10, #0x77
    cas x9, x10, [x11]
    ldr x17, [x11]
    ret

// A tagged pointer: the top byte is ignored (TBI0) at EL0 and in the window
// (the range check looks at bits 55:48 only).
.global tagged_mark
tagged_mark:
    svc #0
    add x0, x12, #0x600
    movz x5, #0x5a00, lsl #48
    orr x0, x0, x5
    movz x1, #7
    ldaddal x1, x2, [x0]
    ldadd x1, x3, [x0]
    ret

// Atomic on the read-only page: the load before it runs; the atomic faults
// (Mem exit at it, precise: nothing written, x3 keeps its value, PAN restored
// by the PAN stub).
.global atomic_ro_mark
atomic_ro_mark:
    svc #0
    add x0, x12, #0x4000
    ldr x2, [x0]
    movz x1, #1
    movz x3, #0x3333
    ldaddal x1, x3, [x0]
    movz x4, #1
    ret

// A CAS whose comparison fails on the read-only page still needs write
// permission: it faults like the others.
.global cas_ro_fail_mark
cas_ro_fail_mark:
    svc #0
    add x0, x12, #0x4000
    add x0, x0, #8
    movz x1, #0x77
    movz x2, #0x88
    casal x1, x2, [x0]
    ret

// Atomic on the unmapped page, through a stack-backed base.
.global atomic_unmapped_mark
atomic_unmapped_mark:
    svc #0
    add x15, x12, #0x5000
    movz w1, #1
    movz w2, #0x2222
    swpalh w1, w2, [x15]
    ret

// A kernel-half pointer: the range check (VA bits 55:48 != 0) leaves through
// the PAN stub before any access; natively the EL0 access faults.
.global kernel_pointer_mark
kernel_pointer_mark:
    svc #0
    movz x0, #0xffff, lsl #48
    movk x0, #0x8000, lsl #32
    movk x0, #0x1000
    movz x1, #1
    movz x2, #0x2222
    ldadd x1, x2, [x0]
    ret

// A user address beyond 2^48 (bit 55 clear, bits 54:48 set): the range check
// also rejects it; natively it is unmapped.
.global high_pointer_mark
high_pointer_mark:
    svc #0
    movz x0, #0x0001, lsl #48
    add x0, x0, x12
    movz x1, #1
    stadd x1, [x0]
    ret

// Misaligned inside a 16-byte block: runs (FEAT_LSE2). Crossing a block: the
// alignment check leaves through the plain Mem stub; natively SIGBUS.
.global misaligned_mark
misaligned_mark:
    svc #0
    add x0, x12, #0x704
    movz x1, #1
    ldadd x1, x2, [x0]
    add x0, x12, #0x70e
    ldaddh w1, w3, [x0]
    add x0, x12, #0x70c
    movz x4, #0x4444
    ldaddal x1, x4, [x0]
    ret

// Halfword CAS crossing a block through a stack-backed base.
.global cas_cross_mark
cas_cross_mark:
    svc #0
    add x14, x12, #0x71f
    movz w1, #0
    movz w2, #1
    casalh w1, w2, [x14]
    ret

// SP-based atomic with SP not 16-byte aligned: the SP check fires first.
.global sp_misaligned_mark
sp_misaligned_mark:
    svc #0
    add sp, x12, #0x2000
    add sp, sp, #8
    movz x1, #1
    ldadd x1, x2, [sp]
    ret

// `msr pan, #1` in user code: rejected by reg-virt (UNDEFINED at EL0), so the
// fragment exits Unsupported before it and userspace runs it natively (SIGILL).
// The atomic before it still runs in the fragment.
.global user_msr_pan_mark
user_msr_pan_mark:
    svc #0
    add x0, x12, #0x800
    movz x1, #9
    stadd x1, [x0]
    .inst 0xd500419f // msr pan, #1
    ret
