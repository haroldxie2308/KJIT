// A7d carry-arithmetic fixture: ADC/ADCS/SBC/SBCS (32 and 64 bit) and the
// NGC/NGCS aliases read NZCV.C. The fragment only adds flag-neutral
// instructions around user code (reg-virt fills/spills, SP/alignment checks,
// the budget check's SUB/CBZ), so a carry produced by one user instruction
// reaches the next. Cases: a 128-bit counter carried across a loop with an SVC
// between ADDS and ADC, 192-bit add and subtract with borrow-dependent branches,
// a signed/unsigned 128-bit compare (`cmp; sbcs xzr`), 32-bit forms, NGC/NGCS,
// stack-backed operands (x13..x17, x29), and SMSUBL/UMSUBL/CRC32*/CRC32C*.
//
//   make harness-test-asm ASM=tests/arm64/adc_chain.s
//
// Initial fixture state: x12 = FIXTURE_DATA_BASE, a 16 KiB RW window (all
// zero); everything else (including SP and NZCV) = 0. All addresses derive
// from x12.

.text
.arch_extension crc
.global adc_chain_entry
adc_chain_entry:
.global hot_svc_mark
hot_svc_mark:
    svc #0

// 128-bit counter x2:x1 starting at 2^64 - 3, +1 per iteration; the carry out
// of the low word is consumed by ADC after an SVC in between (NZCV survives the
// syscall exit and resume).
    movn x1, #2
    movz x2, #0
    movz x0, #6
    movz x8, #172
.Lcount:
    adds x1, x1, #1
    svc #0
    adc x2, x2, xzr
    subs x0, x0, #1
    b.ne .Lcount
    stp x1, x2, [x12]

// 192-bit a = x5:x4:x3 plus b = x15:x14:x13 (stack-backed), carrying through
// every word, then the carry out of the top word picks a branch.
    movn x3, #0
    movn x4, #0
    movz x5, #0x7fff, lsl #48
    movz x13, #1
    movz x14, #0
    movz x15, #0
    adds x6, x3, x13
    adcs x7, x4, x14
    adcs x9, x5, x15
    b.vs .Lsum_overflow
    movz x10, #0x1111
    b .Lsum_done
.Lsum_overflow:
    movz x10, #0x2222
.Lsum_done:
    stp x6, x7, [x12, #16]
    stp x9, x10, [x12, #32]

// 192-bit a - b with b > a: borrows through every word; C clear afterwards.
    movz x3, #5
    movz x4, #0
    movz x5, #0
    movz x13, #6
    subs x6, x3, x13
    sbcs x7, x4, x14
    sbcs x16, x5, x15
    b.cc .Lborrow
    movz x11, #0x3333
    b .Lsub_done
.Lborrow:
    movz x11, #0x4444
.Lsub_done:
    stp x6, x7, [x12, #48]
    stp x16, x11, [x12, #64]

// 128-bit compare x17:x29 against x14:x13: unsigned (b.lo) and signed (b.lt)
// after `cmp lo; sbcs xzr, hi, hi`.
    movz x29, #1
    movz x17, #0x8000, lsl #48
    movz x13, #2
    movz x14, #0
    cmp x29, x13
    sbcs xzr, x17, x14
    cset x0, lo
    cset x1, lt
    csel x2, x29, x13, hs
    stp x0, x1, [x12, #80]
    str x2, [x12, #96]
    ret

// 32-bit forms zero-extend; NGC/NGCS negate with borrow.
.global adc32_ngc_mark
adc32_ngc_mark:
    svc #0
    movn x0, #0
    movz x1, #1
    adds w2, w0, w1
    adc w3, w0, wzr
    adcs w4, w0, w0
    sbc w5, w1, w0
    sbcs w6, wzr, w1
    ngc x7, x1
    ngcs w9, w0
    b.mi .Lneg
    movz x10, #0x55
    b .Lngc_done
.Lneg:
    movz x10, #0x66
.Lngc_done:
    cmp x1, #2
    ngc x11, xzr
    stp x2, x3, [x12, #128]
    stp x4, x5, [x12, #144]
    stp x6, x7, [x12, #160]
    stp x9, x10, [x12, #176]
    str x11, [x12, #192]
    ret

// Multiply-subtract long and CRC32/CRC32C over a word loaded from memory; the
// SMNEGL/UMNEGL aliases use Ra = xzr.
.global msubl_crc_mark
msubl_crc_mark:
    svc #0
    movz x0, #0x3231
    movk x0, #0x3433, lsl #16
    movk x0, #0x3635, lsl #32
    movk x0, #0x3837, lsl #48
    str x0, [x12, #256]
    ldr x1, [x12, #256]
    movn w2, #0
    crc32x w3, w2, x1
    crc32b w3, w3, w1
    crc32h w4, w2, w1
    crc32w w5, w2, w1
    crc32cx w6, w2, x1
    crc32cb w6, w6, w1
    crc32ch w7, w2, w1
    crc32cw w9, w2, w1
    movn x10, #4
    movz x11, #7
    movz x13, #100
    smsubl x14, w10, w11, x13
    umsubl x15, w10, w11, x13
    smnegl x16, w10, w11
    umnegl x17, w11, w10
    stp x3, x4, [x12, #272]
    stp x5, x6, [x12, #288]
    stp x7, x9, [x12, #304]
    stp x14, x15, [x12, #320]
    stp x16, x17, [x12, #336]
    ret
