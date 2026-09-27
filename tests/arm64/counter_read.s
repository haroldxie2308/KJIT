// Counter reads (A10): the arm64 vDSO's clock_gettime fast path. It reads the
// virtual counter with `isb; mrs xN, cntvct_el0` (x11 and x12 in Debian's
// vDSO: the two most frequent Unsupported words under redis's test suite
// before A10), orders the read with a load that depends on it, retries under
// the data page's sequence count, and converts ticks to seconds/nanoseconds
// with the counter frequency.
//
// Initial fixture state: x12 = data window base (all zero: sequence 0,
// cycle_last 0), CNTVCT_EL0 = FIXTURE_CNTVCT, CNTFRQ_EL0 = FIXTURE_CNTFRQ (the
// interpreter's counter does not advance; the native runner emulates both
// reads with these values). The mocked SVCs change nothing.
//
//   make harness-test-asm ASM=tests/arm64/counter_read.s

.text
.global counter_read_entry
counter_read_entry:

// Three clock reads, each followed by a (mocked) syscall: the translated loop
// runs the reads in the fragment, the SVC exits between them.
.global hot_svc_mark
hot_svc_mark:
    svc #0
    mov x3, x12                 // the data page: x12 is a read destination below
    movz x5, #3
.Lread:
    ldr w6, [x3, #0x100]        // sequence
    dmb ishld
    isb
    mrs x11, cntvct_el0
    mrs x12, cntfrq_el0
    // arch_counter_enforce_ordering: a load whose address depends on the count.
    eor x1, x11, x11
    add x1, x3, x1
    ldr xzr, [x1]
    dmb ishld
    ldr w7, [x3, #0x100]
    cmp w6, w7
    b.ne .Lread
    ldr x7, [x3, #0x108]        // cycle_last
    sub x7, x11, x7
    udiv x8, x7, x12            // seconds
    msub x9, x8, x12, x7        // remaining ticks
    movz x10, #0x3b9a, lsl #16
    movk x10, #0xca00           // 1e9
    mul x9, x9, x10
    udiv x9, x9, x12            // nanoseconds
    stp x8, x9, [x3, #0x20]
    stp x11, x12, [x3, #0x30]
    movz x8, #113               // clock_gettime
    svc #0
    subs x5, x5, #1
    b.ne .Lread
    ret

// Reads into registers that register virtualization maps: user x29 (kept in
// x16), stack-backed x16/x17, the runtime-exit channel x9/x10, and XZR.
.global counter_regs_mark
counter_regs_mark:
    svc #0
    mrs x29, cntvct_el0
    mrs x16, cntfrq_el0
    mrs x17, cntvct_el0
    mrs x9, cntfrq_el0
    mrs x10, cntvct_el0
    mrs xzr, cntvct_el0
    mrs xzr, cntfrq_el0
    add x0, x29, x16
    sub x1, x17, x9
    eor x2, x10, x29
    ret
