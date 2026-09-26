// A5 natural-fault fixture: user accesses that fault on their own. Each case
// runs some memory traffic, then an access the page map forbids. The
// translated fragment must leave through that instruction's Mem stub
// (x11 = its PC) with the user state from just before it, so userspace
// re-executes it and takes the fault natively. Natively, the fault is a real
// data abort redirected by the fragment's fault-site table.
//
//   make harness-test-asm ASM=tests/arm64/mem_faults.s
//
// Initial fixture state: x12 = FIXTURE_DATA_BASE, a 16 KiB RW window; the page
// at x12 + 0x4000 is read-only and x12 + 0x5000 is unmapped.

.text
.global mem_faults_entry
mem_faults_entry:
// Store to the read-only page.
.global hot_svc_mark
hot_svc_mark:
    svc #0
    movz x0, #0x1234
    movz x1, #0x5678
    stp x0, x1, [x12, #16]
    ldr x2, [x12, #0x4000]
    str x0, [x12, #0x4000]
    movz x3, #1
    ret

// Pre-index load from the unmapped page: neither rt nor the writeback lands.
.global unmapped_load_mark
unmapped_load_mark:
    svc #0
    add x4, x12, #0x5000
    sub x4, x4, #8
    movz x5, #0x55
    ldr x5, [x4, #8]!
    ret

// Pair load whose second half is unmapped: the first half already loaded, but
// no user register may change.
.global split_ldp_mark
split_ldp_mark:
    svc #0
    add x6, x12, #0x5000
    sub x6, x6, #8
    movz x7, #0x77
    movz x13, #0x1313
    ldp x7, x13, [x6]
    ret
