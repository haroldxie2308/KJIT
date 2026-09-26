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

// A7b: byte store to the read-only page, after a byte load from it succeeds.
.global byte_store_ro_mark
byte_store_ro_mark:
    svc #0
    add x0, x12, #0x4000
    movz w1, #0x77
    sturb w1, [x0, #-1]
    ldrb w2, [x0, #7]
    strb w1, [x0, #7]
    ret

// A7b: unscaled load that starts on the read-only page and runs into the
// unmapped one.
.global unscaled_unmapped_mark
unscaled_unmapped_mark:
    svc #0
    add x3, x12, #0x5000
    movz x4, #0x44
    ldursw x4, [x3, #-2]
    ret

// A7b: register-offset load crossing from the read-only page into the unmapped
// one; target, base and index keep their values.
.global regoffset_cross_mark
regoffset_cross_mark:
    svc #0
    add x5, x12, #0x4000
    movz x6, #0xffc
    movz x7, #0x77
    ldr x7, [x5, x6]
    ret

// A7b: 32-bit pair whose first half is readable and whose second is unmapped; the
// pre-index writeback must not land either.
.global split_ldp32_mark
split_ldp32_mark:
    svc #0
    add x8, x12, #0x5000
    sub x8, x8, #8
    movz x9, #0x99
    movz x13, #0x1313
    ldp w9, w13, [x8, #4]!
    ret
