// A7b literal-load fixture: LDR (literal) W/X, LDRSW (literal) and PRFM
// (literal/immediate/register) whose PC-relative targets are in the fixture data
// window. The translator materializes each absolute address (original PC +
// offset) in scratch and loads it with LDTR*; PRFM becomes a NOP.
//
//   make harness-test-asm ASM=tests/arm64/mem_literal.s
//
// Literal targets are written as `.Ltext + (FIXTURE_DATA_BASE - TEXT_BASE) + n`,
// so this fixture assumes the default text base 0x10000 (TEXT_BASE in
// scripts/compile-asm-fixture.sh) and data window 0x20000. Literal pools inside
// the text itself are not exercised: the harness user page map covers the data
// window only, not the text.
//
// Initial fixture state: x12 = FIXTURE_DATA_BASE, a 16 KiB RW window (all
// zero), a read-only page at x12 + 0x4000 and nothing mapped after it.

.equ TEXT_BASE, 0x10000
.equ DATA_BASE, 0x20000
.equ DATA, DATA_BASE - TEXT_BASE

.text
.Ltext:
.global mem_literal_entry
mem_literal_entry:
.global hot_svc_mark
hot_svc_mark:
    svc #0

    // Seed the literal pool at x12 + 0x100.
    movz x0, #0x8000, lsl #16
    movk x0, #0x0123, lsl #32
    movk x0, #0xfedc, lsl #48
    str x0, [x12, #0x100]
    movn w1, #0x8000, lsl #16           // 0x7fffffff
    str w1, [x12, #0x108]

    ldr x2, .Ltext + DATA + 0x100
    ldr w3, .Ltext + DATA + 0x100       // low word, zero-extended
    ldr w4, .Ltext + DATA + 0x104       // high word
    ldrsw x5, .Ltext + DATA + 0x100     // 0x80000000 sign-extended
    ldrsw x6, .Ltext + DATA + 0x108     // 0x7fffffff
    ldr x7, .Ltext + DATA + 0x104       // straddles the two seeded values
    ldr xzr, .Ltext + DATA + 0x100      // discarded, still a user access
    ldr x13, .Ltext + DATA + 0x4000     // the read-only page is readable

    // Prefetches never fault, even of unmapped memory.
    prfm pldl1keep, .Ltext + DATA + 0x6000
    add x8, x12, #0x6000
    prfm pstl1strm, [x8, #8]
    prfm pldl3keep, [x8, x12, lsl #3]

    // The same literal from inside a loop with an SVC.
    movz x9, #3
    movz x10, #0
    movz x8, #172
.Lloop:
    ldrsw x11, .Ltext + DATA + 0x100
    add x10, x10, x11
    svc #0
    subs x9, x9, #1
    b.ne .Lloop
    ret

// A literal load from the unmapped page after the read-only one: the fragment
// exits Mem at this PC with the pre-instruction state.
.global literal_fault_mark
literal_fault_mark:
    svc #0
    movz x0, #0x55
    ldr x0, .Ltext + DATA + 0x5000
    ret
