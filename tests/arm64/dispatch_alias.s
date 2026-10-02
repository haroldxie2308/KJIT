// A11 dispatch fixture: one `blr` alternating between two callees 16 KiB apart.
// The dispatch table is direct-mapped by pc[13:2] (IBTC_BITS = 12 slots), so two
// targets 0x4000 apart share a slot: each call finds the other callee's record,
// the key compare fails, and the miss goes through the runtime, which publishes the
// target it resolved and so replaces the slot (the replace ping-pong; `ibtc_replace`
// counts it). The returns go to two different resume points and hit.
//
//   make harness-test-asm ASM=tests/arm64/dispatch_alias.s HOT_SVC_SYMBOL=alias_blr_mark
//
// Initial fixture state: x12 = FIXTURE_DATA_BASE, a 16 KiB RW window (all zero);
// every other register is 0.

.text
.global dispatch_alias_entry
dispatch_alias_entry:

.global alias_blr_mark
alias_blr_mark:
    svc #0
    mov x20, x30
    adr x21, alias_a
    adr x22, alias_b
    movz x23, #8
    movz x1, #0
.Lalias_loop:
    blr x21
    blr x22
    subs x23, x23, #1
    b.ne .Lalias_loop
    str x1, [x12, #0x60]
    mov x30, x20
    ret

// The same alternation through two `bl` sites whose targets alias.
.global alias_bl_mark
alias_bl_mark:
    svc #0
    mov x20, x30
    movz x23, #8
    movz x1, #0
.Lalias_bl_loop:
    bl alias_a
    bl alias_b
    subs x23, x23, #1
    b.ne .Lalias_bl_loop
    str x1, [x12, #0x68]
    mov x30, x20
    ret

alias_a:
    add x1, x1, #1
    ret

// alias_b = alias_a + 0x4000 (alias_a is two words).
.space 0x4000 - 8

alias_b:
    add x1, x1, #2
    ret
