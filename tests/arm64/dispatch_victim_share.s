// A11c dispatch fixture: two pairs of main-aliasing callees whose evicted members
// compete for victim slots. The dispatch table is a direct-mapped main part
// (slot pc[13:2]) plus a 256-slot victim part (slot pc[9:2] ^ pc[21:14]); a main-slot
// record that another pc evicts moves to its own victim slot.
//
// Text base 0x10000 (compile-asm-fixture.sh). Callees (offset = pc - 0x10000):
//
//   x  = 0x100   main 0x040, victim 0x44      x2  = x  + 0x4000   (same main slot)
//   y  = 0x500   main 0x140, victim 0x44      y2  = y  + 0x4000
//   y' = 0x604   main 0x181, victim 0x85      y2' = y' + 0x4000
//
// x and y have different main slots but the same victim slot.
//
//   victim_share_mark: calls x, y, x2, y2. x2 evicts x into victim 0x44, then y2
//   evicts y into victim 0x44 too, dropping x. The cold run misses all four calls;
//   afterwards x is in neither slot (the documented limit), y sits in the victim
//   part, x2 and y2 in the main part. The warm run misses once, on x, and then
//   hits (x's republication moves x2 into its own victim slot).
//
//   victim_distinct_mark: the same alternation with y' and y2' in place of y and
//   y2, whose evicted members land in different victim slots (0x44, 0x85): the
//   warm run hits all four calls.
//
//   make harness-test-asm ASM=tests/arm64/dispatch_victim_share.s HOT_SVC_SYMBOL=victim_share_mark
//
// Initial fixture state: x12 = FIXTURE_DATA_BASE, a 16 KiB RW window (all zero);
// every other register is 0.

.text
.global dispatch_victim_share_entry
dispatch_victim_share_entry:

.global victim_share_mark
victim_share_mark:
    svc #0
    mov x20, x30
    adr x21, victim_x
    adr x22, victim_y
    adr x23, victim_x2
    adr x24, victim_y2
    movz x1, #0
    blr x21
    blr x22
    blr x23
    blr x24
    str x1, [x12, #0x78]
    mov x30, x20
    ret

.global victim_distinct_mark
victim_distinct_mark:
    svc #0
    mov x20, x30
    adr x21, victim_x
    adr x22, victim_yd
    adr x23, victim_x2
    adr x24, victim_y2d
    movz x1, #0
    blr x21
    blr x22
    blr x23
    blr x24
    str x1, [x12, #0x80]
    mov x30, x20
    ret

.org 0x100
victim_x:
    add x1, x1, #1
    ret

.org 0x500
victim_y:
    add x1, x1, #2
    ret

.org 0x604
victim_yd:
    add x1, x1, #4
    ret

.org 0x4100
victim_x2:
    add x1, x1, #8
    ret

.org 0x4500
victim_y2:
    add x1, x1, #16
    ret

.org 0x4604
victim_y2d:
    add x1, x1, #32
    ret
