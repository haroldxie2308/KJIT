// A11 dispatch fixture: recursion that exhausts the budget through dispatch. Every
// dispatch attempt, hit or miss, costs one unit of the back-edge budget
// (KJIT_BACKEDGE_BUDGET = 4096 per fragment entry), so a call chain that stays in
// fragment code is bounded: the budget check before a `bl` exits with
// `RetStatus::Budget` at that `bl`, with the state from before it, and userspace
// re-executes the call natively. The original is capped before the same dynamic
// instance of the call.
//
// `rec_down` keeps no frame: x30 is overwritten by every call, x0 counts the depth
// down from 5000, x1 counts the calls made. The 4096th unit of an entry is the
// `bl`'s own check, so the run ends at a `bl` with x0 = 5000 - 4096 + (entries
// restarted by the misses of the cold run).
//
//   make harness-test-asm ASM=tests/arm64/dispatch_recursion.s HOT_SVC_SYMBOL=recursion_budget_mark
//
// Initial fixture state: x12 = FIXTURE_DATA_BASE, a 16 KiB RW window (all zero);
// every other register is 0.

.text
.global dispatch_recursion_entry
dispatch_recursion_entry:

.global recursion_budget_mark
recursion_budget_mark:
    svc #0
    mov x20, x30
    movz x0, #5000
    movz x1, #0
    bl rec_down
    mov x30, x20
    ret

rec_down:
    sub x0, x0, #1
    cbz x0, .Lrec_done
    add x1, x1, #1
    bl rec_down
.Lrec_done:
    add x1, x1, #2
    ret
