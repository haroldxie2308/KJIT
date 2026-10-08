// Execution budget fixture (docs/pipeline.md, "Execution budget (A6)"). Every
// case is a loop right after its hot SVC. A loop that runs its back-edges
// KJIT_BACKEDGE_BUDGET (4096) times in one fragment entry must leave through a
// Budget exit at the back-edge branch, with the user state the original has just
// before that dynamic execution of the branch; shorter loops, and loops whose
// SVC re-enters the fragment (which resets the budget), must run to completion.
//
// Initial fixture state: x12 = data window base (unused here).
// Base PC used by the fixture scripts: 0x10000
//
//   make harness-test-asm ASM=tests/arm64/budget_tight_loop.s

.text

// `b .`: a back-edge to itself. Exits Budget on its 4096th execution.
.global self_loop_mark
self_loop_mark:
    svc #0
    movz x0, #0x1234
    b .
    ret

// A conditional self-loop with a nontrivial NZCV (Z, C and V set, N clear): the
// budget check must leave the flags alone.
.global flags_self_loop_mark
flags_self_loop_mark:
    svc #0
    movz x1, #0x8000, lsl #48
    adds x1, x1, x1
    b.vs .
    ret

// cbnz countdown longer than the budget: exits Budget at the 4096th cbnz with
// x0 = 10000 - 4096.
.global long_countdown_mark
long_countdown_mark:
    svc #0
    movz x0, #10000
    movz x3, #0
1:
    add x3, x3, #2
    sub x0, x0, #1
    cbnz x0, 1b
    ret

// cbnz countdown shorter than the budget: completes without a Budget exit.
.global short_countdown_mark
short_countdown_mark:
    svc #0
    movz x0, #100
1:
    sub x0, x0, #1
    cbnz x0, 1b
    ret

// Boundary: 4095 cbnz executions complete; 4096 exit on the last one (x0 == 0,
// the branch would have fallen through).
.global boundary_complete_mark
boundary_complete_mark:
    svc #0
    movz x0, #4095
1:
    sub x0, x0, #1
    cbnz x0, 1b
    ret

.global boundary_exit_mark
boundary_exit_mark:
    svc #0
    movz x0, #4096
1:
    sub x0, x0, #1
    cbnz x0, 1b
    ret

// tbz loop: counts up until bit 13 is set (8192 back-edges); exits Budget at
// the 4096th tbz with x1 == 4096.
.global tbz_loop_mark
tbz_loop_mark:
    svc #0
    movz x1, #0
1:
    add x1, x1, #1
    tbz x1, #13, 1b
    ret

// Two back-edges share one counter: 100 outer x 50 inner iterations are 5100
// back-edge executions, so the run exits in the middle of an inner loop.
.global nested_loop_mark
nested_loop_mark:
    svc #0
    movz x0, #100
1:
    movz x1, #50
2:
    sub x1, x1, #1
    cbnz x1, 2b
    sub x0, x0, #1
    cbnz x0, 1b
    ret

// Every outer iteration runs an SVC, which leaves the fragment; re-entry
// resets the budget. 3 x (3000 + 1) back-edges in total exceed the budget, but
// no single entry does, so the loop completes.
.global svc_resets_budget_mark
svc_resets_budget_mark:
    svc #0
    movz x8, #172
    movz x0, #3
1:
    svc #0
    movz x1, #3000
2:
    sub x1, x1, #1
    cbnz x1, 2b
    sub x0, x0, #1
    cbnz x0, 1b
    ret
