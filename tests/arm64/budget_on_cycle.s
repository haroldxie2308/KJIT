// Budgeted back-edges fixture (docs/pipeline.md, "Execution budget (A6)",
// "Budgeted back-edges (A22)"). A backward branch carries a budget check only when
// its target block can reach it again inside the fragment. Every case runs through
// the full-pipeline differential (and the native runner on arm64 hosts); the verifier
// accepts exactly the guarded and the unguarded forms below.
//
// - Jumps back to a shared `ret` block are on no cycle: no check, no stub.
// - Real loops keep the check; a Budget exit stays precise next to unguarded
//   backward branches of the same fragment.
// - A call is a sink (its dispatch is charged), so a loop whose only way back goes
//   through a `bl` has no budgeted back-edge in the fragment that holds the return
//   site; the loop around an inner loop keeps the inner check.
//
// Initial fixture state: x12 = FIXTURE_DATA_BASE, everything else 0.
//
//   make harness-test-asm ASM=tests/arm64/budget_on_cycle.s HOT_SVC_SYMBOL=jump_back_to_ret_mark

.text

// A shared `ret` block above two paths that both jump back to it (the `string2ll`
// shape of the census): neither backward `b` is on a cycle.
.global jump_back_to_ret_mark
jump_back_to_ret_mark:
    svc #0
    movz x0, #1
    cbnz x0, 2f
    movz x1, #1
    b 3f
1:
    movz x2, #7
    ret
2:
    movz x1, #2
    b 1b
3:
    movz x1, #3
    b 1b

// The same shape with the other path taken, and with a conditional back to the ret.
.global jump_back_to_ret_other_path_mark
jump_back_to_ret_other_path_mark:
    svc #0
    movz x0, #0
    cbnz x0, 2f
    movz x1, #1
    b 3f
1:
    movz x2, #7
    ret
2:
    movz x1, #2
    cbz x0, 1b
    b 1b
3:
    movz x1, #3
    cbz x0, 1b
    b 1b

// A real loop of 10000 iterations whose exit path jumps back to a shared `ret` (not
// on the loop's cycle). The loop's `b 2b` is guarded and exits Budget on its 4096th
// execution; the unguarded `cbz x0, 1b` is executed 4096 times by then and uses no
// unit.
.global loop_with_shared_ret_mark
loop_with_shared_ret_mark:
    svc #0
    movz x0, #10000
    movz x3, #0
    b 2f
1:
    movz x4, #9
    ret
2:
    add x3, x3, #3
    sub x0, x0, #1
    cbz x0, 1b
    b 2b

// The same loop shorter than the budget: runs to its jump back to the `ret`.
.global short_loop_with_shared_ret_mark
short_loop_with_shared_ret_mark:
    svc #0
    movz x0, #100
    movz x3, #0
    b 2f
1:
    movz x4, #9
    ret
2:
    add x3, x3, #3
    sub x0, x0, #1
    cbz x0, 1b
    b 2b

// A loop whose way from head to back-edge goes through a forward `b` over a `ret`:
// the closing `cbnz` is on a cycle and keeps its check.
.global loop_through_forward_branch_mark
loop_through_forward_branch_mark:
    svc #0
    movz x0, #6000
1:
    sub x0, x0, #1
    tbnz x0, #40, 2f
    b 3f
2:
    ret
3:
    cbnz x0, 1b
    ret

// Nested loops: the outer loop's back-edge and the inner loop's are both on a cycle.
// 70 x 100 = 7000 inner iterations exceed the budget, so the run exits Budget in
// the middle of an inner loop with the outer counter at its exact value.
.global nested_on_cycle_mark
nested_on_cycle_mark:
    svc #0
    movz x0, #70
1:
    movz x1, #100
2:
    sub x1, x1, #1
    cbnz x1, 2b
    sub x0, x0, #1
    cbnz x0, 1b
    ret

// A loop around a call. The fragment entered at the SVC holds the call block; the
// return site (`subs`) is entered through the runtime, so its backward `b.ne` to
// the call block is on no cycle of its fragment: each lap is bounded by the call's
// own unit. 300 laps stay below the budget per entry.
.global loop_with_call_mark
loop_with_call_mark:
    svc #0
    movz x19, #300
    movz x20, #0
    mov x22, x30
1:
    bl .Lleaf
    subs x19, x19, #1
    b.ne 1b
    str x20, [x12, #0x10]
    mov x30, x22
    ret

// Nested loops with a call between them: the inner loop is a real cycle (guarded);
// the outer back-edge is only reachable through the call (unguarded).
.global nested_loops_with_call_mark
nested_loops_with_call_mark:
    svc #0
    movz x19, #20
    movz x20, #0
    mov x22, x30
1:
    movz x1, #30
2:
    sub x1, x1, #1
    cbnz x1, 2b
    bl .Lleaf
    subs x19, x19, #1
    b.ne 1b
    str x20, [x12, #0x10]
    mov x30, x22
    ret

.Lleaf:
    add x20, x20, x19
    eor x20, x20, #0xff
    ret
