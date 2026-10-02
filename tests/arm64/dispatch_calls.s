// A11 dispatch fixture: calls and returns across functions. Every BL, BLR, BR and
// RET of a fragment goes through the dispatch template: on a miss the exit group
// (the runtime translates the target and publishes it), on a hit straight into the
// callee's fragment. The harness runs each case cold (an empty code cache) and warm
// (the cache the cold run left); both must equal the original code following its
// branches (tmp/pipeline.md, "A11 contract", "Harness").
//
// Cases: nested calls with compiler-style frames (stp/ldp x29, x30 on the data
// window), a call chain ended by tail calls (`b`, then `br`), and recursion with
// frames (200 levels: every level is a call and a return through the tables).
// Every case ends in a `ret` to the entry x30 (0): an unreadable target, where the
// run returns to userspace.
//
//   make harness-test-asm ASM=tests/arm64/dispatch_calls.s HOT_SVC_SYMBOL=nested_calls_mark
//
// Initial fixture state: x12 = FIXTURE_DATA_BASE, a 16 KiB RW window (all zero);
// SP and x30 are 0, so every case builds its stack at x12 + 0x2000.

.text
.global dispatch_calls_entry
dispatch_calls_entry:

// main -> f (twice) -> g (twice each) -> h; returns unwind all of it.
.global nested_calls_mark
nested_calls_mark:
    svc #0
    add sp, x12, #0x2000
    mov x20, x30
    movz x0, #1
    bl func_f
    bl func_f
    str x0, [x12, #0x10]
    mov x30, x20
    ret

func_f:
    stp x29, x30, [sp, #-32]!
    mov x29, sp
    str x0, [sp, #16]
    add x0, x0, #3
    bl func_g
    bl func_g
    ldp x29, x30, [sp], #32
    ret

func_g:
    stp x29, x30, [sp, #-16]!
    mov x29, sp
    eor x0, x0, #0x7f
    bl func_h
    ldp x29, x30, [sp], #16
    ret

func_h:
    add x0, x0, x0, lsl #1
    ret

// A call whose callee tail-calls: `b` to the next function, which `br`s to the
// third, which returns to the original caller.
.global tail_calls_mark
tail_calls_mark:
    svc #0
    mov x20, x30
    movz x1, #0
    bl tail_a
    add x1, x1, #100
    mov x30, x20
    ret

tail_a:
    add x1, x1, #1
    b tail_b

tail_b:
    add x1, x1, #2
    adr x9, tail_c
    br x9

tail_c:
    add x1, x1, #4
    ret

// 200 levels of recursion with frames: 200 calls, 200 returns.
.global recursion_frames_mark
recursion_frames_mark:
    svc #0
    add sp, x12, #0x2000
    mov x20, x30
    movz x0, #200
    movz x1, #0
    bl rec_frame
    str x1, [x12, #0x20]
    mov x30, x20
    ret

rec_frame:
    stp x29, x30, [sp, #-16]!
    sub x0, x0, #1
    cbz x0, .Lrec_done
    add x1, x1, x0
    bl rec_frame
.Lrec_done:
    ldp x29, x30, [sp], #16
    ret
