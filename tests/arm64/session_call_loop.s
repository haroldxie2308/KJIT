// Session program (b): a loop of 300 iterations that calls a leaf function with `bl`
// and makes a getppid-like SVC (docs/pipeline.md, "Session recorder (TUI data
// layer)"). Exercises the learning of the callee (a `BL` exit that misses profiles its
// target), the direct `BL` link to it (A16), and `ret` dispatch: once the callee has a
// fragment, a call is a `b` and a return a dispatch hit, with no runtime round trip.
//
// The session starts at `session_call_loop` with x30 = SESSION_EXIT_PC. As a fixture
// the case is `session_call_loop_mark` (x12 = data window, x30 = 0).
//
//   make session-dump ASM=tests/arm64/session_call_loop.s ENTRY_SYMBOL=session_call_loop
//   make harness-test-asm ASM=tests/arm64/session_call_loop.s HOT_SVC_SYMBOL=session_call_loop_mark

.text
.global session_call_loop
session_call_loop:
    movz x8, #172
.global session_call_loop_mark
session_call_loop_mark:
    svc #0
    movz x19, #300
    movz x20, #0
    mov x22, x30
.Lcall_loop:
    bl .Lleaf
    movz x8, #172
    svc #0
    subs x19, x19, #1
    b.ne .Lcall_loop
    str x20, [x12, #0x10]
    mov x30, x22
    ret

.Lleaf:
    add x20, x20, x19
    eor x20, x20, #0xff
    ret
