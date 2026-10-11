// Session program (a): a loop of 300 iterations, each a getppid-like SVC and some ALU
// work (docs/pipeline.md, "Session recorder (TUI data layer)"). The pc after the
// loop's SVC is profiled once per iteration; the 64th hit translates it and the
// remaining iterations run in the fragment, which exits at the SVC each time.
//
// The session starts at `session_svc_loop` with x30 = SESSION_EXIT_PC. As a fixture
// the case is `session_svc_loop_mark` (initial state: x12 = data window, x30 = 0, so
// the final `ret` goes to unreadable text).
//
//   make session-dump ASM=tests/arm64/session_svc_loop.s ENTRY_SYMBOL=session_svc_loop
//   make harness-test-asm ASM=tests/arm64/session_svc_loop.s HOT_SVC_SYMBOL=session_svc_loop_mark

.text
.global session_svc_loop
session_svc_loop:
    movz x8, #172
.global session_svc_loop_mark
session_svc_loop_mark:
    svc #0
    movz x19, #300
    movz x20, #0
.Lsvc_loop:
    movz x8, #172
    svc #0
    eor x21, x20, x19
    add x20, x20, x21, lsl #1
    subs x19, x19, #1
    b.ne .Lsvc_loop
    str x20, [x12, #0x10]
    ret
