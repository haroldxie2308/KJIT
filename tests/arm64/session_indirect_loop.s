// Session program (c): a loop of 300 iterations that calls a leaf function through a
// function pointer (`blr`) and makes a getppid-like SVC (docs/pipeline.md, "Session
// recorder (TUI data layer)"). The `BLR` target and the return point after it are
// learned one after the other (each miss profiles its target); then both the call and
// the return are dispatch hits.
//
// The session starts at `session_indirect_loop` with x30 = SESSION_EXIT_PC. As a
// fixture the case is `session_indirect_loop_mark` (x12 = data window, x30 = 0).
//
//   make session-dump ASM=tests/arm64/session_indirect_loop.s ENTRY_SYMBOL=session_indirect_loop
//   make harness-test-asm ASM=tests/arm64/session_indirect_loop.s HOT_SVC_SYMBOL=session_indirect_loop_mark

.text
.global session_indirect_loop
session_indirect_loop:
    movz x8, #172
.global session_indirect_loop_mark
session_indirect_loop_mark:
    svc #0
    movz x19, #300
    movz x20, #0
    mov x22, x30
    adr x21, .Lleaf_c
.Lindirect_loop:
    blr x21
    movz x8, #172
    svc #0
    subs x19, x19, #1
    b.ne .Lindirect_loop
    str x20, [x12, #0x10]
    mov x30, x22
    ret

.Lleaf_c:
    add x20, x20, x19
    eor x20, x20, #0xf0f0f0f0f0f0f0f0
    ret
