// Undecodable-instruction fixture: after a hot SVC loop, execution reaches an
// instruction outside the decoded A64 subset. The translator must end the block
// with an unsupported runtime exit that returns to userspace at that PC, with
// user state (including runtime-reserved x9/x10/x11) intact.
// Base PC used by the fixture scripts: 0x10000

.text
.global unsupported_exit_entry
unsupported_exit_entry:
.global hot_svc_mark
hot_svc_mark:
    svc #0

    movz x0, #5
    movz x1, #0
    movz x8, #172

.Lloop:
    add x1, x1, #1
    svc #0
    subs x0, x0, #1
    cbnz x0, .Lloop

    str x1, [x12, #16]
    movz x9, #0x1234
    movz x10, #0x5678
    movz x11, #0x9abc

.global unsupported_insn
unsupported_insn:
    mrs x0, tpidr_el0
    ret
