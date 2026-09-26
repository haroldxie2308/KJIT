// Reg-virt rejection fixture: after a hot SVC loop, execution reaches an
// instruction that decodes but that register virtualization rejects as
// CONSTRAINED UNPREDICTABLE (writeback base == Rt). The translator must end the
// block with an unsupported runtime exit that returns to userspace at that PC,
// with user state (including runtime-reserved x9/x10/x11) intact, exactly as for
// an undecodable word.
//
//   make harness-test-asm ASM=tests/arm64/regvirt_reject_exit.s
//
// Initial fixture state: x12 = 0x9000, everything else = 0.
// Base PC used by the fixture scripts: 0x4000

.text
.global regvirt_reject_exit_entry
regvirt_reject_exit_entry:
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
    add x1, x12, #16
    movz x9, #0x1234
    movz x10, #0x5678
    movz x11, #0x9abc

.global rejected_insn
rejected_insn:
    // ldr x1, [x1], #8 -- llvm-mc refuses to assemble it ("unpredictable LDR
    // instruction, writeback base is also a source"), so it is encoded by hand.
    .inst 0xf8408421
    ret
