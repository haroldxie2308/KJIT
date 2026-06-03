// Hard fixture for runtime-reserved and virtualized register exits.
// Each case has its own hot SVC marker. Select a case with HOT_SVC_SYMBOL.
//
// Expected future runs:
//   HOT_SVC_SYMBOL=hot_svc_mark make harness-test-asm ASM=tests/arm64/reserved_regs_hard.s
//   HOT_SVC_SYMBOL=hard_br_x9_mark make harness-test-asm ASM=tests/arm64/reserved_regs_hard.s
//   HOT_SVC_SYMBOL=hard_blr_x10_mark make harness-test-asm ASM=tests/arm64/reserved_regs_hard.s
//   HOT_SVC_SYMBOL=hard_ret_x11_mark make harness-test-asm ASM=tests/arm64/reserved_regs_hard.s
//   HOT_SVC_SYMBOL=hard_br_x16_mark make harness-test-asm ASM=tests/arm64/reserved_regs_hard.s
//   HOT_SVC_SYMBOL=hard_ret_x29_mark make harness-test-asm ASM=tests/arm64/reserved_regs_hard.s

.text
.global toy_translate_entry
toy_translate_entry:
.global hot_svc_mark
hot_svc_mark:
    svc #0

    movz x9, #0x1009
    movz x10, #0x100a
    movz x11, #0x100b

    svc #0

    add x9, x9, #1
    add x10, x10, #2
    add x11, x11, #3

    str x9, [x12, #0]
    str x10, [x12, #8]
    str x11, [x12, #16]

    ret

.global hard_br_x9_mark
hard_br_x9_mark:
    svc #0
    adr x9, hard_exit_target
    br x9

.global hard_blr_x10_mark
hard_blr_x10_mark:
    svc #0
    adr x10, hard_exit_target
    blr x10

.global hard_ret_x11_mark
hard_ret_x11_mark:
    svc #0
    adr x11, hard_exit_target
    ret x11

.global hard_br_x16_mark
hard_br_x16_mark:
    svc #0
    adr x16, hard_exit_target
    br x16

.global hard_ret_x29_mark
hard_ret_x29_mark:
    svc #0
    adr x29, hard_exit_target
    ret x29

hard_exit_target:
    movz x0, #0x7777
    ret
