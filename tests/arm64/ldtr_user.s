// User code that itself contains LDTR/STTR is never translated: at EL0 they
// are ordinary loads/stores, but the fragment runs them at EL1 as its own
// user-access instruction. Admission turns them into an Unsupported exit at
// their PC, so userspace executes them natively.
//
//   make harness-test-asm ASM=tests/arm64/ldtr_user.s
//
// Initial fixture state: x12 = FIXTURE_DATA_BASE; everything else = 0.

.text
.global ldtr_user_entry
ldtr_user_entry:
.global hot_svc_mark
hot_svc_mark:
    svc #0
    movz x0, #0x77
    str x0, [x12, #8]
    ldtr x1, [x12, #8]
    ret

.global sttr_user_mark
sttr_user_mark:
    svc #0
    movz x0, #0x88
    sttr w0, [x12, #-4]
    ret
