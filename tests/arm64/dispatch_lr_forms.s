// A11 dispatch fixture: link-register forms of the dispatched branches.
//
// `blr x30`: the target is the old x30, and the dispatch site must read it before
// its own link write overwrites x30 (the target move precedes the link write;
// docs/pipeline.md, "In-fragment branch dispatch (A11)", Lowering). On a budget exit the whole site
// re-executes natively, which is also correct for `blr x30`.
//
// `ret x5`: a return through another register, to a function entry that a call
// already translated, so the table hits on the second round.
//
//   make harness-test-asm ASM=tests/arm64/dispatch_lr_forms.s HOT_SVC_SYMBOL=blr_x30_mark
//
// Initial fixture state: x12 = FIXTURE_DATA_BASE, a 16 KiB RW window (all zero);
// every other register is 0.

.text
.global dispatch_lr_forms_entry
dispatch_lr_forms_entry:

// Called twice through `blr x30`, the second time from the callee's own table entry.
.global blr_x30_mark
blr_x30_mark:
    svc #0
    mov x20, x30
    movz x1, #0
    adr x30, lr_callee
    blr x30
    adr x30, lr_callee
    blr x30
    add x1, x1, #1000
    str x1, [x12, #0x70]
    mov x30, x20
    ret

lr_callee:
    add x1, x1, #1
    ret

// `bl` into a function that returns through x5 to a target which loops back to the
// call (twice): the `ret x5` is a dispatch site whose target register is x5, and
// the second round hits.
.global ret_x5_mark
ret_x5_mark:
    svc #0
    mov x20, x30
    movz x1, #0
    movz x6, #3
    adr x5, ret_x5_target
.Lret_x5_call:
    bl ret_x5_fn
    // Unreached: ret_x5_fn never returns to its caller.
    movz x1, #0xdead

ret_x5_fn:
    add x1, x1, #3
    ret x5

ret_x5_target:
    sub x6, x6, #1
    cbnz x6, .Lret_x5_call
    str x1, [x12, #0x78]
    mov x30, x20
    ret

// `br x30`, a return spelled as a jump.
.global br_x30_mark
br_x30_mark:
    svc #0
    mov x20, x30
    movz x1, #0
    bl br_x30_fn
    add x1, x1, #50
    mov x30, x20
    ret

br_x30_fn:
    add x1, x1, #7
    br x30
