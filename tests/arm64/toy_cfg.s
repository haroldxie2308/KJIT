// Toy AArch64 control-flow fixture for the shared CFG builder.
// Base PC used by the demo script: 0x4000

.text
.global toy_cfg_demo
toy_cfg_demo:
    movz x0, #1
    cbnz x0, .Lhot
    movz x1, #0x1111
    b .Ljoin

.Lhot:
    movz x1, #0x2222
    tbz x1, #1, .Lcold
    movz x2, #0x3333
    b .Ljoin

.Lcold:
    movz x2, #0x4444

.Ljoin:
    str x1, [x10, #16]
    ldr x3, [x10, #16]
    b .Lexit

.Lexit:
    nop
