// Fixture for runtime-reserved user registers.
// This should fail until register virtualization preserves x9/x10/x11.

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
