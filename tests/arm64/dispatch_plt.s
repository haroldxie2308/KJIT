// A11 dispatch fixture: PLT-shaped indirect calls. A PLT stub is `adrp x16, GOT;
// ldr x17, [x16, #slot]; br x17`: the call lands on the stub (a direct `bl`), the
// stub loads the callee's address from the GOT in user memory and `br`s to it, and
// the callee returns to the stub's caller. The `br`'s target register is the
// stack-backed x17 (or x16), so the dispatch site's target move fills it from its
// frame slot.
//
// The GOT lives in the data window, filled by the case (`adr; str`). The stubs sit
// in the text page at 0x10000, where `adrp x16, 0x10000` (assembled as an absolute
// +16 pages: the PC-relative immediate of an object at address 0) reaches the data
// window at 0x20000. Keep the text under one page.
//
//   make harness-test-asm ASM=tests/arm64/dispatch_plt.s HOT_SVC_SYMBOL=plt_call_mark
//
// Initial fixture state: x12 = FIXTURE_DATA_BASE, a 16 KiB RW window (all zero);
// every other register is 0.

.text
.global dispatch_plt_entry
dispatch_plt_entry:

// Two calls through one stub: the first resolves plt_func (a miss), the second hits.
.global plt_call_mark
plt_call_mark:
    svc #0
    mov x20, x30
    adr x0, plt_func
    str x0, [x12, #0x40]
    movz x1, #0
    bl plt_stub
    bl plt_stub
    str x1, [x12, #0x50]
    mov x30, x20
    ret

// Two stubs, one through x17 and one through x16, two callees, each called twice.
.global plt_two_stubs_mark
plt_two_stubs_mark:
    svc #0
    mov x20, x30
    adr x0, plt_func
    str x0, [x12, #0x40]
    adr x0, plt_func2
    str x0, [x12, #0x48]
    movz x1, #0
    bl plt_stub
    bl plt_stub16
    bl plt_stub
    bl plt_stub16
    str x1, [x12, #0x50]
    mov x30, x20
    ret

.balign 16
plt_stub:
    adrp x16, 0x10000
    ldr x17, [x16, #0x40]
    br x17

.balign 16
plt_stub16:
    adrp x17, 0x10000
    ldr x16, [x17, #0x48]
    br x16

plt_func:
    add x1, x1, #5
    ret

plt_func2:
    add x1, x1, #9
    ret
