// glibc syscall-wrapper fixture: the code right after the `svc` in glibc 2.36
// wrappers (INTERNAL_SYSCALL_ERROR_P and the syscall-template error branch).
// The error path negates the return value and stores errno into the TLS block
// at TPIDR_EL0 + 16, standing in for glibc's `:gottprel:errno` offset.
//
// Initial fixture state: x12 = data window base, TPIDR_EL0 = x12 + 0x3000.
// The mocked SVC leaves every register unchanged, so each error case loads the
// syscall's "return value" into x0 before a second svc.
//
//   make harness-test-asm ASM=tests/arm64/glibc_syscall_wrapper.s

.text
.global glibc_syscall_entry
glibc_syscall_entry:

// Success: x0 = 0 is outside [-4095, -1].
.global hot_svc_mark
hot_svc_mark:
    svc #0
    cmn x0, #1, lsl #12
    b.hi syscall_error
    movz x19, #0x2a
    mov w0, w19
    ret

// Error, `cmn x0, #1, lsl #12; b.hi`, at the boundary x0 = -4095.
.global glibc_error_boundary_mark
glibc_error_boundary_mark:
    svc #0
    movn x0, #4094
    svc #0
    cmn x0, #1, lsl #12
    b.hi syscall_error
    ret

// Error, syscall-template form `cmn x0, #4095; b.cs` with x0 = -EINTR.
.global glibc_error_eintr_mark
glibc_error_eintr_mark:
    svc #0
    movn x0, #3
    svc #0
    cmn x0, #4095
    b.cs syscall_error
    ret

// Not an error: x0 = -4096 is just below the errno range.
.global glibc_not_error_mark
glibc_not_error_mark:
    svc #0
    movn x0, #4095
    svc #0
    cmn x0, #4095
    b.cs syscall_error
    sxtw x1, w0
    cmp x1, x0
    cset w2, eq
    ret

syscall_error:
    neg w0, w0
    mrs x1, tpidr_el0
    str w0, [x1, #16]
    ldr w3, [x1, #16]
    movn x0, #0
    ret
