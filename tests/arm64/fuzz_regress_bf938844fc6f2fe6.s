// Differential-fuzzer regression (roadmap V2), minimized and lifted.
// Failure: Native: x9: interp-original=0xf8b26c02 native-original=0x1705
// Found by `make fuzz` (seed 0x7, program 25; the generator has
// changed since, so that seed no longer reproduces it).
// Runs from default_fixture_state(); the leading movz/movk/str/add/subs
// words materialize the minimized fuzz initial state.

// Regression (fixed): Linux runs EL0 with SP alignment checking
// (SCTLR_EL1.SA0), so a load/store based on SP faults (SIGBUS) when SP is not
// 16-byte aligned. After the pre-index writeback SP = 0x2000c and the
// `ldr x0, [sp], #0` at 0x10010 faults on hardware; the translated code (user
// SP in x17) did not. Now reg-virt checks SP before every SP-based user access
// (`and xS, x17, #15; cbnz xS, <Mem stub>`) and the interpreter models the
// fault, so all three sides stop at 0x10010.

.text
.global hot_svc_mark
hot_svc_mark:
    svc #0
    .inst 0xf2a00040 // 0x10004: movk x0, #2, lsl #16
    .inst 0x9100001f // 0x10008: add sp, x0, #0
    .inst 0xb840cfe0 // 0x1000c: ldr w0, [sp, #0xc]!
    .inst 0xf84007e0 // 0x10010: ldr x0, [sp], #0
    .inst 0xd61f0000 // 0x10014: br x0
