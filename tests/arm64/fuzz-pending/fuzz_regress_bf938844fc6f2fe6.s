// Differential-fuzzer regression (roadmap V2), minimized and lifted.
// Failure: Native: x9: interp-original=0xf8b26c02 native-original=0x1705
// Found by: cargo run --release --manifest-path harness/Cargo.toml --bin fuzz -- \
//   --seed 0x7 --start 25 --iters 1 --max-len 64 --fault-per-mille 10 --no-fall-off
// Runs from default_fixture_state(); the leading movz/movk/str/add/subs
// words materialize the minimized fuzz initial state.

// Diagnosis (open, native only: `make harness-test-native` semantics): Linux
// runs EL0 with SP alignment checking (SCTLR_EL1.SA0), so a load/store whose
// base is SP faults (SIGBUS) when SP is not 16-byte aligned. After the
// pre-index writeback SP = 0x2000c and the `ldr x0, [sp], #0` at 0x10010 faults
// on hardware. The interpreter does not model the check, so interpreter
// original and interpreter fragment agree (x0 = 0, `br x0`), and the translated
// code cannot reproduce it either: user SP lives in x17, where no alignment
// check applies, so KJIT would run code that natively faults.
// The interpreter suite passes this case; the native suite fails it.

.text
.global hot_svc_mark
hot_svc_mark:
    svc #0
    .inst 0xf2a00040 // 0x10004: movk x0, #2, lsl #16
    .inst 0x9100001f // 0x10008: add sp, x0, #0
    .inst 0xb840cfe0 // 0x1000c: ldr w0, [sp, #0xc]!
    .inst 0xf84007e0 // 0x10010: ldr x0, [sp], #0
    .inst 0xd61f0000 // 0x10014: br x0
