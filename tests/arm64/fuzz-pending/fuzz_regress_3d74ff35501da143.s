// Differential-fuzzer regression (roadmap V2), minimized and lifted.
// Failure: StateMismatch: original vs fragment state mismatch for `fuzz`
// Found by: cargo run --release --manifest-path harness/Cargo.toml --bin fuzz -- \
//   --seed 0x1 --start 11 --iters 1 --max-len 64 --fault-per-mille 10
// Runs from default_fixture_state(); the leading movz/movk/str/add/subs
// words materialize the minimized fuzz initial state.

// Diagnosis (open translator bug, layout): blocks are emitted in CFG
// discovery order and a block that ends in a conditional branch relies on
// physically falling through to its not-taken successor. Here the loop's
// `cbnz` (0x10010) must fall through to the `ldp` at 0x10014, but the block at
// 0x10018 (discovered first, as the `tbnz` target) is laid out right after the
// loop. The original faults at 0x10014 (SP = 0 is unmapped) with x0 == 0; the
// fragment skips the `ldp`, runs `movz x0, #4` and exits Unsupported at 0x1001c.
// Fix direction: emit an explicit `b` to the fallthrough block when it is not
// the next laid-out block (or lay blocks out in address order).

.text
.global hot_svc_mark
hot_svc_mark:
    svc #0
    .inst 0xd280008a // 0x10004: movz x10, #4
    .inst 0xb700009c // 0x10008: tbnz r28, #32, 0x10018
    .inst 0xd100054a // 0x1000c: sub x10, x10, #1
    .inst 0xb5ffffca // 0x10010: cbnz x10, 0x10008
    .inst 0xa8c003ef // 0x10014: ldp x15, x0, [sp], #0
    .inst 0xd2800080 // 0x10018: movz x0, #4
    .inst 0x6620197b // 0x1001c: (not in the supported subset)
