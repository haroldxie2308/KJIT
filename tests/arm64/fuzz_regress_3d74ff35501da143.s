// Differential-fuzzer regression (roadmap V2), minimized and lifted.
// Failure: StateMismatch: original vs fragment state mismatch for `fuzz`
// Found by `make fuzz` (seed 0x1, program 11; the generator has
// changed since, so that seed no longer reproduces it).
// Runs from default_fixture_state(); the leading movz/movk/str/add/subs
// words materialize the minimized fuzz initial state.

// Regression (fixed): layout emitted blocks in CFG discovery order while
// lowering relied on physical fall-through. Here the loop's `cbnz` (0x10010)
// must fall through to the `ldp` at 0x10014, but the block at 0x10018
// (discovered first, as the `tbnz` target) was laid out right after the loop:
// the fragment skipped the `ldp`, ran `movz x0, #4` and exited at 0x1001c,
// while the original faults at 0x10014 (SP = 0 is unmapped) with x0 == 0.
// Now: blocks go out in address order (`cfg::layout_block_order`) and layout
// rejects a fall-through successor that is not laid out next.

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
