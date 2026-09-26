// Differential-fuzzer regression (roadmap V2), minimized and lifted.
// Failure: StateMismatch: original vs fragment state mismatch for `fuzz`
// Found by `make fuzz` (seed 0x1, program 85; the generator has
// changed since, so that seed no longer reproduces it).
// Runs from default_fixture_state(); the leading movz/movk/str/add/subs
// words materialize the minimized fuzz initial state.

// Regression (fixed): a block that ended because the next word was past the
// readable text got no successor and no exit, so the fragment ran off its end.
// Now it ends with an `Unsupported` exit at the first unreadable PC (x10 =
// `UNSUPPORTED_WORD_UNREADABLE`): userspace resumes there natively, and the
// original interpreter stops at the same PC through the same decision
// (`cfg::admit_at`).

.text
.global hot_svc_mark
hot_svc_mark:
    svc #0
    .inst 0xf2800040 // 0x10004: movk x0, #2
