// Differential-fuzzer regression (roadmap V2), minimized and lifted.
// Failure: StateMismatch: original vs fragment state mismatch for `fuzz`
// Found by: cargo run --release --manifest-path harness/Cargo.toml --bin fuzz -- \
//   --seed 0x1 --start 85 --iters 1 --max-len 64 --fault-per-mille 10
// Runs from default_fixture_state(); the leading movz/movk/str/add/subs
// words materialize the minimized fuzz initial state.

// Diagnosis (open translator bug, CFG/layout): a block that ends because the
// next word is past the readable text (`CodeRead` after at least one insn)
// gets no successor and no exit, so the fragment executes past its last
// instruction (here: off the end of the fragment; in general into whatever
// block is laid out next). In the kernel that runs arbitrary bytes. The
// runtime reports FellOffFragment with stale pt_regs, so x0 == 0 instead of 2.
// Fix direction: end such a block with a runtime exit that resumes userspace
// at the first unreadable PC (like the Unsupported exit).

.text
.global hot_svc_mark
hot_svc_mark:
    svc #0
    .inst 0xf2800040 // 0x10004: movk x0, #2
