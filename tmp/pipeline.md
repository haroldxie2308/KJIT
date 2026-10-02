# KJIT Explorer Milestones

## Goal
Replace the old harness TUI with an OpenTUI-backed explorer while keeping the
translation/runtime harness untouched.

## Milestones

1. Load the OpenTUI native library from a local checkout or explicit env var.
2. Keep the existing explorer state machine and trace inspection logic shared.
3. Render the explorer with OpenTUI as the only interactive backend.
4. Preserve stepping, command input, export, and fixture checking.
5. Verify the interactive TUI and the noninteractive `--dump --check` path.

## Current status

- OpenTUI backend is wired into `trace-tui`.
- `scripts/run-trace-tui.sh` defaults to OpenTUI and auto-detects a nearby
  OpenTUI checkout if present.
- Mouse wheel scrolling now follows the pane under the pointer, and mouse drag
  selection copies the selected rows to the system clipboard plus
  `tmp/trace-copy.txt`.
- Fixture validation still passes with `scripts/run-asm-fixture.sh`.

# Translator contracts (2026-09-27)

## Unsupported-instruction exit

- An undecodable word no longer fails translation. `build_cfg` ends the block
  before it and records `BasicBlock.unsupported_exit = Some(UnsupportedExit::Insn(..))`.
  Invariant: `pc == end_addr`, `next` is empty, `insns` may be empty (entry
  itself undecodable).
- A PC past the readable text is the same exit: `UnsupportedExit::Unreadable { pc }`
  (V2 fuzzer finding: before, a block that ran into the end of the text got no
  successor and no exit, so the fragment ran off its end). No word exists, so
  `x10` carries the sentinel `UNSUPPORTED_WORD_UNREADABLE = u64::MAX`; a real
  word is always <= `u32::MAX`. Userspace resumes at that PC and fetches (or
  faults) natively, which is exact. This covers falling through the last word
  and a branch or conditional fall-through to a PC past the text (an empty
  block holding only the exit). An unreadable **entry** stays a hard
  `CfgError::CodeRead`: there is no code to translate.
- `cfg::admit_at(code, pc)` is the single decision per PC: read the word, then
  `admit_word`; a read that fails is `Unreadable`.
- The same exit covers a word that decodes but that reg-virt rejects for an
  instruction-intrinsic reason (e.g. `UnpredictableMemoryOp` for
  `ldr x1, [x1], #8`). `cfg::admit_word` is the single decision point: decode,
  then `reg_virt::admit_insn`, which runs `RewritePlan::build` (the check
  `rewrite_user_semantic` runs) over every user-semantic instruction rephrase
  lowers the word into. `RegVirtError::is_instruction_intrinsic` (exhaustive)
  splits the result: intrinsic -> exit; translator-internal -> hard
  `CfgError::RegVirt`. Runtime-exit payloads are not admitted: their only
  user-chosen register is the param0 capture, which accepts every register
  class, so they cannot reject intrinsically.
- Invariant this rests on: reg-virt rewrites each original instruction
  independently of its neighbours. A context-sensitive allocator would have to
  move admission to block level.
- The harness original-code interpreters call `admit_at` (the raw trace view
  `admit_word`), so they stop exactly where the translated code exits, running
  off the end of the text included. There is no separate "fell off the end"
  halt any more.
- Rephrase stays the only producer of the exit; reg-virt never synthesizes it.
- Rephrase lowers it to an exit group: `x9 = RetStatus::Unsupported (6)`,
  `x10 = raw word` (or `UNSUPPORTED_WORD_UNREADABLE`), `x11 = pc`. The runtime always resumes userspace at `x11`
  and never re-enters the fragment at that PC for this status.
- Why it's exact: userspace executes the instruction natively, including taking
  SIGILL itself for a truly undefined word.
- `x10` carrying the word is what the coverage histogram will be built from.
  It is the exact word in both cases; decoding it tells an undecodable word
  from a reg-virt rejection.

## Pair and writeback memory forms in reg-virt

- LDP/STP (64-bit off/pre/post) and LDR/STR imm pre/post (32/64) go through the
  normal per-instruction fill → rewrite → spill plan. A writeback base is
  read-write.
- Constrained-unpredictable encodings (writeback base == transfer register with
  a non-SP base; LDP rt == rt2) are rejected with `UnpredictableMemoryOp`, never
  translated; admission turns that into the Unsupported exit.

## ABI: fragment entry

- The runtime always calls a fragment at its base (the prologue) with
  `x0 = pt_regs`, `x1 = extra params`, `x2 = ABI_ENTRY_ARG_REG` = fragment base
  + an entry offset taken from `ExecutionFragment` (`entry_offset` for the first
  entry, `offset_for_pc(resume_pc)` when continuing after a runtime exit).
- The prologue stores `x2` in frame slot `RUNTIME_FRAME_ENTRY_ADDR_OFFSET` (80)
  before its `pt_regs` loads overwrite it, and ends with
  `ldr x12, [sp, #80]; br x12`. x12 is reg-virt scratch, dead at body entry;
  user x12 is already in its frame slot.
- Invariant: that `br x12` is the only indirect branch in a fragment, and its
  target is never user-controlled — the runtime (harness now, kernel later)
  only passes known entry offsets. V3 checks exactly this.
- Replaces the old resolved `b entry_offset` plus the harness-only redirect of
  that branch on re-entry, which had no native equivalent.

## Native hardware oracle (V1)

- Linux arm64 only (`harness/src/native.rs`, `make harness-test-native`). Three
  states per fixture case must agree: interpreter original, native original,
  native fragment.
- Fixture addresses: text base `0x10000` (compile script default), data window
  `FIXTURE_DATA_BASE = 0x20000`, `FIXTURE_DATA_LEN = 0x4000` (x12), which is the
  whole default user page map (read-write). Fixtures derive every data address
  from x12.
- User memory: the native runs map every page of the interpreter's user page
  map at the same address with the same permission (read-only -> `PROT_READ`),
  and compare every byte of those pages. Initial memory outside them fails.
  The text's pages (see "Harness memory model", text) are mapped that way for
  the native fragment; the native original's own text mapping
  (`PROT_READ | PROT_EXEC`, stop points patched) takes their place.
- Native-unobservable: the interpreter's original read of a text word the
  native original patches (a stop point, the instance cap, or the `BRK_FILL`
  past the text in its mapping) cannot be reproduced on hardware, which reads
  the trap word. Decided from the interpreter's access log
  (`original_reads_patched_text`: any user read overlapping such a word's 4
  bytes). Then only the native fragment is compared; the fuzzer counts the
  program as `native-unobservable`, never as a pass, and a fixture case says so
  in its summary line. Undecodable literal-pool words are patched too, so a
  fixture that wants its text pool observed natively uses pool words that
  decode as admitted non-exit instructions (`mem_literal.s`).
- Native original: stop points come from the interpreter's own halting rule
  (`admit_word`) applied to every text word (SVC -> mock trap; rejected word or
  non-SVC runtime exit -> stop trap; a word past the text -> the `Unreadable`
  Unsupported stop). A
  data abort stops too and must match the interpreter's `Fault` halt (same pc,
  fault address inside the access). A branch exit is then executed by the
  hardware alone, in a text copy where every other word traps, so BL/BLR link
  writes and branch targets come from the CPU, not the model.
- Native fragment: called at its base per "ABI: fragment entry", driven by the
  same `decide_runtime_return` as `URuntime`; the call also checks x18..x29 and
  sp survive (C ABI).
- Counter reads (A10): both native legs replace every `mrs Xt, cntvct_el0` /
  `mrs Xt, cntfrq_el0` (original text and fragment copy) with
  `brk #(0x4c00 | kind << 5 | Rt)`, which the signal handler emulates in place
  (Xt = the `MachineState` value, pc + 4). See "A10", counter modelling.
- No watchdog: a native run that never reaches a stop point hangs the test.

# P1 contracts: memory sandbox, fault exits, execution budget (2026-09-27)

Written before implementation (tasks A4, A5, A6). Code must match this; a change
to it is a design change and gets recorded here first.

## Privilege model

- Every memory access in a fragment is either a **user access** or a **runtime
  access**, decided by the emitted instruction, never by the address:
  - user access = LDTR/STTR family: `LDTR.LDTR_32_ldst_unpriv`,
    `LDTR.LDTR_64_ldst_unpriv`, `LDTRB.LDTRB_32_ldst_unpriv`,
    `LDTRH.LDTRH_32_ldst_unpriv`, `LDTRSB.LDTRSB_32_ldst_unpriv`,
    `LDTRSB.LDTRSB_64_ldst_unpriv`, `LDTRSH.LDTRSH_32_ldst_unpriv`,
    `LDTRSH.LDTRSH_64_ldst_unpriv`, `LDTRSW.LDTRSW_64_ldst_unpriv`,
    `STTR.STTR_32_ldst_unpriv`, `STTR.STTR_64_ldst_unpriv`,
    `STTRB.STTRB_32_ldst_unpriv`, `STTRH.STTRH_32_ldst_unpriv` (13 forms;
    `A64Insn::is_unprivileged_access`, pinned by a test against the generated
    `LDTR*`/`STTR*` mnemonics). These are the only instructions that touch user
    memory. EL0 permissions apply in hardware. Reg-virt emits them with an
    unscaled `simm9` offset only, and never admits one from user code.
  - runtime access = any other load/store. Allowed only on the runtime frame
    (kernel stack, `sp`-based) and the `pt_regs` / extra-params blocks.
- Kernel assumptions this relies on (pinned in K1): hardware PAN on,
  `PSTATE.UAO == 0` while a fragment runs (otherwise `LDTR` at EL1 is a
  privileged access), `ARM64_SW_TTBR0_PAN` off.

## Harness memory model (A4)

- User memory is 4 KiB pages with an EL0 permission each: unmapped, read-only,
  read-write. The runtime-owned ranges (runtime stack, `pt_regs`, extra params)
  are never user-accessible.
- A user access that violates permissions is a **fault**. A runtime access that
  lands outside the runtime-owned ranges is a **PAN violation**: a hard harness
  error, because in the kernel it is an oops.
- The interpreter checks every access of an instruction before it mutates any
  register or byte. A faulting instruction leaves the state bit-identical and
  halts with the fault (pc, address, read/write).
- Fault injection: fail the k-th dynamic user access of a run regardless of
  permissions.
- Fragment accesses are classified by instruction (A5): `LDTR`/`STTR` are user
  accesses (page permissions, fault injection counts only them); every other
  load/store is a runtime access and must lie in the runtime-owned ranges. The
  A4 address-based rule is gone.
- Text (V2 native fuzz finding): the text is a user page, read-only (and
  executable; execute permission is not modelled), holding the text bytes, as
  a process maps it: literal pools in the text load as data, a store faults.
  `with_text_mapped` adds it; `fixture_state(text_base, text)` is
  `default_fixture_state()` plus the text, and every fixture path and the
  fuzzer run from it, so the original and the fragment see the same map.
- Top-byte-ignore (V2 native fuzz finding): Linux sets `TCR_EL1.TBI0`, so bits
  63:56 of a data address with bit 55 clear take no part in translation (bit 55
  set is the kernel half and faults at EL0). A tagged pointer into a mapped page
  works natively. The interpreter applies Linux's `untagged_addr`
  (`addr & sign_extend64(addr, 55)`) to every access address (original code and
  a fragment's LDTR/STTR alike: both translate through the EL0 regime); a base
  writeback keeps the tag. Fault addresses are reported the same way.

## Memory rewrite (A5)

- Reg-virt lowers every user load/store to the LDTR/STTR family (see
  "Privilege model"), using the same per-instruction scratch pool it already
  owns (x12–x15). No second scratch allocator.
- Addressing: `LDTR`/`STTR` take only an unscaled `simm9`. Offsets outside it
  are materialized with `ADD`/`SUB` (imm, optionally `lsl #12`) into scratch.
  Pre/post-index writeback is a separate `ADD`/`SUB` of the base after the
  accesses. `LDP`/`STP` become two accesses.
- **Commit-after-last-access invariant.** Within one original instruction, no
  user-visible location (a direct user register, a stack-backed frame slot,
  the stable x29/sp mappings in x16/x17) is written before the instruction's
  last faulting access. Every access but the last loads into scratch; the last
  may target its final register; register moves, writeback and spills follow.
  So at every fault point the user state equals the state before the original
  instruction.
- If the instruction can't be lowered within the scratch pool, it is an
  intrinsic reg-virt rejection → `Unsupported` exit at that PC (A1 path).
- **SP alignment check** (V2 fuzzer finding). Linux runs EL0 with SP alignment
  checking (`SCTLR_EL1.SA0`): a load/store whose base is SP faults (SIGBUS)
  when SP is not 16-byte aligned. User SP lives in x17 in a fragment, which is
  never checked, so without a check KJIT would run code that natively faults.
  For every user access whose base is SP (immediate and register-offset forms)
  reg-virt emits, before anything else of the instruction,
  `and xS, x17, #15; cbnz xS, <Mem stub of that instruction>` (kind
  `AlignCheck`, shared with the A7c acquire/release alignment check; layout
  resolves the `CBNZ` like a budget check's `CBZ`).
  Flags are untouched. `xS` comes from the same scratch pool (so admission
  accounts for it); it shares the address or pair first-load scratch when the
  instruction has one, both being written only after the check. The `Mem` exit
  returns to userspace at the instruction, which re-executes natively and takes
  the SIGBUS itself: exact. The `CBNZ` is a forward branch into the cold region,
  to an exit-group start (verifier rule 4). The harness interpreter models the
  fault (`FaultCause::SpAlignment`, precise, before any access); the native
  runner matches it at the SP value Linux reports (`el0_sp`).

Implementation decisions (A5):

- `RewritePlan::build` is the single decision for admission and rewriting: it
  now also plans the lowering (`MemLowering`) and allocates all scratch through
  one counter — stack-backed mappings first (operand-role order), then the
  address scratch, then the pair first-load scratch — so admission sees exactly
  the capacity the rewrite uses. Worst case is 4 (`ldp x12, x13, [x14, #496]`:
  base, two targets, address), so `ScratchPoolExhausted` (renamed from
  `TooManyStackBackedRegs`) is unreachable for the current memory forms.
- A pair's first load targets its final register directly only when that is
  XZR or a stack-backed register's scratch that is not the access base;
  otherwise it loads into scratch and a `MOV` follows the second access.
- A writeback of `#0` emits nothing. Offsets beyond 24 bits would be
  `UnencodableMemOffset` (intrinsic); none of the current forms reach it.
- User code containing `LDTR`/`STTR` is rejected by `build` as
  `UnprivilegedUserAccess` (intrinsic → `Unsupported` exit): at EL0 they are
  plain loads/stores, but a fragment runs them at EL1 as its user-access
  instruction. A form whose generated metadata has a `Memory` role but no
  lowering is `UnloweredMemoryForm`, a hard translator error.
- specgen gives `LDTR`/`STTR` the `LDR`/`STR` role inference (Rt written for
  `LDTR`, `A64Mem` offset operand with an unscaled `simm9`).

## Fault sites (A5)

- Each emitted user access is a fault site. `ExecutionFragment` carries a
  table sorted by fragment offset: `(access_offset, stub_offset, ori_pc)`.
- The stub is an ordinary runtime-exit group for `RetStatus::Mem` at
  `ori_pc` (x10 = the original instruction word, x11 = `ori_pc`), virtualized
  by reg-virt like every other exit group, and placed out of line in a cold
  region after the body so nothing falls through into it. One stub per
  original memory instruction; its accesses share it.
- Stub labels are their own label kind. `vlabels` stay the body-entry map
  keyed by original PC.
- Representation: rephrase puts each stub in `RephrasedBlock.cold` (exit groups
  only; reg-virt rejects anything else there). Layout order is prologue,
  epilogue, every block body, then every block's `cold` in block order. Each
  emitted access carries `RephrasedInsnKind::UserAccess`; its stub is named by
  its `ori_pc`, which is unique per original instruction because CFG blocks
  partition the PC space, so no extra field is needed. Layout fails
  (`UntaggedUserAccess`) if the kind and the `LDTR`/`STTR` form ever disagree,
  and (`MissingFaultStub`) if a user access has no stub.
- The kernel's fault fixup (K2) only sets the faulting PC to the stub offset.
  The harness does the same: a user-access fault at a fragment offset jumps to
  the table's stub, and an offset without an entry is a hard error.
- On `Mem` the runtime returns to userspace at x11. Userspace re-executes the
  instruction natively and takes the fault itself, so signals and SIGSEGV
  behave exactly as they do without KJIT. In the harness this is
  `decide_runtime_return` (`URuntimeHalt::ReturnedToUserspace { Mem, x11 }`),
  shared with the native runner.
- The native runner does the same fixup on real hardware: its SIGSEGV/SIGBUS
  handler looks the faulting PC up in the fragment's fault sites, sets the
  ucontext PC to the stub and resumes the fragment; a data abort in the
  fragment without an entry stays a hard failure. `default_fixture_state` maps
  one read-only page after the data window (x12 + 0x4000; x12 + 0x5000 is
  unmapped), and `tests/arm64/mem_faults.s` faults on its own (store to the
  read-only page, pre-index load and split LDP into the unmapped page), so the
  Mem exit is checked interpreter, native original and native fragment.
- Acceptance check (`check_fragment_fault_injection`, every fixture case):
  fragment user accesses are matched to original accesses by (PC, dynamic
  instance, sub-access) and must have equal address/size/kind; for every
  original access k the matching fragment access is failed and the fragment
  must exit `Mem` at the original PC with the pre-instruction user state, store
  units of that instruction excepted. A case whose original run faults on its
  own counts only the accesses before that instruction; the fragment's extra
  accesses must all belong to it.
- Store footprint: when a split `STP` faults on its second access, the first
  8 bytes may already be written. Architecturally that's allowed, and it is
  invisible to a single thread because userspace re-executes the whole `STP`.
  The differential check allows exactly those bytes to be either old or new.

## Execution budget (A6)

- A back-edge is any branch whose target is at or before it in the final
  layout order. Layout order is a block order (`cfg::layout_block_order`), so
  this is known before offsets and can be checked on the final bytes without a
  CFG.
- The prologue stores `KJIT_BACKEDGE_BUDGET` (an ABI constant) in a runtime
  frame slot. Before each back-edge's lowered sequence the fragment runs:
  load slot → `SUB #1` → store slot → `CBZ` to a budget stub. The sequence
  uses scratch, which is dead at an instruction boundary, and must not touch
  NZCV (hence `SUB` + `CBZ`, not `SUBS`).
- The budget stub is an out-of-line exit group like the fault stub, with a
  new status `RetStatus::Budget` and x11 = the PC of the branch instruction.
  Userspace resumes natively at the branch.
- Verifier rule (V3): every backward in-fragment branch is immediately
  preceded by exactly this sequence.

Implementation decisions (A6):

- Status: `RetStatus::Budget = 7`, x10 = the branch's raw word, x11 = its PC.
  `decide_runtime_return` stops with `ReturnedToUserspace { Budget, x11 }`, like
  `Unsupported`/`Mem` (URuntime and the native runner share it).
- ABI (`shared/abi/frame.rs`): `KJIT_BACKEDGE_BUDGET = 4096` (why: one entry runs
  at most 4096 x the longest acyclic path before the runtime re-checks signals
  and `need_resched`; loops under 4096 iterations never pay a round trip).
  Frame grows 192 -> 208 bytes: `RUNTIME_FRAME_BUDGET_OFFSET = 192` (8-byte
  counter), 200..208 padding for 16-byte alignment; every other slot is
  unchanged. The prologue's tail is now
  `movz x12, #4096; str x12, [sp, #192]; ldr x12, [sp, #80]; br x12`
  (prologue 0x98 -> 0xa0 bytes, so `EPILOGUE_OFFSET` = 0xa0).
- Layout order has one definition, `cfg::layout_block_order`: ascending block
  start address (blocks partition the PC space, so a fall-through successor is
  the next block). Rephrase (back-edges), layout (bodies, then cold regions) and
  the harness trace all iterate blocks through it. The program vector itself
  keeps CFG order, so `program[0]` stays the entry block. (Before A6 layout
  emitted CFG discovery order, which broke physical fall-through -- found by
  the V2 fuzzer.) Layout checks the invariant it relies on: a block with a
  successor at its own end (`next` contains `end_addr`) must be followed by that
  block in layout order, else `LayoutError::FallthroughNotAdjacent`. Lowering
  never adds explicit fall-through branches (they would be extra back-edge
  candidates for the budget).
- Pass placement: **rephrase**. It already owns semantic exits and the cold
  stubs (A5), sees the whole CFG, and runs before reg-virt, so the Budget stub
  is virtualized like every other exit group and reg-virt never learns about
  branches or budgets. Back-edge test: visiting blocks in layout order, a
  lowered original instruction contains a user-semantic
  B/B.cond/CBZ/CBNZ/TBZ/TBNZ whose target PC is already placed (every PC
  emitted so far in layout order, the instruction's own included) -- exactly
  "the target's vlabel is at or before the branch". Forward branches into the
  cold region (fault/alignment guards, budget `CBZ`) are not user branches and
  never back-edges. BL is never user-semantic after rephrase. A branch inside a
  UserSynthetic sequence counts; the check then precedes the whole lowered
  sequence of its original instruction (none exist today). Layout only resolves
  the `CBZ` immediate to the stub label, so branch-immediate rewriting stays in
  layout.
- Layout self-check: a user branch that resolves to `target_offset <= offset`
  without a budget check earlier in its original instruction's run of
  instructions fails with `LayoutError::UnguardedBackEdge`; a check whose PC has
  no stub fails with `MissingBudgetStub`. Budget and Mem stubs share the stub
  label map (one stub per original PC: a branch never accesses memory;
  `DuplicateFaultStub` still catches two).
- Kind: `RephrasedInsnKind::BudgetCheck` on all four instructions (not
  user-semantic, not a runtime exit). Reg-virt passes it through unchanged; in
  the cold region or inside an exit group it is `MalformedRuntimeExitGroup`.
- Exact emitted sequence (encodings independent of the PC, except the CBZ
  offset), with nothing between it and the branch except that branch's own
  reg-virt fills (`ldr x12..x15, [sp, #16..#56]`, at most one for today's
  branch forms):

  ```text
  f94063ec  ldr x12, [sp, #192]
  d100058c  sub x12, x12, #1
  f90063ec  str x12, [sp, #192]
  b4xxxxxc  cbz x12, <Budget stub of this PC>     // imm19 -> cold region
            [fills of the branch's stack-backed register]
            <the back-edge branch>
  ```

  So V3's rule is: every in-fragment branch with a non-positive displacement is
  preceded by these four words, then only sp-relative `LDR (imm, 64)` fills of
  the stack-backed slots, then the branch; the CBZ targets a cold-region group
  that sets x9 = 7 and ends in `b` to the epilogue.
- Budget stub: `push_native_resume_exit(Budget, pc, word)` in the block's
  `cold`, in instruction order -- the same 13-instruction group as a Mem stub
  (after reg-virt: x9..x11 preserved to pt_regs first).
- Count semantics: the prologue stores N; each back-edge execution (taken or
  not) decrements first and exits at zero, so executions 1..N-1 of one entry
  run and the N-th exits before the branch. Any fragment entry (SVC resume,
  chaining) restarts at N.
- Harness differential: the fragment runs first
  (`run_fragment_counting_instances`); on a `Budget` exit at pc P the dynamic
  instance k is the number of executions of P's body label (every entry,
  branch and fall-through into P lands there, and for a back-edge it is the
  check's first instruction). The original runs with `InstanceCap { P, k }`
  and halts with `HaltReason::InstanceCap` before executing P for the k-th
  time; `runtime_halt_matches_original` pairs it with `Budget` at P. The cap
  is derived from the fragment, so the differential proves precision, not the
  count; the count is pinned by the harness runtime unit tests (exit on
  exactly the N-th execution, N-1 completes, re-entry restarts).
- Native original: the capped branch word becomes a trap; each earlier arrival
  lets the hardware execute the branch once (in place with every other word
  trapping; a self-branch runs from a scratch page with displacement +8 so the
  hardware only picks taken/not-taken), then the trap is reinstalled.

## Validation order

- V3 (the independent verifier) checks rules that only exist after A5 and A6
  land (user memory only via LDTR/STTR, fault table coverage, the budget
  sequence). It is written against this section and enforces all of them
  (see "Verifier (V3)").

# Verifier (V3) (2026-09-27)

`shared/verify/` is the security boundary: the kernel installs only fragments it
accepts. It is written against this file and `shared::abi`, not the translator.

## Independence

- Imports only `shared::{abi, arm64, platform}`; the unit test
  `verifier_does_not_import_the_translator` scans the module sources and fails on
  any other `crate::shared::` path or on `trans::`/`emit::`.
- It does not reuse translator-side helpers that live in `shared::arm64`
  (`is_unprivileged_access`, `accesses_memory`, `runtime_exit_reason`): its own
  exhaustive match over the generated forms (`rules::classify`) decides what each
  word is, so a new form fails to compile until the verifier classifies it. A
  random-word test cross-checks that classification against the generated
  operand roles.
- Transitive coupling left in place: `shared::arm64` itself imports
  `trans::cfg::RuntimeExitReason` for `runtime_exit_reason`. The verifier never
  calls it.

## Input

`VerifyInput { code: &[u8], fault_sites: &[FaultSiteEntry { access_offset,
stub_offset }], entry_offsets: &[usize] }`, all offsets relative to the fragment
base. `ori_pc` is not part of the input: the stub loads its own resume PC, so the
table's PC column is not safety-relevant. The harness builds the input from
`ExecutionFragment` (`FragmentTables::of`): the entry table is `entry_offset`
plus every `vlabels` offset, because any of them can be the runtime's entry
address.

## Rules (reject with `VerifyError { offset, rule }`)

1. Every body word decodes through the generated decoder and
   `is_decode_undefined` is false.
2. Words `0..PROLOGUE_LEN` and `EPILOGUE_OFFSET..BODY_OFFSET` equal the encoded
   `KJIT_PROLOGUE`/`KJIT_EPILOGUE`. The body never writes SP (a destination in its
   SP meaning, or base writeback) and never writes x29.
   - Decision: x18..x28 and x30 hold user values in the body and the body may
     write them freely. The kernel's callee-saved state is safe because the
     epilogue is byte-exact and reloads it from frame slots the body cannot
     write (rule 3), and SP (which locates the frame) is never written.
   - x29 is protected because the prologue points it at the runtime frame and
     reg-virt keeps user x29 in x16, so an unwinder interrupting a fragment still
     follows a valid frame record.
3. Memory. Every load/store is one of:
   - a user access: the LDTR/STTR family (the single list in `rules::classify`,
     all 13 forms of "Privilege model", byte/half/signed included; the rule is
     the same for every size). It has a fault-site entry at its offset and its
     base is not SP. The table is strictly increasing and every entry is on a
     user access.
   - never a user-code memory form of the subset (A7b: byte/half/signed
     immediate, unscaled, register offset, literal, 32-bit pairs, LDPSW, PRFM;
     A7c: LDAR*, STLR*, LDAPR*): translation only lowers them, so one in a
     fragment is `UserOnlyForm`, even on runtime memory and even with a
     fault-site entry (`FaultSiteNotUserAccess`). PRFM is emitted as `NOP`. An
     acquire/release form at EL1 would be a privileged access to user memory.
     BTI (A7d) is in the same class: rephrase emits it as `NOP`, so one in a
     fragment is `UserOnlyForm` too.
   - a runtime access, offset addressing only (no writeback), either
     - SP-based inside the user-state frame slots `[16, 80)` (stack-backed
       x12..x17, user x29, user sp), or the single kernel-slot read
       `ldr xS, [sp, #176]` (pt_regs pointer, 64-bit, S a reg-virt scratch
       register x12..x15; rule 9). Every other frame slot (caller
       x29/x30, entry address, caller x18..x28, the pt_regs / extra-params
       pointers, the 200..208 padding) and anything outside the 208-byte frame
       is rejected: a body write there is a kernel write primitive through the
       epilogue. The budget counter (192) is rule 6's.
     - based on a register proven to hold the pt_regs pointer, inside
       `regs[0..31]` + `sp` (`[0, 256)`); `pc`, `pstate` and beyond are never
       accessible. Proof is the rule 9 dataflow's pt_regs fact: the register
       was loaded by `ldr xS, [sp, #176]` and not written since, with no join
       point in between.
   - Everything else is rejected: exclusives, PRFUM/RPRFM, DC/IC/AT are
     outside the decoded subset (rule 1); LSE atomics (A8) and SIMD&FP
     loads/stores (A9a) are valid only as a PAN window's access (rule 8), every
     SIMD&FP load/store encoding but the base-only ones is `UserOnlyForm`; pair
     or pre/post forms not matching the above fail the base/range/writeback
     checks.
4. Control flow.
   - Direct branches (B, B.cond, CBZ/CBNZ, TBZ/TBNZ) target the epilogue's
     first word or a body word; never the prologue, the rest of the epilogue,
     or outside the fragment. A target in the cold region must be an exit-group
     start.
   - BL, BR, BLR, RET are rejected in the body; the prologue's `br x12` and the
     epilogue's `ret` are covered by the byte-exact check.
   - The last word is an unconditional `B` (nothing falls off the end).
   - Entry offsets: non-empty, aligned, in the body and before the cold region.
5. System: only `MRS Xt, TPIDR_EL0`, and (A10) `MRS Xt, CNTVCT_EL0` and
   `MRS Xt, CNTFRQ_EL0` (the only MRS encodings the generated subset decodes:
   one generated form each, `Form::MrsUserReg`; every other value of
   o0:op1:CRn:CRm:op2 is rule 1's, pinned exhaustively by
   `mrs_is_allowed_for_exactly_the_user_readable_registers`),
   NOP, and (A7c) `DMB`/`DSB`/`ISB` with any CRm (`DSB` without nXS;
   `Form::Barrier`): allowed anywhere, exit groups included. SVC and ADR/ADRP (a
   kernel address into a user register) are rejected; BTI decodes but is
   `UserOnlyForm` (rule 3); MSR, HVC, SMC, BRK, HLT, ERET, SB, CLREX, DSB nXS,
   WFE/WFI, PAC and every other hint, and cache/TLB maintenance do not decode. A barrier cannot confuse rules 6/7: it is not a fill (so one
   between a budget `cbz` and its back-edge is rejected) and not a branch, user
   access or runtime access.
6. Budget (A6): every back-edge (a direct branch to a body word at or before
   itself; offset order is layout order) is preceded by
   `ldr x12, [sp, #192]; sub x12, x12, #1; str x12, [sp, #192]; cbz x12, <stub>`
   (`RUNTIME_FRAME_BUDGET_OFFSET`, scratch `REG_VIRT_SCRATCH_GPR_START`), then
   any number of reg-virt fill loads `ldr x12..x15, [sp, #16..#56]` and nothing
   else, then the branch. No join point may sit on the `sub`, `str`, `cbz`, a
   fill or the branch, so every path to the back-edge decrements the counter;
   the check's `ldr` may be one (it carries the original PC's label). The `cbz`
   target is a forward exit-group start (the Budget stub).
   - The counter is written only by the prologue's init (byte-exact) and by a
     check's own `str`; the counter is read only by a check's own `ldr`. A
     check that guards no back-edge is rejected like any other counter access
     (`BudgetSlotAccess`).
7. Exit groups: every fault stub (and budget stub) starts an exit group: the word
   before it is an unconditional `B`, and the straight-line run from it contains
   no user access and ends in `b <epilogue>`. The cold region starts at the
   lowest stub offset.

8. PAN windows (A8): see "A8 implementation", "Verifier (V3) rule 8".
9. Confidentiality: no kernel value reaches user-visible state. See
   "Confidentiality (rule 9)" below.

Join points (where the dataflow restarts): entry offsets, stubs, and direct
branch targets; also after every unconditional `B`.

## Confidentiality (rule 9) (2026-09-27)

Rules 2-8 protect integrity. Without rule 9 nothing stopped a kernel address
from reaching a register the epilogue writes back to `pt_regs` (a KASLR /
kernel-stack leak): `mov x0, sp`, `add x0, x29, #0`, `ldr x0, [sp, #176]`,
`ldr x12, [sp, #176]; mov x0, x12`, `str x29, [sp, #16]` (user x12's slot) were
all accepted.

Rule: one forward taint dataflow (`shared/verify/taint.rs`) over the body and
cold region, same linear shape and join conservatism as the old pt_regs
dataflow, which it replaces (rule 3's pt_regs fact is its refinement).

- State: `kernel` = GPRs holding a kernel value; `pt_regs` ⊆ `kernel` = GPRs
  proven to hold the pt_regs pointer. SP is always a kernel value (not tracked).
- Join state (every join point, and after every unconditional `B`): derived at
  verify time by running the transfer function over the byte-exact
  `KJIT_PROLOGUE` from "every GPR is a kernel value". Result: {x29 (the
  runtime frame), x12 (the entry address the prologue's `br` uses)}; pinned by
  `join_state_is_derived_from_the_prologue`.
- Sources: SP read as data; x29 (in the join state, and the body never writes
  it); the entry scratch until overwritten; `ldr xS, [sp, #176]` (-> `pt_regs`
  fact); any other frame slot outside the user-state slots `[16, 80)` (rule 3
  already rejects every such load, rule 9 classifies it anyway).
- Not sources: user-state frame slots; `pt_regs` contents (loaded through the
  proven pointer); `LDTR*` and window-atomic results; `MRS` of TPIDR_EL0,
  CNTVCT_EL0, CNTFRQ_EL0 (A10: EL1 reads what EL0 reads, module init pins it); the
  budget counter (192): the user can count its own back-edges, so it is not
  secret.
- Transfer: a write gets the kernel mark if the instruction reads SP or a
  kernel-valued GPR as data (ALU), or loads a kernel frame slot; loads of user
  state clear it.
- Checks (`VerifyRule`):
  - `KernelValueRead`: an instruction reads SP or a kernel-valued GPR as data
    (ALU source, store data, branch operand, `MOVK`/`BFM` destination, exit
    payload source, `LDTR*`/`STTR*` or window-atomic data, the PAN range check),
    or uses a kernel-valued GPR as the base of a user access / window atomic. A
    kernel value may be a base only of a runtime access: SP for a frame access,
    a proven pt_regs pointer for a `pt_regs` access (rule 3). So a kernel value
    is never stored anywhere and never computed on.
  - `KernelValueAtEdge`: at every control edge the state may hold no kernel
    value outside the join state: every direct branch (into the body or to the
    epilogue), every fall-through into a join point, and every user access /
    window atomic (its fault edge to the stub). This is what makes restarting
    each join point from the join state sound.
  - Exit edges: the epilogue reads no join-state register before writing it
    (x12 and x29 are not in its live-in set x0..x11, x16..x28, x30);
    `join_state_is_dead_in_the_epilogue` computes the live-in set from
    `KJIT_EPILOGUE` and pins both facts.
  - The pt_regs pointer load is admitted only into scratch x12..x15
    (`FrameAccessOutOfRange` otherwise, as for any other kernel slot): scratch
    is never written back to the user, so the pointer can never sit in a
    user-visible register.
- What the translator emits that needed allowing: only the exit-preserve
  sequence `ldr x12, [sp, #176]; str x9/x10/x11, [x12, #72/#80/#88]` in exit
  groups, followed by the payload and `b <epilogue>` with x12 still holding the
  pointer. Safe: x12 is used only as a runtime-access base, and x12 is in the
  join state and dead in the epilogue. No fixture fragment reads SP (other than
  as a frame base), x29 or the entry scratch (checked: every fixture fragment
  verifies).
- Not covered: NZCV at entry holds the trampoline's flags (not an address; the
  body only observes them if it reads flags before setting them, a translator
  semantic issue); the kernel's fault fixup is assumed to change no GPR before
  the stub.
- FP/SIMD registers (A9a): SIMD&FP register fields carry `VecRead`/`VecWrite`
  roles and are plain register numbers, so `reads`/`writes` never count them: a
  write to V12 leaves x12's kernel mark, a read of V12 is not a read of x12.
  The general operands of SIMD&FP forms (FMOV general, DUP/INS general, UMOV,
  addressing) are `Reg*` roles like any other, so a kernel value is rejected
  before it could enter a V register, and V registers never hold one. Pinned by
  `simd_registers_are_not_general_registers_for_rule_9`.

## Cost

One decode pass, one check pass, one pass per table, each exit group walked once:
O(words + fault sites + entries) time, O(words) memory. No recursion, no panics
(the two `panic!`s are in `const` initializers, i.e. compile time).

## Not checked (semantic, not safety)

- That exit payloads set a known `RetStatus` or the right resume PC; the K2
  runtime WARNs and disables KJIT on an unknown status.
- That a fault stub belongs to the access's own original instruction.
- Fall-through between body blocks: any body word is verified code.

## Hook points

- Harness: `run_entry_fixture` verifies before running, so every fixture case
  (interpreter and native suites, `trace-tui --check`) runs only verified
  fragments; the runtime unit-test fragments and the kernel golden are verified
  too. `verify_mutation_tests.rs` is the G1 mutation suite.
- Kernel (K2): `runtime/translate.rs` runs `verify_fragment` on exactly the
  bytes, fault-site table and entry table (`entry_offset` + every `vlabels`
  offset) that `kjit_install` installs; a rejected fragment is counted
  (`translate_verify_rejected`, FallsOffEnd separately) and never installed.

# K2 contract: kernel runtime (2026-09-27)

Written before implementation. Facts checked against `dep/linux` 7.1-rc1:
`arch/arm64/kernel/syscall.c` (`el0_svc_common`, static `invoke_syscall`),
`arch/arm64/mm/fault.c` (`do_page_fault`, `is_el1_permission_fault`),
`arch/arm64/mm/extable.c` (`insn_may_access_user`, `fixup_exception`),
`kernel/extable.c` (`search_exception_tables`), `mm/execmem.c` (no exports).

## Preconditions

- No fragment executes in the kernel until the verifier (V3) and the budget
  (A6) are merged, and every fragment is verified in-kernel before install.
- Kernel config invariants live in `kernel-config/` (K1): shadow call stack
  off (the fragment owns x18), kCFI off, kernel BTI off (the prologue ends
  in `br x12`), hardware PAN on, `ARM64_SW_TTBR0_PAN` off, and `UAO` clear.
- CPU features (A7c, checked at module init by `kjit_check_cpu`,
  `kjit_glue.c`; `insmod` fails with `-ENODEV` and a `pr_err` naming the
  feature): FEAT_LSE2 (sanitised `ID_AA64MMFR2_EL1.AT != 0`) with
  `SCTLR_EL1.nAA` clear, because a misaligned LDAR/STLR/LDAPR inside a 16-byte
  block must not fault natively when the fragment's `LDTR*`/`STTR*` for it
  does not; FEAT_LRCPC (sanitised `ID_AA64ISAR1_EL1.LRCPC != 0`), because
  without it user LDAPR is UNDEFINED natively but would run in a fragment.
  (`SCTLR_EL1.nAA` is read on the loading CPU; Linux never sets it.)
  FEAT_CRC32 (sanitised `ID_AA64ISAR0_EL1.CRC32 != 0`, A7d): without it user
  CRC32*/CRC32C* are UNDEFINED natively and would be an undefined instruction
  at EL1 in a fragment.

## Patch series (`kernel-patches/`, applied by the setup script)

1. **Syscall-return loop** in `el0_svc_common`, after `invoke_syscall` and
   only on the path where `has_syscall_work(flags)` is false:
   `while ((scno = kjit_after_syscall(regs)) >= 0) { orig_x0/syscallno
   setup; invoke_syscall(regs, scno, ...); re-read flags; break on
   syscall work }`. The hook is a static key plus an RCU-protected ops
   pointer that the module registers. It is a no-op when unregistered.
2. **`search_kjit_extables(addr)`**, consulted last in
   `search_exception_tables`. This makes `insn_may_access_user` accept a
   fragment `LDTR`/`STTR`, so demand paging and CoW work exactly like
   `copy_from_user`. A truly bad address reaches `fixup_exception` and
   `regs->pc` is set to the site's `Mem` stub.
   - Entries use the arm64 `exception_table_entry` format with type
     `EX_TYPE_UACCESS_ERR_ZERO` and both registers = 31, so the handler only
     redirects the PC.
   - `insn` and `fixup` are self-relative, so the entries live in the same
     allocation as the code.
3. **Exports** the module needs for RX code memory and I-cache maintenance
   (`execmem_alloc`/`execmem_free` or equivalent, `set_memory_rox`).

## `kjit_after_syscall(regs)` decision

- Return -1 (normal syscall return) unless all of these hold: 64-bit task,
  no pending signal, no `need_resched`, no syscall-work flags, no
  single-step, `regs->regs[0]` not a restart errno, and a fragment exists for
  `(current->mm, regs->pc)`.
- Otherwise run fragments: call the entry with x0 = `regs`, x1 = the extra
  params, x2 = the entry address. On exit the epilogue has written the full
  user state into `regs`. Then:
  - `Svc`, with x11 = the PC after the svc: re-check every condition above.
    If they all still hold, set `regs->pc = x11` and return `regs->regs[8]`,
    so the kernel invokes that syscall. Otherwise set `regs->pc = x11 - 4`
    and return -1; userspace executes the `svc` natively. This makes
    declining always exact.
  - `Ret`/`Br`/`Blr`/`Bl`, target in x10: if a fragment exists for
    `(mm, target)` and the conditions hold, continue there (runtime-loop
    chaining, bounded by a per-syscall iteration cap). Otherwise set
    `regs->pc = target` and return -1.
  - `Unsupported`/`Mem`/`Budget`: set `regs->pc = x11` and return -1.
  - Any other status is a kernel bug: `WARN_ONCE`, then disable KJIT for the
    mm and return -1 with `regs->pc = x11`.

## Code cache

- A per-mm table maps an original PC to a fragment. A fragment is one
  allocation holding: code (ROX after install), its extable, and the PC→offset
  entry table the runtime uses to compute x2. Lookup takes a reference that is
  dropped after the run, because fragments may sleep (page faults) and so
  can't run under `rcu_read_lock`.
- Only text from VMAs that are not writable is translated. An
  `mmu_notifier` on the mm removes fragments whose source pages are
  invalidated, and removes all of them at mm teardown. A fragment already
  running finishes its bounded run; that is equivalent to the old code
  having executed just before the unmap.
- Translation reads user text with `access_process_vm` for the manual trigger
  (debugfs `translate <pid> <pc>`), and in the task's own context
  (`task_work`) for the P3 automatic trigger.

## Known limitation

- rseq critical sections are not honoured inside fragments. glibc only reads
  `cpu_id`, and redis defines no critical sections.

  translated.

# K2 implementation (2026-09-27)

Implements "K2 contract: kernel runtime". Decisions the contract left open, and
where the implementation is stricter than it:

## Kernel tree and patches

- `kernel-patches/000{1,2,3}` on the pinned 7.1-rc1 commit, applied by
  `scripts/kjit-kernel-tree.sh` to `$KJIT_BUILD_ROOT/linux-kjit`, a git worktree
  of `dep/linux` (idempotent via a stamp of base commit + patch hashes;
  fail-fast on local changes, a half-applied `git am` or a patch that does not
  apply). Every profile builds from it; `ARM64_KJIT=y` is a K1 invariant
  (`kjit-invariants.conf`). Why all profiles: the module links against the hook
  symbols, and one module shape is simpler than a K0-only build.
- 0001: `ARM64_KJIT` (selects `MMU_NOTIFIER`; depends on !SCS, !CFI,
  !BTI_KERNEL, !SW_TTBR0_PAN), `include/linux/kjit.h`,
  `arch/arm64/kernel/kjit.c`, the loop in `el0_svc_common`.
  - The ops pointer is protected by **SRCU**, not RCU: `after_syscall` sleeps
    (fragment page faults). Unregister (as of 0006) = static key off,
    `synchronize_srcu`, pointer NULL, `synchronize_srcu`: the first grace
    period drains hook calls in flight while the extable search still finds
    their fixups, the second the extable searches and task_work callbacks
    that loaded the old ops. It never waits for a syscall the loop invoked
    (those run outside the SRCU section). See "Unload race".
  - Loop placement: inside the existing "no syscall work at entry, none at exit,
    no single-step, !DEBUG_RSEQ" branch. After each invoked syscall the flags are
    re-read; syscall work or single-step leaves through `trace_exit`, as upstream
    does when work appears under one syscall.
  - `KJIT_MAX_SYSCALLS_PER_ENTRY = 4096`, checked before the hook is called:
    a pure syscall loop would otherwise never switch voluntarily or pass through
    user mode (RCU Tasks). Cost: one return to EL0 per 4096 syscalls.
  - `invoke_syscall` goes through a `noinline` wrapper so the
    `RANDOMIZE_KSTACK_OFFSET` alloca is released per syscall.
- 0002: `search_kjit_extables()` is the last lookup in
  `search_exception_tables()`, through `ops->search_extable` under the same SRCU;
  skipped in NMI (SRCU readers are not NMI-safe; fragments never run there).
- 0003: `EXPORT_SYMBOL_GPL` for `execmem_alloc`, `execmem_free`,
  `set_memory_ro`, `set_memory_x` (arm64's `set_memory_rox` is the generic
  inline over the last two). `flush_icache_range` already uses exported helpers.

## Hook return value

- Kept `long after_syscall(regs)`: -1 = return to EL0 at `regs->pc`, >= 0 = the
  syscall number to invoke. On `Svc` the runtime returns `(int)regs->regs[8]`
  (the kernel's own entry truncates x8 to `int`); a negative value is declined
  (pc = x11 - 4), so `NO_SYSCALL`-style numbers keep the native path.

## Run conditions (`kjit_can_run`, before every entry and every in-kernel syscall)

- Superset of the contract: 64-bit task, **not ptraced** (`current->ptrace`: a
  tracer may single-step, watch or inspect at any instruction), no bit of
  `(EXIT_TO_USER_MODE_WORK & ~_TIF_FOREIGN_FPSTATE) | _TIF_SYSCALL_WORK |
  _TIF_SINGLESTEP` (signals incl. `NOTIFY_SIGNAL`, both need_resched bits,
  `NOTIFY_RESUME` = task_work/rseq, uprobes, livepatch, MTE async faults),
  x0 not in -ERESTARTSYS..-ERESTART_RESTARTBLOCK. `FOREIGN_FPSTATE` only asks
  for an FP reload before EL0 runs; fragments without FP/SIMD never touch
  those registers, and fragments with FP/SIMD reload them inside their bracket
  (A9b).
- Seccomp-filtered tasks never reach the hook (`TIF_SECCOMP` is syscall work).

## Call ABI (trampoline `kjit_call_fragment`, `kjit_glue.c`)

- `x0 = regs`, `x1 = extra`, `x2 = base + entry offset`, `blr base`; mirrors
  `harness/src/native.rs`. Before the call it loads the user NZCV from
  `regs->pstate[31:28]` into PSTATE; after it writes NZCV back (the fragment
  runs user flag-setting code in hardware). Callee-saved registers, x29/x30 and
  sp come back through the epilogue.
- Extra params = two u64: `[0] = x10 (RET_PARAM0)`, `[1] = x11 (RET_PARAM1)`
  (epilogue `stp x10, x11, [x17]`); `x0` = `RetStatus`. The Rust side matches
  the raw status exactly (0..=7), not `RetStatus::from_reg` (which masks with
  0xFFFF); anything else is the WARN_ONCE + disable path.

## Code cache and lifetimes

- `kjit_mm` per mm, embedding the `mmu_notifier` (`mmu_notifier_get/put`).
  Found from the syscall path through a global RCU hash keyed by `mm`. The hash
  membership owns exactly one notifier reference; whoever unhashes it (mm
  release, or module exit) under `kjit_mm_lock` drops it. Freed in
  `free_notifier` (after the notifier SRCU grace period) with `kfree_rcu`
  (hash readers are RCU readers).
- Table: per-`kjit_mm` RCU hash keyed by the **entry PC** (the PC a translation
  was requested for). The fragment also carries its sorted `vlabels`
  (PC -> offset); branch-exit chaining first looks for the target in the
  fragment that just exited (a verified entry offset), then in the table.
  After an `Svc` exit the next hook call looks the resume PC up in the table
  (the reference is not held across the syscall).
- `kjit_frag` refcount: one held by the table while installed, one per running
  call (`kjit_lookup` = RCU lookup + `refcount_inc_not_zero`). The fragment is
  on the global extable list until its **last** reference is dropped, so a
  fragment removed from its table while it runs keeps its fault fixups. Last
  put: off the list, image freed by `queue_rcu_work` (execmem_free needs
  process context).
- Image = one `execmem_alloc(EXECMEM_BPF)` allocation: code, then one
  `exception_table_entry` per fault site (`EX_TYPE_UACCESS_ERR_ZERO`, both
  registers 31), `flush_icache_range`, `set_memory_rox`.
- Locks: `kjit_mm.lock` -> `kjit_frags_lock` (spinlocks, no allocation under
  either: both are taken inside mmu_notifier invalidation). `kjit_mm_lock` is
  never nested with them.
- Invalidation: every `invalidate_range_start` event whose range intersects a
  fragment's source span `[lo, hi)` (min/max of every byte the translator read)
  removes it; not only unmaps, because a protection change can make the text
  writable and CoW/migration replace pages. Non-blocking-safe (spinlock only).
- Install gate: `kjit_mm.seq` counts started invalidations, `invalidating` the
  ones in progress. The translator snapshots `seq` before reading text;
  `kjit_install` installs only if `seq` is unchanged and nothing is in
  progress, else `-EAGAIN` (retried 3 times; `translate_raced`). Any change to
  the text between the read and the install therefore prevents the install.
- Text reads: `kjit_read_text_page` under `mmap_read_lock`, only from a VMA
  with `VM_EXEC` and without `VM_WRITE`, one page snapshot per page
  (`get_user_pages_remote`, `FOLL_FORCE` for exec-only text). Per translation
  at most 16 pages and 16384 reads (`build_cfg` has no size bound of its own
  and quadratic bookkeeping).
- Teardown: mm release (`release` callback) empties the table and unhashes.
  Module exit: remove debugfs (waits for writers), unregister the hook (waits
  for calls in flight, i.e. every fragment run, with their extable search
  still live; patch 0006, see "Unload race"), claim and empty every
  `kjit_mm`, `mmu_notifier_put`, `mmu_notifier_synchronize`, `rcu_barrier`,
  `destroy_workqueue`.

## Known limitations (in addition to rseq)

- A write to a mapped text file through `write(2)` or a shared writable mapping
  of the same file changes page-cache pages in place without an mmu_notifier
  event on our (non-writable) VMA, so a translation of it is not invalidated.
  The running executable is protected by `ETXTBSY`; shared libraries are not.
- Invalidation is conservative: any notifier event on a fragment's span drops
  it (reclaim of clean text pages, migration), and the install gate retries
  on unrelated invalidations.
- Perf hardware breakpoints/watchpoints on a non-ptraced task are not
  considered.

## Guest tests (G2 and hardening)

- `tests/guest/` (static, `/opt/kjit-tests` in the guest rootfs;
  `make guest-tests GUEST_PROFILE=... K2_ITERATIONS=N`). Every test runs with
  `enable` N and Y: identical stdout and exit status, plus counter checks in the
  enabled run. G2 = `toy_loop`: >= 99% of its syscalls invoked in-kernel.

## K0 kernel bring-up: golden fragment check

- The userspace harness is the reference. `tests/arm64/golden/toy_cfg_hot_svc_mark.rs`
  is generated by `make kernel-golden` (`harness/src/bin/dump-golden.rs`) and holds
  the fixture's `.text` words, `entry_pc`, and the encoded `compile_request`
  fragment. It is plain `const` data so both the harness and the module can
  `include!` it.
- Staleness guard: harness test `kernel_golden_matches_harness_output` re-renders
  the file from its own input words and requires byte-equal source. It does not
  re-assemble `toy_cfg.s`; the input words are only as fresh as the last
  `make kernel-golden`.
- Module init runs `compile_request` over a `CodeProvider` backed by the embedded
  words, encodes, and compares byte-for-byte. PASS/FAIL is `pr_info!`/`pr_err!`
  with the first mismatching offset; FAIL returns `EINVAL` from init.
- Invariant: the module never executes or branches into the golden fragment's
  bytes. (K2 executes only fragments it translated from a live process and
  verified in-kernel; see "K2 implementation".)

# K3: automatic hot-path detection (2026-09-27)

Implements P3 on top of "K2 implementation". Code: `kjit_glue.c` ("Auto
mode"), `runtime/exec.rs`, `runtime/translate.rs`, `runtime/stats.rs`,
`kernel-patches/0004`.

## Profiler

- Where: the syscall-return hook, only when a run is otherwise possible
  (`kjit_can_run`) and there is no fragment: (1) at `regs->pc` after a syscall
  (`KJIT_HOT_SVC_RESUME`), (2) at the target of a `Bl`/`Blr`/`Br`/`Ret` exit
  whose chaining lookup failed (`KJIT_HOT_EXIT_TARGET`, exit-target
  learning). Never after `Unsupported`/`Mem`/`Budget` (userspace resumes
  mid-block; the next syscall resume PC is the profiled point), never when the
  chain cap or a run condition stopped chaining.
- Table: per `kjit_mm`, 256 slots, open addressing over 8 probe slots from
  `hash_64(pc)`. A lookup scans all 8 (no early stop), so freeing a slot needs
  no tombstone. A new PC takes a free slot or one whose window has expired and
  that has no queued request; else the hit is dropped (`auto_prof_full`).
  Under `kjit_mm.lock`. The first eligible syscall of an mm only creates its
  `kjit_mm` (`mmu_notifier_get`, may sleep: mmap write lock,
  `mm_take_all_locks`) and is not counted; after that a hit costs a hash
  lookup, the spinlock and an arch-counter read, and allocates nothing.
- Hot: `hot_threshold` hits within one `hot_window_ms` window (window start =
  first hit; an expired window restarts at the hit). Time is CNTVCT
  (`arch_timer_read_counter`, ticks = ms * CNTFRQ / 1000). On the crossing the
  slot's window restarts whatever happens next.
- Defaults 64 hits / 100 ms (>= 640 hits/s sustained). Why: a translation
  costs ~240 us in the guest (`auto_translate_ns` / requests, K2 micro tests);
  one in-kernel syscall saves at most one EL0 round trip (~120 ns, E0
  `getppid`), so a translation pays back after ~2000 hits, i.e. within ~3 s
  at the threshold rate; bursts of fewer than 64 hits per 100 ms (startup,
  config parsing) are never translated. Module parameters and debugfs.

## Requests (task_work)

- A hot PC that is not in the negative cache, under the caps, and with fewer
  than 8 requests queued for its mm gets its slot marked `queued` and a
  `kjit_request` (kmalloc, the only allocation of the path) queued with
  `kjit_queue_task_work()` (patch 0004, `TWA_RESUME`). Translation never runs
  in the syscall hook.
- The request runs in the requesting task at its next return to user mode (the
  queued `TIF_NOTIFY_RESUME` is a bail flag, so the hook returns first). It
  translates only if `current->mm` is still the request's mm, the task is not
  exiting and auto mode and `enable` are still on (else `auto_req_stale`),
  with `kjit_rs_translate` on the task's own mm: same text rules, same
  verification, same install gate as the manual trigger.
- A request holds no reference. It names its `kjit_mm` by (mm pointer, a
  per-`kjit_mm` 64-bit id) and finds it again under RCU when it finishes, so an
  exited mm or a reused mm address is detected. Finishing frees the slot
  (installed: the table now has the PC; transient failure: it is profiled
  again).
- Module lifetime (patch 0004): the task_work callback is kernel code that
  calls `ops->task_work` under the hook SRCU, and only if the registration
  generation recorded at queue time is current; otherwise it `kfree`s the
  request. `kjit_unregister_hook` already waits for SRCU readers, so after
  module exit no request runs module code, and a request queued by one module
  instance is never handed to a later one. Nothing has to cancel per-task
  work at unload.

## Negative cache

- Final failures (errno): compile/encode (`-EINVAL`), verifier (`-EPERM`),
  untranslatable entry instruction (`-ENOEXEC`), text not in an executable
  non-writable mapping or unmapped (`-EACCES`, `-EFAULT`), text budget
  (`-E2BIG`), and anything unclassified. Transient: `-EAGAIN` (lost the install
  race 4 times), `-ENOMEM`, `-EINTR`, `-ESRCH`, `-ENOSPC` (caps).
- Per `kjit_mm`, 64 PCs, FIFO replacement (`auto_neg_evicted`); checked only
  when a PC crosses the threshold, so a hit never scans it. Not cleared by
  invalidations: a PC whose text is later replaced (dlclose + dlopen at the
  same address) stays untranslated in that mm. Pessimistic, never wrong.
- Entry refusal (all triggers): a translation whose entry word itself would
  take the `Unsupported` exit (`cfg::admit_at`) is refused with `-ENOEXEC`
  (`translate_entry_unsupported`): the fragment could only return to
  userspace at its own entry, at the cost of a call. The negative cache keeps
  the word; the PC's profile slot then counts every later hit as an
  `entry_stop` of that word in `unsupported_top` instead of counting it.

## Caps

- `max_frags_per_mm` 512, `max_code_per_mm` 2 MiB, `max_frags_total` 8192,
  `max_code_total` 64 MiB (module parameters). Checked in `kjit_install` under
  `kjit_mm.lock` (per mm exact; the global counters are read racily across
  mms, so concurrent installs can overshoot by one fragment each), `-ENOSPC`,
  for every trigger. Pre-checked before a request is queued.
- Counts move with table membership (install, `kjit_mm_flush_locked`), not with
  the last reference, so a fragment still running after removal is not
  counted.

## Chaining rules

- On `Bl`/`Blr`/`Br`/`Ret` with target T: if the hook call has made fewer than
  `chain_budget` fragment entries (the first one included; A10, was a fixed
  `MAX_CHAIN` of 16 chained entries) and `kjit_can_run` holds (it also checks
  `enable`), continue at T's verified entry in the fragment that just exited,
  else at the fragment for (mm, T); each chained entry counts `chains`.
  Otherwise userspace resumes at T; if the lookups ran and failed, T is
  profiled. Reaching the budget counts `chain_cap`; a failed run condition
  (at the hook or at a branch exit within the budget) counts `run_declined`.
- Every entry is back-edge-budget-bounded and the run conditions are
  re-checked before each entry and before each in-kernel syscall, so a hook
  call spends at most `chain_budget` bounded runs in fragments between two
  syscalls. See "A10" for what the budget protects and its default.

## Lifetimes

- exec: a new mm, so a new `kjit_mm` on its first syscall; the old one dies at
  mm release; requests queued before the exec are stale.
- fork: mmu notifier subscriptions are not inherited, so the child starts
  empty and profiles on its own. In the parent, `copy_page_range` only walks
  VMAs that need copying (`vma_needs_copy`: an `anon_vma`, or
  `VM_COPY_ON_FORK`); for a CoW one it sends a `PROTECTION_PAGE` invalidation,
  which drops fragments translated from it (conservative, as in K2). Plain
  file-backed text has no `anon_vma`, so its fragments survive a fork; text in
  an anonymous RX mapping does not.
- Thread exit: a queued request runs in `exit_task_work` with `current->mm`
  NULL: stale, its slot is released under RCU.
- Process exit, module unload: as K2 (release/claim empties the table); queued
  requests are freed by the kernel (0004).

## Accounting and diagnostics

- `hook_calls` (per-CPU in C): hook calls while enabled, i.e. syscalls without
  syscall work, in-kernel ones included. `syscalls_in_kernel / hook_calls` is
  the in-kernel fraction (global: the runner isolates the program under test
  by running load generators under `nojit`, an allow-all seccomp filter).
- `unsupported_top`: lock-free table of 1024 words (16 probes; a slot's key is
  claimed once by compare-exchange and never changes). Columns `exits`
  (`Unsupported` exits, x10 = word, `unreadable` for
  `UNSUPPORTED_WORD_UNREADABLE`, any other x10 counts `unsupported_bad_word`)
  and `entry_stops`. Full table: `unsupported_top_dropped`.
- C counters go through one `kjit_rs_note(enum kjit_note, n)` (values mirrored
  in `runtime/stats.rs`, `note_stat`).

## Known limitations

- BTI: a `Blr`/`Br` exit does not model PSTATE.BTYPE. Chaining into a
  fragment, or resuming userspace at the target with the syscall's BTYPE (0),
  skips the landing-pad check that a native indirect branch to a non-`BTI`
  instruction in a guarded page would fail (SIGILL). Only programs with broken
  control flow are affected. (Present since K2 chaining.) Since A7d a `BTI`
  inside translated code is a `NOP`, which is what it is when executed in
  sequence; its landing-pad check is the same unmodelled BTYPE path.
- The first eligible syscall of every mm registers an mmu notifier
  (`mm_take_all_locks`); every process pays it once in auto mode.
- Per-mm table and negative cache are per mm, not per executable: every
  process warms up on its own.

## Findings (kjit-guest, 2026-09-27)

- Semantics: every `run-k3.sh` test gives identical output and exit status
  with auto mode on and off (20 iterations on `kjit-guest-debug` without a
  kernel report).
- Coverage: the in-kernel path extends well past libc wrappers where the code
  is in the subset (`dd bs=1`: 100% of syscalls in the kernel, 8 fragment
  entries per syscall through Ret/Bl/Blr/Br chains; `epoll_echo` 88%,
  `dd bs=4k` 70%, `busybox dd` 64%), but stops at `bti c` (0xd503245f) at
  function entries (Debian's redis and the dev image's static glibc are
  BTI-built), SIMD loads in `memcpy`/`strlen`/`memchr` (`ldr q`, `ldp q`,
  `ld1`, `dup`) and `adc`. redis-server under redis-benchmark: 0 of ~1.59M
  syscalls in the kernel; with A7c's LDAR, every path ends at a `bti c` entry
  (~1.59M entry stops, no Unsupported exits). Before A7c the second blocker
  was `ldar x1, [x0]` (0xc8dffc01, ~0.7M exits). Translating `bti` (a NOP
  outside guarded pages; see the BTI limitation) is the next coverage step:
  done in A7d, together with `adc`; not re-measured in the guest yet.
- Speed: not a goal yet. Fragment entry and exit cost more than the mode
  switches they save when a path chains through many short fragments
  (`dd bs=1`: 100% in kernel and ~40% slower).

# A64 subset contracts (A7a, 2026-09-27)

## Decode admission

- A word decodes only if it matches a generated form's mask/value **and**
  `A64Insn::is_decode_undefined` is false. That function carries the value
  rules the XML keeps in decode pseudocode (`EndOfDecode(Decode_UNDEF)` and
  `DecodeBitMasks` rejections: add/sub shifted `shift == 11` and 32-bit
  `imm6<5>`, add/sub extended `imm3 > 4`, 32-bit logical shifted `imm6<5>`,
  reserved logical immediates, 32-bit bitfield `immr<5>`/`imms<5>`). It is an
  exhaustive match, so a new form must decide whether it has such rules.
- Why: reg-virt only rewrites register fields, so an admitted word's non-register
  fields reach the emitted fragment unchanged. An UNDEFINED encoding admitted
  here would trap at EL1; rejected, it takes the Unsupported exit and userspace
  gets its SIGILL natively.
- Cross-checked against the LLVM disassembler on 300 random words per form
  (all 142 forms): the only disagreements are the known constrained-unpredictable
  memory overlaps, which reg-virt rejects.

## Field constraints in subset.toml

- `[decode.field_constraints]` pins non-operand fields of an exact form to fixed
  values; specgen folds them into mask/value and drops them from the generated
  operands. A constraint on an unconfigured form, a missing/fixed field, a field
  with an operand role, or an out-of-range value fails generation.
- `MRS.MRS_RS_systemmove` was constrained to TPIDR_EL0 (`o0=1 op1=3 CRn=13 CRm=0
  op2=2`); since A10 it has three field instances instead (see "A10"). Kernel
  assumption: while a fragment runs at EL1, TPIDR_EL0 still holds the current
  task's user TLS pointer (Linux switches it only on context switch), so the
  MRS is exact without rewriting.
- SMULH/UMULH pin their should-be-one `Ra` to 31; other values are constrained
  unpredictable and stay undecodable.

## Flags metadata

- `FlagsWrite` is inferred from an assignment to `PSTATE.[N,Z,C,V]` in the
  execute pseudocode (ADDS/SUBS, ANDS/BICS, CCMP/CCMN). The earlier heuristic
  (`AddWithCarry` + `nzcv`) missed ANDS/BICS and CCMP/CCMN. No pass consumes
  flag roles yet.
- `FlagsRead`: `ConditionHolds`, or (A7d) a read of a single flag that is not
  an assignment to it (ADC/SBC's `AddWithCarry(.., PSTATE.C)`; the flattened
  XML text may read `PSTATE .C`).

## K1 kernel config invariants (2026-09-27)

- `kernel-config/kjit-invariants.conf` is merged last by every profile.
  `scripts/setup-kernel-build.sh` fails, naming each option, when any value
  requested by the merged fragments is not in the final `.config` (an
  `is not set` request is also satisfied by an absent symbol).
- Pinned options (Linux 7.1-rc1):

  | Option | Value | Why |
  |---|---|---|
  | `SHADOW_CALL_STACK` | n | fragment owns x18 |
  | `CFI` (kCFI; `CFI_CLANG` is now a transitional alias) | n | kernel calls untyped fragment code indirectly |
  | `ARM64_BTI_KERNEL` | n | prologue ends in `br x12` into code without landing pads |
  | `ARM64_SW_TTBR0_PAN` | n | LDTR/STTR must reach user page tables |
  | `MODULES`, `RUST` | y | kjit.ko is an out-of-tree Rust module |

- Contract items with no Kconfig symbol in 7.1, checked in source:
  - Hardware PAN: `CONFIG_ARM64_PAN` is gone. The `ARM64_HAS_PAN` cpucap is
    always built and enabled when the CPU implements PAN. It is checked at
    runtime: `scripts/guest-run.sh` fails without the boot line
    `CPU features: detected: Privileged Access Never`.
  - `PSTATE.UAO == 0`: `CONFIG_ARM64_UAO` is gone. Nothing in arch/arm64 sets
    UAO, and an exception to EL1 clears it.
  - CPU features FEAT_LSE2 (with `SCTLR_EL1.nAA` clear) and FEAT_LRCPC: not
    configuration but hardware; `kjit.ko` refuses to load without them (see
    "K2 contract", Preconditions).
- Checked and not pinned: `ARM64_LSUI` (futex atomics only), `ARM64_EPAN`
  (privileged accesses only; LDTR/STTR are unprivileged), `ARM64_MTE` (LDTR/STTR
  are checked with TCF0, as in copy_from_user), `ARM64_PTR_AUTH_KERNEL`
  (this is safe only while PAC hints stay outside the decoded subset: they take
  the Unsupported exit and run in userspace; pinned by
  `hint_space_decodes_only_nop_and_bti`, A7d).
- Profiles: `tiny-qemu[-debug]` (K0), `kjit-guest` (Debian/redis userland,
  E0 baseline) and `kjit-guest-debug` (+ generic KASAN, lockdep,
  DEBUG_ATOMIC_SLEEP, DEBUG_LIST). All start from tinyconfig. The guest profiles
  use `PREEMPT` (full), because fragments run preemptible.
- Kernels build out of tree only: `dep/linux` stays a clean source tree, and
  `KBUILD_OUTPUT` defaults to `$KJIT_BUILD_ROOT/$KJIT_KERNEL_PROFILE`. kjit.ko
  (Kbuild `MO=`) and the K0 golden initramfs live in that build dir, so a
  module is always paired with the kernel it was built against.


# Memory form coverage (A7b, 2026-09-27)

## Forms

Added to the subset (exact XML names in `spec/arm64/subset.toml`):

- byte/halfword/signed, unsigned offset + pre + post: `LDRB_imm.LDRB_32_*`,
  `STRB_imm.STRB_32_*`, `LDRH_imm.LDRH_32_*`, `STRH_imm.STRH_32_*`,
  `LDRSB_imm.LDRSB_{32,64}_*`, `LDRSH_imm.LDRSH_{32,64}_*`,
  `LDRSW_imm.LDRSW_64_*` (`*` = `ldst_pos`, `ldst_immpre`, `ldst_immpost`);
- unscaled: `LDUR_gen.LDUR_{32,64}`, `STUR_gen.STUR_{32,64}`, `LDURB`,
  `STURB`, `LDURH`, `STURH`, `LDURSB_{32,64}`, `LDURSH_{32,64}`, `LDURSW_64`
  (all `_ldst_unscaled`);
- register offset: `LDR_reg_gen.LDR_{32,64}`, `STR_reg_gen.STR_{32,64}`,
  `LDRB_reg.LDRB_{32B,32BL}`, `STRB_reg.STRB_{32B,32BL}`, `LDRH_reg.LDRH_32`,
  `STRH_reg.STRH_32`, `LDRSB_reg.LDRSB_{32B,32BL,64B,64BL}`,
  `LDRSH_reg.LDRSH_{32,64}`, `LDRSW_reg.LDRSW_64` (all `_ldst_regoff`);
- pairs: `LDP_gen.LDP_32_ldstpair_*`, `STP_gen.STP_32_ldstpair_*`,
  `LDPSW.LDPSW_64_ldstpair_*` (`off`, `pre`, `post`);
- literal: `LDR_lit_gen.LDR_{32,64}_loadlit`, `LDRSW_lit.LDRSW_64_loadlit`;
- prefetch: `PRFM_imm.PRFM_P_ldst_pos`, `PRFM_lit.PRFM_P_loadlit`,
  `PRFM_reg.PRFM_P_ldst_regoff`;
- unprivileged (emitted only): `LDTRB`, `STTRB`, `LDTRH`, `STTRH`,
  `LDTRSB_{32,64}`, `LDTRSH_{32,64}`, `LDTRSW_64` (`_ldst_unpriv`).

Still out, so undecodable and an Unsupported exit (unit test + fixture cases):
exclusives, LSE atomics, LDNP/STNP, PRFUM, RPRFM (excluded from `PRFM_reg` by
its diagram), and every FP/SIMD load/store. (Acquire/release: A7c.)

## Lowering (one path: `MemShape` -> `plan_mem` -> `emit_mem_lowering`)

`MemShape` = the `LDTR*`/`STTR*` op (element size + extension), `rt`, optional
`rt2`, and an address mode. Every access uses the op with the user form's element
size and extension, so the loaded value needs no fix-up.

| user form class | address into | accesses |
| --- | --- | --- |
| imm offset/pre/post, unscaled (`simm9`-reachable) | base itself, `#off` | 1 (pair: 2 at `off`, `off+size`) |
| same, offset outside `simm9` | scratch = base ± imm (`ADD`/`SUB`, opt. `lsl #12`) | at `#0` (`#size`) |
| register offset `[Xn, Rm, ext #s]` | scratch = `ADD Xs, Xn, Rm, ext #s` (extended register) | 1 at `#0` |
| literal | scratch = absolute `pc + imm19*4` (`MOVZ` + `MOVK` per non-zero halfword) | 1 at `#0` |
| PRFM (any) | none: rephrase emits one `NOP` | 0, no fault stub |

- Ops: `LDR W`/`LDUR W`/`LDP W` -> `LDTR W`; `LDRB` -> `LDTRB`; `LDRH` -> `LDTRH`;
  `LDRSB W/X` -> `LDTRSB W/X`; `LDRSH W/X` -> `LDTRSH W/X`; `LDRSW`, `LDPSW`,
  `LDRSW (literal)` -> `LDTRSW`; stores likewise with `STTR`/`STTRB`/`STTRH`.
- Register offset: the shift is `S ? log2(size) : 0`; the `*BL` byte forms are
  option `LSL` (0b011). No writeback. Scratch worst case stays 4
  (`ldr x12, [x13, x14, lsl #3]`: three stack-backed registers + the address).
- Literal: the address is fixed at translation time from the instruction's
  original PC, exactly as ADR's rephrase. Reading it is a user access, so an
  unmapped or execute-only literal page faults into the `Mem` stub and
  userspace re-executes the load.
- Pair first-load scratch takes `rt`'s width; the follow-up move is a 64-bit
  `MOV`, exact because every pair load (LDP W zero-extends, LDPSW sign-extends)
  writes the whole X register.
- Commit-after-last-access is unchanged: all new address materialization writes
  only scratch, before the first access.

## PRFM is dropped

- A prefetch is a hint: it has no architectural effect on registers or memory
  and never generates a synchronous data abort, whatever the address. Replacing
  it with a `NOP` (kept so the original PC still maps to code) is exact.
- It also keeps the fragment from issuing EL1 prefetches of user addresses.
- Its metadata has no `Memory` role (the specgen `Memory` role now requires an
  actual `Mem{..}` access), so rephrase gives it no fault stub.

## Constrained unpredictable / UNDEFINED

- `is_decode_undefined`: register-offset forms with `option<1> == 0` (sub-word
  index) are UNDEFINED. The `*BL` byte forms and PRFM (register) fix it in their
  diagrams. No other new form has a decode-time UNDEFINED case.
- The generic role-driven reg-virt rule covers every new form: writeback base ==
  transfer register (loads and stores, base not SP) and LDP/LDPSW `rt == rt2`
  are `UnpredictableMemoryOp`. Register offset has no writeback, so `rt == rn`
  or `rt == rm` is well defined and translated.

## specgen changes

- `!=` diagram constraints are generated: a box cell `!= <pattern>` or per-bit
  `Z`/`N` cells (e.g. `LDRB_32B_ldst_regoff`'s `option != 011`) become
  `excludes` `(mask, value)` pairs, checked by the generated decoder and
  `GeneratedInsnSpec::matches`. Without it `LDRB_32B` would claim `LSL` words.
- Load/store operand roles come from the XML, not mnemonic lists: direction
  from the execute pseudocode's `CreateAccDescGPR(MemOp_LOAD|STORE|PREFETCH)`,
  writeback from `address-form`, `Rm` as a 64-bit read (as for ADD extended),
  every `imm*` as `MemOffset`. Roles of the pre-A7b forms are unchanged
  (checked by regenerating before adding forms).
- A register-named field is only a register if a role reads/writes it (PRFM's
  `Rt` is its prefetch operation, a plain `u8`).
- A `MemOffset` field that encodes a `<label>` decodes as a signed word offset.

## Known gaps

- SP alignment: Linux checks SP alignment for SP-based accesses at EL0; a
  misaligned SP base faults natively. Fragments address through x17 with
  `LDTR*`, so they do not fault, and the interpreter does not model the check.
  Only code with a misaligned SP (already broken) is affected; fixtures keep SP
  16-byte aligned.
- Literal pools inside the text are not exercised by fixtures: the harness user
  page map covers the data window only. `mem_literal.s` targets the data window
  through `.Ltext + (DATA_BASE - TEXT_BASE)` and so assumes the default text
  base.

# V2 contract: differential fuzzer (2026-09-27)

- One oracle. `run_differential` runs both sides (original through the
  interpreter, fragment through `URuntime`); `compare_differential` is the only
  state/halt check, used by `run_entry_fixture` (fixture suite, `trace-tui
  --check`) and the fuzzer. It translates, verifies (V3), runs the fragment
  (a `Budget` exit caps the original at the same instance), then the original.
  Bounded runs (`StepLimits`, the fuzzer): a program where neither side halts
  (an SVC in an endless loop restarts the budget) is discarded; one side
  halting alone is a failure. A verifier rejection is its own failure class. A
  fault matches `ReturnedToUserspace { Mem }` at the same PC (the A5 contract)
  and is a verdict like every other halt. The A5 store footprint applies to
  natural faults too (found by the fuzzer: an `STP` straddling into the
  read-only page): the store units written before the faulting access may hold
  their new value (`faulting_store_footprint`, `compare_differential`).
- Generation is driven by the generated metadata only: `GENERATED_A64_SUBSET`
  (fixed mask/value, fields), operand roles, `get_reg` (SP/ZR mode), the
  generated `mem_operand()` accessor (offset signedness and scale are read back
  from the decoder) and `literal_address`. No per-form tables in the fuzzer.
  Register-offset forms read their index from registers holding small values;
  literal loads target the data window. Instances `admit_word` rejects are
  kept for 3% of slots (they exercise the Unsupported exit).
- Non-verdicts are counted, never passed: original did not halt (discarded);
  `chained` (the original stopped at a BL/BLR/BR/RET whose
  target the fragment translated; the runtime continues there, the interpreter
  does not). Deferred: model chaining in the original runner (continue at a
  translated exit target, as `decide_runtime_return` does) instead of skipping.
- Minimizer signature: failure kind + how the original halted, so deleting an
  exit cannot turn one bug into another (a fall-off-the-end program).
- Bugs found, now regression fixtures in `tests/arm64/` (a fixture that still
  fails waits in `tests/arm64/fuzz-pending/`, which the suite skips):
  1. Fall-through adjacency (`fuzz_regress_3d74ff35501da143.s`): see "Execution
     budget (A6)", layout order.
  2. Running off the readable text (`fuzz_regress_4d8286952cad317f.s`): see
     "Unsupported-instruction exit", `Unreadable`.
  3. EL0 SP alignment (`fuzz_regress_bf938844fc6f2fe6.s`): see "Memory rewrite
     (A5)", SP alignment check.
- The fixed-seed slice in `make harness-test` (2000 programs) must have no
  failure.

# Barriers and acquire/release (A7c, 2026-09-27)

Why: a static scan of glibc 2.36 (redis's libc) has 493/510 syscall sites fully
translatable; `dmb ishld` (5) and `ldar w` (2) are among the first blockers, and
malloc, stdio locks and refcounts use both throughout.

## Forms

Added (exact XML names, `spec/arm64/subset.toml`):

- barriers: `DMB.DMB_BO_barriers`, `DSB.DSB_BO_barriers`, `ISB.ISB_BI_barriers`,
  every CRm value: the named options and the reserved ones, which the XML
  defines as behaving like SY (DSB CRm 0000/0100 are SSBB/PSSBB). The nXS DSB
  (`DSB_BOn_barriers`, FEAT_XS) stays out.
- acquire/release, base register only: `LDAR.LDAR_LR{32,64}_ldstord`,
  `LDARB.LDARB_LR32_ldstord`, `LDARH.LDARH_LR32_ldstord`,
  `STLR.STLR_SL{32,64}_ldstord`, `STLRB.STLRB_SL32_ldstord`,
  `STLRH.STLRH_SL32_ldstord`, `LDAPR.LDAPR_{32,64}L_memop`,
  `LDAPRB.LDAPRB_32L_memop`, `LDAPRH.LDAPRH_32L_memop` (12 forms).
- Their should-be-one fields are pinned in `[decode.field_constraints]`
  (`Rs = 31, Rt2 = 31`; LDAPR `Rs = 31`), like SMULH's `Ra`: other values are
  CONSTRAINED UNPREDICTABLE and stay undecodable.
- Still out: exclusives (LDXR/STXR/LDAXR/STLXR/...), LSE atomics (LDADD, CAS,
  SWP, ...), FEAT_LRCPC2 `LDAPUR`/`STLUR`, FEAT_LRCPC3 writeback `LDAPR`/`STLR`,
  FP/SIMD (unit test, `unsupported_exit.s`, mutation words).
- `is_decode_undefined`: none of the new forms has a value rule. LDAPR's
  decode is UNDEFINED only without FEAT_LRCPC, a CPU property (see
  assumptions).

## Barriers: emitted unchanged

- They are user-semantic instructions with no operand roles; reg-virt rewrites
  nothing, so the word reaches the fragment unchanged.
- Same effect at EL1 as at EL0 for every observer of user memory: DMB/DSB order
  the fragment's memory accesses (the `LDTR*`/`STTR*` are the user's accesses)
  the same way; DSB additionally waits for maintenance operations, which the
  fragment has none of; the DSB pseudocode's FEAT_XS `nXS` rule treats EL0 and
  EL1 alike; ISB is a context synchronization with nothing EL-specific.
- Interpreter: no-ops. The model has one observer (a single thread, no caches,
  no speculation), where every access is already in program order, so no
  barrier can change an outcome. Ordering is not differentially tested; see
  the mapping argument below.

## Acquire/release lowering

No unprivileged ordered access exists without FEAT_LSUI, so reg-virt lowers
every ordered form through the one memory path (`MemShape { ordered: true,
addr: MemAddr::Base }` -> `plan_mem` -> `emit_mem_lowering`):

| user form | emitted (after fills) |
| --- | --- |
| `LDAR{,B,H} / LDAPR{,B,H} Rt, [Xn]`, `STLR{,B,H} Rt, [Xn]`, Xn not SP | [alignment check]; `dmb ish`; `LDTR*/STTR* Rt, [Xn, #0]`; `dmb ish` |
| same, Xn = SP | SP check (`and xS, x17, #15; cbnz xS`); `dmb ish`; access via x17; `dmb ish` |

- Op per form: the same element size and extension as the plain load/store
  (`LDAR W`/`LDAPR W` -> `LDTR W`, `LDAR X`/`LDAPR X` -> `LDTR X`,
  `LDARB`/`LDAPRB` -> `LDTRB`, `LDARH`/`LDAPRH` -> `LDTRH`, `STLR W/X` ->
  `STTR W/X`, `STLRB` -> `STTRB`, `STLRH` -> `STTRH`).
- The fences are `RegVirtHelper` instructions: runtime-owned, no registers.
  The access is the usual `UserAccess` fault site with the instruction's `Mem`
  stub; commit-after-last-access holds unchanged (the trailing fence writes
  nothing; a load-acquire into a stack-backed register spills after it).
  A fault on the access leaves after the leading fence: an extra barrier, no
  effect.
- Scratch: stack-backed `Rt`/`Rn` plus one for the alignment check: at most 3.

### Why the full-fence mapping is correct

`DMB ISH` (CRm 1011, reads and writes both sides) orders every memory access
before it in program order before every access after it, for every observer in
the Inner Shareable domain, which holds every CPU that can run the process
(Linux's `smp_mb()`).

- Acquire (LDAR, and LDAPR's weaker RCpc acquire): the access must be observed
  before every later access. The trailing fence gives exactly that.
- Release (STLR): every earlier access must be observed before the store. The
  leading fence gives exactly that.
- RCsc (LDAR): a store-release followed in program order by a load-acquire must
  be observed in that order. The fence after the STTR (and the one before the
  LDTR) sits between them.
- Multi-copy atomicity: Armv8 is other-multi-copy-atomic for every store, not
  only STLR, so the `STTR` of a store-release becomes visible to all other
  observers at once, as the STLR would. Single-copy atomicity of the access
  itself is that of an access of the same size and address; LDAR/STLR are only
  more atomic for misaligned-within-16-byte addresses under FEAT_LSE2 (see "Not
  verified").
- The mapping is strictly stronger (it also orders earlier accesses before a
  load-acquire and a store-release before later accesses), so every execution
  it allows is one the original allows. Weaker (one-sided) mappings are a
  later optimization, not a correctness need.
- Dropping a fence is a correctness bug but not a safety one: the verifier
  (V3) checks safety, not ordering, and accepts a fragment without them.

### Alignment

- `LDTR*`/`STTR*` never alignment-fault (SCTLR_EL1.A = 0). An ordered access
  does: `AArch64_UnalignedAccessFaults` with `acqsc`/`acqpc`/`relsc` faults a
  misaligned access iff SCTLR_ELx.nAA == 0 and it crosses a 16-byte boundary.
  Linux leaves nAA clear. Probed on the native host (Apple M1 Max, FEAT_LSE2,
  Linux container): `ldar x` at block offsets 1..8 runs, 9..15 SIGBUS
  (BUS_ADRALN); `ldar w` faults from 13, `ldarh` at 15; `stlr`/`ldapr` alike.
- So for every ordered access wider than a byte whose base is not SP, reg-virt
  emits before the fences (kind `AlignCheck`, flags untouched):
  `and xS, xN, #15; add xS, xS, #(size - 1); and xS, xS, #16; cbnz xS, <Mem stub>`
  (bit 4 of `(addr & 15) + size - 1` is set iff the access crosses). The Mem exit
  returns to userspace at the instruction, which re-executes natively and takes
  the SIGBUS itself: exact. `CBNZ` (imm19), not `TBNZ` (imm14, +-32 KiB), so a
  large fragment cannot put the cold region out of range. An SP base needs no
  such check: the SP check already requires SP 16-byte aligned and the access is
  at SP. Bytes are always aligned.
- Interpreter: an ordered access that crosses a 16-byte boundary is a
  `FaultCause::Alignment` fault before any access (after the SP check, as in the
  pseudocode), on the untagged address; the native original reports it as a
  SIGBUS at the instruction, which the generic fault match accepts.

### Kernel assumptions (pinned: module init, see "K2 contract", Preconditions)

- FEAT_LSE2 with SCTLR_EL1.nAA == 0. On a CPU without FEAT_LSE2 every misaligned
  ordered access faults natively, while a fragment runs a misaligned one that
  stays inside a 16-byte block: more permissive than native (never unsafe:
  still an EL0-permission `LDTR*`/`STTR*`). The kernel should require
  `ID_AA64MMFR2_EL1.AT != 0`, or the translator would need the stricter check
  (`and xS, xN, #(size - 1); cbnz`).
- FEAT_LRCPC for LDAPR: without it user LDAPR is UNDEFINED (SIGILL natively)
  but the fragment would run it. The kernel should require
  `ID_AA64ISAR1_EL1.LRCPC != 0`, or LDAPR must leave the subset on such CPUs.

## Verifier (V3) changes

- `rules::classify`: DMB/DSB/ISB -> `Form::Barrier` (allowed like NOP, in the
  body and in exit groups); the 12 ordered forms -> `Form::UserOnly`. Rule 5
  above lists the allowlist. The random-word cross-check treats a barrier like
  an ALU word (no memory/control roles).
- Mutation suite: new classes "insert acquire/release user form (A7c)" and
  "insert non-allowlisted barrier-like system op (A7c)" (DSB nXS, SB, CLREX,
  WFE, WFI, YIELD, ESB); `ldaxr`, `stlxr`, `cas` and the LRCPC2/3 forms joined
  the foreign words. Removing a fence is deliberately not a mutation class.

## specgen changes

- `CreateAccDescAcqRel(MemOp_LOAD|STORE, ...)` and `CreateAccDescLDAcqPC(...)`
  (load) are load/store access descriptors for role inference; exclusive and
  atomic descriptors still are not.
- A register field of a load/store is an operand only if its decode or
  postdecode pseudocode binds it (`UInt(Rt2)`): LDAR's `Rs`/`Rt2` get no role
  and can be pinned.
- A load/store's register roles come from the load/store inference alone, not
  from the generic `X(n)`/`X(t) =` scan: the execute pseudocode is shared by a
  section's encodings (STLR's ldstord form shares the LRCPC3 writeback form's
  `X{64}(n) = address`). No existing form's metadata changed (checked by
  regenerating before adding the forms).
- A base-register-only form has no `MemOffset`, so it keeps plain `rn`/`rt`
  fields (no `A64Mem`); reg-virt builds `MemAddr::Base(rn)` and the fuzzer
  derives the base from the `MemBase` role as for register-offset forms.

## Not verified

- Ordering. The interpreter is single-threaded and the native oracle runs one
  thread; no test observes a reordering. The mapping rests on the argument
  above.
- Single-copy atomicity of a misaligned-within-16-byte `LDTR*`/`STTR*` under
  FEAT_LSE2 (LDAR/STLR/LDAPR are single-copy atomic there; aligned accesses are
  single-copy atomic either way).


# BTI, carry arithmetic, CRC32 (A7d, 2026-09-27)

Why: in the K3 guest runs every redis path stopped at `bti c` (0xd503245f) at
function entries (~1.58M entry stops), and busybox/coreutils at `adc`.

## Forms

Added (exact XML names, `spec/arm64/subset.toml`):

- `BTI.BTI_HB_hints` (targets none/c/j/jc). The diagram fixes CRm = 0100 and
  op2<0> = 0, so only the four BTI words match; every other HINT-space word
  (PACIASP/AUTIASP/PACIBSP/AUTIBSP/XPACLRI, YIELD, WFE, SEV, CSDB, CHKFEAT, the
  odd op2 values next to BTI) stays undecodable (unit test over all 128 hint
  immediates; mutation class "insert non-subset hint / PAC (A7d)").
- `ADC.ADC_{32,64}_addsub_carry`, `ADCS.ADCS_{32,64}_addsub_carry`,
  `SBC.SBC_{32,64}_addsub_carry`, `SBCS.SBCS_{32,64}_addsub_carry` (NGC/NGCS are
  SBC/SBCS with Rn = 31).
- `SMSUBL.SMSUBL_64WA_dp_3src`, `UMSUBL.UMSUBL_64WA_dp_3src` (SMNEGL/UMNEGL:
  Ra = 31).
- `CRC32.CRC32{B,H,W}_32C_dp_2src`, `CRC32.CRC32X_64C_dp_2src`,
  `CRC32C.CRC32C{B,H,W}_32C_dp_2src`, `CRC32C.CRC32CX_64C_dp_2src`. Generated
  without specgen work beyond the width fix below; their `sf`/`sz` UNDEFINED
  combinations are fixed by each form's diagram.
- `is_decode_undefined`: no new value rule. BTI without FEAT_BTI is
  `Decode_NOP`; CRC32's remaining UNDEFINED case is a missing FEAT_CRC32, a
  CPU property the module checks at init (see "K2 contract", Preconditions).

## BTI is rephrased to NOP

- Executed in sequence, BTI is a NOP. Its only effect is the landing-pad check
  of an indirect branch into a guarded page (PSTATE.BTYPE). A fragment is never
  one: entries come from the runtime through the prologue's `br x12` with
  kernel BTI off (K1), and a `Blr`/`Br` exit does not carry BTYPE (see "K3",
  BTI limitation). So a `NOP` is exact for every correct program; a native BTI
  fault on broken control flow is missed, as before.
- One `NOP` (user-synthetic, like PRFM's) keeps the original PC mapped to
  fragment code, so a BTI can be an entry, a branch target and a back-edge
  target.
- No BTI reaches EL1: the verifier classifies BTI as `UserOnly`
  (`UserOnlyForm`), so the allowlisted HINT space stays exactly NOP. Mutation
  class "insert BTI (A7d)".
- Harness interpreter: NOP (the original runs it in sequence).

## Carry arithmetic

- Pure ALU (`Form::Alu`): no memory, control-flow or system effect. They read
  NZCV.C; ADCS/SBCS write NZCV. Generated metadata now says `FlagsRead` for
  exactly these 8 forms (see "Flags metadata"); nothing consumes it.
- Correct only because the fragment keeps NZCV intact between user
  instructions: nothing the translator emits sets flags (reg-virt fills/spills
  are LDR/STR, the SP and alignment checks AND/ADD/CBNZ, the budget check
  LDR/SUB/STR/CBZ, exit payloads MOVZ/MOVK/ORR); the budget-check unit test
  pins it for that sequence, and the kernel trampoline loads/stores user NZCV
  around every fragment call (K2). `adc_chain.s` carries C across an SVC exit
  and resume, and across stack-backed fills.
- Interpreter: `AddWithCarry(Rn, Rm or NOT(Rm), PSTATE.C)` on the operand
  width, flags only for the S forms.

## SMSUBL/UMSUBL, CRC32

- `Form::Alu`. Interpreter: `Ra - sext/zext(Wn) * sext/zext(Wm)`; CRC as the
  bit-reflected update of the pseudocode's `Poly32Mod2` (polynomials
  0x04C11DB7 / 0x1EDC6F41, LSB first, no pre/post inversion), checked against
  the standard "123456789" check values and on hardware.

## specgen changes

- `FlagsRead` inference (above). Only the 8 carry forms gain it.
- A register role derived from the execute pseudocode takes its width from the
  field's assembler operand when there is one, and an operand's own `<W..>`/
  `<X..>` wins over the form's `datatype`: CRC32X/CRC32CX are `datatype = 64`
  forms with `<Wd>, <Wn>, <Xm>`. Effect on existing forms: SMADDL/UMADDL lose
  their spurious 64-bit read roles of `Wn`/`Wm` (decoded widths unchanged);
  nothing else changes (checked by regenerating). Widths only matter to
  reg-virt as known vs `Unknown`; the decoded width drives the pretty-printer.

## Tests

- `tests/arm64/bti_entry.s`: `bti c` entries, a `bti j` loop head reached by
  the budgeted back-edge, `bti` mid-block, `bti jc`, calls out through
  `bl`/`blr`/`br`, callees translated at their own `bti c`/`bti j`/`bti jc`
  entries; `paciasp` as an entry word and `autiasp` before `ret` still exit
  `Unsupported`.
- `tests/arm64/adc_chain.s`: 128-bit counter with an SVC between ADDS and ADC,
  192-bit add/subtract with carry/borrow-dependent branches, 128-bit
  signed/unsigned compare (`cmp; sbcs xzr`), 32-bit forms, NGC/NGCS, stack-backed
  operands, SMSUBL/UMSUBL/SMNEGL/UMNEGL and every CRC32 form.
- Unit tests: hint space, new-form decode and CRC32 `sf`/`sz` UNDEFINED words,
  carry boundaries, 128-bit chains, CRC check values, verifier `UserOnlyForm`
  for every BTI target.

## Not verified

- The kernel module build and the new FEAT_CRC32 check (no kernel build tree in
  this environment); guest coverage (redis, busybox) after A7d.
- BTYPE is still not modelled (unchanged limitation).

# A8 contract: user LSE atomics through a PAN window (2026-09-27)

Written before implementation. Why: under K4, redis's paths end at
`ldadd` (libgcc outline atomics pick LSE when HWCAP_ATOMICS is set);
there is no unprivileged LSE form without FEAT_LSUI, which no current
hardware has. Linux's own futex code (`arch/arm64/include/asm/futex.h`)
performs privileged accesses to user memory by clearing PAN after
`access_ok`; this contract does the same inside a fragment, with a
shape the independent verifier can check word by word.

## Scope

- In: LSE single-register atomics: `LDADD/LDCLR/LDEOR/LDSET/LDSMAX/
  LDSMIN/LDUMAX/LDUMIN` (all size and A/L/AL variants), `SWP*`, `CAS*`
  (not `CASP`), and the `ST<op>` aliases (Rt = XZR forms of LD<op>).
- Out, still Unsupported: exclusives (`LDXR/STXR/LDAXR/STLXR`, pairs).
  Why: a fragment executes fills/spills (plain stores to the kernel
  stack) between the user's LDXR and STXR, which may clear the local
  exclusive monitor (IMPLEMENTATION DEFINED), and exception returns
  clear it; correctness would survive (STXR failure is always legal
  and the budget bounds the retry loop) but progress would not.
- Out: `CASP`, FEAT_LSE128, FEAT_LSUI forms.

## Lowering (per atomic, through the single memory-lowering path)

```
  <address into scratch sA: Rn (mapped), no offset for LSE>
  ubfx sB, sA, #48, #8        ; VA bits [55:48]
  cbnz sB, <PAN stub>         ; not a TTBR0 user address below 2^48 -> Mem exit
  msr  pan, #0
  <the user's LSE atomic, operands remapped, base = sA>   ; fault site -> PAN stub
  msr  pan, #1
  <register moves / spills>   ; commit-after-last-access as usual
```

- The range check accepts any top byte (TBI0 ignores bits [63:56] for
  TTBR0 accesses at EL1 too) and requires bits [55:48] == 0: bit 55
  selects TTBR0 vs TTBR1, and user VA is 48 bits (K1 pins
  `ARM64_VA_BITS_48`; the module checks `vabits_actual == 48` at init
  and refuses to load otherwise). Rejected addresses exit through the
  same PAN stub (harmless: `msr pan, #1` with PAN already set).
- The PAN stub is the instruction's ordinary `Mem` exit group preceded
  by `msr pan, #1`. The atomic's fault-site entry points at it: the
  extable fixup resumes with the faulting context's PSTATE (PAN = 0),
  so the stub must restore PAN before anything else.
- SP-based atomics keep the SP alignment check; LSE atomics require
  natural alignment (a misaligned address faults natively) — add the
  same flag-free alignment check to the PAN stub path as A7c's
  acquire/release forms, unless FEAT_LSE2 makes that access legal
  (then match native: aligned-within-16-bytes is fine).
- Exceptions inside the window: Linux runs with SCTLR_EL1.SPAN = 0, so
  taking an exception to EL1 sets PAN, and ERET restores the window's
  PAN = 0. Preemption saves/restores PSTATE the same way.

## Kernel requirements (module init refuses to load otherwise)

- FEAT_LSE present (else user LSE is UNDEFINED natively).
- `vabits_actual == 48`.
- No MTE in use (`!system_supports_mte()`): a privileged access does
  not honour the user's tag-check mode the way LDTR/STTR do.
- Known exposure, same as the kernel's own futex ops without EPAN: a
  privileged atomic can read an execute-only user page that an EL0
  access could not. Recorded, not mitigated.

## Verifier (V3) rule

- `msr pan, #0` appears only as the exact window: immediately preceded
  by `ubfx sB, sA, #48, #8; cbnz sB, <stub S>`, immediately followed by
  exactly one LSE atomic whose base register is sA and whose fault-site
  entry points at S, immediately followed by `msr pan, #1`. No join
  point inside the window. S is an exit-group start whose first word is
  `msr pan, #1`.
- `msr pan, #1` appears only as the window end or as the first word of
  a PAN stub. No other MSR is allowed.
- A PAN stub is a legal target only for window cbnz and fault sites of
  window atomics (other branches into a PAN stub are harmless but are
  rejected to keep the rule simple).

## Harness

- The interpreter models PSTATE.PAN for fragment runs: a privileged
  access (the LSE atomic) to user memory is legal only while PAN = 0,
  otherwise it is a PAN violation (hard error). Original-code runs
  execute LSE atomics as EL0 user accesses.
- The native runner executes fragments at EL0, where `msr pan` is
  UNDEFINED: its fragment copy replaces the two MSRs with NOPs (the
  atomic at EL0 already has user permissions). Documented as the one
  native-leg deviation.

# A8 implementation (2026-09-27)

Implements "A8 contract". Decisions the contract left open:

## Forms (`spec/arm64/subset.toml`)

- The 160 LSE single-register atomics, exact XML names:
  `LD{ADD,CLR,EOR,SET,SMAX,SMIN,UMAX,UMIN}{,B,H}.*_memop`, `SWP{,B,H}.*_memop`
  (each: `_32`/`_64` or `_32` for B/H, times none/A/AL/L) and
  `CAS{,B,H}.*_comswap` (`C32`/`C64`, times none/A/AL/L). `ST<op>` is `LD<op>`
  with Rt = XZR (decodes as that form). CASP, FEAT_LSE128 (`LDCLRP`, `SWPP`,
  ...), FEAT_LSUI and exclusives stay undecodable.
- `MSR_imm.MSR_SI_pstate` pinned to PSTATE.PAN by `[decode.field_constraints]`
  (`op1 = 0, op2 = 4`); CRm (the immediate) stays an operand. Every other
  PSTATE field (UAO, SPSel, DAIFSet/Clr, DIT, TCO, SSBS, ALLINT, SM/ZA) and
  CFINV/XAFLAG/AXFLAG stay undecodable (unit test over all op1/op2/CRm).
- `is_decode_undefined`: none of them has an encoding rule (missing FEAT_LSE /
  FEAT_PAN are CPU properties the module checks).
- specgen: an execute pseudocode building `CreateAccDescAtomicOp(...)` (the
  access goes through `MemAtomic{..}`, which the `Mem{..}` rule did not match)
  gives `MemBase Rn` and `Memory`; register roles come from the generic `X(..)`
  scan (CAS: Rs read + write, Rt read; LD<op>/SWP: Rs read, Rt write). No
  existing form's metadata changed (JSON compared before/after).
- `A64Insn::lse_atomic()` (op, size, rs, rt, rn) and `msr_pan()`: translator
  and harness helpers, pinned against the generated mnemonics. The verifier
  does not use them (own list in `rules::classify`).

## Lowering (reg-virt, `RewritePlan::build` -> `plan_atomic` -> `emit_atomic_window`)

`RewritePlan.mem` is `MemPlan::Unpriv(MemLowering) | MemPlan::Atomic(..)`: the
same build/plan/emit point as every other memory form.

| step | emitted | kind |
| --- | --- | --- |
| fills | `ldr xS, [sp, #slot]` of stack-backed Rs/Rt(read)/Rn | RegVirtHelper |
| SP base only | `and sB, x17, #15; cbnz sB, <Mem stub>` | AlignCheck |
| base not stack-backed | `mov sA, <mapped Rn>` (x17 for SP, x16 for x29) | RegVirtHelper |
| size > 1, base not SP | `and sB, sA, #15; add sB, sB, #(size-1); and sB, sB, #16; cbnz sB, <Mem stub>` | AlignCheck |
| range check | `ubfx sB, sA, #48, #8; cbnz sB, <PAN stub>` | RangeCheck |
| window | `msr pan, #0; <atomic, Rs/Rt mapped, Rn = sA>; msr pan, #1` | PanToggle, WindowAccess, PanToggle |
| spills | `str xS, [sp, #slot]` of the written stack-backed register | RegVirtHelper |

- `sA` is the stack-backed base's own fill scratch, else a fresh scratch;
  `sB` is always a fresh scratch. Worst case 4 (three stack-backed operands +
  `sB`, or two + `sA` + `sB`), so admission never runs out (unit test over all
  160 forms x 10 register classes per operand).
- Commit-after-last-access: before the atomic only scratch is written; the
  atomic writes its destination (Rt, or CAS's Rs) only when it retires; spills
  follow `msr pan, #1`.
- Alignment: LSE atomics use `AArch64_UnalignedAccessFaults`'s
  `exclusive || atomicop` rule: with FEAT_LSE2 they fault iff not inside one
  `MemSingleGranule()` block, IMPLEMENTATION DEFINED >= 16 bytes, independent
  of `nAA`. The check uses 16 (the minimum): an access it lets through never
  faults natively; one it stops leaves for userspace, which re-executes it
  natively, so on hardware with a larger granule it is conservative, never
  wrong. Probed natively (M1, native fixture): `ldaddal x` at +12 SIGBUSes.
- Two stubs per atomic that has an SP or alignment check. The contract's
  verifier rule allows a PAN stub only as the target of the window `cbnz` and
  of the atomic's fault site, so the alignment/SP checks (and they only) leave
  through a plain `Mem` stub of the same PC; the PAN stub is `msr pan, #1`
  (`RephrasedInsnKind::PanRestore`) + the same `Mem` exit group. Rephrase
  emits the plain one only when reg-virt will branch to it
  (`atomic_needs_check_stub`: size > 1 or an SP base); a byte atomic on a
  register base has only its PAN stub.
- User `msr pan` is rejected by `RewritePlan::build` (`PanUserForm`,
  intrinsic): Unsupported exit, userspace takes its SIGILL.
- Layout: PAN stubs have their own label map (one per PC, next to the plain
  stub map); a `RangeCheck` `cbnz` and a `WindowAccess` fault site resolve to
  the PAN stub, `AlignCheck` to the plain stub. `UntaggedPanWindow` if a kind
  and the instruction (LSE atomic / `msr pan`) disagree; `MissingPanStub`.

## Verifier (V3) rule 8 (`find_pan_windows`, `shared/verify/mod.rs`)

- `rules::classify`: the 160 atomics -> `WindowAtomic { rn }`; `msr pan, #0`
  -> `PanClear`, `#1` -> `PanSet`, any other CRm -> `MsrOther` (rejected:
  `Msr`).
- Pre-pass over the words: every `PanClear` at i must have `ubfx sB, sA, #48,
  #8` (64-bit UBFM, immr = `USER_VA_BITS`, imms = `PAN_WINDOW_RANGE_TOP_BIT`,
  sA/sB < 31) at i-2, `cbnz xsB, S` (64-bit) at i-1 with S > i+2 and S's word
  `PanSet`, a `WindowAtomic` with `rn == sA` at i+1 and `PanSet` at i+2
  (`PanWindow` otherwise). It records S as a PAN stub.
- Fault table: a `WindowAtomic` site must name its window's S
  (`PanStubTarget`; outside a window `AtomicOutsideWindow`); an LDTR/STTR site
  must not name a PAN stub. Every stub is still an exit group (rule 7), whose
  walk now accepts `PanSet` as its first word only.
- Branches: a target that is a PAN stub is legal only from a window `cbnz`
  aimed at it (`PanStubTarget`).
- Join points: none on the window's `cbnz`, either MSR or the atomic (the
  `ubfx` may be one: it recomputes the checked value).
- Main pass: `WindowAtomic` outside a window -> `AtomicOutsideWindow` (and it
  consumes its fault-site entry like a user access); `PanSet` neither a window
  end nor a PAN stub -> `PanSetOutsideWindow`.
- Constants come from `shared::abi` (`USER_VA_BITS = 48`,
  `PAN_WINDOW_RANGE_TOP_BIT = 55`).

## Harness

- Interpreter: `execute_atomic`: one read-modify-write access that needs write
  permission (a failing CAS too: its access descriptor is read + write), the
  EL0 SP check (original code), the 16-byte block alignment rule, then
  permissions; LD<op>/SWP return the old value in Rt, CAS in Rs (32-bit forms
  zero-extend); a failed CAS writes no memory.
- Fragment runs model PSTATE.PAN (`URuntime.pan`, set at every entry;
  `AccessContext::Fragment.pan`): `msr pan` writes it; a window atomic with
  PAN set is a hard error (PAN violation); with PAN clear it is
  `Privilege::Window`, counted with the user accesses (fault injection) and
  checked against the user page permissions, and it is a hard error on
  runtime memory or beyond 2^48. Every return to the runtime requires PAN set
  (hard error otherwise); a unit test removes a PAN stub's `msr` and gets it.
- Native runner: the fragment copy has NOPs for every `msr pan` (EL0 cannot
  execute it); the documented native-leg deviation.
- Fuzzer: plain slots pick an instruction section first, then an encoding
  (`Catalog::sections_of_class`), so the 160 atomic encodings (30 sections)
  do not crowd out the other memory forms. Forms are still generated from
  metadata only.

## Kernel

- `kjit_check_cpu`: FEAT_LSE (sanitised `ID_AA64ISAR0_EL1.Atomic >= IMP`),
  `vabits_actual == 48`, `!system_supports_mte()`, and additionally
  `SCTLR_EL1.SPAN == 0` (the contract's assumption that an exception inside a
  window sets PAN; `cpu_enable_pan()` establishes it). Each refusal is
  `-ENODEV` with a `pr_err` naming the cause.
- `kjit-invariants.conf` pins `CONFIG_ARM64_VA_BITS_48=y`.
- Nothing else changes: the fault site is an ordinary extable entry
  (`EX_TYPE_UACCESS_ERR_ZERO`), so `insn_may_access_user` accepts the atomic's
  EL1 permission faults, demand paging and CoW go through `handle_mm_fault`
  like `copy_from_user`, and an unresolvable fault resumes at the PAN stub.

## Findings (2026-09-27)

- Harness: every fixture case (87, incl. `tests/arm64/lse_atomics.s`: every
  operation and size, CAS success/failure, `st<op>`, SP / x12..x17 / x29 /
  x9..x11 operands, a refcount loop with an SVC, a tagged pointer, faults on
  the read-only and unmapped page, a kernel-half and a >2^48 pointer,
  misaligned inside and across a 16-byte block, SP misaligned, user `msr pan`)
  agrees interpreter, native original and native fragment, and passes the
  fragment fault-injection differential through the windows. Natively a CAS
  whose compare fails on a read-only page faults, and `ldaddal x` at +12 of a
  block SIGBUSes. Mutation suite: every A8 class 100% rejected.
- kjit-guest, `make redis-campaign`: `RESULT PASS`; suite same outcome for
  all 2518 distinct tests; 5.8% of the suite's syscalls in the kernel (3.12M
  of 53.9M; before: 5.0%), no `Mem` exit, no verifier rejection. Benchmark
  unchanged (0.0% default, 1.6% `-P 16`, 0.7% 256 clients): the paths now
  run past `ldadd` and stop at `dup v0.16b, w1` (0x4e010c20, SIMD; ~2.0M
  Unsupported exits per default run), so SIMD, not atomics, is the next
  redis blocker; under the suite also `mrs CNTVCT_EL0` (0xd53be04b).
- kjit-guest-debug, `K4_ITERATIONS=3`: `RESULT PASS`, dmesg clean (KASAN,
  lockdep); suite 4.5% in the kernel. K2 and K3 guest suites PASS on
  kjit-guest.

## Not verified

- A PAN window interrupted or preempted on real hardware is only argued
  (SPAN = 0 is checked at init); no test forces an exception inside the
  three-instruction window.
- An atomic inside a window that faults in the kernel (demand paging, CoW)
  and is retried: the guest runs had no such fault on a window atomic that
  was visible in counters (`exit_mem` 0; retried faults are not counted).
- Execute-only user pages (readable by a window atomic): recorded exposure,
  not tested.
- Multi-threaded atomicity/ordering of the window atomic vs other threads is
  the hardware's own (the same instruction runs), not tested by the
  single-threaded harness.

# K4: redis under KJIT (2026-09-27)

Goal: redis in the guest under the auto mode with exactly native behaviour,
checked by redis's own suite, redis-benchmark and adversarial tests, on
`kjit-guest` and `kjit-guest-debug`. Entry point `make redis-campaign`
(`scripts/redis-campaign.sh`, guest side `tests/guest/k4-*.sh`); usage and
latest numbers in README, "K4: Redis under KJIT".

## Environment

- redis 7.0.15 (= Debian bookworm's `redis-server` version), official tarball
  (sha256 pinned from redis-hashes), built in `debian:bookworm` with upstream's
  default flags, test modules built, installed as `/opt/redis` with
  `tclsh8.6` in `redis.cpio`, a cached rootfs layer between `base.cpio` and
  `tests.cpio` (`mk-guest-rootfs.sh --rebuild-redis`). Not built with
  `-mbranch-protection=standard`: Debian's redis is not (bookworm's
  dpkg-buildflags add none; its binary has no PAC and three `bti c`), so this
  keeps the distro's code shape. The BTI-built code on redis's paths is glibc.
- `kjit-guest.conf` gains the PL031 RTC (`RTC_CLASS`, `RTC_HCTOSYS`,
  `RTC_DRV_PL031`): without a wall clock the guest starts at 1970 + uptime and
  `unit/dump` (`RESTORE ... ABSTTL now-3000`) raises a test-client exception
  that aborts the whole suite. And `COREDUMP`/`ELF_CORE`, so the crash test
  compares core behaviour.
- Load generators run under `nojit` (allow-all seccomp), so the global
  counters are the server's (plus the runner shell and redis-cli calls).
- `DEBUG`, `MODULE` need `--enable-debug-command yes`,
  `--enable-module-command yes` (7.0 defaults are `no`).

## Pass criteria

- Suite: both runs reach "The End" (a test-client `[exception]` aborts
  runtest), and the same outcome for every test. Compared: the distinct
  `<status> <name>` lines with digit runs masked, plus the `err` lines
  exactly. Raw multisets are not comparable even between two runs of one
  kernel: `integration/psync2` loops for a fixed time (a varying number of
  `CYCLE <n>` / `Set #<a> to replicate from #<b>` / `(x = <random>)` tests).
- Benchmark: the full default test set completes in all three runs;
  `exit_invalid`, `translate_verify_rejected`, `unsupported_bad_word` stay 0
  (every phase); the off/on consistency dataset (`DBSIZE`, `DEBUG DIGEST`,
  sha256 of a full read-back) is identical.
- Adversarial: identical deterministic stdout KJIT off and on (exit statuses
  137/0/138/139, crash-report signal/si_code lines, digests before and after
  restarts, OOM error text); `K4_REQUIRE_HOT=1` (default) requires fragment
  entries during each load phase before the disruptive event.
- No kernel report on the serial console or in the campaign's `dmesg`.

## Exclusions

- None from the default `./runtest` list: all 84 units run (with one
  backported upstream test fix, see below). runtest itself
  ignores the 15 `large-memory` tests (need `--large-memory` and > 4 GiB).
  Not run: `--accurate`, `runtest-moduleapi`, `runtest-cluster`,
  `runtest-sentinel`, TLS (built without TLS).
- `DEBUG SEGFAULT` mmaps a read-only page and writes it, so the faulting
  address varies with ASLR; only its page alignment is compared.
- `maxmemory` with random keys (eviction samples randomly): only invariants
  (keys evicted, `used_memory` <= 33 MiB, noeviction OOM error text).
- No system memory pressure beyond `maxmemory`: the guest kernel has no
  compaction/migration and no swap, and initramfs text cannot be reclaimed,
  so reclaim/migration of hot text is not exercised here (K2 invalidation is
  covered by munmap and module unload).

## Findings

- kjit-guest, main at A7d: see README for numbers. No semantic difference in
  the suite, the benchmark consistency check or any adversarial test.
- kjit-guest-debug (generic KASAN, lockdep, DEBUG_ATOMIC_SLEEP, DEBUG_LIST),
  `make redis-campaign GUEST_PROFILE=kjit-guest-debug K4_ITERATIONS=10`:
  suite 2856 / 2869 passed without / with KJIT, 0 failed, same outcome for
  all 2518 distinct tests (3.4% of 38.0M syscalls in the kernel, 467M
  fragment entries, 11070 translations); 10 iterations of K2 micro tests +
  benchmark + 10 adversarial tests (100 adversarial runs, 10 consistency
  checks) all PASS; no BUG/WARNING/KASAN/lockdep/RCU report on the serial
  console or in dmesg (lockdep stayed enabled). ~13 min per iteration.
- Coverage: with A7d's BTI the paths leave libc and run through redis
  (~9.5 fragment entries per syscall under redis-benchmark), but 0-1.6% of the
  server's syscalls reach the kernel: nearly every path ends at `ldadd x0,
  x0, [x1]` (0xf8200020) in libgcc's `__aarch64_ldadd8_relax`, the outline
  atomic behind redis's `atomicIncr` (stat counters after every read/write).
  The suite adds `mrs CNTVCT_EL0` (0xd53be04b, vDSO clock reads), `ldadd w`,
  `casa`, `swpl` and SIMD `ldr q`/`dup`. LSE atomics have no unprivileged
  form without FEAT_LSUI, so translating them is a design decision (e.g. a
  PAN-cleared window with a fault site, as the kernel's futex ops do), not a
  subset addition.
- Before A7d, with redis built `-mbranch-protection=standard` (an experiment,
  then dropped, see Environment): paths stopped at `autiasp` (0xd50323bf,
  4.0M Unsupported exits per default benchmark run) and `bti c` (0.64M entry
  stops). PAC hints cannot simply run at EL1 (kernel keys are installed), so
  PAC-built distros need their own lowering.
- Speed: under the suite the KJIT run took 302 s vs 251 s (psync2's
  time-bounded loops ran fewer cycles); pipelined SET 1.92M vs 2.33M req/s.

## Test race in redis 7.0.15's suite (backported fix)

- 1 of 8 KJIT-on full-suite runs (7 kjit-guest, 1 debug; 0 of 5 KJIT-off runs)
  failed `unit/client-eviction` "client evicted due to percentage of
  maxmemory" (`assert {![client_exists $cname]}` right after writing a query
  of 7% of maxmemory from another connection), which left `maxmemory 6mb`
  set, so the next test's client was evicted and runtest aborted with an
  `[exception]`. Not reproduced in 110 + 110 runs of the unit alone KJIT
  on/off (60 with 6 CPU hogs) nor in 8000 iterations of the scenario in a
  tclsh loop.
- Cause: a race in the 7.0 test. The eviction happens when the server has
  read the query; the test checks CLIENT LIST on another connection right
  after flushing it, so the check can run first. KJIT's slower syscall path
  widens that window. Upstream fixed exactly these two asserts with
  `wait_for_condition`: redis/redis 447ce11a64bb ("solve race conditions in
  tests", #13433: the tot-mem check) and 64a40b20d906 ("Async IO Threads",
  #13695, test hunk only: the eviction check).
- Fix: `tests/guest/redis-patches/0001-*.patch` backports those two hunks
  verbatim onto 7.0.15 (header cites both commits). `mk-guest-rootfs.sh`
  applies every `tests/guest/redis-patches/*.patch` to the unpacked, still
  hash-checked tarball (`patch --forward --batch`, fail-fast) and records
  `<patch sha256> <name> on redis-7.0.15.tar.gz <tarball sha256>` in
  `/opt/redis/KJIT-PATCHES`. The test is neither skipped nor retried.

## Known limitations

- Counters are global; in-kernel fractions include the runner's own shell,
  sleep and redis-cli processes (small against the server's load).
- A test that fails identically with and without KJIT would pass the
  comparison; the baseline has no failed test today.

# A9 contract: FP/SIMD in fragments (2026-09-27)

Written before implementation. Why: after A8, redis's request paths
(epoll_pwait→read, read→read, read→write) are blocked only by FP/SIMD
code, almost all of it glibc memcpy/memset/strlen (`ldp/stp/stur/ldr q`,
`ld1`, `dup`, `cmeq`, `shrn`, `umaxp`, `fmov`, `bit`, `movi`). Facts
from `dep/linux` 7.1 `arch/arm64/kernel/fpsimd.c`: the user FP/SIMD
state stays live in the registers during a syscall unless
TIF_FOREIGN_FPSTATE is set (context switch, kernel-mode NEON);
kernel-mode NEON in softirq context saves the task's live state and
takes the registers (`kernel_neon_begin`, `get_cpu_fpsimd_context`
uses `local_bh_disable`); hardirq context never uses NEON
(`may_use_simd`); `fpsimd_restore_current_state()` reloads the user
state and is not exported.

## Translator

- FP/SIMD register operands are NOT virtualized: V0–V31, FPCR, FPSR
  are user registers live in hardware while a fragment runs (see
  kernel rules). GPR operands of FP/SIMD forms (`fmov x, d`,
  `dup v, w`, `umov`, addressing) go through reg-virt as usual.
- In scope first (A9a): data-movement and integer SIMD used by glibc
  string/memory routines and the E1 list: FP/SIMD loads/stores
  (LDR/STR/LDUR/STUR q/d/s/h/b imm forms, LDP/STP q/d/s, LD1/ST1
  multiple structures 1–4 regs, no-writeback and post-index), DUP
  (element, general), INS/UMOV/MOV element, MOVI/MVNI, FMOV
  (general↔FP, register), CMEQ/CMHI/CMHS/CMGT/CMGE/CMTST (reg, zero),
  AND/ORR/EOR/BIC/ORN/BIT/BIF/BSL/NOT (vector), ADD/SUB (vector),
  ADDP/UMAXP/UMINP/ADDV/UMAXV/UMINV, SHRN/USHR/SHL/USHLL/XTN, EXT,
  REV16/32/64 (vector), CNT, TBL (1 reg). Floating-point arithmetic,
  conversions and compares (FADD, UCVTF, FCMPE, ...) stay Unsupported
  in A9a: their rounding/exception semantics need FPCR/FPSR modelling
  that nothing requires yet.
- FP/SIMD memory forms have no unprivileged variants, so each is
  lowered as ONE privileged access inside an A8 PAN window: address
  into sA; `ubfx sB, sA, #48, #8; cbnz sB, <PAN stub>`; `msr pan, #0`;
  the user instruction with base sA (post-index writeback done
  separately after the window, as for GPR forms); `msr pan, #1`. It is
  the same instruction the user would execute, so its fault behaviour
  (including which destination registers of a multi-register load are
  written before an abort) is the architecture's, identical to native.
  SP-based accesses keep the SP alignment check. Commit-after-last-
  access applies to the GPR state (writeback after the window).
- `ExecutionFragment` needs no FP flag; the verifier computes it.

## Verifier (V3)

- Generalize the A8 window rule: the single instruction inside a PAN
  window is one of the allowed privileged user-access forms (LSE
  atomics from A8, FP/SIMD loads/stores from A9) with base sA and a
  fault site pointing at the window's PAN stub; nothing else.
- FP/SIMD register-only forms are allowed anywhere in the body.
- `verify_fragment` returns `VerifyOk { uses_fpsimd: bool }`: true iff
  any FP/SIMD form appears. The kernel uses THIS value (independent of
  the translator) to decide how to run the fragment.

## Kernel (A9b)

- A fragment with `uses_fpsimd` runs only inside:
  `local_bh_disable()` (on non-RT; this also makes the task
  non-preemptible) → if TIF_FOREIGN_FPSTATE, reload the user state
  (kernel patch 0005 exports `fpsimd_restore_current_state`) →
  `pagefault_disable()` → run → `pagefault_enable()` →
  `local_bh_enable()`. Chaining into another fragment re-enters this
  bracket per fragment.
- With pagefaults disabled, any user-access fault in such a fragment
  (LDTR*/STTR* or a window access) takes the fixup path → Mem exit →
  userspace re-executes natively and handles the fault; the next run
  finds the page present. Correct, occasionally slower.
- Refuse to install `uses_fpsimd` fragments when the system supports
  SVE or SME (streaming mode and ZA state change the rules; not
  modelled yet). The M-series HVF guest has neither.
- The budget bounds the non-preemptible run like any other fragment.

## Harness

- `MachineState` gains V0–V31 (128-bit) and FPCR/FPSR, compared in the
  differential and native checks (the native runner reads/writes them
  through the signal frame's fpsimd context and its call trampoline).
- The interpreter implements exactly the A9a forms, with the PAN window
  modelled as in A8.

# A9a implementation (2026-09-27)

Implements the Translator, Verifier and Harness parts of "A9 contract" (the
Kernel part is A9b). Decisions the contract left open:

## Forms (`spec/arm64/subset.toml`, 157)

- Loads/stores (82): `LDR_imm_fpsimd.LDR_{B,H,S,D,Q}_ldst_{immpost,immpre,pos}`,
  `STR_imm_fpsimd.STR_*` (same 15), `LDUR_fpsimd.LDUR_{B,H,S,D,Q}_ldst_unscaled`,
  `STUR_fpsimd.STUR_*`, `LDP_fpsimd.LDP_{S,D,Q}_ldstpair_{post,pre,off}`,
  `STP_fpsimd.STP_*`, `LD1_advsimd_mult.LD1_asisdlse_R{1..4}_{1..4}v`,
  `LD1_asisdlsep_I{n}_i{n}`, `LD1_asisdlsep_R{n}_r{n}`, and the same 12 of
  `ST1_advsimd_mult`.
- Register-only (75): `DUP_advsimd_elt` (scalar, vector), `DUP_advsimd_gen`,
  `INS_advsimd_elt`, `INS_advsimd_gen`, `UMOV_advsimd` (W, X), `MOVI_advsimd` (all
  six), `MVNI_advsimd` (all three), `FMOV_float_gen.FMOV_{S32,32S,D64,64D,V64I,64VX}`,
  `FMOV_float.FMOV_{S,D}_floatdp1`, `CMEQ/CMHI/CMHS/CMGT/CMGE/CMTST` (register and,
  where it exists, zero; scalar and vector), `AND/ORR/EOR/BIC/ORN/BIT/BIF/BSL`
  (vector), `NOT`, `ADD/SUB` (scalar, vector), `ADDP` (vector, scalar pair),
  `UMAXP`, `UMINP`, `ADDV`, `UMAXV`, `UMINV`, `SHRN`, `USHR`/`SHL` (scalar,
  vector), `USHLL`, `XTN`, `EXT`, `REV16/32/64`, `CNT`, `TBL_asimdtbl_L1_1`.
- Out (Unsupported exit, `a9a_subset_boundary` test and `unsupported_exit.s`):
  half-precision FMOV (FEAT_FP16: an EL1 UNDEF on a CPU without it would be an
  oops), FP arithmetic/conversion/compare, register-offset and literal SIMD&FP
  loads/stores, LD2-4, single-structure and replicate loads, LDNP/STNP, TBL/TBX
  with 2-4 table registers, ORR/BIC (vector, immediate), FMOV (vector,
  immediate), saturating arithmetic.

## specgen

- Register file of a field: a field is a SIMD&FP register iff an assembler
  operand encoded in it says "SIMD&FP" in its hover text. Its roles are the new
  `A64OperandRole::VecRead { field }` / `VecWrite { field }`; it renders as a
  plain `u8`, not an `A64Reg`, so no general-register code (reg-virt, the
  verifier's `reads`/`writes`, the fuzzer's register picker) can mistake it for
  one. Pseudocode accessors of the other register file on that field are dropped
  (FMOV (general) shares one pseudocode for both directions: `X(d)` and
  `Vpart(d, part)`).
- `Vec*` roles come from `V{..}(x)` / `Vpart{..}(x, part)` accessors (write iff
  `=` follows the call's closing parenthesis; `V{128}((n+i) MOD 32)` names `n`),
  with the variable map from decode + postdecode (loads bind `t` in postdecode).
- SIMD&FP loads/stores: direction from `CreateAccDescASIMD(MemOp_LOAD|STORE)`;
  `Rt`/`Rt2` get `VecWrite`/`VecRead` (LD1/ST1 name the first of their
  registers), base and offset roles as for general loads/stores, LD1/ST1
  post-index writeback from `as-structure-post-index`.
- No role names a field the encoding fixes completely (LD1 post-index by
  immediate fixes `Rm = 31`; before, the iclass-level field kept a `RegRead`).
- Every pre-A9a form's metadata is byte-identical (JSON compared).
- `form_base_word(spec)`: a spec's value with each `!=` exclusion escaped (SHRN/
  USHR/SHL/USHLL `immh != 0000`); the tests and the fuzzer catalog probe forms
  with it instead of `spec.value`, which those forms exclude.

## `is_decode_undefined`

DUP/INS/UMOV `imm5 == x0000`; DUP (vector, general) `imm5 == x1000 && Q == 0`;
UMOV (32-bit) `imm5 == x1000`; `size:Q == 110` for every vector CM*, ADD, SUB,
ADDP; `size == 11` for UMAXP, UMINP, XTN; ADDV/UMAXV/UMINV `size == 11 ||
size:Q == 100`; SHRN/USHLL `immh<3>`; vector USHR/SHL `immh<3> && Q == 0`; EXT
`Q == 0 && imm4<3>`; REV16 `size != 0`, REV32 `size >= 2`, REV64 `size == 3`;
CNT `size != 0`. Every other rule is fixed by the diagram (scalar forms fix
`size = 11` / `immh<3> = 1`, loads/stores fix size/opc per encoding) or is a
missing FEAT_FP/FEAT_AdvSIMD. Cross-checked against LLVM's disassembler
(`a9a_decode_admission_agrees_with_llvm_disassembler`, ignored test: 300 random
words per form, 46954 words, 2346 decode-undefined, 0 disagreements).

## Lowering (one path: `WindowInsn` -> `plan_window` -> `emit_window`)

A8's `plan_atomic`/`emit_atomic_window` became `plan_window`/`emit_window` over
`WindowInsn::{Atomic, FpSimd}`; `A64Insn::fpsimd_mem()` (translator and harness
helper, pinned against the generated forms) gives a SIMD&FP load/store's base,
pre-access offset, writeback and base-only access.

| step | emitted | kind |
| --- | --- | --- |
| fills | stack-backed base / LD1 index | RegVirtHelper |
| SP base | `and sB, x17, #15; cbnz sB, <Mem stub>` | AlignCheck |
| offset 0, base stack-backed | sA = the base's fill scratch | |
| offset 0, otherwise | `mov sA, <mapped base>` | RegVirtHelper |
| offset != 0 | `add/sub sA, <mapped base>, #offset` (1-2 words) | RegVirtHelper |
| range check | `ubfx sB, sA, #48, #8; cbnz sB, <PAN stub>` | RangeCheck |
| window | `msr pan, #0; <base-only access on sA>; msr pan, #1` | PanToggle, WindowAccess, PanToggle |
| writeback | `add/sub <base>, <base>, #amount` or `add <base>, <base>, <Xm>` | Original |
| spills | written stack-backed base | RegVirtHelper |

- The window holds the user's access in its base-only encoding (LDR/STR
  unsigned offset `#0`, LDP/STP signed offset `#0`, LD1/ST1 without post-index)
  on sA = the access's start address. Why: the range check then covers the first
  byte, and an access is at most 64 bytes, so it cannot reach bit 55 (the TTBR1
  half) whatever offset the user encoded; checking only the base would let
  `ldur q0, [x0, #-256]` with a small x0 wrap into the kernel half. Same size,
  registers and element order as the user's instruction, so its fault behaviour
  is the architecture's.
- Only SP-based accesses have a plain Mem stub (`window_needs_check_stub`):
  SIMD&FP accesses to Normal memory never alignment-fault at EL0
  (SCTLR_EL1.A = 0), so there is no block check.
- Scratch worst case stays 4: stack-backed base and LD1/ST1 index, sA, sB (unit
  test over every form x 10 base classes x 9 index classes).
- Rejected (intrinsic, Unsupported exit): SIMD&FP LDP `t == t2` (CONSTRAINED
  UNPREDICTABLE; the `VecWrite` overlap rule next to the GPR one), and LD1/ST1
  post-indexed by the base register itself (the existing writeback-overlap
  rule; conservative, the architecture defines it).
- Register-only forms: only their `Reg*` operands are mapped; V registers never.
- Layout: `WindowAccess` <=> `is_pan_window_access()` (LSE atomic or base-only
  SIMD&FP load/store); any other SIMD&FP load/store in a fragment is
  `UntaggedPanWindow`. Fault sites of window accesses resolve to the PAN stub.

## Verifier (V3)

- `rules::classify`: `Form::WindowAtomic` became `Form::WindowAccess { rn,
  fpsimd }`: the LSE atomics and the 24 base-only SIMD&FP load/store encodings
  with offset 0 (the one list of window accesses). Every other SIMD&FP
  load/store encoding, and a base-only one with a nonzero offset, is
  `UserOnly`. The 75 register-only forms are `Form::Simd`: allowed anywhere,
  exit groups included.
- Rule 8 unchanged otherwise: the access at `i+1` is any `WindowAccess` on sA
  with its fault site at the window's PAN stub; one outside a window is
  `AtomicOutsideWindow` (the name predates A9a).
- `verify_fragment` returns `VerifyOk { uses_fpsimd }`: true iff some word is
  `Form::Simd` or a `WindowAccess` with `fpsimd`. The harness cross-checks it on
  every differential run against the translator's view (an instruction with a
  `Vec*` role); the kernel's `runtime/translate.rs` refuses to install such a
  fragment (`Failure::FpSimd`, -EINVAL, counted in `translate_compile_failed`)
  until A9b (lifted there: "A9b implementation").
- Rule 9: see "Confidentiality (rule 9)", FP/SIMD registers.

## Harness

- `MachineState.v: [u128; 32]`, `fpcr`, `fpsr` (derived `PartialEq`: every
  comparison includes them). `harness/src/simd.rs`: every A9a form from its XML
  pseudocode (V writes zero-extend, `Vpart(d, 1)` keeps the low half, LD1/ST1
  one access per element in register-then-element order, TBL index >= 16 -> 0,
  SHRN/XTN write their half with `Vpart(d, Q)`).
- Window accesses in a fragment (`check_window_accesses`, shared with the
  atomics): PAN must be clear, the first access must start below 2^48 (a hard
  error otherwise: the range check exists to prevent it), no access may touch
  runtime memory; a later access past 2^48 is an ordinary fault.
- Fault footprint (`Footprint`, was the A5 store footprint): natively (M1, both
  original and fragment) a faulting `ldp q0, q1` crossing into an unmapped page
  has loaded q0, a faulting `ld1 {v4-v7}` has loaded v4 and v5, and a faulting
  `stp q` crossing into a read-only page has written its first 16 bytes. The
  architecture allows it (an aborted load's destinations are UNKNOWN; a SIMD&FP
  access is several single-copy-atomic parts) and userspace redoes the
  instruction anyway. So each byte of the faulting store on a writable page, and
  each byte of a faulting SIMD&FP load's destination V registers, may hold its
  old or its complete-execution value.
- Fault injection keys an LD1/ST1's element accesses by their order within one
  execution of the window access; the store-footprint normalization is
  byte-wise (16/32-byte units).
- Native runner: V0-V31/FPCR/FPSR go into user code through the SIGTRAP frame's
  `fpsimd_context` (first record of `__reserved`) and come back from every
  event's frame; the call trampoline loads them from `NativeCtx::fp` right before
  `blr` and stores them right after; they are carried across fragment calls as
  the kernel keeps them live. `msr pan` is still NOPed. FPCR/FPSR states stay
  inside `FPCR_USER_BITS` (AHP, DN, FZ, RMode, FZ16) / `FPSR_USER_BITS` (QC,
  cumulative flags), the bits the hardware keeps.
- Fuzzer: V registers random (zero, all-ones, a repeated lane, random with zero
  bytes, random), FPCR/FPSR random within the masks in 25% of states; forms come
  from the metadata as before (V fields are plain immediates to it). The
  minimizer lifts V registers with `fmov dN, x0` / `fmov vN.d[1], x0`; a state
  that still needs FPCR/FPSR cannot be lifted (no A9a form writes them).
- Fixtures: `simd_memcpy.s` (glibc memcpy loop, medium and long paths, SP-based),
  `simd_strlen.s` (glibc strlen, loop and short), `simd_memset.s` (dup + stp q
  loop, movi + st1 by register), `simd_ops.s` (every register-only form),
  `simd_faults.s` (ldp q into unmapped, stp q into read-only, str q post-index on
  read-only, ld1 x4 into unmapped, st1 x2 into read-only, SP misaligned ldr q /
  pre-index str q, kernel-half and > 2^48 pointers, a tagged pointer, LDP
  `t == t2`); `unsupported_exit.s` now ends at `ldr q1, [x12, x4]` and `fadd`.

## Findings (2026-09-27)

- Native (M1 Max, Linux arm64 container; original and fragment alike): a
  faulting SIMD&FP access is not all-or-nothing. `ldp q0, q1` from the last 16
  bytes of a read-only page into an unmapped one leaves q0 loaded; `ld1 {v4-v7}`
  running into an unmapped page leaves v4 and v5 loaded; `stp q0, q1` from the
  last 16 bytes of a writable page into a read-only one writes those 16 bytes.
  Hence the `Footprint` extension (Harness above); with it every fixture case
  agrees three ways.
- `make harness-test`: 110 fixture cases (22 new), all with the fragment
  fault-injection differential through SIMD&FP windows (e.g. 117 injected
  faults in `simd_strlen.s`, 149 in `memset_zero_mark`); mutation suite 110
  fragments, every A9a class rejected 100% (see the class table it prints).
- `make harness-test-native`: 220 tests, 110 fixture cases three-way equal
  (registers, V0-V31, FPCR, FPSR, memory, halt).
- `make fuzz ITERS=100000` (seed 1): 99730 run, 0 failed (270 non-terminating
  discarded); the 157 A9a forms: 527718 instances generated (702-9509 per form),
  4.6M original steps executed (532-109176 per form). Native fuzz (seed 7,
  20000, `--native` in the container): 19874 native-passed, 76
  native-unobservable, 0 failed; A9a forms 121-1919 instances, 48-48497 steps
  per form.
- `make spec-test-encoding`: 193 new LLVM cases (every A9a form at least once)
  plus the decode-admission cross-check above.

## Not verified

- The kernel side (A9b) and the kernel module build: `runtime/translate.rs`'s
  refusal of `uses_fpsimd` fragments was not compiled (no kernel build tree in
  this environment); no guest run.
- FPCR/FPSR bits outside `FPCR_USER_BITS`/`FPSR_USER_BITS` (trap enables, AFP
  bits) are never generated; no A9a form reads them, so fragments only carry
  them.
- Hardware other than the M1 for the partial-fault behaviour: the footprint
  rule allows what the architecture allows per byte, not a specific order.
- LD1/ST1 post-indexed by their own base register (rejected conservatively) and
  SIMD&FP LDP `t == t2` (rejected): no fixture shows their native behaviour.
- Multi-threaded observers of a window SIMD&FP access (single-copy atomicity of
  its parts) are the hardware's own; not tested.

# A9b implementation (2026-09-27)

Implements the Kernel part of "A9 contract" exactly as written; nothing in it
turned out unworkable. No `shared/` change.

## Kernel patch 0005

`arm64: fpsimd: export fpsimd_restore_current_state() for the KJIT runtime`:
one `EXPORT_SYMBOL_GPL`. The function already does the whole reload (FP/SIMD
absent, SVE/SME, `get_cpu_fpsimd_context()` nesting inside our
`local_bh_disable()`, binding to the CPU), so the module duplicates none of it.
`kernel_neon_begin/end` (already exported) are the wrong tool: they save the
user state and take the registers away from it.

## Module

- `kjit_install(..., uses_fpsimd)` stores `VerifyOk.uses_fpsimd` (the
  verifier's verdict on the installed bytes, never the translator's) in
  `struct kjit_frag`; `runtime/exec.rs`'s `Running` reads it once per lookup,
  and `Running::call` picks `kjit_call_fragment_fpsimd()` or the unchanged
  `kjit_call_fragment()` for every entry, chained entries included (a chain
  into the same fragment keeps the flag, one into another fragment takes that
  fragment's).
- `kjit_call_fragment_fpsimd()` (C): `local_bh_disable()` → if
  `TIF_FOREIGN_FPSTATE`: `fpsimd_restore_current_state()`, count
  `fpsimd_restores` → `pagefault_disable()` → the ordinary trampoline →
  `pagefault_enable()` → per-CPU max of the bracket's arch-counter ticks →
  `local_bh_enable()`. The flag test is not racy: inside the bracket nothing
  can set it (no context switch, no softirq; hardirqs never touch FP/SIMD
  state).
- `CONFIG_PREEMPT_RT` is a build error: there `local_bh_disable()` neither
  disables preemption nor excludes softirq NEON the way the bracket needs.
- Refusal: `kjit_fpsimd_supported()` = FP/SIMD present, no SVE, no SME
  (`system_supports_*`, final CPU caps). Otherwise a `uses_fpsimd` fragment is
  refused after verification: `fpsimd_refused_sve_sme`, -ENODEV (final: the
  auto mode negative-caches the PC). Init logs once when that is the case. The
  guest has neither SVE (`ARM64_SVE` not even configured) nor SME, so the path
  is compiled but not exercised.
- The A9a refusal (`Failure::FpSimd`, counted as a compile failure) is gone.
- Stats: `fpsimd_entries`, `fpsimd_restores`, `fpsimd_exit_mem` (Mem exits of
  FP/SIMD runs, all taken with page faults disabled), `fpsimd_refused_sve_sme`,
  and `fpsimd_run_max_ns` (the longest bracket on any CPU since load, per-CPU
  maximum of CNTVCT deltas converted with CNTFRQ; not reset by debugfs).
- The non-FP/SIMD path calls the same trampoline as before; the only change on
  it is that `fragment_entries` is counted before the call instead of after.
  K2 micro-test counters are identical to the A8 runs (the +12 entries per
  test are the three extra stat reads of `kjit_snap`).

## Why the bracket is enough

- Preemption: none inside the bracket (`local_bh_disable()` raises
  `preempt_count` on !RT). `local_bh_enable()` between chained entries is a
  preemption point, so the non-preemptible stretch is one fragment run, not a
  chain.
- Softirq kernel-mode NEON: cannot run inside the bracket (softirqs are
  masked, also at irq exit). Pending softirqs run in `local_bh_enable()` after
  the run; one that uses NEON calls `fpsimd_save_user_state()`, which saves the
  registers as current's state (they are: `TIF_FOREIGN_FPSTATE` is clear and
  the state bound) and sets the flag, so the exit path or the next bracket
  reloads exactly what the fragment wrote.
- Hardirqs: `may_use_simd()` is false in hardirq/NMI; no handler touches the
  registers.
- Context switch after the bracket (or during a later in-kernel syscall):
  `fpsimd_thread_switch()` saves the bound live state; the next bracket or the
  exit path reloads it (`fp_switch`: ~1 reload per run).
- Kernel-mode NEON inside an in-kernel syscall between two runs
  (`kernel_neon_begin` saves the user state and sets the flag): the next
  bracket reloads it, same path.
- A fault inside an FP/SIMD fragment: `do_page_fault()` sees
  `faulthandler_disabled()` → `no_context` → `fixup_exception()` → the
  fragment's extable (patch 0002) → the access's PAN or Mem stub → `Mem` exit
  → userspace re-executes the access natively and takes the fault there
  (demand paging, CoW, SIGSEGV with the native siginfo). Nothing on this path
  sleeps; `handle_mm_fault` is never reached. The next run finds the page
  present. PAN-window permission faults take the same A8 path
  (`is_el1_permission_fault` → `search_exception_tables`).
- Signals: delivered only by the normal exit path after the hook returned
  (`kjit_can_run` declines with a signal pending). By then the user state is
  either live and bound or saved with the flag set, so `setup_sigframe`'s
  `fpsimd_context` holds exactly what the fragments produced, and sigreturn
  restores it (`fp_signal`: the handler overwrites v0-v31, FPCR and FPSR).
- ptrace: a traced task never runs fragments, so a tracer's FP regset access
  never races a run. exec: `flush_thread()` sets the flag, and the new mm has
  no fragments.

## Tests (tests/guest, K2 suite; K3 runs them in auto mode)

`fp_loop`, `fp_regs`, `fp_switch`, `fp_signal`, `fp_fault` (`ro_store`,
`unmapped_load`, `null_ld1`, `demand`), `fp_budget`; see README, "K2 kernel
runtime". Every one KJIT off vs on with byte-identical stdout and status, plus
self-checks (data, V registers, FPCR/FPSR against the values set) and, with
`KJIT_EXPECT`, counter checks. The runner also requires `fpsimd_restores >= 1`
for `fp_switch`, `fpsimd_exit_mem >= 1` per fault mode and `>= 100` for
`demand`.

## Measurements (kjit-guest, M1 host, HVF, 4 vCPUs)

- `make guest-tests`: ALL PASS. `fp_loop` 39991 FP/SIMD entries for 20000
  iterations (99.98% of 40000 syscalls in kernel), `fp_regs` 199952,
  `fp_switch` 79982 entries and 39991 reloads (every run after the other
  process ran on CPU 0), `fp_signal` 399925 entries, 14 reloads, ~37 signals,
  `fp_fault demand` 512 FP/SIMD `Mem` exits for 512 first touches and none
  for the second pass; every fault mode same siginfo. Non-FP/SIMD tests: same
  counters as before A9b.
- `make guest-tests-k3`: ALL PASS; the FP/SIMD tests in auto mode give the
  same picture (`fp_switch` 39866 reloads).
- `make redis-campaign GUEST_PROFILE=kjit-guest`: RESULT PASS. Suite 5.5% of
  syscalls in the kernel (3.12M of 56.9M; A8: 5.8%), 32.9M FP/SIMD entries,
  4.0M reloads, 61312 `Mem` exits, all FP/SIMD (first touches under
  `pagefault_disable()`), no verifier rejection, no invalid exit, no
  `fpsimd_refused_sve_sme`. Benchmark 0.0% / 1.6% / 0.7% (default / `-P 16`
  / 256 clients), unchanged: 2.0M FP/SIMD entries in the default run and no
  Unsupported exit left; the paths now end at `MAX_CHAIN` (4.34M `chain_cap`
  for 4.36M syscalls, ~17 entries per syscall). Suite `unsupported_top`:
  `mrs CNTVCT_EL0` (0xd53be04b 1.59M, 0xd53be04c 0.39M), `fcmpe d0, #0.0`
  (0x1e602018, 28k), `sxtl` (0x0f20a400, 277).
- `make redis-campaign GUEST_PROFILE=kjit-guest-debug K4_ITERATIONS=3`
  (generic KASAN, lockdep incl. PROVE_RCU, DEBUG_ATOMIC_SLEEP): RESULT PASS,
  suite identical (2857 / 2858 ok, 0 failed, 2518 distinct outcomes), 4.7% in
  kernel, 22.0M FP/SIMD entries, 2.8M reloads, 59822 FP/SIMD `Mem` exits; 30
  adversarial runs and 3 consistency checks PASS; the K2 micro tests (FP/SIMD
  ones included, auto mode) pass in every iteration. No `BUG:`/`WARNING:`,
  KASAN, lockdep, "sleeping function called from invalid context",
  "scheduling while atomic", softirq or RCU-stall line in any serial log or
  the campaign dmesg. (`DEBUG_PREEMPT` is not in the profile.) `make
  guest-tests GUEST_PROFILE=kjit-guest-debug` (K2, self-registration): ALL
  PASS, 512 FP/SIMD `Mem` exits in `fp_fault demand`, `fp_budget` max 149 µs.
- Non-preemptible time (`fpsimd_run_max_ns`, wall clock of the bracket,
  interrupts included): K2 suite 36 µs before `fp_budget`, 160 µs after it
  (a budget-exhausting 256 KiB SIMD copy, the designed worst case of one
  run); K3 suite 83 µs; redis suite 946 µs. A diagnostic build (not kept)
  logged every bracket over 50 µs during a redis suite run (max 643 µs that
  run): of the first 399, 389 had at least one interrupt inside; the longest
  interrupt-free fragment run was 94 µs (a `tclsh` memcpy ending in a `Mem`
  exit), and several brackets whose fragment ran for under 1 µs still spanned
  72-361 µs, with or without an interrupt, i.e. host-side vCPU stalls and
  interrupt handling, not fragment code, make up the tail. Fragment code
  itself is bounded by `KJIT_BACKEDGE_BUDGET` (4096 back-edges) per run; one
  run of the largest loop body seen (glibc memcpy's 64-byte loop) is ~100 µs
  here.

## Findings

- Lifting the A9a refusal did not change the in-kernel fractions (the paths
  were already long enough to meet the chain cap); FP/SIMD runs are ~4% of
  the suite's fragment entries. The bracket's own cost was not measured.
- Every `Mem` exit under the suite is now an FP/SIMD one (61312): glibc
  memcpy/memset into fresh pages (tclsh, redis-server) fault under
  `pagefault_disable()` and are redone natively. Same in K3's `jit_churn`
  (memcpy into a fresh mmap every round: every FP/SIMD entry a `Mem` exit).
  Correct; a cost only where first touches dominate.
- redis-benchmark's request path now runs with no Unsupported exit at all,
  but it is longer than 16 fragment entries between two syscalls, so
  `MAX_CHAIN` returns it to userspace every time; the in-kernel fraction
  does not move until chaining changes (next work: `MAX_CHAIN` or fragment
  size, not coverage).

## Not verified

- SVE/SME systems: the refusal is compiled but never taken (no SVE/SME in
  the guest; `ARM64_SVE` is not configured). `PREEMPT_RT` is only a build
  error, not tested.
- Softirq kernel-mode NEON racing a bracket: the guest config has no
  NEON crypto/checksum users on its paths, so the "softirq saves after
  `local_bh_enable()`" case is argued from `fpsimd.c`, not observed. The
  reload path itself is exercised by context switches (`fp_switch`, redis).
- FPCR trap-enable bits, FPMR, and FEAT_AFP/NEP: never set by the tests; no
  A9a form reads them.
- The worst-case bracket duration on bare metal: all numbers are wall clock
  inside an HVF guest, host stalls included.

# A10: chain budget and counter reads (2026-09-27)

## Chain budget (kernel module)

- Root cause of the A9b plateau: `MAX_CHAIN = 16` was a placeholder, not
  derived from the invariant it protects. Chaining already re-checks every run
  condition (signals, both need_resched bits, work flags, `enable`) before
  every entry, so the cap only has to bound the work one hook call does in
  fragments without a syscall (a user-mode transition or voluntary sleep is
  what RCU Tasks waits for; the syscall loop's 4096-per-kernel-entry cap
  exists for the same reason).
- Now `chain_budget`: fragment entries per hook call, the first one included
  (`runtime/exec.rs` `run_chain`; 1 disables chaining). Module parameter
  (`param_set_uint_minmax`) and debugfs `chain_budget` (writes outside
  1..65536 fail with `-EINVAL`); read once per hook call. `chain_cap` still
  counts branch exits that the budget stopped.
- Stats: `chain_max` (most entries in one hook call since load) and
  `chain_hist_<lo>_<hi>` (hook calls that ran a fragment, by entries, log2
  buckets 1..65536, exact because the budget is at most 2^16).
- Default 1024. Measured with `chain_budget=65536` (kjit-guest, redis-benchmark
  `-n 100000`, auto mode; entries per hook call): default run 2.0M calls with
  32-63 entries, 0.93M with 128-255, 1.07M with 256-511, max 505; 256
  clients the same shape; `-P 16` 16-request batches 2048-8191 entries (70k
  calls, max 4980). 1024 covers every non-pipelined request path with 2x
  headroom. A pipelined batch grows with the pipeline depth, so no fixed
  budget covers all of them; one that hits the budget costs one extra EL0
  round trip per 1024 entries (the default run averaged ~60 ns of server
  wall clock per entry, syscalls included, so well under 1%), not
  correctness.
- Bound: one hook call runs at most `chain_budget` entries, each bounded by
  the back-edge budget (4096) and ended by a branch exit; a user loop that is
  CPU-bound but calls functions (no syscall) returns to userspace after
  `chain_budget` entries and finishes natively until its next syscall
  (`tests/guest/call_loop.c`: 5000 calls per syscall, one `chain_cap` per
  syscall unless a run condition ended the hook call first, counted in
  `run_declined`; `chain_max` == `chain_budget`). Worst case per hook call is
  `chain_budget` x the longest budget-bounded run (the largest seen, glibc's
  64-byte memcpy loop, ~100 us per run): 1024 x 100 us = ~0.1 s, 64x the old
  16-entry bound.
- Preemption does not depend on the budget: the guest profiles are `PREEMPT`
  (full; `PREEMPT_LAZY` and `PREEMPT_DYNAMIC` off), where the tick's
  `resched_curr_lazy()` sets `TIF_NEED_RESCHED` (`get_lazy_tif_bit()`, lazy
  only with `PREEMPT_LAZY`), and the IRQ return to EL1 preempts a running
  non-FP/SIMD fragment directly (`preempt_count` 0). The per-entry
  `need_resched` check matters for `PREEMPT_NONE`/`VOLUNTARY`/`LAZY`; an
  FP/SIMD run is not preemptible, but its bracket ends with every entry.

## Unload race (found by A10, fixed in kernel patch 0006)

- `kjit_unregister_hook()` (patch 0001) disabled the hook's static key and
  cleared the ops pointer before it waited for the calls in flight, and
  `search_kjit_extables()` (patch 0002) returned nothing once the key was
  off. A fragment still running in a hook call in flight during `rmmod` that
  took a user-access fault then had no fixup: an oops. With 16-entry chains
  the window was small; with 1024 it hit `jit_churn` in `make guest-tests-k3`
  (an FP/SIMD fragment's `str q0` under `pagefault_disable()`, first touch of
  a fresh page, module `GOING`).
- Invariant: fragment extables stay reachable until every hook call that
  could be running a fragment has returned.
- Fix (patch 0006): unregister = static key off (no new hook calls),
  `synchronize_srcu` (calls in flight, chained entries included, drain while
  the ops pointer is still published), pointer NULL, `synchronize_srcu`
  (extable searches and task_work callbacks that loaded the old ops finish).
  `kjit_call_after_syscall()` re-checks the static key inside its SRCU
  section: `kjit_syscall_loop()` checks it only before its first call, so
  without the re-check a loop in progress could start a new hook call after
  the first grace period, and its fragment would fault after the pointer was
  cleared. A call that saw the key enabled entered SRCU before
  `static_branch_disable()` returned (arm64 patching IPIs every CPU), so the
  first grace period waits for it. `search_kjit_extables()` consults only the
  SRCU-protected pointer (still skipped in NMI). Cost: with no runtime
  registered, an address no other table claims takes an SRCU read section
  instead of a static branch.
- task_work (patch 0004) is unchanged: `kjit_task_work_fn()` calls
  `ops->task_work` only while the queuing registration's ops is published,
  and the second grace period waits for callbacks that loaded it.
- The interim module-side workaround (its own SRCU around every hook call and
  an `enable` clear + `synchronize_srcu()` in module exit) is removed; the
  `enable` checks that remain serve the debugfs switch only. In-flight chains
  now run to their normal end (chain budget or exit) during unload.
- Regression test: `tests/guest/unload_fault.c` + `unload-stress.sh`
  (`run-k3.sh` step (v), 20 cycles): threads loop over fresh anonymous
  regions; `gpr` threads make 512-entry chains whose callee entries each
  demand-page a new page inside the fragment (a hook call in flight across
  hundreds of faults), `fp` threads store with `st1` from an FP/SIMD callee
  (the Mem-stub fixup that first hit). Checks that every load ran faulting
  FP/SIMD fragments before its `rmmod`. Negative control: the kernel without
  0006 and the module without its workaround oopses on the first `rmmod`
  ("Unable to handle kernel paging request" at the gpr callee's
  `str x6, [x9]`, module `kjit(O-)`).

## Counter reads (translator, verifier, module)

- Forms: `MRS.MRS_RS_systemmove` becomes three generated instances,
  `MrsMrsRsSystemmove{TpidrEl0,CntvctEl0,CntfrqEl0}` (keys
  `MRS.MRS_RS_systemmove@<REG>`), through the new
  `[decode.field_instances."<form>"]` table in `subset.toml`: per instance a
  field-constraint set (same checks as `field_constraints`, plus: a form is in
  only one of the two tables, at least one instance, names `[A-Z0-9_]+`, no
  two instances decode the same words). Every other system register stays
  undecodable. CNTVCTSS_EL0 (FEAT_ECV) is not admitted: the XML has no
  system-register database to check it against, the hosts have no ECV
  (`/proc/cpuinfo` has no `ecv`), and without ECV it is UNDEFINED, which a
  fragment would execute at EL1. The guest kernel's vDSO reads it only under
  the `ARM64_HAS_ECV` alternative (`__arch_counter_get_cntvct()`).
- Semantics at EL1: `VirtualCounterTimer()` (shared pseudocode) is
  `PhysicalCountInt() - CNTVOFF_EL2` for EL0 and EL1 alike (outside a VHE
  host, where both skip the offset); CNTFRQ_EL0 is one register. Equal to the
  EL0 read only while EL0 reads the hardware: module init requires, on every
  online CPU, `CNTKCTL_EL1.EL0VCTEN` set (also what makes CNTFRQ_EL0
  readable at EL0) and no out-of-line erratum handler for CNTVCT
  (`has_erratum_handler(read_cntvct_el0)`; `arch_counter_set_user_access()`
  clears EL0VCTEN on such a CPU and the kernel emulates EL0 reads with the
  workaround's stable read). Both are per CPU and set at
  `CPUHP_AP_ARM_ARCH_TIMER_STARTING`, so the check is a `CPUHP_AP_ONLINE_DYN`
  callback: it runs on every online CPU at load (failure: `-ENODEV`, the load
  fails) and on every CPU onlined while kjit is loaded (failure: that CPU does
  not come online). EL0VCTEN changes later only for compat tasks
  (`ARM64_ERRATUM_1418040`), which never run fragments.
- Verifier: rule 5 allows exactly the three instances (`Form::MrsUserReg`);
  rule 9 treats their results as user values (they read no GPR, so the write
  clears any kernel mark, like `movz`). Tests: every o0:op1:CRn:CRm:op2 value
  x 4 Rt in the body and an exit group (exactly three accepted, the rest
  `Undecodable`); mutation class "insert MRS of a non-allowlisted system
  register (A10)" (15 words: CNTPCT, CNTPCTSS, CNTVCTSS, CNTV_CTL, TPIDRRO,
  CNTKCTL_EL1, TPIDR_EL1, SP_EL0, CNTVOFF_EL2, MIDR_EL1, CTR_EL0, NZCV, FPCR,
  the o0 = 0 twin of CNTVCT, `msr cntvct_el0`) at every body word, 100%
  rejected.
- Counter modelling, interpreter: `MachineState::{cntvct_el0, cntfrq_el0}`,
  read-only, set in the initial state (`FIXTURE_CNTVCT` = 0xa1b2c3d4e5,
  `FIXTURE_CNTFRQ` = 24 MHz for fixtures and the fuzzer) and never advanced.
  A step-derived counter cannot work: the fragment executes more instructions
  than the original (prologue, fills, budget checks), so no dynamic index is
  common to both. A constant is a legal behaviour of the real counter (reads
  are only non-decreasing; two reads within one tick are equal) and keeps the
  differential check exact: a read routed to the wrong register or a lost
  value shows in every register computed from it.
- Counter modelling, native runner: hardware reads differ run to run and from
  the constant, so both native legs replace every counter MRS (original text
  and fragment copy) with `brk #(0x4c00 | kind << 5 | Rt)`, and the signal
  handler emulates it in place (Xt = the run's `MachineState` value, XZR
  ignored, pc + 4, the run's TPIDR_EL0 back last), like the mocked SVC.
  Every register is still compared exactly. Not checked natively: only the
  hardware read itself (EL0 readability, which the module pins at EL1). A
  patched word counts as native-unobservable if the original reads it as data.
- Fixture `tests/arm64/counter_read.s`: the vDSO clock_gettime shape (seq
  load, `dmb ishld`, `isb`, `mrs x11, cntvct_el0`, `mrs x12, cntfrq_el0`, the
  dependent `ldr xzr` ordering load, seq re-check, ticks to s/ns with
  `udiv`/`msub`/`mul`, stores, `svc` loop), and reads into x29, x16, x17, x9,
  x10 and XZR. LLVM encoding cases for all three instances; the fuzzer draws
  them from the generated metadata like every form (`MRS` section).

## Measurements (kjit-guest, M1 host, HVF, 4 vCPUs)

- `make guest-tests`: ALL PASS; `call_loop` 2000 `chain_cap` for 2000
  syscalls, `chain_max` 1024. `make guest-tests-k3`: ALL PASS (after the
  unload-race fix; the first run hit it, see above).
- `make redis-campaign GUEST_PROFILE=kjit-guest`: RESULT PASS. Suite 2866 /
  2868 passed without / with KJIT, 0 failed, same outcome for all 2518
  distinct tests; 40.0% of the suite's syscalls in the kernel (13.8M of
  34.4M; A9b: 5.5%), 7.6G fragment entries, 46355 translations, no verifier
  rejection or invalid exit. Benchmark in-kernel fraction (A9b -> A10):
  default 0.0% -> 78.8%, `-P 16` 1.6% -> 39.5%, 256 clients 0.7% -> 78.7%
  (~140 fragment entries per syscall). Default and 256-client runs never hit
  the budget (`chain_cap` 0, longest chain 505 entries); `-P 16` hits it
  71371 times (its 16-request batches, 2048-8191 entries measured with a
  65536 budget). Datasets identical KJIT off and on; 10 adversarial tests
  PASS; dmesg clean.
- `make redis-campaign GUEST_PROFILE=kjit-guest-debug K4_ITERATIONS=3`
  (generic KASAN, lockdep incl. PROVE_RCU, DEBUG_ATOMIC_SLEEP): RESULT PASS.
  Suite 2853 / 2880 passed without / with KJIT, 0 failed, same outcome for
  all 2518 distinct tests, 39.5% in kernel (13.8M of 35.0M); 30 adversarial
  runs (15 module unload/reload cycles under load among them) and 3
  consistency checks PASS; benchmark 79.7% / 39.5% / 79.7%; no BUG/WARNING/
  KASAN/lockdep/RCU line in any serial log or the campaign dmesg (only the
  boot banners). `fcmp d8, d8` (0x1e682100) shows up in the debug run's
  benchmark top (~96k).
- New `unsupported_top` head. Benchmark: `ldr d0, [x14, x12, lsl #3]`
  (0xfc6c79c0, SIMD&FP register offset, 104k), `ucvtf d0, x11` (0x9e630160,
  36k), `yield` (0xd503203f). Suite: `str q0, [x0, x3]` (0x3ca36800, 7.9M),
  `ucvtf d0, x11` (1.2M), `ldr d0, [x14, x12, lsl #3]` (0.74M), `dc zva, x3`
  (0xd50b7423, 0.52M), `scvtf d8, x1` (0x9e620028, 0.17M), `mrs x21, fpcr`
  (0xd53b4415, 82k). `mrs cntvct_el0` (A9b's top, 2.0M) is gone.
- Speed (not a goal, but it moved a lot): redis-benchmark `-t set,get
  -n 200000`, one server, after a warm-up run (req/s SET / GET):
  KJIT off 274k / 275k (`-P 16`: 1.85M / 2.53M); `chain_budget` 16 (A9b
  behaviour, 0% in kernel) 293k / 305k (1.53M / 2.15M); `chain_budget` 1024
  (98% in kernel) 62k / 71k (332k / 329k). Running redis's request path in
  fragments is 4-6x slower than native: ~140 fragment entries per syscall,
  each paying the call trampoline, the prologue/epilogue `pt_regs` round
  trip, a table lookup and refcount for cross-fragment chains and, for
  FP/SIMD fragments, the bracket; the mode switches saved (~120 ns each) do
  not pay for that. Entry cost, not coverage, is now the limit.

## Not verified

- CPU hotplug: the counter check's online callback is exercised only at load
  (the guest never onlines a CPU later); the erratum branch and the
  EL0VCTEN-clear branch never run on this hardware.
- The worst-case time of one hook call (1024 budget-bounded runs) was not
  measured; the ~0.1 s bound is computed from the A9b per-run maximum.
- Preemption inside chains under `PREEMPT_NONE`/`VOLUNTARY`/`LAZY`: argued
  from the per-entry `need_resched` check, not run (the guest is `PREEMPT`).
- CNTVCTSS_EL0 and hosts with FEAT_ECV.

# A11 contract: in-fragment branch dispatch (2026-09-29)

Written before implementation. Why: A10 put 98% of redis-benchmark's
syscalls in the kernel and made it 4-6x slower than native. Every `BL`,
`BLR`, `BR` and `RET` ends a run: epilogue (31-GPR `pt_regs` writeback),
trampoline, Rust dispatch, run conditions, label search or `kjit_lookup`
(RCU hash + refcount), prologue (31-GPR load) and, for FP/SIMD fragments,
the bracket, ~140 times per syscall. The ~240 ns one in-kernel syscall saves
cannot pay for that at any per-entry cost the runtime path can reach
(break-even is ~1.7 ns per entry), so the number of runtime round trips has
to drop, not only their price. Goal: a branch whose target already has a
translation continues there from inside fragment code, and the runtime is
entered only on a miss.

## Step 0: baseline (before any A11 code)

The A10 slowdown is attributed to entry cost by deduction, and its
`chain_budget=16` run (~17 entries per syscall, faster than KJIT off)
contradicts a linear per-entry cost. Measure first, on kjit-guest, at least
3 runs per point: `call_loop` KJIT off/on wall clock (fixed cost of one
non-FP/SIMD entry; plus an FP/SIMD-callee variant for the bracket), and
`redis-benchmark -t set,get -n 200000` at `chain_budget` 1, 16, 64, 256, 1024
with the `fragment_entries`/`fpsimd_entries` deltas. If time per entry from
the sweep matches the microbenchmark, round trips are the cost and A11
removes them. If it is much larger, the loss is inside fragment code or the
in-kernel syscall path, and A11 alone will not recover it. Either way these
numbers are the before/after baseline.

## Mechanism: one dispatch path for every branch exit

- Per `kjit_mm`, two direct-mapped **dispatch tables** (IBTC) of
  `2^IBTC_BITS` slots, `IBTC_BITS = 12` (32 KiB each): `table_all` and
  `table_nofp`. A slot is 0 or a pointer to a **record**
  `{ u64 pc; u64 host; }`: a user PC and the absolute address of a verified
  entry of a live fragment of this mm translated for exactly that PC. Slot
  index = `pc[13:2]`.
- Records are the fragment's labels: `struct kjit_label` becomes
  `{ u64 pc; u64 host; }` (host = image + offset, filled at install, sorted by
  pc, immutable after install), so no second copy of the entry table exists.
  `kjit_frag_offset_for_pc` becomes a host lookup on the same array.
- `table_all` may hold records of every fragment; `table_nofp` only records of
  fragments with `uses_fpsimd == false`. A run of an FP/SIMD fragment (inside
  the bracket) dispatches through `table_all`; any other run through
  `table_nofp`. So a run outside the bracket can never reach FP/SIMD code, and
  a bracketed run may continue into non-FP/SIMD code (its faults become `Mem`
  exits, as for any bracketed access: correct).
- Only the runtime writes tables. Fragment code only reads them, and only
  through the dispatch template below.
- Why not patched direct branches: a patched `b` per BL site is the cheapest
  possible transfer, but it needs text patching of ROX images (CMODX-legal
  only for B/BL/NOP words), a ±128 MiB range between images, per-target
  incoming-link lists for unlinking, and it cannot cover `BR`/`BLR`/`RET`,
  which still need a table. One table-based path covers all four kinds with
  no text writes and makes unlinking a single store. Direct links remain a
  later optimization on top of the same records and lifetimes (see Deferred).

## ABI

- Extra params grow from 2 to 3 words: `[0]`, `[1]` = x10, x11 out (epilogue,
  unchanged), `[2]` = the run's dispatch table (in). The runtime always passes
  a valid table: a run executes a fragment of `current->mm`, and the tables
  are allocated with that mm's first install.
- Frame: the padding slot 200..208 becomes `RUNTIME_FRAME_IBTC_OFFSET = 200`
  (table pointer). The frame stays 208 bytes. The prologue stores it while x1
  still holds the extra pointer: `ldr x12, [x1, #16]; str x12, [sp, #200]`.
  The prologue grows by 2 words, `EPILOGUE_OFFSET` moves with it, and the
  rule 9 join state is re-derived from the new prologue (expected unchanged:
  {x29, x12}).
- Kernel BTI stays off (K1): the dispatch `br x12` lands on unmarked words, as
  the prologue's does.

## Lowering (rephrase; one site per original `BL`/`BLR`/`BR`/`RET`)

In the body, in this order, replacing today's `b <exit group>`:

```text
ldr  x12, [sp, #192]            ; budget check (rule 6 form) -> Budget stub
sub  x12, x12, #1
str  x12, [sp, #192]
cbz  x12, <Budget stub of pc>
<T -> x13>                      ; BL: movz/movk of the target;
                                ; BLR/BR/RET: mov or fill from the target's mapping,
                                ; before any x30 write (`blr x30`)
<x30 = resume>                  ; BL/BLR only (existing link write)
ldr  x12, [sp, #200]            ; --- dispatch template (byte-exact) ---
ubfx x14, x13, #2, #12
ldr  x12, [x12, x14, lsl #3]
cbz  x12, <exit group of pc>
ldr  x14, [x12]
sub  x14, x14, x13
cbnz x14, <exit group of pc>
ldr  x12, [x12, #8]
br   x12
```

- The exit group is today's branch exit for the site (same status, x11 =
  resume) with x10 taken from x13, so a miss behaves exactly like A10.
  `SUB`/`CBZ`/`CBNZ` keep NZCV (user state) untouched, as the budget check
  already does.
- Budget: every dispatch attempt costs one unit of the existing
  `KJIT_BACKEDGE_BUDGET` counter, whether it hits or misses. The check
  precedes the whole lowered branch, so a Budget exit leaves the state from
  before the instruction and userspace re-executes the branch natively (also
  correct for `blr x30`). This is what bounds recursion and call loops, which
  no longer pass through the runtime.
- Scratch: x12 (kernel values only), x13 (T, a user value), x14. x15 stays
  free. All are dead at original-instruction boundaries; x13 stays live from
  the site into its own exit group, which is part of the same original
  instruction's lowering.
- `B`/`B.cond` inside the CFG are unchanged (in-fragment). `SVC` is not a
  branch: its resume stays a runtime path (the syscall runs in the hook loop
  anyway).

## Verifier (V3)

The bytes alone no longer determine every branch target: a dispatch target
comes from a table the runtime owns. What the verifier still proves is that
the only way to use a table is the exact template, that it cannot read out of
bounds, that it is budget-charged, and that no kernel value escapes. What the
runtime must guarantee (table content) is stated under Kernel and tested
there.

- Rule 2: the prologue's byte-exact check covers the two new words.
- Rule 3: new runtime accesses, valid only as template words: `ldr x12, [sp,
  #200]` (first word), `ldr x12, [x12, x14, lsl #3]` (x14 the preceding
  `ubfx x14, x13, #2, #12`, so the index is < 2^12 by construction),
  `ldr x14, [x12]`, `ldr x12, [x12, #8]`. Slot 200 is never written by the
  body and never read outside a template's first word.
- Rule 4: `br x12` is allowed only as a template's last word. `BL`, `BLR`,
  `RET` and every other `BR` stay rejected.
- Template: the 9 words are byte-exact (registers, `#200`, `#2`, `#12`, `#8`).
  There is no join point from the preceding budget check's `sub` to the `br`.
  Both `cbz`/`cbnz` target the same forward exit-group start.
- Rule 6: a budget check may guard a template as well as a back-edge. Between
  its `cbz` and the template's first word: only data-processing words,
  reg-virt fills and the link write. No branch, no memory access other than
  fills, no join point.
- Rule 9: inside a template, the `ldr x12` results are kernel values. The key
  load `ldr x14, [x12]` is not a source (a user PC the runtime copied from a
  user branch target). `cbz x12` and `br x12` may read kernel x12. At both
  miss edges and at the `br`, the kernel set is {x12, x29} = the join state.
  x13 must be non-kernel at the `ubfx` (the existing `KernelValueRead`).
- `VerifyOk` is unchanged. The runtime needs nothing new from the verifier.

## Kernel

- Tables: `kvzalloc` of both at a `kjit_mm`'s first install (failure: that
  install fails with -ENOMEM, like any install allocation); freed with the
  `kjit_mm`, after a hook-SRCU grace period.
- Insert: whenever the runtime resolves a branch exit's target T to a
  fragment F and an entry (`entry_for` or lookup), it publishes F's label for
  T under `kmm->lock`, only if F is not retired: `smp_store_release` into
  `table_all[h(T)]`, and into `table_nofp[h(T)]` if `!F.uses_fpsimd`.
  A slot holding a record for another pc is replaced (direct-mapped); one
  holding a live record for the same pc is kept, whichever fragment it belongs
  to (all are translations of the same text). Without that, fragments sharing
  a pc take turns in the slot on every resolution (A11b measured 36.1M inserts,
  all of them replaces, under the default benchmark). Readers are ordered by
  the address dependency slot -> record -> fields.
- Invariant (not verified, owned by the runtime): every non-zero slot of a
  table points at a label of a non-retired fragment of this `kjit_mm` whose
  host is `image + a verified entry offset`, for exactly the label's pc; a
  `table_nofp` slot never points into an FP/SIMD fragment.
- Retire (`kjit_mm_flush_locked`, `kjit_bad_status`, mm release, module
  exit), under `kmm->lock`: mark F retired; for each label, for each table,
  if `slot[h(pc)] == &label` then `WRITE_ONCE(slot, 0)`; `hash_del_rcu`. Then
  the free runs after a **hook-SRCU grace period** (`call_srcu`, legal in the
  non-blocking mmu-notifier path). Its callback takes F off the extable list
  and queues the existing RCU free (`execmem_free` in process context).
- Lifetime change: a linked run enters fragments it never looked up, so
  per-run references cannot protect them. The per-run `kjit_frag` refcount
  and `kjit_frag_put` go. Every fragment execution already happens inside the
  hook call's `kjit_hook_srcu` read section (patch 0001/0006), so "freed only
  after a hook-SRCU grace period following retirement" protects every run,
  linked or not. It also gives the A10 extable invariant ("fixups stay
  reachable until every hook call that could run the fragment has returned")
  by construction. Kernel **patch 0007** exports `kjit_hook_call_srcu(head,
  cb)` and `kjit_hook_srcu_barrier()`. Module exit: unregister (drain),
  retire everything, `kjit_hook_srcu_barrier()`, `rcu_barrier()`,
  `destroy_workqueue()`.
- Run: `extra[2] = F.uses_fpsimd ? table_all : table_nofp` for the fragment F
  the run enters.
- Stats: `ibtc_insert`, `ibtc_replace` (a slot held another record),
  `ibtc_clear` (retire), `ibtc_fpsimd_boundary` (a branch exit of a non-FP/SIMD
  run whose target resolved to an FP/SIMD fragment). Hits are not counted
  (no atomics in fragment code). `fragment_entries`, `chains` and `exit_*`
  now count runtime round trips only: not comparable with A10 numbers.

## Run conditions and bounds (amends K2 "Run conditions", K3 "Chaining rules")

- Run conditions are re-checked at every runtime entry and every in-kernel
  syscall, as today, but no longer at every call and return. Between two
  checks a run executes at most `KJIT_BACKEDGE_BUDGET` budget units (one per
  back-edge or dispatch attempt). Each unit is at most one acyclic path of
  one fragment plus a template. So the A10 per-hook-call worst case
  (`chain_budget` x 4096 x longest acyclic path) is unchanged, but typical
  runs get much longer.
- Signal / `need_resched` / `enable` latency is one run, not one call. Under
  full `PREEMPT` a non-FP/SIMD run is still preempted directly. An FP/SIMD run
  is non-preemptible for its whole length, now across fragments: re-measure
  `fpsimd_run_max_ns`.
- A thread that loaded a slot before retirement may enter a retired F and run
  it until its next dispatch or exit. This is the same class as today's run
  that continues in a fragment removed from its table, now bounded by one run.

## Harness (A11a)

- A code cache in the harness runtime mirroring the kernel's: fragments by
  entry pc, both tables, labels as records, insert on resolution and retire
  with the same rules. On `NeedsTranslation` the harness translates T,
  installs it and continues (like the kernel's chaining). The native runner
  maps every fragment RX and passes `extra[2]`. The interpreter models tables
  and records as runtime memory and executes the template.
- Every `_mark` case runs **cold** (empty tables: every transfer misses, as
  A10) and **warm** (the same case again on the populated cache: transfers
  hit). Both must equal native.
- New fixtures: nested calls and returns across functions; recursion that
  exhausts the budget through dispatch (native resume at the call);
  PLT-shaped `adrp/ldr/br x17`; one `blr` alternating between two callees
  16 KiB apart (same slot: replace ping-pong); `blr x30` and `ret x5`; a
  non-FP/SIMD caller of an FP/SIMD callee (the `table_nofp` invariant
  asserted, those transfers go through the runtime); callee retired between
  the cold and warm run (warm misses on it).
- Verifier mutation classes, each 100% rejected: every template word altered
  (register, `#200`, `ubfx` lsb/width, `#8`), key compare dropped, `br` of x13
  or x14, a join point inside, no budget check, slot 200 read outside a
  template or written anywhere, a kernel value in x13.

## Kernel tests (A11b)

- `call_loop`: 5000 calls per syscall now hit the budget (Budget exit, native
  resume), not `chain_cap`; its `KJIT_EXPECT` changes accordingly. The
  `chain_budget` checks move to an always-missing transfer (the 16 KiB alias
  ping-pong, `alias_loop`), which still chains through the runtime.
- `link_race`: threads calling across fragments whose callee text sits in its
  own mapping, while another thread munmaps/remaps/mprotects it. KJIT on/off
  identical output; `kjit-guest-debug` clean (KASAN, lockdep).
- `unload-stress` with linked runs in flight.
- `make redis-campaign` on both profiles: PASS. Report req/s against KJIT off,
  `fragment_entries` per syscall, `exit_budget`, the `ibtc_*` counters and
  `fpsimd_run_max_ns`, next to the Step 0 baseline.

## Deferred (and why that is safe)

- Patched direct `b` for `BL` sites and a return-address stack for `RET`: pure
  speed on top of the same records and lifetimes. Revisit if a profile shows
  the ~20-word dispatch sequence dominating fragment time.
- A bracket that spans non-FP/SIMD runs (so non-FP/SIMD -> FP/SIMD transfers
  stop missing): decide from `ibtc_fpsimd_boundary`. It trades page faults
  handled in place for `Mem` exits and longer non-preemptible stretches.
- Re-entering after a Budget exit (instead of resuming in userspace): needs
  Budget resume PCs to be entry labels. Decide from `exit_budget`.
- In-fragment code quality (budget counter read-modify-write through memory,
  stack-backed x12..x15, `LDTR` imm9-only splits): separate work. Step 0
  tells whether it matters.

# A11b implementation (2026-10-02)

Implements the "Kernel", "Run conditions and bounds" and "Kernel tests (A11b)"
sections of "A11 contract" exactly as written; nothing in them turned out
unworkable. Built and run against the A10 translator (no `shared/` change):
the fragment prologue does not read `extra[2]` and fragments contain no
dispatch template yet, so no transfer can hit a table until A11a is merged.
Everything the runtime does around the tables is exercised anyway (the
runtime publishes on every resolution, retirement clears, lifetimes are the
new ones).

## Kernel patch 0007

`arm64: kjit: export the hook's SRCU callback queue for the runtime`:
`kjit_hook_call_srcu(head, cb)` (`call_srcu()` on `kjit_hook_srcu`) and
`kjit_hook_srcu_barrier()` (`srcu_barrier()`), both `EXPORT_SYMBOL_GPL`; the
`srcu_struct` stays private to `arch/arm64/kernel/kjit.c`. No new state or
lock. `scripts/kjit-kernel-tree.sh` picks it up by its glob (the stamp covers
its hash). Verified: the series applies to 254f49634ee1 and both guest
kernels build with it.

## Lifetime (`kjit_glue.c`)

- The per-run `kjit_frag` refcount, `kjit_frag_put` and `Running`'s `Drop` are
  gone. `kjit_lookup` takes no reference; a fragment is valid for the hook call
  that found it, which is inside `kjit_hook_srcu`'s read section.
- `kjit_frag_retire_locked(kmm, f)` (all four retire paths go through
  `kjit_mm_flush_locked`: invalidation, `kjit_bad_status`, mm release, module
  exit): `f->retired = true`, clears every slot of both tables that holds one
  of its labels (`WRITE_ONCE`), counts `ibtc_clear`, then
  `kjit_hook_call_srcu(&f->retire, ...)`. The callback (workqueue context, BHs
  off) takes the fragment off `kjit_all_frags` and queues the existing
  `queue_rcu_work` free. The extable invariant of A10 ("fixups stay reachable
  until every hook call that could run the fragment has returned") now holds
  by construction.
- A fragment whose install failed was never visible, so it is unlisted and
  freed directly (`kjit_frag_unlist_and_free`), without a hook grace period.
- `kjit_mm`: `table_all` / `table_nofp`, `kvzalloc`ed (32 KiB each) by the
  first install that finds none, outside `kmm->lock`, published together under
  it (the race loser frees its copy), before the fragment becomes visible.
  `-ENOMEM` fails that install. Freed with the `kjit_mm` after a hook-SRCU
  grace period; a `kjit_mm` that never had a table (most processes in auto
  mode) skips it and goes straight to `kvfree_rcu`.
- Module exit: unregister, kill every `kjit_mm` (retires everything),
  `mmu_notifier_synchronize()` (the free callbacks that queue the table
  frees have run), `kjit_hook_srcu_barrier()`, `rcu_barrier()`,
  `destroy_workqueue()`. The barrier has to sit after
  `mmu_notifier_synchronize()`.

## Labels, tables, publishing

- `struct kjit_label { u64 pc; u64 host; }`, sorted, immutable after install;
  `kjit_install` takes a separate input array `struct kjit_entry { pc, offset }`
  (what Rust sends; the C side turns it into labels). Decision: two types
  rather than one with `host` overloaded as an offset on input. `kjit_install`
  now also rejects (-EINVAL) tables without a label for `entry_pc` at
  `entry_offset`, so `kjit_lookup`'s entry is `f->entry_label->host` (the
  `entry_offset` field is gone).
- `kjit_lookup(pc, link, &entry)` and `kjit_frag_link(f, pc)` are the two
  resolution points the runtime uses on a branch exit (a lookup in the same
  fragment first, then the table, as before): both end in
  `kjit_ibtc_publish(f, label)`. An SVC-resume lookup does not publish (it is
  not a branch exit).
- `kjit_ibtc_publish`: skips (no lock) when the slot already holds the label
  in the table(s) it belongs to; otherwise `kmm->lock`, only if `!f->retired`,
  `smp_store_release` into `table_all` and, unless `uses_fpsimd`,
  `table_nofp`. The lock-free skip is the common case under A10 chaining
  (every exit re-resolves) and in the FP/SIMD boundary case.
- Counters: `ibtc_insert` and `ibtc_replace` count slot stores, so one
  resolution of a non-FP/SIMD target counts up to twice (one per table);
  `ibtc_clear` counts cleared slots; `ibtc_fpsimd_boundary` is counted in Rust
  (`exec.rs`) where a non-FP/SIMD run resolves into an FP/SIMD fragment. The
  A11 caveat about `fragment_entries`/`chains`/`exit_*` is in `stats.rs`.
- Run: `Running` carries `kjit_frag_table(f)` (`uses_fpsimd ? table_all :
  table_nofp`) and `call` stores it in `extra[EXTRA_DISPATCH_TABLE_INDEX]`
  (`runtime/ffi.rs`, 2; extra block of `EXTRA_WORDS` = 3). The frame slot and
  the prologue read are A11a's.
- Run conditions: unchanged in the runtime (checked at every runtime entry and
  every in-kernel syscall); the bound change is the translator's budget unit.
  `chain_budget` now bounds runtime round trips per hook call.

## Tests (tests/guest)

- `call_loop`: `KJIT_EXPECT=dispatch`: `exit_budget + run_declined >= outer -
  2 * warmup`, and more calls per svc than the 4096-unit budget. Its
  `chain_budget` / `chain_cap` / `chain_max` checks moved to `alias_loop`
  (nothing was dropped, only moved).
- `alias_loop`: one `blr x5` alternating between two callees exactly 16 KiB
  apart (asserted at start: same `pc[13:2]`). `KJIT_EXPECT=alias`: the old
  call_loop checks (`chain_cap` + `run_declined` per outer iteration, `chain_max
  <= chain_budget`, more calls than the budget) plus `ibtc_replace >= chain_cap
  * budget / 4` (the ping-pong). `run-k2.sh` also requires `ibtc_replace >= 1`
  and runs it as a kill test.
- `link_race`: callers (`blr` into a callee in its own memfd-backed mapping, an
  svc per round of 256 calls) against a remapper that never makes the mapping
  unexecutable or writable: `MAP_FIXED` replacement from a memfd variant,
  exec-only <-> read-exec `mprotect`, `MADV_DONTNEED`, each followed by a
  translate request (non-auto). 2 s storm, every batch's sum checked; then
  staleness (replace by a variant adding 1000, in-place rewrite via RWX to one
  adding 3000: the next calls must run the new code) and a steady phase. KJIT
  on/off output identical. The callee/return-site slot collision is avoided by
  remapping until the two differ.
- `unload_fault` (unload-stress): two more modes, `link` and `linkfp` (bl/ret
  across three fragments; the middle one FP/SIMD in `linkfp`, so a non-FP/SIMD
  run enters an FP/SIMD fragment and the bracketed run continues into
  non-FP/SIMD code). `unload-stress.sh` counts loads with `ibtc_insert > 0` and
  few runtime entries per in-kernel syscall (`entries <= 8 * in_kernel`).
- `k4-lib.sh` report: `ibtc insert/replace/clear/fpsimd_boundary`, runtime
  entries and Budget exits per in-kernel syscall, `fpsimd_run_max_ns`;
  `k4-bench.sh` fails a phase with `ibtc_insert == 0`; `run-k3.sh`'s report
  prints the `ibtc` counters.

### Checks that can only pass after the A11a merge

1. `call_loop` `KJIT_EXPECT=dispatch` (Budget exits need bl/ret hits).
2. `link_race` steady phase, `KJIT_EXPECT=link`: at most 4 runtime entries per
   round of 256 calls (about 513 without dispatch; measured 1026004 / 2000).
3. `unload-stress.sh`: `entries <= 8 * in_kernel` inside the `linked` count
   (needs dispatch; hundreds per syscall without).

Counters that count runtime entries may also need a second look after the
merge: `kill_hot`'s "more than 1000 fragment entries in 1 s", and the
`kjit_check_fpsimd` entry-count checks of the `fp_*` tests.

## Verification (kjit-guest, M1 host, HVF, 4 vCPUs)

Pre-merge, with exactly the three checks above relaxed in a temporary copy of
`tests/guest` (call_loop restored to its pre-A11 text and `chain` expectation,
the link_race steady bound and the unload-stress entry bound disabled; the
tree was restored afterwards):

- `make guest-tests`: ALL PASS. `alias_loop` chain_cap 2000, chain_max 1024,
  ibtc_replace 2047998 (about one per blr, both tables); `link_race` storm
  about 1000 invalidated fragments and 2000 cleared slots, no mismatch.
- `make guest-tests-k3`: ALL PASS (20 unloads with linked runs in flight).
- `make redis-campaign K4_ARGS=--no-suite`: RESULT PASS, ibtc_insert > 0 in all
  three benchmark phases.
- `kjit-guest-debug` (KASAN, lockdep, DEBUG_ATOMIC_SLEEP): `make guest-tests`
  ALL PASS, and `make guest-tests-k3` ALL PASS (20 unloads with linked runs
  in flight, under KASAN and lockdep); no BUG/WARNING/KASAN/lockdep line in
  either (guest-run fails on kernel reports).

Observation, not a defect of the contract: under redis-benchmark nearly every
slot store replaces another record (default phase: ibtc_insert 36.1M,
ibtc_replace 36.1M, for 4.2M syscalls). Redis's hot targets (hundreds, over
about 2 MiB of text) collide in a 4096-slot direct-mapped table, so a
fraction of the transfers will keep missing even with A11a; and
`ibtc_fpsimd_boundary` is 28.5M (about 7 per syscall): every non-FP/SIMD ->
FP/SIMD transfer goes through the runtime. Measure the real hit rate after the
merge before deciding on associativity or on a bracket that spans runs.

## Not verified

- Any dispatch hit: no fragment contains the template here. The concurrency
  of a run reading a slot against a retire, and the table free against runs in
  flight, are argued (every read is inside a hook SRCU section; slots are
  cleared before the grace period starts), and exercised only through the
  hook calls and chains, not through template reads.
- Retire cost under the spinlock: it walks every label of the fragment and
  compares two slots each; a fragment of ~16k labels, 512 per mm, is a
  millisecond-scale hold in a worst-case mm teardown. Not measured.
- Memory held between retirement and the end of the hook-SRCU grace period
  (previously freed one RCU grace period after the last run): bounded by churn
  times the longest hook call; `jit_churn` passes, no number measured.
