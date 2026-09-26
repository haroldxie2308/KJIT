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
       `ldr xN, [sp, #176]` (pt_regs pointer). Every other frame slot (caller
       x29/x30, entry address, caller x18..x28, the pt_regs / extra-params
       pointers, the 200..208 padding) and anything outside the 208-byte frame
       is rejected: a body write there is a kernel write primitive through the
       epilogue. The budget counter (192) is rule 6's.
     - based on a register proven to hold the pt_regs pointer, inside
       `regs[0..31]` + `sp` (`[0, 256)`); `pc`, `pstate` and beyond are never
       accessible. Proof is forward dataflow in straight-line code: the register
       was loaded by `ldr xN, [sp, #176]` and not written since, with no join
       point in between.
   - Everything else is rejected: exclusives, atomics, SIMD, PRFUM/RPRFM, DC/IC/AT
     are outside the decoded subset (rule 1); pair or pre/post forms not
     matching the above fail the base/range/writeback checks.
4. Control flow.
   - Direct branches (B, B.cond, CBZ/CBNZ, TBZ/TBNZ) target the epilogue's
     first word or a body word; never the prologue, the rest of the epilogue,
     or outside the fragment. A target in the cold region must be an exit-group
     start.
   - BL, BR, BLR, RET are rejected in the body; the prologue's `br x12` and the
     epilogue's `ret` are covered by the byte-exact check.
   - The last word is an unconditional `B` (nothing falls off the end).
   - Entry offsets: non-empty, aligned, in the body and before the cold region.
5. System: only `MRS Xt, TPIDR_EL0` (the only MRS the generated subset decodes),
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

Join points (where the dataflow restarts): entry offsets, stubs, and direct
branch targets; also after every unconditional `B`.

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
    (fragment page faults). Unregister = static key off, pointer NULL,
    `synchronize_srcu`: it waits for hook calls in flight, never for a syscall
    the loop invoked (those run outside the SRCU section).
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
  for an FP reload before EL0 runs; fragments never touch FP/SIMD.
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
  for calls in flight), claim and empty every `kjit_mm`, `mmu_notifier_put`,
  `mmu_notifier_synchronize`, `rcu_barrier`, `destroy_workqueue`.

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
  `MAX_CHAIN` (16) chained entries and `kjit_can_run` holds (it now also checks
  `enable`), continue at T's verified entry in the fragment that just exited,
  else at the fragment for (mm, T); each chained entry counts `chains`.
  Otherwise userspace resumes at T; if the lookups ran and failed, T is
  profiled. Reaching the cap counts `chain_cap`.
- Every entry is budget-bounded and the run conditions are re-checked before
  each entry and before each in-kernel syscall, so a hook call spends at most
  16 budget-bounded runs in fragments between syscalls.

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
- `MRS.MRS_RS_systemmove` is constrained to TPIDR_EL0 (`o0=1 op1=3 CRn=13 CRm=0
  op2=2`). Kernel assumption (pin in K-tasks): while a fragment runs at EL1,
  TPIDR_EL0 still holds the current task's user TLS pointer (Linux switches it
  only on context switch), so the MRS is exact without rewriting.
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
