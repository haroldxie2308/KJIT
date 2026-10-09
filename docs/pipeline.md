# KJIT design: goals, architecture and current contracts

This file is the programmatic design document. It states the goal, the
architecture and translation pipeline, and the contracts the code must match,
each in its current form. When a decision changes a contract, the contract here
is rewritten (the old rule is superseded, not appended to) and the change is
recorded as a new entry in `docs/journal/`.

Everything experimental or historical lives in `docs/journal/YYYY-MM-DD.md`:
measurements, findings, benchmarks, test campaigns, implementation records and
their decisions-with-reasons, "Not verified" lists, defect analyses. Contracts
are written here first, before implementation. A journal entry is cited as
`docs/journal/<date>.md, "<entry title>"`; the index at the end of this file
lists them per milestone.

Milestone names (A1..A11, K0..K4, P1, V1..V3) are the project's task labels;
they stay in headings so that code comments can cite them.

## Contents

1. Goal and non-goals
2. Architecture and translation pipeline
3. Fragment ABI
4. Translator contracts
5. A64 subset and generated metadata
6. Verifier (V3)
7. Harness contracts
8. Kernel runtime (K2)
9. Automatic hot-path detection (K3)
10. Validation of the kernel runtime (K2-K4)
11. Open decisions and known limitations
12. Journal index

## 1. Goal and non-goals

KJIT translates hot userspace syscall-adjacent AArch64 code into kernel-space
executable code so the program can avoid repeated userspace/kernel context
switches. The only target architecture is ARM64/AArch64.

```text
raw userspace bytes -> generated typed A64Insn -> raw kernel-safe bytes
```

Correctness goal: a translated program behaves exactly as it does natively.
Wherever a fragment cannot or should not run an instruction in the kernel, it
exits to userspace at that instruction, which re-executes natively (an
`Unsupported`, `Mem` or `Budget` exit, or a declined syscall), so declining is
always exact. Safety goal: the kernel runs only fragments that an independent
verifier accepted (section 6), and user memory is touched only through
instructions that carry EL0 permissions (section 4, Privilege model).

Speed is not a goal yet; semantic equivalence comes first. Validation is
layered: as much as possible is proven in userspace (the harness) before any
kernel execution.

Non-goals: x86; a generic JIT framework; an Arm decoder beyond the selected A64
subset (`spec/arm64/subset.toml` is canonical); performance optimization before
semantic equivalence; kernel-first debugging of translator bugs.

## 2. Architecture and translation pipeline

### Components

- `spec/arm64/subset.toml` and `specgen/`: the supported Arm XML subset and the
  generator of `A64Insn` (decode, encode, operand roles, flags metadata).
- `shared/` (`no_std + alloc`, runs in userspace and kernel): `arm64`
  (generated subset), `trans` (`cfg`, `rephrase`, `reg_virt`), `emit`
  (`layout`), `abi`, `verify`, `platform`.
- `harness/`: the userspace proving ground. An interpreter for original code
  and for fragments, `URuntime` (the future kernel executor's model), a native
  hardware runner (Linux arm64 only), the differential fuzzer, the harness code
  cache, fixtures (`tests/arm64`).
- `runtime/` (Rust) and `kjit_glue.c` (C): the kernel module. Hook decision
  (`runtime/exec.rs`), translate and verify at install (`runtime/translate.rs`),
  counters (`runtime/stats.rs`), FFI (`runtime/ffi.rs`); the per-mm code cache,
  call trampoline, debugfs and the auto mode (`kjit_glue.c`).
- `kernel-patches/`: seven patches on the pinned Linux 7.1-rc1 tree (section 8,
  Patch series). Guest tests: `tests/guest`.

### Passes

The pipeline stays A64-to-A64; there is no architecture-neutral IR.

1. Decode raw bytes into generated `A64Insn` values with original PC.
2. Admission: `cfg::admit_at(code, pc)` is the single decision per PC (read the
   word, then `admit_word`: generated decode + `is_decode_undefined`, then
   `reg_virt::admit_insn`). Anything not admitted becomes an `Unsupported` exit.
3. Build the reachable CFG from the entry PC through a `CodeProvider`;
   `cfg::layout_block_order` is the one block order (ascending start address).
4. Rephrase: semantic boundary instructions stay typed A64. It is the only
   producer of runtime exits, the cold-region stubs (`Mem`, `Budget`), the
   back-edge budget checks and the dispatch sites; it lowers `ADR`/`ADRP` to
   absolute addresses, `PRFM` and `BTI` to `NOP`.
5. Reg-virt: register virtualization as a separate structured pass.
   `RewritePlan::build` is the single decision for admission and for the
   lowering of every user-semantic instruction; reg-virt knows nothing about
   branches or budgets.
6. Layout: one executable fragment (prologue, epilogue, block bodies, then the
   cold region of every block), virtual labels, branch immediates. Layout owns
   branch-immediate rewriting and checks the invariants it relies on.
7. Emit bytes with generated `A64Insn::encode()`.
8. Decode and verify the emitted bytes again (section 6). The verifier is not
   part of the translator: it imports only `shared::{abi, arm64, platform}`.

Unknown dynamic targets always return to the runtime; no fragment branches to a
raw user-controlled target in kernel space.

### Layers of validation

Interpreter (original vs fragment, `compare_differential`), native hardware
oracle (section 7), differential fuzzer, verifier mutation suite, then the
kernel golden check, the guest tests (K2/K3), and the redis campaign (K4).
Kernel safety is not claimed from harness-only tests; QEMU/kernel tests are not
the first debugging tool for translator logic.

## 3. Fragment ABI

`shared/abi` is the canonical ABI contract (constants, prologue, epilogue,
dispatch template). The harness and the kernel executor consume those names.

### ABI: fragment entry

- The runtime always calls a fragment at its base (the prologue) with
  `x0 = pt_regs`, `x1 = extra params`, `x2 = ABI_ENTRY_ARG_REG` = fragment base
  + an entry offset taken from `ExecutionFragment` (`entry_offset` for the first
  entry, `offset_for_pc(resume_pc)` when continuing after a runtime exit). The
  kernel trampoline is `kjit_call_fragment` (section 8, Call ABI); the native
  runner mirrors it, and also checks that x18..x29 and sp survive (C ABI).
- Extra params are three u64 (`EXTRA_PARAMS_WORDS = 3`):
  `[0]` = x10 out (`RET_PARAM0`), `[1]` = x11 out (`RET_PARAM1`), written by the
  epilogue `stp x10, x11, [x17]`; `[2]` = the run's dispatch table in
  (`EXTRA_PARAM_IBTC_TABLE_INDEX = 2`, `EXTRA_PARAM_IBTC_TABLE_OFFSET = 16`).
  The runtime always passes a valid table: a run executes a fragment of
  `current->mm`, and the tables are allocated with that mm's first install.
  `x0` returned = `RetStatus`.
- The prologue stores `x2` in frame slot `RUNTIME_FRAME_ENTRY_ADDR_OFFSET` (80)
  before its `pt_regs` loads overwrite it, stores the dispatch table pointer
  (`ldr x12, [x1, #16]; str x12, [sp, #200]`, after the pt_regs/extra pointer
  store and before the `ldp x0, x1` that overwrites x1), stores the budget
  counter (`movz x12, #4096; str x12, [sp, #192]`), and ends with
  `ldr x12, [sp, #80]; br x12`. x12 is reg-virt scratch, dead at body entry;
  user x12 is already in its frame slot. `PROLOGUE_LEN_BYTES` =
  `EPILOGUE_OFFSET` = 0xa8.
- Invariant: that `br x12` is the only indirect branch in a fragment other than
  a dispatch template's (section 4, In-fragment branch dispatch), and its target is never user-controlled:
  the runtime (harness and kernel) only passes known entry offsets. V3 checks
  exactly this.
- Kernel BTI is off (K1): the prologue's and the dispatch template's `br x12`
  land on unmarked words.
- Function-boundary behavior is part of correctness: translation tests model
  entry arguments, runtime-exit status/params, link-register policy, prologue,
  epilogue and register writeback consistently with `shared/abi`.

### Runtime frame

The frame is 208 bytes (`shared/abi/frame.rs`), kernel stack, `sp`-based:

| Offset | Content |
|---|---|
| `[16, 80)` | user-state slots: stack-backed user x12..x17, user x29, user sp |
| 80 | entry address (`RUNTIME_FRAME_ENTRY_ADDR_OFFSET`) |
| 176 | the pt_regs pointer (kernel slot; the only kernel slot the body may read, into a scratch register x12..x15) |
| 192 | back-edge/dispatch budget counter (8 bytes, `RUNTIME_FRAME_BUDGET_OFFSET`) |
| 200 | the run's dispatch table pointer (`RUNTIME_FRAME_IBTC_OFFSET`) |
| other | caller x29/x30, caller x18..x28, the pt_regs / extra-params pointers (kernel state; the body can neither read nor write them) |

The epilogue reloads the kernel's callee-saved state from frame slots the body
cannot write and writes the full user state back into `pt_regs`.

### Return statuses and exit groups

A runtime exit is an exit group: `x9 = RetStatus`, `x10` = param0, `x11` =
param1, then `b <epilogue>`; reg-virt preserves x9..x11 to `pt_regs` first
(the group is 13 instructions for a `Mem`/`Budget` stub). Statuses are
`Svc, Bl, Blr, Br, Ret, Mem, Unsupported (6), Budget (7)`, in that order, raw
values 0..=7; the kernel matches the raw value exactly and treats anything else
as a kernel bug (section 8, kjit_after_syscall decision).

| Status | x10 | x11 |
|---|---|---|
| `Svc` | | PC after the `svc` |
| `Bl`/`Blr`/`Br`/`Ret` | the target | the resume PC |
| `Mem` | the original instruction word | `ori_pc` |
| `Unsupported` | the raw word, or `UNSUPPORTED_WORD_UNREADABLE = u64::MAX` | the PC |
| `Budget` | the branch's raw word | the branch's PC |

`decide_runtime_return` is the one harness decision for what a returned status
means; `URuntime` and the native runner share it. `Unsupported`, `Mem` and
`Budget` stop with `ReturnedToUserspace { status, x11 }`.

## 4. Translator contracts

### Unsupported-instruction exit

- An undecodable word does not fail translation. `build_cfg` ends the block
  before it and records `BasicBlock.unsupported_exit = Some(UnsupportedExit::Insn(..))`.
  Invariant: `pc == end_addr`, `next` is empty, `insns` may be empty (entry
  itself undecodable).
- A PC past the readable text is the same exit: `UnsupportedExit::Unreadable { pc }`.
  Without it a block that ran into the end of the text had no successor and no
  exit, and the fragment ran off its end. No word exists, so `x10` carries the
  sentinel `UNSUPPORTED_WORD_UNREADABLE = u64::MAX`; a real word is always
  <= `u32::MAX`. Userspace resumes at that PC and fetches (or faults)
  natively, which is exact. This covers falling through the last word and a
  branch or conditional fall-through to a PC past the text (an empty block
  holding only the exit). An unreadable **entry** stays a hard
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
  halt.
- Rephrase stays the only producer of the exit; reg-virt never synthesizes it.
- Rephrase lowers it to an exit group: `x9 = RetStatus::Unsupported (6)`,
  `x10 = raw word` (or `UNSUPPORTED_WORD_UNREADABLE`), `x11 = pc`. The runtime
  always resumes userspace at `x11` and never re-enters the fragment at that PC
  for this status.
- Why it is exact: userspace executes the instruction natively, including taking
  SIGILL itself for a truly undefined word. `x10` is the exact word in both
  cases; decoding it tells an undecodable word from a reg-virt rejection (the
  coverage histogram is built from it).
- Entry refusal (kernel): a translation whose entry word itself would take
  this exit is refused (section 9, Negative cache).

### Pair and writeback memory forms in reg-virt

- LDP/STP (64-bit off/pre/post) and LDR/STR imm pre/post (32/64) go through the
  normal per-instruction fill -> rewrite -> spill plan. A writeback base is
  read-write.
- Constrained-unpredictable encodings (writeback base == transfer register with
  a non-SP base; LDP rt == rt2; SIMD&FP LDP `t == t2`; LD1/ST1 post-indexed by
  the base register itself, which the architecture defines but is rejected
  conservatively) are rejected with `UnpredictableMemoryOp`, never translated;
  admission turns that into the `Unsupported` exit. Register-offset forms have
  no writeback, so `rt == rn` or `rt == rm` is well defined and translated.

### Privilege model

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
    memory, except the PAN-window accesses (LSE atomics, SIMD&FP loads/stores:
    see their sections). EL0 permissions apply in hardware. Reg-virt emits them
    with an unscaled `simm9` offset only, and never admits one from user code.
  - runtime access = any other load/store. Allowed only on the runtime frame
    (kernel stack, `sp`-based), the `pt_regs` / extra-params blocks and the
    dispatch table and records.
- Kernel assumptions this relies on (pinned in K1): hardware PAN on,
  `PSTATE.UAO == 0` while a fragment runs (otherwise `LDTR` at EL1 is a
  privileged access), `ARM64_SW_TTBR0_PAN` off.
- User code containing `LDTR`/`STTR` is rejected by `RewritePlan::build` as
  `UnprivilegedUserAccess` (intrinsic -> `Unsupported` exit): at EL0 they are
  plain loads/stores, but a fragment runs them at EL1 as its user-access
  instruction. A form whose generated metadata has a `Memory` role but no
  lowering is `UnloweredMemoryForm`, a hard translator error.

### Memory rewrite (A5)

- Reg-virt lowers every user load/store to the LDTR/STTR family, using the same
  per-instruction scratch pool it already owns (x12-x15). No second scratch
  allocator: `RewritePlan::build` plans the lowering (`MemLowering`) and
  allocates all scratch through one counter (stack-backed mappings first, then
  the address scratch, then the pair first-load scratch), so admission sees
  exactly the capacity the rewrite uses. Worst case is 4;
  `ScratchPoolExhausted` is unreachable for the current forms.
- Addressing: `LDTR`/`STTR` take only an unscaled `simm9`. Offsets outside it
  are materialized with `ADD`/`SUB` (imm, optionally `lsl #12`) into scratch;
  offsets beyond 24 bits are `UnencodableMemOffset` (intrinsic). Pre/post-index
  writeback is a separate `ADD`/`SUB` of the base after the accesses (nothing
  for `#0`). `LDP`/`STP` become two accesses.
- **Commit-after-last-access invariant.** Within one original instruction, no
  user-visible location (a direct user register, a stack-backed frame slot,
  the stable x29/sp mappings in x16/x17) is written before the instruction's
  last faulting access. Every access but the last loads into scratch; the last
  may target its final register; register moves, writeback and spills follow.
  So at every fault point the user state equals the state before the original
  instruction.
- If the instruction cannot be lowered within the scratch pool, it is an
  intrinsic reg-virt rejection -> `Unsupported` exit at that PC.
- **SP alignment check.** Linux runs EL0 with SP alignment checking
  (`SCTLR_EL1.SA0`): a load/store whose base is SP faults (SIGBUS) when SP is
  not 16-byte aligned. User SP lives in x17 in a fragment, which is never
  checked, so without a check KJIT would run code that natively faults. For
  every user access whose base is SP (immediate and register-offset forms)
  reg-virt emits, before anything else of the instruction,
  `and xS, x17, #15; cbnz xS, <Mem stub of that instruction>` (kind
  `AlignCheck`, shared with the acquire/release alignment check; layout
  resolves the `CBNZ` like a budget check's `CBZ`). Flags are untouched. `xS`
  comes from the same scratch pool; it shares the address or pair first-load
  scratch when the instruction has one, both being written only after the
  check. The `Mem` exit returns to userspace at the instruction, which
  re-executes natively and takes the SIGBUS itself: exact. The `CBNZ` is a
  forward branch into the cold region, to an exit-group start (verifier rule
  4). The interpreter models the fault (`FaultCause::SpAlignment`, precise,
  before any access); the native runner matches it at the SP value Linux
  reports (`el0_sp`).

### Fault sites (A5)

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
  partition the PC space. Layout fails (`UntaggedUserAccess`) if the kind and
  the `LDTR`/`STTR` form ever disagree, and (`MissingFaultStub`) if a user
  access has no stub. Budget and `Mem` stubs share the stub label map (one stub
  per original PC: a branch never accesses memory; `DuplicateFaultStub` still
  catches two).
- The kernel's fault fixup (K2) only sets the faulting PC to the stub offset.
  The harness does the same: a user-access fault at a fragment offset jumps to
  the table's stub, and an offset without an entry is a hard error.
- On `Mem` the runtime returns to userspace at x11. Userspace re-executes the
  instruction natively and takes the fault itself, so signals and SIGSEGV
  behave exactly as they do without KJIT.
- The native runner does the same fixup on real hardware: its SIGSEGV/SIGBUS
  handler looks the faulting PC up in the fault sites of every fragment of the
  cache, sets the ucontext PC to the stub and resumes the fragment; a data
  abort in the fragment without an entry stays a hard failure.
  `default_fixture_state` maps one read-only page after the data window
  (x12 + 0x4000; x12 + 0x5000 is unmapped).
- Acceptance check (`check_fragment_fault_injection`, every fixture case):
  fragment user accesses are matched to original accesses by (PC, dynamic
  instance, sub-access) and must have equal address/size/kind; for every
  original access k the matching fragment access is failed and the fragment
  must exit `Mem` at the original PC with the pre-instruction user state, with
  the fault footprint excepted. A case whose original run faults on its own
  counts only the accesses before that instruction; the fragment's extra
  accesses must all belong to it.
- Fault footprint (`Footprint`): a faulting instruction may already have
  written part of its effect, which the architecture allows and userspace
  redoes anyway. When a split `STP` faults on its second access the first 8
  bytes may be written; a faulting SIMD&FP load may have loaded some of its
  destination registers or written part of a store (observed natively, for
  original and fragment alike; examples in the journal, "A9a implementation"). The
  differential check allows each byte of the faulting
  store on a writable page, and each byte of a faulting SIMD&FP load's
  destination V registers, to hold its old or its complete-execution value
  (byte-wise, in 16/32-byte units). It applies to natural faults too. Fault
  injection keys an LD1/ST1's element accesses by their order within one
  execution of the window access.

### Execution budget (A6)

- A back-edge is any branch whose target is at or before it in the final
  layout order. Layout order is a block order (`cfg::layout_block_order`:
  ascending block start address; blocks partition the PC space, so a
  fall-through successor is the next block), so this is known before offsets
  and can be checked on the final bytes without a CFG. The program vector keeps
  CFG order (`program[0]` is the entry block). Layout fails with
  `LayoutError::FallthroughNotAdjacent` when a block with a successor at its
  own end is not followed by it, so lowering never adds explicit fall-through
  branches (they would be extra back-edge candidates).
- The prologue stores `KJIT_BACKEDGE_BUDGET = 4096` (an ABI constant) in the
  runtime frame slot 192. Why 4096: one entry runs at most 4096 x the longest
  acyclic path before the runtime re-checks signals and `need_resched`; loops
  under 4096 iterations never pay a round trip. The counter is an 8-byte slot;
  the budget unit is one back-edge execution or one dispatch attempt (see
  In-fragment branch dispatch (A11)).
- Before each back-edge's lowered sequence the fragment runs: load slot ->
  `SUB #1` -> store slot -> `CBZ` to a budget stub. The sequence uses scratch,
  which is dead at an instruction boundary, and must not touch NZCV (hence
  `SUB` + `CBZ`, not `SUBS`). Exact words, with nothing between them and the
  branch except that branch's own reg-virt fills (`ldr x12..x15,
  [sp, #16..#56]`):

  ```text
  f94063ec  ldr x12, [sp, #192]
  d100058c  sub x12, x12, #1
  f90063ec  str x12, [sp, #192]
  b4xxxxxc  cbz x12, <Budget stub of this PC>     // imm19 -> cold region
            [fills of the branch's stack-backed register]
            <the back-edge branch>
  ```

- Count semantics: the prologue stores N; each unit (taken or not) decrements
  first and exits at zero, so units 1..N-1 of one entry run and the N-th exits
  before the branch. Any fragment entry (SVC resume, chaining) restarts at N.
- The budget stub is an out-of-line exit group like the fault stub
  (`push_native_resume_exit(Budget, pc, word)` in the block's `cold`, in
  instruction order -- the same 13-instruction group as a `Mem` stub), with
  `RetStatus::Budget = 7`, x10 = the branch's raw word, x11 = its PC.
  Userspace resumes natively at the branch.
- Pass placement: **rephrase**. It owns semantic exits and the cold stubs, sees
  the whole CFG, and runs before reg-virt, so the Budget stub is virtualized
  like every other exit group and reg-virt never learns about branches or
  budgets. Back-edge test: visiting blocks in layout order, a lowered original
  instruction contains a user-semantic B/B.cond/CBZ/CBNZ/TBZ/TBNZ whose target
  PC is already placed (every PC emitted so far in layout order, the
  instruction's own included). Forward branches into the cold region
  (fault/alignment guards, budget `CBZ`) are not user branches and never
  back-edges. A branch inside a UserSynthetic sequence counts; the check then
  precedes the whole lowered sequence of its original instruction. Layout only
  resolves the `CBZ` immediate to the stub label.
- Kind: `RephrasedInsnKind::BudgetCheck` on all four instructions (not
  user-semantic, not a runtime exit). Reg-virt passes it through unchanged; in
  the cold region or inside an exit group it is `MalformedRuntimeExitGroup`.
- Layout self-check: a user branch that resolves to `target_offset <= offset`
  without a budget check earlier in its original instruction's run of
  instructions fails with `LayoutError::UnguardedBackEdge`; a check whose PC has
  no stub fails with `MissingBudgetStub`.
- Verifier rule (V3, rule 6): every backward in-fragment branch is preceded by
  exactly this sequence.
- Harness differential: the fragment runs first
  (`run_fragment_counting_instances`); on a `Budget` exit at pc P the dynamic
  instance k is the number of executions of P's body label (every entry,
  branch and fall-through into P lands there; for a back-edge it is the
  check's first instruction). The original runs with `InstanceCap { P, k }` and
  halts with `HaltReason::InstanceCap` before executing P for the k-th time;
  `runtime_halt_matches_original` pairs it with `Budget` at P. The cap is
  derived from the fragment, so the differential proves precision, not the
  count; the count is pinned by the harness runtime unit tests (exit on exactly
  the N-th unit, N-1 completes, re-entry restarts). In cached runs, pc P's
  instance count is the sum of the executions of P's label over the fragments
  holding one.
- Native original: the capped branch word becomes a trap; each earlier arrival
  lets the hardware execute the branch once (in place with every other word
  trapping; a self-branch runs from a scratch page with displacement +8 so the
  hardware only picks taken/not-taken), then the trap is reinstalled. A capped
  `BL/BLR/BR/RET` runs in place the same way
  (`step_capped_branch`).

### In-fragment branch dispatch (A11)

Every `BL`, `BLR`, `BR` and `RET` is lowered to an in-fragment table-based
transfer; the runtime is entered only on a miss. One path covers all four
kinds, needs no text writes (so no ROX patching, no +-128 MiB range limit, no
incoming-link lists) and makes unlinking a single store. `B`/`B.cond` inside the
CFG stay in-fragment. `SVC` is not a branch: its resume stays a runtime path.

- Tables (kernel side, section 8): per `kjit_mm` two dispatch tables. Each is
  one array of 8-byte slots: a direct-mapped main part of `2^IBTC_BITS` slots
  (`IBTC_BITS = 12`), main index `pc[13:2]` (`IBTC_INDEX_LSB = 2`), followed by
  a victim part of `2^IBTC_VICTIM_BITS` slots (`IBTC_VICTIM_BITS = 8`) at byte
  offset `IBTC_VICTIM_OFFSET = 2^IBTC_BITS * 8` (32 KiB), victim index
  `((pc ^ (pc >> IBTC_VICTIM_FOLD_SHIFT)) >> 2) & 0xff` with
  `IBTC_VICTIM_FOLD_SHIFT = 12`, i.e. `pc[9:2] ^ pc[21:14]`; table size
  `(4096 + 256) * 8` = 34 KiB (`IBTC_TABLE_BYTES`). A slot is 0 or a pointer to
  a record `{ u64 pc; u64 host; }` (`IBTC_RECORD_PC_OFFSET = 0`,
  `IBTC_RECORD_HOST_OFFSET = 8`, `IBTC_RECORD_BYTES = 16`): a user PC and the
  absolute address of a verified entry of a live fragment of this mm translated
  for exactly that PC. Only the runtime writes tables; fragment code reads them
  only through the template below.
- Why a victim part (A11c, decided 2026-10-09): under redis the direct-mapped
  table lost 18.5 transfers per SET request to two-pc ping-pongs between pcs
  16 KiB apart, with the table otherwise nearly empty (aliasing, not capacity).
  A 256-slot victim part removed them (0.002 conflicts per request) at +2 KiB per
  table with a main-slot hit identical to the direct-mapped one; 2-way sets of
  the same total size left a 4-pc set conflicting, a folded index alone halved
  them, 4096x2 ways matched the victim part at twice the memory
  ([2026-10-09, dispatch-table conflict variants](journal/2026-10-09.md)).
  Known limit: two evicted pcs may share a victim slot (none seen in 12 boots).
- Publish and retire slot planning (which slots to store, in which order) is one
  pure function set in `shared/abi`, called by the kernel runtime (under
  `kmm->lock`) and by the harness code cache, so the harness mirrors the kernel
  by construction. For target T with label L, per table L belongs in:
  - nothing if T's main slot or T's victim slot already holds a record for T
    (any fragment's: all are translations of the same text);
  - else, if T's main slot is empty: store L there;
  - else (the main slot holds a record R for another pc P): store R into P's
    victim slot (dropping whatever it held), then store L into T's main slot.
    Both are single 8-byte release stores in that order, so every slot always
    holds 0 or a live record.
  - Retire of a fragment clears, for each of its labels, the label's main slot
    and the label's victim slot where they still point at the label.
- `table_all` may hold records of every fragment; `table_nofp` only records of
  fragments with `uses_fpsimd == false`. A run of an FP/SIMD fragment (inside
  the bracket) dispatches through `table_all`; any other run through
  `table_nofp`, so a run outside the bracket can never reach FP/SIMD code, and
  a bracketed run may continue into non-FP/SIMD code (its faults become `Mem`
  exits, as for any bracketed access: correct).
- Lowering (rephrase; one site per original `BL`/`BLR`/`BR`/`RET`), in the
  body, replacing a plain `b <exit group>`:

  ```text
  ldr  x12, [sp, #192]            ; budget check (rule 6 form) -> Budget stub
  sub  x12, x12, #1
  str  x12, [sp, #192]
  cbz  x12, <Budget stub of pc>
  <T -> x13>                      ; BL: movz/movk of the target;
                                  ; BLR/BR/RET: mov or fill from the target's mapping,
                                  ; before any x30 write (`blr x30`)
  <x30 = resume>                  ; BL/BLR only (existing link write)
  ldr  x12, [sp, #200]            ; --- dispatch template (byte-exact, 20 words) ---
  ubfx x14, x13, #2, #12          ; main probe: slot pc[13:2]
  ldr  x12, [x12, x14, lsl #3]
  cbz  x12, 1f
  ldr  x14, [x12]
  sub  x14, x14, x13
  cbnz x14, 1f
  ldr  x12, [x12, #8]
  br   x12
1:ldr  x12, [sp, #200]            ; victim probe
  eor  x14, x13, x13, lsr #12
  ubfx x14, x14, #2, #8           ; victim slot pc[9:2] ^ pc[21:14]
  add  x12, x12, #8, lsl #12      ; victim part at table + 32 KiB
  ldr  x12, [x12, x14, lsl #3]
  cbz  x12, <exit group of pc>
  ldr  x14, [x12]
  sub  x14, x14, x13
  cbnz x14, <exit group of pc>
  ldr  x12, [x12, #8]
  br   x12
  ```

  - New kinds `DispatchTarget` (T into physical x13) and `DispatchLookup` (a
    template word). BL's target move is the usual four `movz`/`movk` words;
    BLR/BR/RET use `orr x13, xzr, Xm` with `Xm` the *user* register, which
    reg-virt maps with the capture machinery the exit group's RET_PARAM0
    already had (stack-backed x12..x17 are loaded from their slot, user x29/sp
    are read from x16/x17, everything else is copied). Order is fixed so
    `blr x30` reads x30 into x13 before the link write.
  - The exit group (the miss path) is the site's plain branch exit (same
    status, x11 = resume) with x10 taken from x13, so a miss behaves exactly
    as a plain exit. Its param0 copy is `add x10, x13, #0`, not `orr x10, xzr,
    x13` (that shape is the param0 capture of a *user* register and would load
    user x13's slot); `validate_runtime_exit_payload` lets exactly this word
    read physical x13 (`is_dispatch_miss_param0_copy`), any other payload
    reading a stack-backed number is still rejected.
  - `SUB`/`CBZ`/`CBNZ` keep NZCV (user state) untouched, as the budget check
    already does.
  - Budget: every dispatch attempt costs one unit of the `KJIT_BACKEDGE_BUDGET`
    counter, whether it hits or misses. The check precedes the whole lowered
    branch, so a Budget exit leaves the state from before the instruction and
    userspace re-executes the branch natively (also correct for `blr x30`). This
    is what bounds recursion and call loops, which no longer pass through the
    runtime. `rephrase` puts the budget check (same four words, same cold
    Budget stub) before the whole site, as for a back-edge.
  - Scratch: x12 (kernel values only), x13 (T, a user value), x14. x15 stays
    free. All are dead at original-instruction boundaries; x13 stays live from
    the site into its own exit group. `DISPATCH_SLOT_REG = 12`,
    `DISPATCH_TARGET_REG = 13`, `DISPATCH_KEY_REG = 14`.
  - Layout resolves the main probe's two miss branches to the victim probe's
    first word (template word 9) and the victim probe's two to the word after
    the final `br`, so the exit group directly follows the template inside the
    body (not in the cold region). `LayoutError::MalformedDispatchTemplate` for
    a template that is cut short or has no word after its final `br`.
  - One dispatch attempt is one budget unit, whichever probe hits.
- The template is `KJIT_DISPATCH_TEMPLATE` (20 `A64Insn`s, miss offsets 0) in
  `shared/abi`, next to `KJIT_PROLOGUE`, with
  `dispatch_template_matches(&[u32])`, which compares encoded words (the
  encoding is the contract, like the prologue's check), frees only the four
  `imm19` fields and returns them; a test pins the twenty words to `llvm-mc`'s
  encodings. There is one template: no variant selection.
- Verifier: see rules 2, 3, 4, 6, 7, 9 (section 6). The bytes alone no longer
  determine every branch target (a dispatch target comes from a table the
  runtime owns); the verifier proves that the only way to use a table is the
  exact template, that it cannot read out of bounds, that it is
  budget-charged, and that no kernel value escapes. What the runtime must
  guarantee (table content) is the invariant in section 8.
- Run conditions and bounds: see section 8, Run conditions (kjit_can_run).

### Memory form coverage (A7b)

The exact supported forms are in `spec/arm64/subset.toml`. Still out (so
undecodable and an `Unsupported` exit): exclusives, LDNP/STNP, PRFUM, RPRFM
(excluded from `PRFM_reg` by its diagram). LSE atomics, acquire/release and
SIMD&FP load/stores have their own sections.

Lowering (one path: `MemShape` -> `plan_mem` -> `emit_mem_lowering`).
`MemShape` = the `LDTR*`/`STTR*` op (element size + extension), `rt`, optional
`rt2`, an address mode and an `ordered` flag. Every access uses the op with the
user form's element size and extension, so the loaded value needs no fix-up.

| user form class | address into | accesses |
| --- | --- | --- |
| imm offset/pre/post, unscaled (`simm9`-reachable) | base itself, `#off` | 1 (pair: 2 at `off`, `off+size`) |
| same, offset outside `simm9` | scratch = base +- imm (`ADD`/`SUB`, opt. `lsl #12`) | at `#0` (`#size`) |
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
  writes the whole X register. A pair's first load targets its final register
  directly only when that is XZR or a stack-backed register's scratch that is
  not the access base; otherwise it loads into scratch and a `MOV` follows the
  second access.
- Commit-after-last-access is unchanged: all address materialization writes
  only scratch, before the first access.
- **PRFM is dropped.** A prefetch is a hint: no architectural effect on
  registers or memory, and never a synchronous data abort, whatever the
  address. Replacing it with a `NOP` (kept so the original PC still maps to
  code) is exact, and keeps the fragment from issuing EL1 prefetches of user
  addresses. Its metadata has no `Memory` role (the specgen `Memory` role
  requires an actual `Mem{..}` access), so rephrase gives it no fault stub.
- `is_decode_undefined`: register-offset forms with `option<1> == 0` (sub-word
  index) are UNDEFINED. The `*BL` byte forms and PRFM (register) fix it in
  their diagrams. The generic role-driven reg-virt rule covers every form:
  writeback base == transfer register (base not SP) and LDP/LDPSW `rt == rt2`
  are `UnpredictableMemoryOp`.

### Barriers and acquire/release (A7c)

Barriers (`DMB`, `DSB`, `ISB`, every CRm; the nXS `DSB` stays out) are emitted
unchanged: user-semantic instructions with no operand roles. DMB/DSB order the
fragment's memory accesses (the `LDTR*`/`STTR*` are the user's accesses) the
same way at EL1; DSB additionally waits for maintenance operations, which the
fragment has none of (the DSB pseudocode's FEAT_XS `nXS` rule treats EL0 and EL1
alike); ISB is a context synchronization with nothing
EL-specific. The interpreter treats them as no-ops (one observer, no caches, no
speculation); ordering is not differentially tested.

No unprivileged ordered access exists without FEAT_LSUI, so reg-virt lowers
every ordered form (`LDAR{,B,H}`, `LDAPR{,B,H}`, `STLR{,B,H}`, base register
only) through the one memory path (`MemShape { ordered: true, addr:
MemAddr::Base }`):

| user form | emitted (after fills) |
| --- | --- |
| `LDAR{,B,H} / LDAPR{,B,H} Rt, [Xn]`, `STLR{,B,H} Rt, [Xn]`, Xn not SP | [alignment check]; `dmb ish`; `LDTR*/STTR* Rt, [Xn, #0]`; `dmb ish` |
| same, Xn = SP | SP check (`and xS, x17, #15; cbnz xS`); `dmb ish`; access via x17; `dmb ish` |

- Op per form: the same element size and extension as the plain load/store
  (`LDAR W`/`LDAPR W` -> `LDTR W`, `LDAR X`/`LDAPR X` -> `LDTR X`,
  `LDARB`/`LDAPRB` -> `LDTRB`, `LDARH`/`LDAPRH` -> `LDTRH`, `STLR W/X` ->
  `STTR W/X`, `STLRB` -> `STTRB`, `STLRH` -> `STTRH`).
- The fences are `RegVirtHelper` instructions: runtime-owned, no registers. The
  access is the usual `UserAccess` fault site with the instruction's `Mem`
  stub; commit-after-last-access holds unchanged (the trailing fence writes
  nothing; a load-acquire into a stack-backed register spills after it). A
  fault on the access leaves after the leading fence: an extra barrier, no
  effect. Scratch: stack-backed `Rt`/`Rn` plus one for the alignment check: at
  most 3.
- The `Rs`/`Rt2` should-be-one fields are pinned in `[decode.field_constraints]`
  (`Rs = 31, Rt2 = 31`; LDAPR `Rs = 31`); other values are CONSTRAINED
  UNPREDICTABLE and stay undecodable. Out: exclusives, LSE atomics (they have
  their own section), FEAT_LRCPC2 `LDAPUR`/`STLUR`, FEAT_LRCPC3 writeback
  `LDAPR`/`STLR`.

Why the full-fence mapping is correct. `DMB ISH` (CRm 1011, reads and writes
both sides) orders every memory access before it in program order before every
access after it, for every observer in the Inner Shareable domain, which holds
every CPU that can run the process (Linux's `smp_mb()`).

- Acquire (LDAR, and LDAPR's weaker RCpc acquire): the access must be observed
  before every later access: the trailing fence.
- Release (STLR): every earlier access must be observed before the store: the
  leading fence.
- RCsc (LDAR): a store-release followed in program order by a load-acquire must
  be observed in that order: the fence after the STTR (and the one before the
  LDTR) sits between them.
- Multi-copy atomicity: Armv8 is other-multi-copy-atomic for every store, not
  only STLR, so the `STTR` of a store-release becomes visible to all other
  observers at once. Single-copy atomicity of the access itself is that of an
  access of the same size and address; LDAR/STLR are only more atomic for
  misaligned-within-16-byte addresses under FEAT_LSE2.
- The mapping is strictly stronger (it also orders earlier accesses before a
  load-acquire and a store-release before later accesses), so every execution
  it allows is one the original allows. Weaker (one-sided) mappings are a later
  optimization, not a correctness need.
- Dropping a fence is a correctness bug but not a safety one: the verifier
  checks safety, not ordering, and accepts a fragment without them. Removing a
  fence is deliberately not a verifier mutation class.

Alignment. `LDTR*`/`STTR*` never alignment-fault (SCTLR_EL1.A = 0). An ordered
access does: `AArch64_UnalignedAccessFaults` with `acqsc`/`acqpc`/`relsc`
faults a misaligned access iff SCTLR_ELx.nAA == 0 and it crosses a 16-byte
boundary. Linux leaves nAA clear. So for every ordered access wider than a byte
whose base is not SP, reg-virt emits before the fences (kind `AlignCheck`,
flags untouched):
`and xS, xN, #15; add xS, xS, #(size - 1); and xS, xS, #16; cbnz xS, <Mem stub>`
(bit 4 of `(addr & 15) + size - 1` is set iff the access crosses). The Mem exit
returns to userspace at the instruction, which re-executes natively and takes
the SIGBUS itself: exact. `CBNZ` (imm19), not `TBNZ` (imm14, +-32 KiB), so a
large fragment cannot put the cold region out of range. An SP base needs no
such check: the SP check already requires SP 16-byte aligned and the access is
at SP. Bytes are always aligned. Interpreter: an ordered access that crosses a
16-byte boundary is a `FaultCause::Alignment` fault before any access (after
the SP check), on the untagged address; the native original reports it as a
SIGBUS at the instruction.

Kernel assumptions (pinned at module init, section 8, Preconditions): FEAT_LSE2
with SCTLR_EL1.nAA == 0 (without it every misaligned ordered access faults
natively, while a fragment runs a misaligned one that stays inside a 16-byte
block: more permissive than native, never unsafe; the alternative would be the
stricter check `and xS, xN, #(size - 1); cbnz`); FEAT_LRCPC for LDAPR
(without it user LDAPR is UNDEFINED natively but the fragment would run it).

### BTI, carry arithmetic, CRC32 (A7d)

- **BTI is rephrased to NOP.** Executed in sequence, BTI is a NOP; its only
  effect is the landing-pad check of an indirect branch into a guarded page
  (PSTATE.BTYPE). A fragment is never one: entries come from the runtime
  through the prologue's `br x12` with kernel BTI off (K1), and a `Blr`/`Br`
  exit does not carry BTYPE (section 11, Known limitations: BTI). So a `NOP` is exact for every
  correct program; a native BTI fault on broken control flow is missed. One
  `NOP` (user-synthetic, like PRFM's) keeps the original PC mapped to fragment
  code, so a BTI can be an entry, a branch target and a back-edge target. No
  BTI reaches EL1: the verifier classifies BTI as `UserOnly` (`UserOnlyForm`),
  so the allowlisted HINT space stays exactly NOP. Only the four `BTI` words
  decode (CRm = 0100, op2<0> = 0); every other HINT-space word (PAC hints,
  YIELD, WFE, SEV, CSDB, CHKFEAT, ...) stays undecodable and takes the
  `Unsupported` exit (pinned by `hint_space_decodes_only_nop_and_bti`).
  Harness interpreter: NOP.
- **Carry arithmetic** (`ADC`, `ADCS`, `SBC`, `SBCS`, 32/64): pure ALU
  (`Form::Alu`). They read NZCV.C; ADCS/SBCS write NZCV. Correct only because
  the fragment keeps NZCV intact between user instructions: nothing the
  translator emits sets flags (reg-virt fills/spills are LDR/STR, the SP and
  alignment checks AND/ADD/CBNZ, the budget check LDR/SUB/STR/CBZ, the dispatch
  template LDR/UBFX/SUB/CBZ/CBNZ, exit payloads MOVZ/MOVK/ORR), and the kernel
  trampoline loads/stores user NZCV around every fragment call. Interpreter:
  `AddWithCarry(Rn, Rm or NOT(Rm), PSTATE.C)` on the operand width, flags only
  for the S forms.
- `SMSUBL`/`UMSUBL`, `CRC32*`/`CRC32C*`: `Form::Alu`. Interpreter:
  `Ra - sext/zext(Wn) * sext/zext(Wm)`; CRC as the bit-reflected update of the
  pseudocode's `Poly32Mod2` (polynomials 0x04C11DB7 / 0x1EDC6F41, LSB first, no
  pre/post inversion). CRC32 needs FEAT_CRC32 (module init check).

### LSE atomics through a PAN window (A8)

Why: there is no unprivileged LSE form without FEAT_LSUI, which no current
hardware has. Linux's own futex code performs privileged accesses to user
memory by clearing PAN after `access_ok`; a fragment does the same inside a
window of a shape the independent verifier can check word by word. The window
is also what SIMD&FP loads/stores use (see FP/SIMD).

- In: LSE single-register atomics: `LDADD/LDCLR/LDEOR/LDSET/LDSMAX/LDSMIN/
  LDUMAX/LDUMIN` (all size and A/L/AL variants), `SWP*`, `CAS*` (not `CASP`),
  and the `ST<op>` aliases (Rt = XZR forms of LD<op>): 160 forms in
  `subset.toml`. `MSR_imm.MSR_SI_pstate` is pinned to PSTATE.PAN
  (`[decode.field_constraints]`, `op1 = 0, op2 = 4`; CRm, the immediate, stays
  an operand); every other PSTATE field and CFINV/XAFLAG/AXFLAG stay
  undecodable. A user `msr pan` is rejected by `RewritePlan::build`
  (`PanUserForm`, intrinsic): Unsupported exit, userspace takes its SIGILL.
- Out, still Unsupported: exclusives (`LDXR/STXR/LDAXR/STLXR`, pairs). Why: a
  fragment executes fills/spills (plain stores to the kernel stack) between the
  user's LDXR and STXR, which may clear the local exclusive monitor
  (IMPLEMENTATION DEFINED), and exception returns clear it; correctness would
  survive (STXR failure is always legal and the budget bounds the retry loop)
  but progress would not. Also out: `CASP`, FEAT_LSE128, FEAT_LSUI forms.
- Lowering (reg-virt, `RewritePlan::build` -> `plan_window` -> `emit_window`;
  `RewritePlan.mem` is `MemPlan::Unpriv(MemLowering) | MemPlan::Window(..)`):

  | step | emitted | kind |
  | --- | --- | --- |
  | fills | `ldr xS, [sp, #slot]` of stack-backed Rs/Rt(read)/Rn | RegVirtHelper |
  | SP base only | `and sB, x17, #15; cbnz sB, <Mem stub>` | AlignCheck |
  | base not stack-backed | `mov sA, <mapped Rn>` (x17 for SP, x16 for x29) | RegVirtHelper |
  | size > 1, base not SP | `and sB, sA, #15; add sB, sB, #(size-1); and sB, sB, #16; cbnz sB, <Mem stub>` | AlignCheck |
  | range check | `ubfx sB, sA, #48, #8; cbnz sB, <PAN stub>` | RangeCheck |
  | window | `msr pan, #0; <atomic, Rs/Rt mapped, Rn = sA>; msr pan, #1` | PanToggle, WindowAccess, PanToggle |
  | spills | `str xS, [sp, #slot]` of the written stack-backed register | RegVirtHelper |

  - `sA` is the stack-backed base's own fill scratch, else a fresh scratch; `sB`
    is always a fresh scratch. Worst case 4, so admission never runs out.
  - Commit-after-last-access: before the atomic only scratch is written; the
    atomic writes its destination (Rt, or CAS's Rs) only when it retires; spills
    follow `msr pan, #1`.
  - The range check accepts any top byte (TBI0 ignores bits [63:56] for TTBR0
    accesses at EL1 too) and requires bits [55:48] == 0: bit 55 selects TTBR0
    vs TTBR1, and user VA is 48 bits (`USER_VA_BITS = 48`,
    `PAN_WINDOW_RANGE_TOP_BIT = 55`; K1 pins `ARM64_VA_BITS_48`; the module
    checks `vabits_actual == 48` at init). Rejected addresses exit through the
    same PAN stub (harmless: `msr pan, #1` with PAN already set).
  - The PAN stub is the instruction's ordinary `Mem` exit group preceded by
    `msr pan, #1` (`RephrasedInsnKind::PanRestore`). The atomic's fault-site
    entry points at it: the extable fixup resumes with the faulting context's
    PSTATE (PAN = 0), so the stub must restore PAN before anything else.
  - Alignment: SP-based atomics keep the SP alignment check. LSE atomics use
    `AArch64_UnalignedAccessFaults`'s `exclusive || atomicop` rule: with
    FEAT_LSE2 they fault iff not inside one `MemSingleGranule()` block,
    IMPLEMENTATION DEFINED >= 16 bytes, independent of `nAA`. The check uses 16
    (the minimum): an access it lets through never faults natively; one it
    stops leaves for userspace, which re-executes it natively, so on hardware
    with a larger granule it is conservative, never wrong.
  - Two stubs per atomic that has an SP or alignment check: the verifier's rule
    allows a PAN stub only as the target of the window `cbnz` and of the
    atomic's fault site, so the alignment/SP checks (and they only) leave
    through a plain `Mem` stub of the same PC. Rephrase emits the plain one only
    when reg-virt will branch to it (`atomic_needs_check_stub`: size > 1 or an
    SP base); a byte atomic on a register base has only its PAN stub.
  - Layout: PAN stubs have their own label map (one per PC); a `RangeCheck`
    `cbnz` and a `WindowAccess` fault site resolve to the PAN stub, `AlignCheck`
    to the plain stub. `UntaggedPanWindow` if a kind and the instruction
    disagree; `MissingPanStub`.
  - Exceptions inside the window: Linux runs with SCTLR_EL1.SPAN = 0, so taking
    an exception to EL1 sets PAN, and ERET restores the window's PAN = 0.
    Preemption saves/restores PSTATE the same way.
- Kernel requirements (`kjit_check_cpu`, module init refuses to load with
  `-ENODEV` and a `pr_err` naming the cause): FEAT_LSE (sanitised
  `ID_AA64ISAR0_EL1.Atomic >= IMP`), `vabits_actual == 48`, no MTE in use
  (`!system_supports_mte()`: a privileged access does not honour the user's
  tag-check mode the way LDTR/STTR do), and `SCTLR_EL1.SPAN == 0`
  (`cpu_enable_pan()` establishes it). Nothing else changes in the kernel: the
  fault site is an ordinary extable entry (`EX_TYPE_UACCESS_ERR_ZERO`), so
  `insn_may_access_user` accepts the atomic's EL1 permission faults, demand
  paging and CoW go through `handle_mm_fault` like `copy_from_user`, and an
  unresolvable fault resumes at the PAN stub. Known exposure, same as the
  kernel's own futex ops without EPAN: a privileged atomic can read an
  execute-only user page that an EL0 access could not (recorded, not
  mitigated; section 11).
- Verifier: rule 8 (section 6).
- Harness: the interpreter models PSTATE.PAN for fragment runs; see section 7,
  Harness memory model (A4).

### FP/SIMD in fragments (A9)

Why: redis's request paths (epoll_pwait->read, read->read, read->write) are
blocked only by FP/SIMD code, almost all of it glibc memcpy/memset/strlen.
Kernel facts (`dep/linux` 7.1 `arch/arm64/kernel/fpsimd.c`): the user FP/SIMD
state stays live in the registers during a syscall unless TIF_FOREIGN_FPSTATE is
set (context switch, kernel-mode NEON); kernel-mode NEON in softirq context
saves the task's live state and takes the registers (`kernel_neon_begin`,
`get_cpu_fpsimd_context` uses `local_bh_disable`); hardirq context never uses
NEON (`may_use_simd`); `fpsimd_restore_current_state()` reloads the user state.

Translator:

- FP/SIMD register operands are NOT virtualized: V0-V31, FPCR, FPSR are user
  registers live in hardware while a fragment runs. GPR operands of FP/SIMD
  forms (`fmov x, d`, `dup v, w`, `umov`, addressing) go through reg-virt as
  usual. `ExecutionFragment` needs no FP flag; the verifier computes it.
- In scope (157 forms in `subset.toml`; 82 loads/stores, 75 register-only):
  FP/SIMD loads/stores (LDR/STR/LDUR/STUR q/d/s/h/b imm forms, LDP/STP q/d/s,
  LD1/ST1 multiple structures 1-4 regs, no-writeback and post-index), DUP
  (element, general), INS/UMOV/MOV element, MOVI/MVNI, FMOV (general<->FP,
  register), CMEQ/CMHI/CMHS/CMGT/CMGE/CMTST (reg, zero), AND/ORR/EOR/BIC/ORN/
  BIT/BIF/BSL/NOT (vector), ADD/SUB (vector), ADDP/UMAXP/UMINP/ADDV/UMAXV/UMINV,
  SHRN/USHR/SHL/USHLL/XTN, EXT, REV16/32/64 (vector), CNT, TBL (1 reg).
  Out (Unsupported exit): half-precision FMOV (FEAT_FP16: an EL1 UNDEF on a CPU
  without it would be an oops), floating-point arithmetic/conversion/compare
  (their rounding/exception semantics need FPCR/FPSR modelling that nothing
  requires yet), register-offset and literal SIMD&FP loads/stores, LD2-4,
  single-structure and replicate loads, LDNP/STNP, TBL/TBX with 2-4 table
  registers, ORR/BIC (vector, immediate), FMOV (vector, immediate), saturating
  arithmetic.
- FP/SIMD memory forms have no unprivileged variants, so each is lowered as ONE
  privileged access inside an A8 PAN window (`WindowInsn::{Atomic, FpSimd}` ->
  `plan_window` -> `emit_window`; `A64Insn::fpsimd_mem()` gives a SIMD&FP
  load/store's base, pre-access offset, writeback and base-only access):

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
    unsigned offset `#0`, LDP/STP signed offset `#0`, LD1/ST1 without
    post-index) on sA = the access's start address. Why: the range check then
    covers the first byte, and an access is at most 64 bytes, so it cannot reach
    bit 55 (the TTBR1 half) whatever offset the user encoded; checking only the
    base would let `ldur q0, [x0, #-256]` with a small x0 wrap into the kernel
    half. Same size, registers and element order as the user's instruction, so
    its fault behaviour (including which destination registers of a
    multi-register load are written before an abort) is the architecture's,
    identical to native.
  - Only SP-based accesses have a plain `Mem` stub
    (`window_needs_check_stub`): SIMD&FP accesses to Normal memory never
    alignment-fault at EL0 (SCTLR_EL1.A = 0), so there is no block check.
  - Scratch worst case stays 4: stack-backed base and LD1/ST1 index, sA, sB.
  - Register-only forms: only their `Reg*` operands are mapped; V registers
    never.
  - Layout: `WindowAccess` <=> `is_pan_window_access()` (LSE atomic or base-only
    SIMD&FP load/store); any other SIMD&FP load/store in a fragment is
    `UntaggedPanWindow`. Fault sites of window accesses resolve to the PAN stub.
- Decode: `is_decode_undefined` carries the per-form value rules (DUP/INS/UMOV
  `imm5 == x0000`; DUP (vector, general) `imm5 == x1000 && Q == 0`; UMOV
  (32-bit) `imm5 == x1000`; `size:Q == 110` for every vector CM*, ADD, SUB,
  ADDP; `size == 11` for UMAXP, UMINP, XTN; ADDV/UMAXV/UMINV `size == 11 ||
  size:Q == 100`; SHRN/USHLL `immh<3>`; vector USHR/SHL `immh<3> && Q == 0`;
  EXT `Q == 0 && imm4<3>`; REV16 `size != 0`, REV32 `size >= 2`, REV64 `size ==
  3`; CNT `size != 0`). Every other rule is fixed by the diagram or is a missing
  FEAT_FP/FEAT_AdvSIMD.
- Verifier: the `WindowAccess` list and `uses_fpsimd` (section 6, rule 8).

Kernel (A9b):

- A fragment with `uses_fpsimd` runs only inside the bracket
  `kjit_call_fragment_fpsimd()`: `local_bh_disable()` (on non-RT; this also
  makes the task non-preemptible) -> if `TIF_FOREIGN_FPSTATE`,
  `fpsimd_restore_current_state()` (kernel patch 0005 exports it; it already
  does the whole reload: FP/SIMD absent, SVE/SME, `get_cpu_fpsimd_context()`
  nesting inside our `local_bh_disable()`, binding to the CPU) ->
  `pagefault_disable()` -> the ordinary trampoline -> `pagefault_enable()` ->
  `local_bh_enable()`. The flag test is not racy: inside the bracket nothing
  can set it (no context switch, no softirq; hardirqs never touch FP/SIMD
  state). `kernel_neon_begin/end` are the wrong tool: they save the user state
  and take the registers away from it. A chained or dispatched entry into
  another fragment uses that fragment's own mode: the runtime picks the
  bracket from `uses_fpsimd` at every runtime entry, and a bracketed run
  dispatching through `table_all` continues across fragments inside the one
  bracket (section 8, Dispatch tables (A11, kernel side)).
- `VerifyOk.uses_fpsimd` (the verifier's verdict on the installed bytes, never
  the translator's) is stored in `struct kjit_frag`; the kernel uses it, not
  the translator's view, to decide how to run.
- With pagefaults disabled, any user-access fault in such a fragment
  (LDTR*/STTR* or a window access) takes the fixup path -> `Mem` exit ->
  userspace re-executes natively and handles the fault; the next run finds the
  page present. Correct, occasionally slower. `do_page_fault()` sees
  `faulthandler_disabled()` -> `no_context` -> `fixup_exception()` -> the
  fragment's extable (patch 0002) -> the access's PAN or Mem stub; nothing on
  this path sleeps and `handle_mm_fault` is never reached.
- Refuse to install `uses_fpsimd` fragments when the system supports SVE or SME
  (streaming mode and ZA state change the rules; not modelled):
  `kjit_fpsimd_supported()` = FP/SIMD present, no SVE, no SME
  (`system_supports_*`, final CPU caps); otherwise `fpsimd_refused_sve_sme`,
  `-ENODEV` after verification (final: the auto mode negative-caches the PC).
  `CONFIG_PREEMPT_RT` is a build error: there `local_bh_disable()` neither
  disables preemption nor excludes softirq NEON the way the bracket needs.
- Why the bracket is enough:
  - Preemption: none inside the bracket (`local_bh_disable()` raises
    `preempt_count` on !RT). The non-preemptible stretch is one run, bounded by
    the budget (section 11, Open decisions: a run now spans fragments).
  - Softirq kernel-mode NEON cannot run inside the bracket (softirqs are masked,
    also at irq exit). Pending softirqs run in `local_bh_enable()` after the
    run; one that uses NEON calls `fpsimd_save_user_state()`, which saves the
    registers as current's state (`TIF_FOREIGN_FPSTATE` is clear and the state
    bound) and sets the flag, so the exit path or the next bracket reloads
    exactly what the fragment wrote.
  - Hardirqs: `may_use_simd()` is false in hardirq/NMI.
  - Context switch after the bracket (or during a later in-kernel syscall):
    `fpsimd_thread_switch()` saves the bound live state; the next bracket or the
    exit path reloads it. Kernel-mode NEON inside an in-kernel syscall between
    two runs saves the user state and sets the flag: the next bracket reloads it.
  - Signals are delivered only by the normal exit path after the hook returned
    (`kjit_can_run` declines with a signal pending): the user state is either
    live and bound or saved with the flag set, so `setup_sigframe`'s
    `fpsimd_context` holds exactly what the fragments produced, and sigreturn
    restores it.
  - ptrace: a traced task never runs fragments, so a tracer's FP regset access
    never races a run. exec: `flush_thread()` sets the flag, and the new mm has
    no fragments.

### Counter reads (A10)

- Forms: `MRS.MRS_RS_systemmove` has three generated instances,
  `MrsMrsRsSystemmove{TpidrEl0,CntvctEl0,CntfrqEl0}` (keys
  `MRS.MRS_RS_systemmove@<REG>`), through the `[decode.field_instances."<form>"]`
  table in `subset.toml` (per instance a field-constraint set, same checks as
  `field_constraints`, plus: a form is in only one of the two tables, at least
  one instance, names `[A-Z0-9_]+`, no two instances decode the same words).
  Every other system register stays undecodable. CNTVCTSS_EL0 (FEAT_ECV) is
  not admitted: the XML has no system-register database to check it against,
  the hosts have no ECV, and without ECV it is UNDEFINED, which a fragment would
  execute at EL1.
- Kernel assumption: while a fragment runs at EL1, TPIDR_EL0 still holds the
  current task's user TLS pointer (Linux switches it only on context switch),
  so the MRS is exact without rewriting.
- Semantics at EL1: `VirtualCounterTimer()` is `PhysicalCountInt() -
  CNTVOFF_EL2` for EL0 and EL1 alike (outside a VHE host, where both skip the
  offset); CNTFRQ_EL0 is one register. Equal to the EL0 read only while EL0 reads
  the hardware: module init requires, on every online CPU,
  `CNTKCTL_EL1.EL0VCTEN` set (also what makes CNTFRQ_EL0 readable at EL0) and no
  out-of-line erratum handler for CNTVCT (`has_erratum_handler(read_cntvct_el0)`;
  `arch_counter_set_user_access()` clears EL0VCTEN on such a CPU and the kernel
  emulates EL0 reads with the workaround's stable read). Both are per CPU and
  set at `CPUHP_AP_ARM_ARCH_TIMER_STARTING`, so the check is a
  `CPUHP_AP_ONLINE_DYN` callback: it runs on every online CPU at load (failure:
  `-ENODEV`, the load fails) and on every CPU onlined while kjit is loaded
  (failure: that CPU does not come online). EL0VCTEN changes later only for
  compat tasks (`ARM64_ERRATUM_1418040`), which never run fragments.
- Verifier: rule 5 allows exactly the three instances (`Form::MrsUserReg`);
  rule 9 treats their results as user values.
- Harness counter modelling: see section 7.

## 5. A64 subset and generated metadata

The canonical subset is `spec/arm64/subset.toml`; `specgen/` generates
`spec/arm64/generated/*` from the Arm XML (never edited by hand).

### Decode admission

- A word decodes only if it matches a generated form's mask/value **and**
  `A64Insn::is_decode_undefined` is false. That function carries the value rules
  the XML keeps in decode pseudocode (`EndOfDecode(Decode_UNDEF)` and
  `DecodeBitMasks` rejections: add/sub shifted `shift == 11` and 32-bit
  `imm6<5>`, add/sub extended `imm3 > 4`, 32-bit logical shifted `imm6<5>`,
  reserved logical immediates, 32-bit bitfield `immr<5>`/`imms<5>`, and the
  per-form rules of the memory, SIMD&FP forms listed in their sections). It is
  an exhaustive match, so a new form must decide whether it has such rules.
- Why: reg-virt only rewrites register fields, so an admitted word's
  non-register fields reach the emitted fragment unchanged. An UNDEFINED
  encoding admitted here would trap at EL1; rejected, it takes the `Unsupported`
  exit and userspace gets its SIGILL natively.
- A form that is UNDEFINED only for a missing CPU feature (FEAT_LSE, FEAT_PAN,
  FEAT_LRCPC, FEAT_CRC32, FEAT_FP/AdvSIMD) is a CPU property: the module checks
  it at init (section 8, Preconditions), not the decoder.

### Field constraints in subset.toml

- `[decode.field_constraints]` pins non-operand fields of an exact form to fixed
  values; specgen folds them into mask/value and drops them from the generated
  operands. A constraint on an unconfigured form, a missing/fixed field, a field
  with an operand role, or an out-of-range value fails generation.
  `[decode.field_instances."<form>"]` (A10) defines several instances of one
  form, each its own constraint set: a form is in only one of the two tables,
  at least one instance, names `[A-Z0-9_]+`, no two instances decode the same
  words. Used for `MRS` (`TpidrEl0`, `CntvctEl0`, `CntfrqEl0`).
- SMULH/UMULH pin their should-be-one `Ra` to 31, and the acquire/release forms
  their `Rs`/`Rt2` (LDAPR `Rs`); other values are constrained unpredictable and
  stay undecodable. `MSR_imm.MSR_SI_pstate` is pinned to PSTATE.PAN (A8).

### Flags metadata

- `FlagsWrite` is inferred from an assignment to `PSTATE.[N,Z,C,V]` in the
  execute pseudocode (ADDS/SUBS, ANDS/BICS, CCMP/CCMN).
- `FlagsRead`: `ConditionHolds`, or a read of a single flag that is not an
  assignment to it (ADC/SBC's `AddWithCarry(.., PSTATE.C)`; the flattened XML
  text may read `PSTATE .C`). No pass consumes flag roles yet.

### Generated-metadata conventions

- `!=` diagram constraints are generated: a box cell `!= <pattern>` or per-bit
  `Z`/`N` cells become `excludes` `(mask, value)` pairs, checked by the generated
  decoder and `GeneratedInsnSpec::matches`. `form_base_word(spec)` is a spec's
  value with each `!=` exclusion escaped; tests and the fuzzer catalog probe
  forms with it instead of `spec.value`.
- Load/store operand roles come from the XML, not mnemonic lists: direction from
  the execute pseudocode's access descriptor (`CreateAccDescGPR(MemOp_LOAD|
  STORE|PREFETCH)`, `CreateAccDescAcqRel`, `CreateAccDescLDAcqPC`,
  `CreateAccDescASIMD`; `CreateAccDescAtomicOp` gives `MemBase Rn` and `Memory`),
  writeback from `address-form` / `as-structure-post-index`, `Rm` as a 64-bit
  read (as for ADD extended), every `imm*` as `MemOffset`; a `MemOffset` field
  that encodes a `<label>` decodes as a signed word offset. The `Memory` role
  requires an actual access (`Mem{..}` or `MemAtomic{..}`), so PRFM has none.
- A register-named field is only a register if a role reads/writes it (PRFM's
  `Rt` is its prefetch operation, a plain `u8`). A register field of a
  load/store is an operand only if its decode or postdecode pseudocode binds it
  (LDAR's `Rs`/`Rt2` get no role and can be pinned). A load/store's register
  roles come from the load/store inference alone, not the generic `X(n)`/`X(t)`
  scan (the execute pseudocode is shared by a section's encodings). A
  base-register-only form has no `MemOffset`, so it keeps plain `rn`/`rt` fields
  (no `A64Mem`). No role names a field the encoding fixes completely.
- A register role derived from the execute pseudocode takes its width from the
  field's assembler operand when there is one, and an operand's own `<W..>`/
  `<X..>` wins over the form's `datatype`. Widths only matter to reg-virt as
  known vs `Unknown`; the decoded width drives the pretty-printer.
- Register file of a field: a field is a SIMD&FP register iff an assembler
  operand encoded in it says "SIMD&FP" in its hover text. Its roles are
  `A64OperandRole::VecRead { field }` / `VecWrite { field }`, derived from
  `V{..}(x)` / `Vpart{..}(x, part)` accessors; it renders as a plain `u8`, not an
  `A64Reg`, so no general-register code (reg-virt, the verifier's
  `reads`/`writes`, the fuzzer's register picker) can mistake it for one.
  Pseudocode accessors of the other register file on that field are dropped.


## 6. Verifier (V3)

`shared/verify/` is the security boundary: the kernel installs only fragments it
accepts. It is written against this file and `shared::abi`, not the translator.

### Independence

- Imports only `shared::{abi, arm64, platform}`; the unit test
  `verifier_does_not_import_the_translator` scans the module sources and fails on
  any other `crate::shared::` path or on `trans::`/`emit::`.
- It does not reuse translator-side helpers that live in `shared::arm64`
  (`is_unprivileged_access`, `accesses_memory`, `runtime_exit_reason`,
  `lse_atomic`, `fpsimd_mem`, `msr_pan`): its own exhaustive match over the
  generated forms (`rules::classify`) decides what each word is, so a new form
  fails to compile until the verifier classifies it. A random-word test
  cross-checks that classification against the generated operand roles.
- Transitive coupling left in place: `shared::arm64` itself imports
  `trans::cfg::RuntimeExitReason` for `runtime_exit_reason`. The verifier never
  calls it.
- Constants come from `shared::abi` (`USER_VA_BITS = 48`,
  `PAN_WINDOW_RANGE_TOP_BIT = 55`, the frame and dispatch constants).

### Input

`VerifyInput { code: &[u8], fault_sites: &[FaultSiteEntry { access_offset,
stub_offset }], entry_offsets: &[usize] }`, all offsets relative to the fragment
base. `ori_pc` is not part of the input: the stub loads its own resume PC, so the
table's PC column is not safety-relevant. The harness builds the input from
`ExecutionFragment` (`FragmentTables::of`): the entry table is `entry_offset`
plus every `vlabels` offset, because any of them can be the runtime's entry
address (and, since A11, a dispatch target). `verify_fragment` returns
`VerifyOk { uses_fpsimd: bool }`: true iff some word is `Form::Simd` or a
`WindowAccess` with `fpsimd`. The kernel uses this value (independent of the
translator) to decide how to run the fragment; the harness cross-checks it on
every differential run against the translator's view (an instruction with a
`Vec*` role). The runtime needs nothing else from the verifier.

### Rules

Reject with `VerifyError { offset, rule }`.

1. Every body word decodes through the generated decoder and
   `is_decode_undefined` is false.
2. Words `0..PROLOGUE_LEN` and `EPILOGUE_OFFSET..BODY_OFFSET` equal the encoded
   `KJIT_PROLOGUE`/`KJIT_EPILOGUE` (the prologue includes the dispatch-table
   store). The body never writes SP (a destination in its SP meaning, or base
   writeback) and never writes x29.
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
     user access or a window access (rule 8).
   - never a user-code memory form of the subset: byte/half/signed immediate,
     unscaled, register offset, literal, 32-bit pairs, LDPSW, PRFM (A7b);
     LDAR*, STLR*, LDAPR* (A7c); every SIMD&FP load/store encoding but the
     base-only offset-0 window ones (A9a). Translation only lowers them, so one
     in a fragment is `UserOnlyForm`, even on runtime memory and even with a
     fault-site entry (`FaultSiteNotUserAccess`). PRFM is emitted as `NOP`. An
     acquire/release form at EL1 would be a privileged access to user memory.
     BTI (A7d) is in the same class: rephrase emits it as `NOP`, so one in a
     fragment is `UserOnlyForm` too.
   - a runtime access, offset addressing only (no writeback), either
     - SP-based inside the user-state frame slots `[16, 80)` (stack-backed
       x12..x17, user x29, user sp), or the single kernel-slot read
       `ldr xS, [sp, #176]` (pt_regs pointer, 64-bit, S a reg-virt scratch
       register x12..x15; rule 9), or a dispatch-template word (rule 4). Every
       other frame slot (caller x29/x30, entry address, caller x18..x28, the
       pt_regs / extra-params pointers) and anything outside the 208-byte frame
       is `FrameAccessOutOfRange`: a body write there is a kernel write
       primitive through the epilogue. The budget counter (192) is rule 6's;
       slot 200 (dispatch table pointer) is never written by the body and read
       only as a template's first word.
     - based on a register proven to hold the pt_regs pointer, inside
       `regs[0..31]` + `sp` (`[0, 256)`); `pc`, `pstate` and beyond are never
       accessible. Proof is the rule 9 dataflow's pt_regs fact: the register
       was loaded by `ldr xS, [sp, #176]` and not written since, with no join
       point in between.
   - Everything else is rejected: exclusives, PRFUM/RPRFM, DC/IC/AT are outside
     the decoded subset (rule 1); LSE atomics and SIMD&FP loads/stores are valid
     only as a PAN window's access (rule 8); pair or pre/post forms not matching
     the above fail the base/range/writeback checks.
4. Control flow.
   - Direct branches (B, B.cond, CBZ/CBNZ, TBZ/TBNZ) target the epilogue's first
     word or a body word; never the prologue, the rest of the epilogue, or
     outside the fragment. A target in the cold region must be an exit-group
     start.
   - BL, BLR, RET and every BR are rejected in the body, except `br x12` as the
     last word of a dispatch template (below); the prologue's `br x12` and the
     epilogue's `ret` are covered by the byte-exact check.
   - The last word is an unconditional `B` (nothing falls off the end).
   - Entry offsets: non-empty, aligned, in the body and before the cold region.
   - Dispatch templates (A11, A11c, `find_dispatch_templates`): every `br x12`
     must be word 8 or word 19 of the byte-exact 20-word template
     (`dispatch_template_matches`: registers, `#200`, `#2`, `#12`, `#8`, the
     `eor ... lsr #12`, `ubfx ... #2, #8`, `add ... #8, lsl #12`). The main
     probe's two miss branches name the template's word 9; that internal edge
     is the only edge into a template and does not make word 9 a join point
     (the dataflow carries the state across it). The victim probe's two miss
     branches name the same forward body word after word 19. Accesses inside a
     template skip the generic access check (being exact), so both slot loads
     stay inside the table by construction (main index < 2^12 from
     `ubfx #2, #12`; victim index < 2^8 from `ubfx #2, #8` at offset 32 KiB).
     There is no join point from the preceding budget check's `sub` to the final
     `br` (`DispatchTemplate`).
5. System: only `MRS Xt, TPIDR_EL0`, `MRS Xt, CNTVCT_EL0` and `MRS Xt,
   CNTFRQ_EL0` (A10; the only MRS encodings the generated subset decodes, one
   generated form each, `Form::MrsUserReg`; every other value of
   o0:op1:CRn:CRm:op2 is rule 1's, pinned exhaustively by
   `mrs_is_allowed_for_exactly_the_user_readable_registers`), NOP, and `DMB`/
   `DSB`/`ISB` with any CRm (`DSB` without nXS; `Form::Barrier`): allowed
   anywhere, exit groups included. SVC and ADR/ADRP (a kernel address into a user
   register) are rejected; BTI decodes but is `UserOnlyForm` (rule 3); MSR other
   than the PAN window's (rule 8), HVC, SMC, BRK, HLT, ERET, SB, CLREX, DSB nXS,
   WFE/WFI, PAC and every other hint, and cache/TLB maintenance do not decode.
   A barrier cannot confuse rules 6/7: it is not a fill (so one between a budget
   `cbz` and its back-edge is rejected) and not a branch, user access or runtime
   access.
6. Budget (A6, A11): every back-edge (a direct branch to a body word at or before
   itself; offset order is layout order) is preceded by
   `ldr x12, [sp, #192]; sub x12, x12, #1; str x12, [sp, #192]; cbz x12, <stub>`
   (`RUNTIME_FRAME_BUDGET_OFFSET`, scratch `REG_VIRT_SCRATCH_GPR_START`), then
   any number of reg-virt fill loads `ldr x12..x15, [sp, #16..#56]` and nothing
   else, then the branch. The same check guards a dispatch template: between its
   `cbz` and the template's first word only data-processing words, reg-virt
   fills and the link write are allowed (at most `DISPATCH_GUARD_MAX_GAP = 16`
   of them; BL's 4 target + 4 link words is the longest real site, 8, so the
   walk back is O(1)); no branch, no memory access other than fills, no join
   point. No join point may sit on the `sub`, `str`, `cbz`, a fill or the
   guarded branch, so every path to it decrements the counter; the check's `ldr`
   may be one (it carries the original PC's label). The `cbz` target is a forward
   exit-group start (the Budget stub).
   - The counter is written only by the prologue's init (byte-exact) and by a
     check's own `str`; it is read only by a check's own `ldr`. A check that
     guards nothing is rejected like any other counter access
     (`BudgetSlotAccess`); a gap violation is `MissingBudgetCheck`.
7. Exit groups: every fault stub, budget stub and template miss target starts an
   exit group: the word before it is an unconditional `B` or a template's `br`,
   and the straight-line run from it contains no user access and ends in
   `b <epilogue>`. The cold region starts at the lowest stub offset. A PAN stub's
   first word is `msr pan, #1`, accepted as the first word only.
8. PAN windows (A8, generalized by A9): `msr pan, #0` appears only as the exact
   window. `rules::classify` yields `Form::WindowAccess { rn, fpsimd }` for the
   160 LSE atomics and the 24 base-only offset-0 SIMD&FP load/store encodings
   (the one list of window accesses), `PanClear` (`msr pan, #0`), `PanSet`
   (`#1`), and `MsrOther` (any other CRm: rejected, `Msr`). Pre-pass
   `find_pan_windows`: every `PanClear` at i must have `ubfx sB, sA, #48, #8`
   (64-bit UBFM, immr = `USER_VA_BITS`, imms = `PAN_WINDOW_RANGE_TOP_BIT`,
   sA/sB < 31) at i-2, `cbnz xsB, S` (64-bit) at i-1 with S > i+2 and S's word
   `PanSet`, a `WindowAccess` with `rn == sA` at i+1 and `PanSet` at i+2
   (`PanWindow` otherwise). It records S as a PAN stub.
   - Fault table: a `WindowAccess` site must name its window's S
     (`PanStubTarget`; outside a window `AtomicOutsideWindow`, a name that
     predates A9a); an LDTR/STTR site must not name a PAN stub. Every stub is
     still an exit group (rule 7).
   - Branches: a target that is a PAN stub is legal only from a window `cbnz`
     aimed at it (`PanStubTarget`). Other branches into it are harmless but are
     rejected to keep the rule simple.
   - Join points: none on the window's `cbnz`, either MSR or the access (the
     `ubfx` may be one: it recomputes the checked value).
   - Main pass: a `WindowAccess` outside a window -> `AtomicOutsideWindow` (and
     it consumes its fault-site entry like a user access); `PanSet` neither a
     window end nor a PAN stub -> `PanSetOutsideWindow`. `msr pan, #1` appears
     only as the window end or as the first word of a PAN stub.
   - The 75 register-only SIMD&FP forms are `Form::Simd`: allowed anywhere, exit
     groups included.
9. Confidentiality: no kernel value reaches user-visible state; see
   "Confidentiality (rule 9)" below.

Join points (where the dataflow restarts): entry offsets, stubs, and direct
branch targets; also after every unconditional `B`.

### Confidentiality (rule 9)

Rules 2-8 protect integrity. Rule 9 stops a kernel address reaching a register
the epilogue writes back to `pt_regs` (a KASLR / kernel-stack leak): `mov x0, sp`,
`add x0, x29, #0`, `ldr x0, [sp, #176]`, `ldr x12, [sp, #176]; mov x0, x12`,
`str x29, [sp, #16]` (user x12's slot) must all be rejected.

One forward taint dataflow (`shared/verify/taint.rs`) over the body and cold
region; rule 3's pt_regs fact is its refinement.

- State: `kernel` = GPRs holding a kernel value; `pt_regs` ⊆ `kernel` = GPRs
  proven to hold the pt_regs pointer. SP is always a kernel value (not tracked).
- Join state (every join point, and after every unconditional `B`): derived at
  verify time by running the transfer function over the byte-exact
  `KJIT_PROLOGUE` from "every GPR is a kernel value". Result: {x29 (the runtime
  frame), x12 (the entry address the prologue's `br` uses)}; pinned by
  `join_state_is_derived_from_the_prologue`.
- Sources: SP read as data; x29 (in the join state, and the body never writes
  it); the entry scratch until overwritten; `ldr xS, [sp, #176]` (-> `pt_regs`
  fact); any other frame slot outside the user-state slots `[16, 80)` (rule 3
  already rejects every such load, rule 9 classifies it anyway); inside a
  dispatch template every `ldr x12` and the `add x12` result.
- Not sources: user-state frame slots; `pt_regs` contents (loaded through the
  proven pointer); `LDTR*` and window-access results; `MRS` of TPIDR_EL0,
  CNTVCT_EL0, CNTFRQ_EL0 (EL1 reads what EL0 reads, module init pins it; they
  read no GPR, so the write clears any kernel mark, like `movz`); the budget
  counter (192): the user can count its own back-edges, so it is not secret; the
  template's key load `ldr x14, [x12]` (a user PC the runtime copied from a user
  branch target).
- Transfer: a write gets the kernel mark if the instruction reads SP or a
  kernel-valued GPR as data (ALU), or loads a kernel frame slot; loads of user
  state clear it. `step_dispatch_template` is the transfer function for the
  template's twenty words: x12 is the only register that ever holds a kernel
  value inside it; every other word's result is user-derived.
- Checks (`VerifyRule`):
  - `KernelValueRead`: an instruction reads SP or a kernel-valued GPR as data
    (ALU source, store data, branch operand, `MOVK`/`BFM` destination, exit
    payload source, `LDTR*`/`STTR*` or window-access data, the PAN range check),
    or uses a kernel-valued GPR as the base of a user access / window access. A
    kernel value may be a base only of a runtime access: SP for a frame access,
    a proven pt_regs pointer for a `pt_regs` access (rule 3). So a kernel value
    is never stored anywhere and never computed on. Exceptions inside a
    template: `cbz x12`, `br x12` and the victim probe's `add x12, x12, #8, lsl
    #12` may read kernel x12; x13 must be non-kernel where `ubfx`/`eor`/`sub`
    read it.
  - `KernelValueAtEdge`: at every control edge the state may hold no kernel value
    outside the join state: every direct branch (into the body or to the
    epilogue), every fall-through into a join point, every user access / window
    access (its fault edge to the stub), and, in a template, every miss edge and
    both `br`s, which carry only the join state {x12, x29}. This is what makes
    restarting each join point from the join state sound.
  - Exit edges: the epilogue reads no join-state register before writing it (x12
    and x29 are not in its live-in set x0..x11, x16..x28, x30);
    `join_state_is_dead_in_the_epilogue` computes the live-in set from
    `KJIT_EPILOGUE` and pins both facts.
  - The pt_regs pointer load is admitted only into scratch x12..x15
    (`FrameAccessOutOfRange` otherwise, as for any other kernel slot): scratch is
    never written back to the user, so the pointer can never sit in a
    user-visible register.
- What the translator emits that needed allowing: the exit-preserve sequence
  `ldr x12, [sp, #176]; str x9/x10/x11, [x12, #72/#80/#88]` in exit groups,
  followed by the payload and `b <epilogue>` with x12 still holding the pointer.
  Safe: x12 is used only as a runtime-access base, and x12 is in the join state
  and dead in the epilogue.
- Not covered: NZCV at entry holds the trampoline's flags (not an address; the
  body only observes them if it reads flags before setting them, a translator
  semantic issue); the kernel's fault fixup is assumed to change no GPR before
  the stub.
- FP/SIMD registers: SIMD&FP register fields carry `VecRead`/`VecWrite` roles
  and are plain register numbers, so `reads`/`writes` never count them: a write
  to V12 leaves x12's kernel mark, a read of V12 is not a read of x12. The
  general operands of SIMD&FP forms (FMOV general, DUP/INS general, UMOV,
  addressing) are `Reg*` roles like any other, so a kernel value is rejected
  before it could enter a V register, and V registers never hold one. Pinned by
  `simd_registers_are_not_general_registers_for_rule_9`.

### Cost, scope, hook points

- Cost: one decode pass, one check pass, one pass per table, each exit group
  walked once: O(words + fault sites + entries) time, O(words) memory. No
  recursion, no panics (the two `panic!`s are in `const` initializers, i.e.
  compile time).
- Not checked (semantic, not safety): that exit payloads set a known
  `RetStatus` or the right resume PC (the K2 runtime WARNs and disables KJIT on
  an unknown status); that a fault stub belongs to the access's own original
  instruction; fall-through between body blocks (any body word is verified
  code); that ordering fences are present.
- Harness: `run_entry_fixture` verifies before running, so every fixture case
  (interpreter and native suites, `trace-tui --check`) runs only verified
  fragments; the runtime unit-test fragments and the kernel golden are verified
  too. `verify_mutation_tests.rs` is the G1 mutation suite: each mutation class
  must be rejected 100%.
- Kernel (K2): `runtime/translate.rs` runs `verify_fragment` on exactly the
  bytes, fault-site table and entry table (`entry_offset` + every `vlabels`
  offset) that `kjit_install` installs; a rejected fragment is counted
  (`translate_verify_rejected`, FallsOffEnd separately) and never installed.

## 7. Harness contracts

The harness is the kernel executor's model: it mocks machine state and executes
the translated `ExecutionFragment` through the same function-call boundary the
kernel uses (section 3). It consumes `shared/` as the translation core and owns
no duplicate translation logic.

### Harness memory model (A4)

- User memory is 4 KiB pages with an EL0 permission each: unmapped, read-only,
  read-write. The runtime-owned ranges (runtime stack, `pt_regs`, extra params,
  the dispatch tables and records) are never user-accessible.
- A user access that violates permissions is a **fault**. A runtime access that
  lands outside the runtime-owned ranges is a **PAN violation**: a hard harness
  error, because in the kernel it is an oops.
- The interpreter checks every access of an instruction before it mutates any
  register or byte. A faulting instruction leaves the state bit-identical and
  halts with the fault (pc, address, read/write).
- Fault injection: fail the k-th dynamic user access of a run regardless of
  permissions.
- Fragment accesses are classified by instruction: `LDTR`/`STTR` (and window
  accesses) are user accesses (page permissions, fault injection counts only
  them); every other load/store is a runtime access and must lie in the
  runtime-owned ranges.
- Text: the text is a user page, read-only (and executable; execute permission
  is not modelled), holding the text bytes, as a process maps it: literal pools
  in the text load as data, a store faults. `with_text_mapped` adds it;
  `fixture_state(text_base, text)` is `default_fixture_state()` plus the text,
  and every fixture path and the fuzzer run from it, so the original and the
  fragment see the same map.
- Top-byte-ignore: Linux sets `TCR_EL1.TBI0`, so bits 63:56 of a data address
  with bit 55 clear take no part in translation (bit 55 set is the kernel half
  and faults at EL0). A tagged pointer into a mapped page works natively. The
  interpreter applies Linux's `untagged_addr` (`addr & sign_extend64(addr, 55)`)
  to every access address (original code and a fragment's LDTR/STTR alike: both
  translate through the EL0 regime); a base writeback keeps the tag. Fault
  addresses are reported the same way.
- PSTATE.PAN in fragment runs: `URuntime.pan` is set at every entry
  (`AccessContext::Fragment.pan`); `msr pan` writes it. A window access with
  PAN set is a hard error (PAN violation). With PAN clear it is
  `Privilege::Window`: counted with the user accesses (fault injection) and
  checked against the user page permissions, and a hard error on runtime memory.
  The first access of a window access must start below 2^48 (a hard error
  otherwise: the range check exists to prevent it); a later access past 2^48 is
  an ordinary fault. Every return to the runtime requires PAN set (hard error
  otherwise). Original-code runs execute LSE atomics and SIMD&FP accesses as EL0
  user accesses.
- `execute_atomic`: one read-modify-write access that needs write permission (a
  failing CAS too: its access descriptor is read + write), the EL0 SP check
  (original code), the 16-byte block alignment rule, then permissions;
  LD<op>/SWP return the old value in Rt, CAS in Rs (32-bit forms zero-extend); a
  failed CAS writes no memory.
- `MachineState` carries V0-V31 (`v: [u128; 32]`), `fpcr`, `fpsr` (derived
  `PartialEq`: every comparison includes them). `harness/src/simd.rs` implements
  every A9a form from its XML pseudocode (V writes zero-extend, `Vpart(d, 1)`
  keeps the low half, LD1/ST1 one access per element in register-then-element
  order, TBL index >= 16 -> 0, SHRN/XTN write their half with `Vpart(d, Q)`).
- Counters: `MachineState::{cntvct_el0, cntfrq_el0}` are read-only, set in the
  initial state (`FIXTURE_CNTVCT` = 0xa1b2c3d4e5, `FIXTURE_CNTFRQ` = 24 MHz for
  fixtures and the fuzzer) and never advanced. A step-derived counter cannot
  work: the fragment executes more instructions than the original (prologue,
  fills, budget checks), so no dynamic index is common to both. A constant is a
  legal behaviour of the real counter (reads are only non-decreasing; two reads
  within one tick are equal) and keeps the differential check exact: a read
  routed to the wrong register or a lost value shows in every register computed
  from it.

### Native hardware oracle (V1)

- Linux arm64 only (`harness/src/native.rs`, `make harness-test-native`). Three
  states per fixture case must agree: interpreter original, native original,
  native fragment.
- Fixture addresses: text base `0x10000` (compile script default), data window
  `FIXTURE_DATA_BASE = 0x20000`, `FIXTURE_DATA_LEN = 0x4000` (x12), which is the
  whole default user page map (read-write). Fixtures derive every data address
  from x12.
- User memory: the native runs map every page of the interpreter's user page map
  at the same address with the same permission (read-only -> `PROT_READ`), and
  compare every byte of those pages. Initial memory outside them fails. The
  text's pages (see "Harness memory model (A4)", text) are mapped that way for the
  native fragment; the native original's own text mapping
  (`PROT_READ | PROT_EXEC`, stop points patched) takes their place.
- Native-unobservable: the interpreter's original read of a text word the native
  original patches (a stop point, the instance cap, or the `BRK_FILL` past the
  text in its mapping) cannot be reproduced on hardware, which reads the trap
  word. Decided from the interpreter's access log (`original_reads_patched_text`:
  any user read overlapping such a word's 4 bytes). Then only the native fragment
  is compared; the fuzzer counts the program as `native-unobservable`, never as a
  pass, and a fixture case says so in its summary line. Undecodable literal-pool
  words are patched too, so a fixture that wants its text pool observed natively
  uses pool words that decode as admitted non-exit instructions
  (`mem_literal.s`).
- Native original: stop points come from the interpreter's own halting rule
  (`admit_word`) applied to every text word (SVC -> mock trap; rejected word or
  non-SVC runtime exit -> stop trap; a word past the text -> the `Unreadable`
  Unsupported stop). A data abort stops too and must match the interpreter's
  `Fault` halt (same pc, fault address inside the access). A branch exit is then
  executed by the hardware alone, in a text copy where every other word traps, so
  BL/BLR link writes and branch targets come from the CPU, not the model. In
  cached runs the original follows branches (`stop_point_words(follow = true)`:
  BL/BLR/BR/RET are plain code), caps at any branch or an SVC, and reports an
  instruction abort at a followed branch's target as the `Unsupported` stop.
  Limit: a capped indirect branch to itself would spin; no case caps one.
- Native fragment: called at its base per "ABI: fragment entry", driven by the
  same `decide_runtime_return` as `URuntime`; the call also checks x18..x29 and sp
  survive (C ABI). Deviation: EL0 cannot execute `msr pan`, so the fragment copy
  replaces both MSRs of a window with NOPs (the access at EL0 already has user
  permissions) -- the one native-leg deviation. Cached runs: `FaultFixup` covers
  every fragment of the cache; `run_cached` calls fragments through the real
  tables and records (one RW mapping `[table_all | table_nofp | records]`, hosts
  are the RX mappings' addresses) with `extra[2]` the table of the entered
  fragment; after cold and warm the native cache's statistics must equal the
  interpreter's and its memory every record/slot word of the interpreter cache's
  image.
- V0-V31/FPCR/FPSR go into user code through the SIGTRAP frame's
  `fpsimd_context` (first record of `__reserved`) and come back from every
  event's frame; the call trampoline loads them from `NativeCtx::fp` right before
  `blr` and stores them right after; they are carried across fragment calls as
  the kernel keeps them live. FPCR/FPSR states stay inside `FPCR_USER_BITS` (AHP,
  DN, FZ, RMode, FZ16) / `FPSR_USER_BITS` (QC, cumulative flags), the bits the
  hardware keeps.
- Counter reads (A10): both native legs replace every `mrs Xt, cntvct_el0` /
  `mrs Xt, cntfrq_el0` (original text and fragment copy) with
  `brk #(0x4c00 | kind << 5 | Rt)`, which the signal handler emulates in place
  (Xt = the run's `MachineState` value, XZR ignored, pc + 4, the run's TPIDR_EL0
  back last), like the mocked SVC. Every register is still compared exactly. Not
  checked natively: only the hardware read itself (EL0 readability, which the
  module pins at EL1). A patched word counts as native-unobservable if the
  original reads it as data.
- No watchdog: a native run that never reaches a stop point hangs the test.

### Differential oracle and fuzzer (V2)

- One oracle. `run_differential` runs both sides (original through the
  interpreter, fragment through `URuntime`); `compare_differential` is the only
  state/halt check, used by `run_entry_fixture` (fixture suite, `trace-tui
  --check`) and the fuzzer. It translates, verifies (V3), runs the fragment (a
  `Budget` exit caps the original at the same instance), then the original.
  Bounded runs (`StepLimits`, the fuzzer): a program where neither side halts (an
  SVC in an endless loop restarts the budget) is discarded; one side halting
  alone is a failure. A verifier rejection is its own failure class. A fault
  matches `ReturnedToUserspace { Mem }` at the same PC (section 4, Fault sites)
  and is a verdict like every other halt; the fault footprint applies to natural
  faults too (`faulting_store_footprint`, `compare_differential`).
- Generation is driven by the generated metadata only: `GENERATED_A64_SUBSET`
  (fixed mask/value, fields), operand roles, `get_reg` (SP/ZR mode), the
  generated `mem_operand()` accessor (offset signedness and scale are read back
  from the decoder) and `literal_address`. No per-form tables in the fuzzer.
  Register-offset forms read their index from registers holding small values;
  literal loads target the data window. Instances `admit_word` rejects are kept
  for 3% of slots (they exercise the Unsupported exit). Plain slots pick an
  instruction section first, then an encoding (`Catalog::sections_of_class`), so
  the 160 atomic encodings (30 sections) do not crowd out the other memory forms.
  V registers are random (zero, all-ones, a repeated lane, random with zero
  bytes, random) and FPCR/FPSR random within the masks in 25% of states; the
  minimizer lifts V registers with `fmov dN, x0` / `fmov vN.d[1], x0` (a state
  that still needs FPCR/FPSR cannot be lifted).
- Non-verdicts are counted, never passed: original did not halt (discarded);
  `chained` (the original stopped at a BL/BLR/BR/RET whose target the fragment
  translated; the runtime continues there, the interpreter does not).
  Deferred: model chaining in the original runner. (Cached runs, below, follow
  branches.)
- Minimizer signature: failure kind + how the original halted, so deleting an
  exit cannot turn one bug into another (a fall-off-the-end program).
- Bugs the fuzzer finds become regression fixtures in `tests/arm64/` (a fixture
  that still fails waits in `tests/arm64/fuzz-pending/`, which the suite skips).
  The fixed-seed slice in `make harness-test` (2000 programs) must have no
  failure. `make harness-test` also runs the differential check on every `_mark`
  case of every `tests/arm64/*.s` fixture.

### Code cache and cached runs (A11a)

- `harness/src/code_cache.rs` mirrors the kernel's store: fragments by entry pc,
  labels as records `{pc, host}` (`vlabels` sorted by pc), the two tables
  (`table_all`, `table_nofp`, main and victim part), `publish` and `retire`
  through the shared slot planning of section 4 (the same functions the kernel
  calls; `ibtc_insert`/`ibtc_replace`/`ibtc_clear`), `check_invariants`
  (non-zero slot -> a label of a live fragment, at that label's main or victim
  index; `table_nofp` never an FP/SIMD fragment, from the *verifier's*
  `uses_fpsimd`), and `decide`.
  Pure bookkeeping over an address layout; every table or record change is queued
  as an 8-byte `(addr, value)` write for the backend (interpreter `MachineState`
  memory, or the native runner's mapping). Records of retired fragments stay in
  memory (nothing points at them); record addresses are never reused, the code
  stays mapped.
- `URuntime` executes over a cache: pc -> (fragment, offset), fault sites per
  fragment, `extra[2]` = `table_for(entered.uses_fpsimd)` at every entry, tables
  and records in runtime-owned ranges (a PAN violation outside them). The
  interpreter models tables and records as runtime memory and executes the
  template. `URuntime::new(fragment, ..)` is a cache of one fragment that never
  publishes (empty tables, every exit misses).
- `decide` translates the target of every branch exit on a miss, `RET` included
  (a return point is never a fragment entry, so without it no `RET` site could
  ever hit; the kernel learns them through exit-target learning, the harness at
  once). A target that is not readable text has no fragment: stop with
  `ReturnedToUserspace { Unsupported, target }`, which is what the following
  original halts on (`admit_at` -> `Unreadable`). The kernel refuses a
  translation whose entry word is itself unsupported; the harness translates it
  (the fragment exits `Unsupported` at its first word): same observable run.
- The cache has the kernel's default `chain_budget` (1024 entries, first
  included) and `decide` returns to userspace at an SVC exit once spent
  (`ReturnedToUserspace { Svc, resume }`); the original is capped before that SVC
  (`InstanceCap`, native too). Only SVC exits stop: a branch exit stop would need
  "stop after the k-th branch" on the original side. An endless cycle must pass
  the runtime at an `SVC` (a loop without one is bounded by the budget).
- An SVC exit continues in the first live fragment with a label for the resume pc
  (entry-keyed fragment first); any label for the pc is a correct continuation.
- Cached runs (`cached_run.rs`) compare with the original *following* its
  branches (`OriginalStepper::follow_branches`), so the run ends where a fragment
  run ends: a fault, an `Unsupported` pc, a `Budget` exit (capped over all
  fragments, see Execution budget), or the chain budget.
- Every `_mark` case runs **cold** (empty tables: every transfer misses) and
  **warm** (the same case again on the populated cache: transfers hit). Both must
  equal native.
- `dispatch_tests.rs` asserts what the suite alone does not: warm runs of
  calls/PLT/`blr x30`/`ret x5` take no runtime entry, aliasing callees replace
  each other's slot and keep missing warm, the FP/SIMD callee is in `table_all`
  only, the recursion exits `Budget` at its `bl`, a retired callee misses in the
  warm run and is translated and published again (interpreter and native).
- Verifier mutation classes for dispatch (each 100% rejected): every template
  word altered (register, `#200`, `ubfx` lsb/width, `#8`), key compare dropped,
  `br` of x13 or x14, a join point inside, no budget check, slot 200 read outside
  a template or written anywhere, a kernel value in x13.

## 8. Kernel runtime (K2)

Facts checked against `dep/linux` 7.1-rc1: `arch/arm64/kernel/syscall.c`
(`el0_svc_common`, static `invoke_syscall`), `arch/arm64/mm/fault.c`
(`do_page_fault`, `is_el1_permission_fault`), `arch/arm64/mm/extable.c`
(`insn_may_access_user`, `fixup_exception`), `kernel/extable.c`
(`search_exception_tables`), `mm/execmem.c`.

### Preconditions

- Every fragment is verified in-kernel (section 6) before install; nothing
  unverified executes.
- Kernel config invariants live in `kernel-config/kjit-invariants.conf` (K1,
  below).
- CPU and platform requirements, checked at module init by `kjit_check_cpu`
  (`kjit_glue.c`); `insmod` fails with `-ENODEV` and a `pr_err` naming the cause:
  - FEAT_LSE2 (sanitised `ID_AA64MMFR2_EL1.AT != 0`) with `SCTLR_EL1.nAA` clear
    (read on the loading CPU; Linux never sets it): a misaligned
    LDAR/STLR/LDAPR inside a 16-byte block must not fault natively when the
    fragment's `LDTR*`/`STTR*` for it does not.
  - FEAT_LRCPC (sanitised `ID_AA64ISAR1_EL1.LRCPC != 0`): without it user LDAPR
    is UNDEFINED natively but would run in a fragment.
  - FEAT_CRC32 (sanitised `ID_AA64ISAR0_EL1.CRC32 != 0`): without it user
    CRC32*/CRC32C* are UNDEFINED natively and would be an undefined instruction
    at EL1 in a fragment.
  - FEAT_LSE (sanitised `ID_AA64ISAR0_EL1.Atomic >= IMP`); `vabits_actual == 48`;
    `!system_supports_mte()`; `SCTLR_EL1.SPAN == 0` (section 4, LSE atomics through a PAN window (A8)).
  - Counter access (section 4, Counter reads): on every online CPU
    `CNTKCTL_EL1.EL0VCTEN` set and no out-of-line CNTVCT erratum handler, as a
    `CPUHP_AP_ONLINE_DYN` callback (a CPU that fails it does not come online
    while kjit is loaded).
  - `CONFIG_PREEMPT_RT` is a build error.
  - SVE/SME are not a load failure: `uses_fpsimd` fragments are refused per
    fragment on such a system (section 4, FP/SIMD in fragments). Init logs once.
- The module never executes or branches into the K0 golden fragment's bytes
  (below).

### Kernel config invariants (K1)

- `kernel-config/kjit-invariants.conf` is merged last by every profile.
  `scripts/setup-kernel-build.sh` fails, naming each option, when any value
  requested by the merged fragments is not in the final `.config` (an
  `is not set` request is also satisfied by an absent symbol).
- Pinned options (Linux 7.1-rc1):

  | Option | Value | Why |
  |---|---|---|
  | `SHADOW_CALL_STACK` | n | fragment owns x18 |
  | `CFI` (kCFI; `CFI_CLANG` is a transitional alias) | n | kernel calls untyped fragment code indirectly |
  | `ARM64_BTI_KERNEL` | n | prologue and dispatch end in `br x12` into code without landing pads |
  | `ARM64_SW_TTBR0_PAN` | n | LDTR/STTR must reach user page tables |
  | `ARM64_VA_BITS_48` | y | the PAN window range check assumes 48-bit user VA |
  | `MODULES`, `RUST` | y | kjit.ko is an out-of-tree Rust module |

- Contract items with no Kconfig symbol in 7.1, checked in source: hardware PAN
  (`CONFIG_ARM64_PAN` is gone; the `ARM64_HAS_PAN` cpucap is always built and
  enabled when the CPU implements PAN; `scripts/guest-run.sh` fails without the
  boot line `CPU features: detected: Privileged Access Never`);
  `PSTATE.UAO == 0` (`CONFIG_ARM64_UAO` is gone; nothing in arch/arm64 sets UAO,
  and an exception to EL1 clears it); CPU features FEAT_LSE2/FEAT_LRCPC are
  hardware, `kjit.ko` refuses to load without them.
- Checked and not pinned: `ARM64_LSUI` (futex atomics only), `ARM64_EPAN`
  (privileged accesses only; LDTR/STTR are unprivileged), `ARM64_MTE` (LDTR/STTR
  are checked with TCF0, as in copy_from_user; window accesses require no MTE in
  use), `ARM64_PTR_AUTH_KERNEL` (safe only while PAC hints stay outside the
  decoded subset: they take the Unsupported exit and run in userspace; pinned by
  `hint_space_decodes_only_nop_and_bti`).
- Profiles: `tiny-qemu[-debug]` (K0), `kjit-guest` (Debian/redis userland) and
  `kjit-guest-debug` (+ generic KASAN, lockdep, DEBUG_ATOMIC_SLEEP, DEBUG_LIST).
  All start from tinyconfig. The guest profiles use `PREEMPT` (full), because
  fragments run preemptible.
- Kernels build out of tree only: `dep/linux` stays a clean source tree, and
  `KBUILD_OUTPUT` defaults to `$KJIT_BUILD_ROOT/$KJIT_KERNEL_PROFILE`. kjit.ko
  (Kbuild `MO=`) and the K0 golden initramfs live in that build dir, so a module
  is always paired with the kernel it was built against.

### Patch series

The series in `kernel-patches/` is applied onto the pinned 7.1-rc1 commit by `scripts/kjit-kernel-tree.sh` to
`$KJIT_BUILD_ROOT/linux-kjit`, a git worktree of `dep/linux` (idempotent via a
stamp of base commit + patch hashes; fail-fast on local changes, a half-applied
`git am` or a patch that does not apply). Every profile builds from it
(`ARM64_KJIT=y` is a K1 invariant): the module links against the hook symbols,
and one module shape is simpler than a K0-only build.

1. **0001, syscall-return hook.** `ARM64_KJIT` (selects `MMU_NOTIFIER`; depends
   on !SCS, !CFI, !BTI_KERNEL, !SW_TTBR0_PAN), `include/linux/kjit.h`,
   `arch/arm64/kernel/kjit.c`, and a loop in `el0_svc_common`, after
   `invoke_syscall` and only on the path where `has_syscall_work(flags)` is
   false: `while ((scno = kjit_after_syscall(regs)) >= 0) { orig_x0/syscallno
   setup; invoke_syscall(regs, scno, ...); re-read flags; break on syscall work
   }`. The hook is a static key plus an **SRCU**-protected ops pointer that the
   module registers (SRCU, not RCU: `after_syscall` sleeps for fragment page
   faults); a no-op when unregistered.
   - Loop placement: inside the existing "no syscall work at entry, none at exit,
     no single-step, !DEBUG_RSEQ" branch. After each invoked syscall the flags
     are re-read; syscall work or single-step leaves through `trace_exit`, as
     upstream does when work appears under one syscall.
   - `KJIT_MAX_SYSCALLS_PER_ENTRY = 4096`, checked before the hook is called: a
     pure syscall loop would otherwise never switch voluntarily or pass through
     user mode (RCU Tasks). Cost: one return to EL0 per 4096 syscalls.
   - `invoke_syscall` goes through a `noinline` wrapper so the
     `RANDOMIZE_KSTACK_OFFSET` alloca is released per syscall.
2. **0002, `search_kjit_extables(addr)`**, consulted last in
   `search_exception_tables`, through `ops->search_extable` under the same SRCU;
   skipped in NMI (SRCU readers are not NMI-safe; fragments never run there). This
   makes `insn_may_access_user` accept a fragment `LDTR`/`STTR` (or window
   access), so demand paging and CoW work exactly like `copy_from_user`. A truly
   bad address reaches `fixup_exception` and `regs->pc` is set to the site's stub.
   Entries use the arm64 `exception_table_entry` format with type
   `EX_TYPE_UACCESS_ERR_ZERO` and both registers = 31, so the handler only
   redirects the PC; `insn` and `fixup` are self-relative, so the entries live in
   the same allocation as the code. It consults only the SRCU-protected pointer
   (patch 0006).
3. **0003, exports** for RX code memory and I-cache maintenance:
   `EXPORT_SYMBOL_GPL` for `execmem_alloc`, `execmem_free`, `set_memory_ro`,
   `set_memory_x` (arm64's `set_memory_rox` is the generic inline over the last
   two). `flush_icache_range` already uses exported helpers.
4. **0004, `kjit_queue_task_work()`** (`TWA_RESUME`): lets the runtime defer work
   to the task's return to user mode (auto-mode translation requests). The
   task_work callback is kernel code that calls `ops->task_work` under the hook
   SRCU, and only if the registration generation recorded at queue time is
   current; otherwise it `kfree`s the request.
5. **0005**: `EXPORT_SYMBOL_GPL(fpsimd_restore_current_state)` for the FP/SIMD
   bracket.
6. **0006, keep fragment fixups until unregister has drained its calls**: see
   "Hook lifetime and unload (patch 0006)" below.
7. **0007**: `kjit_hook_call_srcu(head, cb)` (`call_srcu()` on `kjit_hook_srcu`)
   and `kjit_hook_srcu_barrier()` (`srcu_barrier()`), both `EXPORT_SYMBOL_GPL`;
   the `srcu_struct` stays private to `arch/arm64/kernel/kjit.c`. No new state or
   lock.

### kjit_after_syscall decision

- `long after_syscall(regs)`: -1 = return to EL0 at `regs->pc`, >= 0 = the
  syscall number to invoke. Return -1 (normal syscall return) unless the run
  conditions hold (below) and a fragment exists for `(current->mm, regs->pc)`.
- Otherwise run fragments: call the entry with x0 = `regs`, x1 = the extra
  params, x2 = the entry address. On exit the epilogue has written the full user
  state into `regs`. Then:
  - `Svc`, with x11 = the PC after the svc: re-check every run condition. If they
    all still hold, set `regs->pc = x11` and return `(int)regs->regs[8]` (the
    kernel's own entry truncates x8 to `int`), so the kernel invokes that
    syscall. A negative value (so `NO_SYSCALL`-style numbers keep the native path), or a
    failed condition, sets `regs->pc = x11 - 4` and returns -1; userspace executes
    the `svc` natively. This makes declining
    always exact.
  - `Ret`/`Br`/`Blr`/`Bl`, target in x10 (a dispatch miss or a plain exit): chain
    into a fragment for the target when the chaining rules allow (section 9,
    Chaining rules; bounded by `chain_budget`, runtime-loop chaining); otherwise
    set `regs->pc = target` and return -1.
  - `Unsupported`/`Mem`/`Budget`: set `regs->pc = x11` and return -1.
  - Any other status is a kernel bug: `WARN_ONCE`, then disable KJIT for the mm
    and return -1 with `regs->pc = x11`.
- With dispatch (A11), `fragment_entries`, `chains` and `exit_*` count runtime
  round trips only.

### Run conditions (kjit_can_run)

- Checked before every runtime entry and every in-kernel syscall; since A11
  not at every call and return of a linked run.
- 64-bit task; **not ptraced** (`current->ptrace`: a tracer may single-step,
  watch or inspect at any instruction); no bit of `(EXIT_TO_USER_MODE_WORK &
  ~_TIF_FOREIGN_FPSTATE) | _TIF_SYSCALL_WORK | _TIF_SINGLESTEP` (signals incl.
  `NOTIFY_SIGNAL`, both need_resched bits, `NOTIFY_RESUME` = task_work/rseq,
  uprobes, livepatch, MTE async faults); x0 not in
  -ERESTARTSYS..-ERESTART_RESTARTBLOCK; `enable` set. `FOREIGN_FPSTATE` only asks
  for an FP reload before EL0 runs; fragments without FP/SIMD never touch those
  registers, and fragments with FP/SIMD reload them inside their bracket.
- Seccomp-filtered tasks never reach the hook (`TIF_SECCOMP` is syscall work).
- Bounds: between two checks a run executes at most `KJIT_BACKEDGE_BUDGET`
  budget units (one per back-edge or dispatch attempt), each at most one acyclic
  path of one fragment plus a template. So the per-hook-call worst case is
  `chain_budget` x 4096 x the longest acyclic path, and typical runs are much
  longer than before dispatch. Signal / `need_resched` / `enable` latency is one
  run, not one call. Under full `PREEMPT` a non-FP/SIMD run is still preempted
  directly; an FP/SIMD run is non-preemptible for its whole length, across
  fragments (section 11). A thread that loaded a table slot before retirement may
  enter a retired fragment and run it until its next dispatch or exit: the same
  class as a run that continues in a fragment removed from its table, which is
  equivalent to the old code having executed just before the unmap, bounded by
  one run.

### Call ABI (kjit_call_fragment trampoline)

- `x0 = regs`, `x1 = extra`, `x2 = base + entry offset`, `blr base`; mirrors
  `harness/src/native.rs`. Before the call it loads the user NZCV from
  `regs->pstate[31:28]` into PSTATE; after it writes NZCV back (the fragment runs
  user flag-setting code in hardware). Callee-saved registers, x29/x30 and sp
  come back through the epilogue.
- Extra params = three u64 (section 3); `Running::call` stores the dispatch table
  of the entered fragment in `extra[EXTRA_DISPATCH_TABLE_INDEX]` (2). The Rust
  side matches the raw status exactly (0..=7), not `RetStatus::from_reg` (which
  masks with 0xFFFF); anything else is the `WARN_ONCE` + disable path.
- FP/SIMD fragments are called through `kjit_call_fragment_fpsimd()` (the bracket
  of section 4, FP/SIMD in fragments), chosen from the entered fragment's
  `uses_fpsimd` at every runtime entry.
- Stats for the bracket: `fpsimd_entries`, `fpsimd_restores`, `fpsimd_exit_mem`
  (Mem exits of FP/SIMD runs, all taken with page faults disabled),
  `fpsimd_refused_sve_sme`, `fpsimd_run_max_ns` (the longest bracket on any CPU
  since load, per-CPU maximum of CNTVCT deltas converted with CNTFRQ; not reset by
  debugfs).

### Code cache and lifetimes

- `kjit_mm` per mm, embedding the `mmu_notifier` (`mmu_notifier_get/put`). Found
  from the syscall path through a global RCU hash keyed by `mm`. The hash
  membership owns exactly one notifier reference; whoever unhashes it (mm
  release, or module exit) under `kjit_mm_lock` drops it. Freed in `free_notifier`
  (after the notifier SRCU grace period): after a hook-SRCU grace period if it
  ever had dispatch tables, else straight to `kvfree_rcu` (most processes in auto
  mode never have tables).
- Table: per-`kjit_mm` RCU hash keyed by the **entry PC** (the PC a translation
  was requested for). The fragment also carries its labels
  `struct kjit_label { u64 pc; u64 host; }` (host = image + a verified entry
  offset, sorted by pc, immutable after install); `kjit_install` takes a separate
  input array `struct kjit_entry { pc, offset }` and rejects (-EINVAL) tables
  without a label for `entry_pc` at `entry_offset`. Branch-exit resolution first
  looks for the target in the fragment that just exited (`kjit_frag_link(f,
  pc)`), then in the table (`kjit_lookup(pc, link, &entry)`; the entry is
  `f->entry_label->host`); both end in `kjit_ibtc_publish(f, label)`. After an `Svc` exit the next hook call
  looks the resume PC up in the table (no reference is held across the syscall;
  it does not publish: it is not a branch exit).
- Only text from VMAs that are not writable is translated. Translation reads
  user text with `access_process_vm` for the manual trigger (debugfs
  `translate <pid> <pc>`), and in the task's own context (`task_work`) for the
  automatic trigger. Text reads: `kjit_read_text_page` under `mmap_read_lock`,
  only from a VMA with `VM_EXEC` and without `VM_WRITE`, one page snapshot per
  page (`get_user_pages_remote`, `FOLL_FORCE` for exec-only text). Per
  translation at most 16 pages and 16384 reads (`build_cfg` has no size bound of
  its own and quadratic bookkeeping).
- Image = one `execmem_alloc(EXECMEM_BPF)` allocation: code, then one
  `exception_table_entry` per fault site (`EX_TYPE_UACCESS_ERR_ZERO`, both
  registers 31), `flush_icache_range`, `set_memory_rox`. The fragment is on the
  global extable list (`kjit_all_frags`) until its retirement callback.
- Locks: `kjit_mm.lock` -> `kjit_frags_lock` (spinlocks, no allocation under
  either: both are taken inside mmu_notifier invalidation). `kjit_mm_lock` is
  never nested with them.
- Invalidation: every `invalidate_range_start` event whose range intersects a
  fragment's source span `[lo, hi)` (min/max of every byte the translator read)
  retires it; not only unmaps, because a protection change can make the text
  writable and CoW/migration replace pages. Non-blocking-safe (spinlock only).
  The mmu notifier also retires everything at mm teardown.
- Install gate: `kjit_mm.seq` counts started invalidations, `invalidating` the
  ones in progress. The translator snapshots `seq` before reading text;
  `kjit_install` installs only if `seq` is unchanged and nothing is in progress,
  else `-EAGAIN` (retried 3 times; `translate_raced`). Any change to the text
  between the read and the install therefore prevents the install.
- Caps are checked in `kjit_install` (section 9, Caps).
- **Fragment lifetime (hook SRCU).** Every fragment execution happens inside the
  hook call's `kjit_hook_srcu` read section (patches 0001/0006), and a linked run
  enters fragments it never looked up, so there are no per-run references:
  `kjit_lookup` takes none, and a fragment is valid for the hook call that found
  it. `kjit_frag_retire_locked(kmm, f)` (all four retire paths go through
  `kjit_mm_flush_locked`: invalidation, `kjit_bad_status`, mm release, module
  exit), under `kmm->lock`: `f->retired = true`; for each label, for each
  dispatch table, if `slot[h(pc)] == &label` then `WRITE_ONCE(slot, 0)` (counts
  `ibtc_clear`); `hash_del_rcu`; then `kjit_hook_call_srcu(&f->retire, ...)`
  (`call_srcu`, legal in the non-blocking mmu-notifier path). The callback
  (workqueue context, BHs off) takes the fragment off `kjit_all_frags` and
  queues the existing RCU free (`queue_rcu_work`: `execmem_free` needs process
  context). So a fragment is freed only after a hook-SRCU grace period following
  retirement, which protects every run, linked or not, and gives the extable
  invariant (below) by construction. A fragment whose install failed was never
  visible, so it is unlisted and freed directly (`kjit_frag_unlist_and_free`).
- Teardown: mm release (`release` callback) retires everything in the table and
  unhashes. Module exit: remove debugfs (waits for writers), unregister the hook
  (waits for calls in flight, i.e. every fragment run, with their extable search
  still live), claim and kill every `kjit_mm` (retires everything),
  `mmu_notifier_put`, `mmu_notifier_synchronize()` (the free callbacks that queue
  the table frees have run), `kjit_hook_srcu_barrier()`, `rcu_barrier()`,
  `destroy_workqueue()`. The barrier has to sit after
  `mmu_notifier_synchronize()`.

### Dispatch tables (A11, kernel side)

- Per `kjit_mm`, `table_all` and `table_nofp` (section 4, In-fragment branch
  dispatch): `kvzalloc`ed (34 KiB each: main and victim part) by the first install that finds none,
  outside `kmm->lock`, published together under it (the race loser frees its
  copy), before the fragment becomes visible. `-ENOMEM` fails that install. Freed
  with the `kjit_mm` after a hook-SRCU grace period.
- Insert: whenever the runtime resolves a branch exit's target T to a fragment F
  and an entry, `kjit_ibtc_publish` skips (no lock) when T's main or victim slot
  already holds a record for T in each table it belongs to; otherwise it takes
  `kmm->lock` and, only if F is not retired, applies the shared slot plan
  (section 4) to `table_all` and, unless `uses_fpsimd`, to `table_nofp`, each
  store an `smp_store_release`. A record for the same pc is never replaced,
  whichever fragment it belongs to (without that, fragments sharing a pc take
  turns in a slot on every resolution). Readers are ordered by the address
  dependency slot -> record -> fields.
- Retire clears the main and victim slot of each label where they still point
  at it (section 4).
- Invariant (not verified, owned by the runtime): every non-zero slot of a table
  (main or victim part) points at a label of a non-retired fragment of this
  `kjit_mm`, stored at that label's own main or victim index, whose host is
  `image + a verified entry offset`, for exactly the label's pc; a `table_nofp`
  slot never points into an FP/SIMD fragment.
- Run: `extra[2]` = `F.uses_fpsimd ? table_all : table_nofp` for the fragment F
  the run enters.
- Stats: `ibtc_insert`, `ibtc_replace` (a slot store, and one over another
  record; a resolution can store up to twice per table, a victim move and the
  main store, so up to four for a non-FP/SIMD target in both tables), `ibtc_clear`
  (cleared slots), `ibtc_fpsimd_boundary` (counted in Rust, `exec.rs`: a
  branch exit of a non-FP/SIMD run whose target resolved to an FP/SIMD
  fragment). Hits are not counted (no atomics in fragment code).

### Chain budget (A10)

- `chain_budget`: fragment entries per hook call, the first one included
  (`runtime/exec.rs` `run_chain`; 1 disables chaining). Module parameter
  (`param_set_uint_minmax`) and debugfs `chain_budget` (writes outside 1..65536
  fail with `-EINVAL`); read once per hook call. Default 1024. Why a budget at
  all: chaining re-checks every run condition before every entry, so the cap only
  has to bound the work one hook call does in fragments without a syscall (a
  user-mode transition or voluntary sleep is what RCU Tasks waits for; the
  syscall loop's 4096-per-kernel-entry cap exists for the same reason). Why 1024:
  it covers every non-pipelined request path with 2x headroom (measurements in
  the journal); a pipelined batch grows with the pipeline depth, so no fixed
  budget covers all of them, and one that hits the budget costs one extra EL0
  round trip per 1024 entries, not correctness.
- With dispatch (A11), `chain_budget` bounds runtime round trips per hook call.
- Stats: `chain_cap` (branch exits that the budget stopped), `run_declined`,
  `chain_max` (most entries in one hook call since load), `chain_hist_<lo>_<hi>`
  (hook calls that ran a fragment, by entries, log2 buckets 1..65536).
- Bound: one hook call runs at most `chain_budget` runtime entries, each bounded
  by the budget and ended by a branch exit; a user loop that is CPU-bound but
  calls functions (no syscall) returns to userspace after its budget and
  finishes natively until its next syscall.
- Preemption does not depend on the budget: the guest profiles are `PREEMPT`
  (full; `PREEMPT_LAZY` and `PREEMPT_DYNAMIC` off), where the tick's
  `resched_curr_lazy()` sets `TIF_NEED_RESCHED`, and the IRQ return to EL1
  preempts a running non-FP/SIMD fragment directly (`preempt_count` 0). The
  per-entry `need_resched` check matters for `PREEMPT_NONE`/`VOLUNTARY`/`LAZY`.

### Hook lifetime and unload (patch 0006)

- Invariant: fragment extables stay reachable until every hook call that could
  be running a fragment has returned.
- Unregister = static key off (no new hook calls), `synchronize_srcu` (calls in
  flight, chained entries included, drain while the ops pointer is still
  published), pointer NULL, `synchronize_srcu` (extable searches and task_work
  callbacks that loaded the old ops finish). `kjit_call_after_syscall()`
  re-checks the static key inside its SRCU section: `kjit_syscall_loop()` checks
  it only before its first call, so without the re-check a loop in progress could
  start a new hook call after the first grace period, and its fragment would
  fault after the pointer was cleared. A call that saw the key enabled entered
  SRCU before `static_branch_disable()` returned (arm64 patching IPIs every CPU),
  so the first grace period waits for it. `search_kjit_extables()` consults only
  the SRCU-protected pointer (still skipped in NMI). Cost: with no runtime
  registered, an address no other table claims takes an SRCU read section instead
  of a static branch. It never waits for a syscall the loop invoked (those run
  outside the SRCU section).
- task_work (patch 0004) calls `ops->task_work` only while the queuing
  registration's ops is published, and the second grace period waits for
  callbacks that loaded it; after module exit no request runs module code, and a
  request queued by one module instance is never handed to a later one. In-flight
  chains run to their normal end (chain budget or exit) during unload.
- The `enable` checks that remain in the module serve the debugfs switch only.

### K0 golden fragment check

- The userspace harness is the reference. `tests/arm64/golden/toy_cfg_hot_svc_mark.rs`
  is generated by `make kernel-golden` (`harness/src/bin/dump-golden.rs`) and holds
  the fixture's `.text` words, `entry_pc`, and the encoded `compile_request`
  fragment. It is plain `const` data so both the harness and the module can
  `include!` it.
- Staleness guard: harness test `kernel_golden_matches_harness_output` re-renders
  the file from its own input words and requires byte-equal source. It does not
  re-assemble `toy_cfg.s`; the input words are only as fresh as the last
  `make kernel-golden`. It embeds the prologue and a `ret` site, so it is
  regenerated whenever either changes.
- Module init runs `compile_request` over a `CodeProvider` backed by the embedded
  words, encodes, and compares byte-for-byte. PASS/FAIL is `pr_info!`/`pr_err!`
  with the first mismatching offset; FAIL returns `EINVAL` from init.
- Invariant: the module never executes or branches into the golden fragment's
  bytes. K2 executes only fragments it translated from a live process and
  verified in-kernel.

## 9. Automatic hot-path detection (K3)

Code: `kjit_glue.c` ("Auto mode"), `runtime/exec.rs`, `runtime/translate.rs`,
`runtime/stats.rs`, `kernel-patches/0004`.

### Profiler

- Where: the syscall-return hook, only when a run is otherwise possible
  (`kjit_can_run`) and there is no fragment: (1) at `regs->pc` after a syscall
  (`KJIT_HOT_SVC_RESUME`), (2) at the target of a `Bl`/`Blr`/`Br`/`Ret` exit
  whose chaining lookup failed (`KJIT_HOT_EXIT_TARGET`, exit-target learning).
  Never after `Unsupported`/`Mem`/`Budget` (userspace resumes mid-block; the
  next syscall resume PC is the profiled point), never when the chain budget or
  a run condition stopped chaining.
- Table: per `kjit_mm`, 256 slots, open addressing over 8 probe slots from
  `hash_64(pc)`. A lookup scans all 8 (no early stop), so freeing a slot needs
  no tombstone. A new PC takes a free slot or one whose window has expired and
  that has no queued request; else the hit is dropped (`auto_prof_full`). Under
  `kjit_mm.lock`. The first eligible syscall of an mm only creates its `kjit_mm`
  (`mmu_notifier_get`, may sleep: mmap write lock, `mm_take_all_locks`) and is
  not counted; after that a hit costs a hash lookup, the spinlock and an
  arch-counter read, and allocates nothing.
- Hot: `hot_threshold` hits within one `hot_window_ms` window (window start =
  first hit; an expired window restarts at the hit). Time is CNTVCT
  (`arch_timer_read_counter`, ticks = ms * CNTFRQ / 1000). On the crossing the
  slot's window restarts whatever happens next.
- Defaults 64 hits / 100 ms (>= 640 hits/s sustained); module parameters and
  debugfs. Why: a translation costs far more than the one EL0 round trip an
  in-kernel syscall saves, so it must be amortized over many hits; bursts of
  fewer than 64 hits per 100 ms (startup, config parsing) are never translated.
  Numbers: `docs/journal/2026-09-27.md`, "K3: automatic hot-path detection".

### Requests (task_work)

- A hot PC that is not in the negative cache, under the caps, and with fewer
  than 8 requests queued for its mm gets its slot marked `queued` and a
  `kjit_request` (kmalloc, the only allocation of the path) queued with
  `kjit_queue_task_work()` (patch 0004, `TWA_RESUME`). Translation never runs in
  the syscall hook.
- The request runs in the requesting task at its next return to user mode (the
  queued `TIF_NOTIFY_RESUME` is a bail flag, so the hook returns first). It
  translates only if `current->mm` is still the request's mm, the task is not
  exiting and auto mode and `enable` are still on (else `auto_req_stale`), with
  `kjit_rs_translate` on the task's own mm: same text rules, same verification,
  same install gate as the manual trigger.
- A request holds no reference. It names its `kjit_mm` by (mm pointer, a
  per-`kjit_mm` 64-bit id) and finds it again under RCU when it finishes, so an
  exited mm or a reused mm address is detected. Finishing frees the slot
  (installed: the table now has the PC; transient failure: it is profiled again).
- Module lifetime: see section 8, Hook lifetime and unload (patch 0006; task_work is
  patch 0004). Nothing
  has to cancel per-task work at unload.

### Negative cache

- Final failures (errno): compile/encode (`-EINVAL`), verifier (`-EPERM`),
  untranslatable entry instruction (`-ENOEXEC`), text not in an executable
  non-writable mapping or unmapped (`-EACCES`, `-EFAULT`), text budget
  (`-E2BIG`), `uses_fpsimd` on a system with SVE/SME (`-ENODEV`), and anything
  unclassified. Transient: `-EAGAIN` (lost the install race 4 times), `-ENOMEM`,
  `-EINTR`, `-ESRCH`, `-ENOSPC` (caps).
- Per `kjit_mm`, 64 PCs, FIFO replacement (`auto_neg_evicted`); checked only when
  a PC crosses the threshold, so a hit never scans it. Not cleared by
  invalidations: a PC whose text is later replaced (dlclose + dlopen at the same
  address) stays untranslated in that mm. Pessimistic, never wrong.
- Entry refusal (all triggers): a translation whose entry word itself would take
  the `Unsupported` exit (`cfg::admit_at`) is refused with `-ENOEXEC`
  (`translate_entry_unsupported`): the fragment could only return to userspace at
  its own entry, at the cost of a call. The negative cache keeps the word; the
  PC's profile slot then counts every later hit as an `entry_stop` of that word
  in `unsupported_top` instead of counting it.

### Caps

- `max_frags_per_mm` 512, `max_code_per_mm` 2 MiB, `max_frags_total` 8192,
  `max_code_total` 64 MiB (module parameters). Checked in `kjit_install` under
  `kjit_mm.lock` (per mm exact; the global counters are read racily across mms,
  so concurrent installs can overshoot by one fragment each), `-ENOSPC`, for every
  trigger. Pre-checked before a request is queued.
- Counts move with table membership (install, `kjit_mm_flush_locked`), not with
  the end of the grace period, so a fragment still running after removal is not
  counted.

### Chaining rules

- On `Bl`/`Blr`/`Br`/`Ret` with target T (a dispatch miss or plain exit): if the
  hook call has made fewer than `chain_budget` fragment entries (the first one
  included) and `kjit_can_run` holds (it also checks `enable`), continue at T's
  verified entry in the fragment that just exited, else at the fragment for
  (mm, T); each chained entry counts `chains`. Otherwise userspace resumes at T;
  if the lookups ran and failed, T is profiled. Reaching the budget counts
  `chain_cap`; a failed run condition (at the hook or at a branch exit within the
  budget) counts `run_declined`.
- Every entry is back-edge-budget-bounded and the run conditions are re-checked
  before each runtime entry and before each in-kernel syscall, so a hook call
  spends at most `chain_budget` bounded runs in fragments between two syscalls.
  See section 8, Chain budget (A10), for what the budget protects and its
  default.

### Lifetimes

- exec: a new mm, so a new `kjit_mm` on its first syscall; the old one dies at mm
  release; requests queued before the exec are stale.
- fork: mmu notifier subscriptions are not inherited, so the child starts empty
  and profiles on its own. In the parent, `copy_page_range` only walks VMAs that
  need copying (`vma_needs_copy`: an `anon_vma`, or `VM_COPY_ON_FORK`); for a CoW
  one it sends a `PROTECTION_PAGE` invalidation, which drops fragments translated
  from it (conservative). Plain file-backed text has no `anon_vma`, so its
  fragments survive a fork; text in an anonymous RX mapping does not.
- Thread exit: a queued request runs in `exit_task_work` with `current->mm` NULL:
  stale, its slot is released under RCU.
- Process exit, module unload: release/claim empties the table; queued requests
  are freed by the kernel (0004).

### Accounting and diagnostics

- `hook_calls` (per-CPU in C): hook calls while enabled, i.e. syscalls without
  syscall work, in-kernel ones included. `syscalls_in_kernel / hook_calls` is the
  in-kernel fraction (global: the runner isolates the program under test by
  running load generators under `nojit`, an allow-all seccomp filter).
- `unsupported_top`: lock-free table of 1024 words (16 probes; a slot's key is
  claimed once by compare-exchange and never changes). Columns `exits`
  (`Unsupported` exits, x10 = word, `unreadable` for
  `UNSUPPORTED_WORD_UNREADABLE`, any other x10 counts `unsupported_bad_word`) and
  `entry_stops`. Full table: `unsupported_top_dropped`.
- C counters go through one `kjit_rs_note(enum kjit_note, n)` (values mirrored in
  `runtime/stats.rs`, `note_stat`).

## 10. Validation of the kernel runtime (K2-K4)

- Guest tests (G2): `tests/guest/` (static, `/opt/kjit-tests` in the guest
  rootfs; `make guest-tests GUEST_PROFILE=... K2_ITERATIONS=N`; K3 runs them in
  auto mode, `run-k3.sh`). Every test runs with `enable` N and Y: identical
  stdout and exit status, plus counter checks in the enabled run. G2 =
  `toy_loop`: >= 99% of its syscalls invoked in-kernel.
- Redis campaign (K4): `make redis-campaign` (`scripts/redis-campaign.sh`, guest
  side `tests/guest/k4-*.sh`). Goal: redis in the guest under the auto mode with
  exactly native behaviour. Pass criteria:
  - Suite: both runs reach "The End" (a test-client `[exception]` aborts
    runtest), and the same outcome for every test. Compared: the distinct
    `<status> <name>` lines with digit runs masked, plus the `err` lines exactly.
    Raw multisets are not comparable even between two runs of one kernel:
    `integration/psync2` loops for a fixed time.
  - Benchmark: the full default test set completes in all three runs;
    `exit_invalid`, `translate_verify_rejected`, `unsupported_bad_word` stay 0
    (every phase), and each phase has `ibtc_insert > 0`; the off/on consistency
    dataset (`DBSIZE`, `DEBUG DIGEST`, sha256 of a full read-back) is identical.
  - Adversarial: identical deterministic stdout KJIT off and on (exit statuses
    137/0/138/139, crash-report signal/si_code lines, digests before and after
    restarts, OOM error text); `K4_REQUIRE_HOT=1` (default) requires fragment
    entries during each load phase before the disruptive event.
  - No kernel report on the serial console or in the campaign's `dmesg`.
- Exclusions: none from the default `./runtest` list (all 84 units run, with one
  backported upstream test fix; runtest itself ignores the 15 `large-memory`
  tests). Not run: `--accurate`, `runtest-moduleapi`, `runtest-cluster`,
  `runtest-sentinel`, TLS. `DEBUG SEGFAULT` mmaps a read-only page and writes it,
  so the faulting address varies with ASLR; only its page alignment is compared.
  `maxmemory` with random keys: only invariants (keys evicted, `used_memory` <=
  33 MiB, noeviction OOM error text). No system memory pressure beyond
  `maxmemory`: reclaim/migration of hot text is not exercised (K2 invalidation is
  covered by munmap and module unload).

## 11. Open decisions and known limitations

Current items only. Each links to the journal entry it comes from, which holds
the reasoning, the numbers and the full list of what was not verified there.

### Open decisions

- **FP/SIMD bracket length is a whole run.** A bracketed run dispatches through
  `table_all` and continues into non-FP/SIMD code, so once a run enters an
  FP/SIMD fragment everything after it until the next runtime exit runs with
  preemption and page faults disabled: up to `KJIT_BACKEDGE_BUDGET` units, each an
  acyclic path of any fragment (before A11 the bracket ended at the FP/SIMD
  fragment's first branch exit). Correct, but a preemption-latency regression the
  contract allowed without bounding. Options: (a) FP/SIMD runs dispatch only into
  FP/SIMD fragments (a third table), so the bracket covers FP/SIMD code only and
  every return into integer code is a runtime entry; (b) a smaller budget for
  bracketed runs; (c) accept and document the bound. Decision pending.
  [2026-10-05 11:47, A11 integration](journal/2026-10-05.md).
- **A11 deferred items**, each safe to defer because it is pure speed or policy
  on top of the same records and lifetimes: patched direct `b` for `BL` sites and
  a return-address stack for `RET` (revisit if a profile shows the ~20-word
  dispatch sequence dominating fragment time); a bracket that spans non-FP/SIMD
  runs so that non-FP/SIMD -> FP/SIMD transfers stop missing (decide from
  `ibtc_fpsimd_boundary`; it trades page faults handled in place for `Mem` exits
  and longer non-preemptible stretches); re-entering after a Budget exit instead
  of resuming in userspace (needs Budget resume PCs to be entry labels; decide
  from `exit_budget`); in-fragment code quality (budget counter read-modify-write
  through memory, stack-backed x12..x15, `LDTR` imm9-only splits).
  [2026-10-02 16:25, A11 contract pinned](journal/2026-10-02.md).
- **Dispatch table conflicts: decided (A11c victim part, section 4).** Misses
  were classified (conflicts from a few two-pc aliases, not capacity) and five
  table shapes measured; hits are still not counted (no atomics in fragment
  code). [2026-10-09](journal/2026-10-09.md).
- **Where the remaining A11 loss sits.** Of the remaining slowdown against
  native, a minority is runtime round trips and the larger part is inside
  fragment code (dispatch sequences, budget accounting, windowed memory
  accesses), inferred from counters and two models, not timed per phase.
  [2026-10-05 11:47](journal/2026-10-05.md).
- **V2 chaining.** The fuzzer counts `chained` as a non-verdict; modelling
  chaining in the original runner of the single-fragment fuzzer is deferred
  (cached runs follow branches). [2026-09-27 03:40](journal/2026-09-27.md).
- **PAC-built binaries.** PAC hints cannot simply run at EL1 (kernel keys are
  installed), so PAC-built distros need their own lowering; today they take the
  `Unsupported` exit and run in userspace.
  [2026-09-27 10:20, K4](journal/2026-09-27.md).

### Known limitations

Kernel runtime:

- rseq critical sections are not honoured inside fragments (glibc only reads
  `cpu_id`, redis defines none). [2026-09-27 01:22](journal/2026-09-27.md).
- A write to a mapped text file through `write(2)` or a shared writable mapping
  of the same file changes page-cache pages in place without an mmu_notifier
  event on our (non-writable) VMA, so a translation of it is not invalidated. The
  running executable is protected by `ETXTBSY`; shared libraries are not.
  Invalidation is otherwise conservative (any notifier event on a fragment's
  span drops it; the install gate retries on unrelated invalidations). Perf
  hardware breakpoints/watchpoints on a non-ptraced task are not considered.
  [2026-09-27 03:30](journal/2026-09-27.md).
- BTI: a `Blr`/`Br` exit does not model PSTATE.BTYPE. Chaining or dispatching into
  a fragment, or resuming userspace at the target with the syscall's BTYPE (0),
  skips the landing-pad check that a native indirect branch to a non-`BTI`
  instruction in a guarded page would fail (SIGILL). Only programs with broken
  control flow are affected. A `BTI` inside translated code is a `NOP`.
  [2026-09-27 05:06](journal/2026-09-27.md), [05:46](journal/2026-09-27.md).
- Auto mode: the first eligible syscall of every mm registers an mmu notifier
  (`mm_take_all_locks`), so every process pays it once; the per-mm table and
  negative cache are per mm, not per executable, so every process warms up on its
  own; the negative cache is not cleared by invalidations (pessimistic, never
  wrong). [2026-09-27 05:06](journal/2026-09-27.md).
- Campaign comparisons: counters are global (in-kernel fractions include the
  runner's own shell, sleep and redis-cli processes), and a test that fails
  identically with and without KJIT would pass the comparison (the baseline has
  no failed test today). [2026-09-27 10:20](journal/2026-09-27.md).
- The verifier does not cover NZCV at entry (the trampoline's flags: not an
  address) and assumes the kernel's fault fixup changes no GPR before the stub.
  [2026-09-27 13:01](journal/2026-09-27.md).
- A PAN-window access can read an execute-only user page that an EL0 access could
  not (the kernel's own futex ops have the same exposure without EPAN):
  recorded, not mitigated. `kjit.ko` refuses to load when MTE is in use.
  [2026-09-27 12:07](journal/2026-09-27.md).
- SVE/SME systems: `uses_fpsimd` fragments are refused (`-ENODEV`, negative
  cached); that path is compiled but has never run. `PREEMPT_RT` is a build error.
  [2026-09-27 16:16](journal/2026-09-27.md).
- CNTVCTSS_EL0 (FEAT_ECV) is not admitted. EL0VCTEN is checked per online CPU at
  load and at CPU online. [2026-09-27 19:01](journal/2026-09-27.md).

Translator coverage:

- Not translated (take the `Unsupported` exit and run natively): exclusives
  (LDXR/STXR family), `CASP`, FEAT_LSE128/LSUI forms, LDNP/STNP, PRFUM, RPRFM,
  floating-point arithmetic/conversion/compare, register-offset and literal
  SIMD&FP loads/stores, LD2-4, single-structure and replicate loads, TBL/TBX with
  2-4 registers, half-precision FMOV, PAC hints and every HINT other than NOP and
  BTI, `MRS` of anything but TPIDR_EL0/CNTVCT_EL0/CNTFRQ_EL0, `dc zva`, `MSR` other
  than PAN. Words seen blocking redis paths after A10: SIMD&FP register-offset
  `ldr d0, [x14, x12, lsl #3]` and `str q0, [x0, x3]`, `ucvtf`/`scvtf`/`fcmp`,
  `dc zva`, `mrs x21, fpcr`, `yield`. [2026-09-27 19:01](journal/2026-09-27.md).
- Constrained-unpredictable cases rejected conservatively: SIMD&FP LDP `t == t2`
  and LD1/ST1 post-indexed by their own base register (no fixture shows their
  native behaviour). [2026-09-27 14:35](journal/2026-09-27.md).
- FPCR/FPSR bits outside `FPCR_USER_BITS`/`FPSR_USER_BITS` (trap enables, AFP
  bits) are never generated by the tests; no translated form reads them.
  [2026-09-27 14:35](journal/2026-09-27.md).

### Not verified (open risks)

Recorded in full in the entries named; none is known to be wrong.

- Ordering of the `DMB ISH` mapping and single-copy atomicity of misaligned
  accesses under FEAT_LSE2: argued, no test observes a reordering.
  [2026-09-27 04:10](journal/2026-09-27.md).
- A PAN window interrupted or preempted on real hardware (SPAN = 0 is checked at
  init); a window atomic that faults in the kernel and is retried; multi-threaded
  atomicity of window accesses. [2026-09-27 12:07](journal/2026-09-27.md).
- Partial-fault behaviour of SIMD&FP accesses on hardware other than the M1; the
  softirq-NEON-versus-bracket case (argued from `fpsimd.c`); the worst-case
  bracket duration on bare metal (all numbers are wall clock inside an HVF guest).
  [2026-09-27 14:35](journal/2026-09-27.md), [16:16](journal/2026-09-27.md).
- CPU hotplug of the counter check, the erratum and EL0VCTEN-clear branches; the
  worst-case time of one hook call (`chain_budget` budget-bounded runs: computed,
  not measured);
  preemption inside chains under `PREEMPT_NONE`/`VOLUNTARY`/`LAZY`.
  [2026-09-27 19:01](journal/2026-09-27.md).
- Dispatch: the concurrency of a run reading a slot against a retire and of a
  table free against runs in flight is argued (every read is inside a hook SRCU
  section; slots are cleared before the grace period starts); retire cost under
  the spinlock for a fragment with very many labels is not measured; memory held between
  retirement and the end of the hook-SRCU grace period is not measured.
  [2026-10-02 17:10](journal/2026-10-02.md).
- `fpsimd_run_max_ns` tails after A11 are far above the A9b figure in redis
  benchmark and suite runs, on a host running other work; host vCPU stalls versus
  whole-run brackets were not separated.
  [2026-10-05 11:47](journal/2026-10-05.md).
- The two failures of the debug redis campaign on the A11 tree are attributed to
  flaky redis tests from the KJIT-off runs, not excluded as KJIT-induced.
  [2026-10-05 11:47](journal/2026-10-05.md).

## 12. Journal index

One file per day in `docs/journal/`, entries timestamped, newest last. By
milestone:

| Milestone | Entries |
|---|---|
| Trace explorer (OpenTUI) | [2026-06-08 22:44](journal/2026-06-08.md) |
| A1 unsupported exit, pair/writeback reg-virt | contract only (section 4) |
| P1: A4 memory model, A5 sandbox and fault sites, A6 budget | [2026-09-27 01:11](journal/2026-09-27.md) pinned contracts; [01:57](journal/2026-09-27.md) A5 decisions; [02:20](journal/2026-09-27.md) A6 decisions |
| V1 native oracle, entry ABI | [2026-09-27 01:38](journal/2026-09-27.md) |
| K0 golden check, K1 config invariants | contract only (section 8) |
| K2 kernel runtime | [2026-09-27 01:22](journal/2026-09-27.md) contract; [03:30](journal/2026-09-27.md) implementation |
| A7a subset admission | [2026-09-27 01:49](journal/2026-09-27.md) |
| A7b memory forms | [2026-09-27 02:42](journal/2026-09-27.md) |
| V2 differential fuzzer | [2026-09-27 03:40](journal/2026-09-27.md) |
| V3 verifier | contract (section 6); rule 9: [2026-09-27 13:01](journal/2026-09-27.md) |
| A7c barriers, acquire/release | [2026-09-27 04:10](journal/2026-09-27.md) |
| K3 auto mode | [2026-09-27 05:06](journal/2026-09-27.md) |
| A7d BTI, carry, CRC32 | [2026-09-27 05:46](journal/2026-09-27.md) |
| A8 LSE atomics, PAN window | [2026-09-27 09:58](journal/2026-09-27.md) contract; [12:07](journal/2026-09-27.md) implementation |
| K4 redis campaign | [2026-09-27 10:20](journal/2026-09-27.md) campaign; [10:20](journal/2026-09-27.md) client-eviction race |
| A9 FP/SIMD | [2026-09-27 10:22](journal/2026-09-27.md) contract; [14:35](journal/2026-09-27.md) A9a; [16:16](journal/2026-09-27.md) A9b |
| A10 chain budget, counter reads | [2026-09-27 19:01](journal/2026-09-27.md); unload race [2026-09-28 00:09](journal/2026-09-28.md); `run_declined` [2026-09-28 00:16](journal/2026-09-28.md) |
| A11 in-fragment dispatch | [2026-10-02 16:25](journal/2026-10-02.md) contract; [17:10](journal/2026-10-02.md) A11b; [17:14](journal/2026-10-02.md) Step 0; [17:28](journal/2026-10-02.md) A11a; [2026-10-05 11:47](journal/2026-10-05.md) integration |
| Documentation restructure | [2026-10-09 00:54](journal/2026-10-09.md) |
