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
  before it and records `BasicBlock.unsupported_exit = Some(UnsupportedInsn { pc, word })`.
  Invariant: `pc == end_addr`, `next` is empty, `insns` may be empty (entry
  itself undecodable). Only `DecodeError::UnsupportedWord` converts; code-read
  failures keep their old behavior.
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
- The harness original-code interpreters and the raw trace view call
  `admit_word` too, so they stop exactly where the translated code exits.
- Rephrase stays the only producer of the exit; reg-virt never synthesizes it.
- Rephrase lowers it to an exit group: `x9 = RetStatus::Unsupported (6)`,
  `x10 = raw word`, `x11 = pc`. The runtime always resumes userspace at `x11`
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
- Native original: stop points come from the interpreter's own halting rule
  (`admit_word`) applied to every text word (SVC -> mock trap; rejected word or
  non-SVC runtime exit -> stop trap; first word past the text -> fell off). A
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
  - user access = `LDTR`/`STTR` (and later unprivileged forms). These are the
    only instructions that touch user memory. EL0 permissions apply in hardware.
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
- Until A5 lands, fragment accesses are classified by address (runtime-owned →
  runtime access, anything else → user access). A5 deletes that rule and
  classifies by instruction as above.

## Memory rewrite (A5)

- Reg-virt lowers every user load/store to `LDTR`/`STTR` (forms
  `LDTR.LDTR_{32,64}_ldst_unpriv`, `STTR.STTR_{32,64}_ldst_unpriv`), using the
  same per-instruction scratch pool it already owns (x12–x15). No second
  scratch allocator.
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
- The kernel's fault fixup (K2) only sets the faulting PC to the stub offset.
  The harness does the same: a user-access fault at a fragment offset jumps to
  the table's stub, and an offset without an entry is a hard error.
- On `Mem` the runtime returns to userspace at x11. Userspace re-executes the
  instruction natively and takes the fault itself, so signals and SIGSEGV
  behave exactly as they do without KJIT.
- Store footprint: when a split `STP` faults on its second access, the first
  8 bytes may already be written. Architecturally that's allowed, and it is
  invisible to a single thread because userspace re-executes the whole `STP`.
  The differential check allows exactly those bytes to be either old or new.

## Execution budget (A6)

- A back-edge is any branch whose target is at or before it in the final
  layout order. Layout order is the block order, so this is known before
  offsets and can be checked on the final bytes without a CFG.
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

## Validation order

- V3 (the independent verifier) checks rules that only exist after A5 and A6
  land (user memory only via LDTR/STTR, fault table coverage, the budget
  sequence). It is written against this section and merged after A6.

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
- Invariant: the module never executes or branches into the emitted bytes. That
  waits for an independent in-kernel verifier.
