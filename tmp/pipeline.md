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
