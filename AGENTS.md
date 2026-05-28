# AGENTS.md

Guidance for AI agents working in this repository.

## Project Goal

KJIT translates hot userspace syscall-adjacent AArch64 code into kernel-space
executable code so the program can avoid repeated userspace/kernel context
switches. The only target architecture is ARM64/AArch64. Do not add generic
multi-architecture abstraction unless the user explicitly asks for it.

The high-level translation model is:

```text
raw userspace bytes -> generated typed A64Insn -> raw kernel-safe bytes
```

The current development strategy is to validate as much as possible in
userspace before doing kernel-specific execution work. Kernel debugging was the
main historical pain point, so the harness is not a side project: it is the
primary userspace proving ground for translation correctness.

Current non-goals:

- No x86 support.
- No generic JIT framework.
- No full Arm decoder beyond the selected A64 subset.
- No performance optimization before semantic equivalence.
- No kernel-first debugging for translator bugs.

## Read First

- `tmp/pipeline.md`: active design notes and pipeline requirements.
- `README.md`: user-facing architecture and workflow overview. Keep it current.
- `old-version/`: historical implementation and ideas. Use it as reference, not
  as code to bulk-copy.
- `spec/arm64/subset.toml`: canonical supported Arm XML subset.
- `specgen/`: Rust generator for instruction metadata/code derived from Arm XML.
- `shared/`: code intended to be usable from both userspace and kernel space.
- `harness/`: userspace validation harness for translated fragments.

## Working Style

- Be concise.
- Criticize weak plans before implementing them. Surface missing invariants,
  hidden kernel assumptions, and unnecessary abstraction.
- Prefer the smallest design that proves the next correctness layer.
- Do not add optimization hooks, bookkeeping fields, ABI versioning, or broad
  generalization until the current pipeline needs them.
- Keep changes scoped. Avoid drive-by cleanup unless it directly reduces risk
  for the task.
- If a decision affects the architecture, update `tmp/pipeline.md`. If it
  affects how the project is understood or used, update `README.md`.

## Architecture Boundaries

### `shared/`

`shared/` is for logic that can run in userspace and kernel space.

Rules:

- Target `no_std + alloc`; use `core` by default.
- Use allocation deliberately through shared wrappers such as the existing Vec
  abstraction. Add map/string/container wrappers only when a concrete need
  appears.
- Do not use `std`, filesystem APIs, process APIs, environment APIs, printing,
  userspace logging, or host-specific assumptions.
- Do not rely on panics for normal control flow.
- Keep allocation and ownership policy easy to audit.
- Keep interfaces agnostic to execution environment.

The root `shared/` directory is the source of truth. `harness/src/shared/`
is a synced copy used by the standalone harness. Edit root `shared/` first, then
run `make harness-sync` or `make harness-prepare`. Do not make durable changes only in
the harness copy because they can be overwritten.

### `harness/`

The harness may use `std`, files, fixtures, CLI helpers, and deterministic
mocking. It should consume `shared/` as the compiler/runtime core and should not
own duplicate translation logic.

The harness mental model is the future kernel executor:

- It mocks machine state.
- It executes the translated `ExecutionFragment` through the same function-call
  style boundary the kernel will eventually use.
- It models prologue, epilogue, runtime exits, register writeback, and syscall
  stubs before kernel deployment.

### Kernel Work

Do not jump to kernel execution first. Kernel integration should come after the
instruction encoding and userspace translation/runtime layers pass for the
relevant subset. Kernel work should consume already-validated executable bytes
and still revalidate minimally at the boundary.

## Translation Pipeline

Keep the pipeline A64-to-A64. Do not introduce a separate architecture-neutral
IR unless there is a proven need.

Current conceptual passes:

1. Decode raw bytes into generated `A64Insn` values with original PC/provenance.
2. Validate the supported subset and operand restrictions.
3. Build a reachable CFG from `TranslationRequest.entry_pc` using a
   `CodeProvider`.
4. Rephrase semantic boundary instructions while preserving typed A64
   instructions.
5. Virtualize registers as a separate structured pass.
6. Resolve layout into one executable fragment with prologue, body, runtime
   exits, epilogue, and virtual labels.
7. Emit bytes using generated `A64Insn::encode()`.
8. Decode/validate emitted bytes again.

Runtime exits such as `BL`, `BLR`, `BR`, `RET`, and `SVC` must be represented
explicitly. Unknown dynamic targets must return to runtime; never branch to a
raw user-controlled target in kernel space.

## ABI Contract

`shared/abi.rs` is the canonical ABI contract. It owns the shared function
boundary constants, return-status registers, prologue, epilogue, instruction
size, and wrapper offsets. Keep the harness and future kernel executor
aligned with that file instead of duplicating ABI facts elsewhere.

Function-boundary behavior is part of correctness. Translation tests must model
entry arguments, runtime-exit status/params, link-register policy, prologue,
epilogue, and register writeback consistently with `shared/abi.rs`.

## Instruction Generation

Instruction-related code should be generated from Arm technical XML as much as
possible. Avoid handwritten opcode constants, mini-assemblers, or manual wiring
that belongs in `specgen/`.

Normal flow:

1. Add or adjust exact forms in `spec/arm64/subset.toml`.
2. Update `specgen/` if the generator needs more metadata.
3. Run `make spec-gen`.
4. Keep checked-in generated artifacts in sync:
   - `spec/arm64/generated/a64_subset.rs`
   - `spec/arm64/generated/a64_subset.json`
   - `harness/src/shared/arm64/generated.rs`

The Rust `specgen/` generator is the canonical generation path. Do not hand-edit
`spec/arm64/generated/*` or the harness copy of generated A64 code. Change
`spec/arm64/subset.toml` or `specgen/`, regenerate, then inspect the diff. The
root `shared/arm64/generated.rs` should remain a thin include wrapper for the
generated subset unless there is a deliberate build-layout change.

## Old Version Policy

`old-version/` contains important prior work. Read it to recover algorithms,
contracts, and cautionary examples. Do not bulk-move old code into `shared/`.
Audit helpers one at a time for purity, kernel suitability, and fit with the new
typed A64 pipeline.

Treat old conflict-resolution/register-allocation logic as a prototype, not as
the new design base. Prefer deterministic, inspectable mappings first, even if
they are slower.

## Testing And Verification

Correctness is layered. Use the lowest relevant layer first.

Common commands:

```sh
make harness-test
make harness-dump-cfg
make harness-test-asm
make spec-test-encoding
make spec-gen
```

`make spec-test-encoding` compares generated encoding against LLVM assembler output
and is marked ignored inside the Rust test suite. Use it when touching encoding
or generated instruction forms.

Build/kernel commands are intended for the Linux dev container:

```sh
make prepare
make rust-analyzer
make module-build
make qemu-run
```

Do not claim kernel safety from harness-only tests. Do not use QEMU/kernel tests
as the first debugging tool for translator logic.

Definition of done by change type:

- Shared translation/runtime logic: run `make harness-test`.
- CFG or rephrase behavior: run `make harness-dump-cfg` or
  `make harness-test-asm`, whichever matches the touched path.
- Generated instruction or encoding changes: run `make spec-gen` and
  `make spec-test-encoding`.
- Architecture or workflow changes: update `tmp/pipeline.md` and, when
  user-facing, `README.md`.

## Documentation Rules

- Record active development requirements and design changes in
  `tmp/pipeline.md`.
- Keep `README.md` aligned with the actual architecture and workflow.
- Prefer concrete contracts over aspirational prose.
- If a design is deferred, state the invariant that lets it remain deferred.

## Code Preferences

- Minimal code first.
- No unnecessary optimization.
- No unnecessary bookkeeping fields.
- Prefer structured typed APIs over string parsing or ad hoc byte manipulation.
- Use generated A64 operand metadata where possible.
- Keep branch immediate rewriting in layout/emit, not semantic rephrase.
- Keep register virtualization separate from branch/runtime-exit handling.
- Keep userspace-only convenience out of `shared/`.
- Avoid duplicating decode/encode logic in the harness.
