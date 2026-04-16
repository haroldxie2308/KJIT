# Userspace Test Harness Outline

## Goal

Build a fast userspace validation harness that checks translation correctness before kernel execution is involved.

The harness should compare:

- original ARM64 bytes interpreted with an ARM64 subset model
- translated lowered IR interpreted with an independent IR model
- encoded translated bytes interpreted again as ARM64

## Why Before Rewrite

- the current handwritten assembler is a likely bug source
- kernel execution is slow and difficult to debug
- the rewrite needs a semantic contract and regression suite

## Initial Scope

Supported in the first implementation:

- 64-bit GPR subset
- `NOP`
- `MOVZ`, `MOVK`
- `ADR`, `ADRP`
- `ADD`, `SUB`
- `CMP` through `SUBS`
- `B`, `B.cond`, `CBZ`, `CBNZ`
- `LDR`, `STR` unsigned immediate (64-bit)

Deferred:

- `SVC`
- BL/RET runtime protocol used by UCA
- kernel prologue/epilogue
- page permissions, executable memory, profiling, lifting policy

## Architecture

Standalone Cargo crate:

- `userspace-harness/src/model.rs`
  - machine state
  - flags
  - register and memory helpers
- `userspace-harness/src/arm64.rs`
  - decode supported ARM64 subset from bytes
  - interpret decoded ARM64 instructions
- `userspace-harness/src/lowered.rs`
  - lowered IR
  - lowered IR interpreter
  - encoder from lowered IR back to ARM64 bytes
- `userspace-harness/src/translate.rs`
  - translation from decoded ARM64 instructions to lowered IR
  - target remapping for control flow
- `userspace-harness/src/cases.rs`
  - deterministic built-in cases
- `userspace-harness/src/bin/userspace-harness.rs`
  - CLI entrypoint

Repo integration:

- `make userspace-harness-test`
- `make userspace-harness-run`
- Docker-backed execution through `scripts/docker-dev.sh`

## Validation Pipeline

For each built-in case:

1. interpret original ARM64 bytes
2. translate to lowered IR
3. interpret lowered IR
4. encode lowered IR to ARM64 bytes
5. interpret encoded ARM64 bytes
6. compare normalized machine states

Normalized comparison should include:

- general-purpose registers
- flags
- modeled memory
- halt reason

Normalized comparison should exclude raw final PC equality because translated code size can differ from original.

## Key Design Rule

The lowered IR interpreter is the main oracle for translation correctness.

The harness must avoid relying exclusively on the encoded ARM64 path to validate itself.

## First Test Cases

- `adr_to_load_imm`
  - verifies lowering of `ADR` into explicit immediate materialization
- `adrp_to_load_imm`
  - verifies page-based address materialization
- `conditional_branch_taken`
  - verifies flags and `B.cond`
- `compare_and_branch_not_zero`
  - verifies `CBNZ`
- `memory_roundtrip`
  - verifies `STR` + `LDR`

## Near-term Extensions

- add `TBZ` / `TBNZ`
- add more load/store addressing forms
- add wider ALU coverage
- add corpus-driven random programs within the supported subset
- later connect translator model to real rewrite modules
