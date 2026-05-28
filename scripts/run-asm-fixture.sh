#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEFAULT_ASM_PATH="$ROOT_DIR/tests/arm64/toy_cfg.s"
ASM_PATH="${1:-${ASM_PATH:-$DEFAULT_ASM_PATH}}"
OUT_DIR="$ROOT_DIR/tmp/asm-fixture"

eval "$(bash "$ROOT_DIR/scripts/compile-asm-fixture.sh" "$ASM_PATH" "$OUT_DIR")"

printf 'fixture: %s\n' "$COMPILED_ASM_PATH"
printf 'text_base: %s\n' "$COMPILED_TEXT_BASE"
printf 'entry_symbol: %s\n' "$COMPILED_ENTRY_SYMBOL"
printf 'entry_pc: %s\n' "$COMPILED_ENTRY_PC"

cargo run \
    --manifest-path "$ROOT_DIR/harness/Cargo.toml" \
    --bin trace-tui \
    -- --check --dump "$COMPILED_BIN_PATH" "$COMPILED_TEXT_BASE" "$COMPILED_ENTRY_PC"
