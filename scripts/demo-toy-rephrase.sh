#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ASM_PATH="${1:-$ROOT_DIR/tests/arm64/toy_cfg.s}"
TEXT_BASE="${TEXT_BASE:-0x4000}"
OUT_DIR="$ROOT_DIR/tmp/toy-rephrase-demo"

mkdir -p "$OUT_DIR"

eval "$(TEXT_BASE="$TEXT_BASE" bash "$ROOT_DIR/scripts/compile-asm-fixture.sh" "$ASM_PATH" "$OUT_DIR")"

printf 'fixture: %s\n' "$COMPILED_ASM_PATH"
printf 'text_base: %s\n' "$COMPILED_TEXT_BASE"
printf 'hot_svc_symbol: %s\n' "$COMPILED_HOT_SVC_SYMBOL"
printf 'hot_svc_pc: %s\n' "$COMPILED_HOT_SVC_PC"
printf 'entry_pc: %s\n' "$COMPILED_ENTRY_PC"

cargo run \
    --manifest-path "$ROOT_DIR/harness/Cargo.toml" \
    --bin dump-rephrase \
    -- "$COMPILED_BIN_PATH" "$COMPILED_TEXT_BASE" "$COMPILED_ENTRY_PC"
