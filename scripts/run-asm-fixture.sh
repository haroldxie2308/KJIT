#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ASM_PATH="${1:-$ROOT_DIR/tests/arm64/toy_cfg.s}"
ENTRY_SYMBOL="${ENTRY_SYMBOL:-toy_translate_entry}"
TEXT_BASE="${TEXT_BASE:-0x4000}"
OUT_DIR="$ROOT_DIR/tmp/asm-fixture"
OBJ_PATH="$OUT_DIR/fixture.o"
BIN_PATH="$OUT_DIR/fixture.text.bin"

mkdir -p "$OUT_DIR"

llvm-mc -triple=aarch64 "$ASM_PATH" -filetype=obj -o "$OBJ_PATH"
llvm-objcopy --only-section=.text -O binary "$OBJ_PATH" "$BIN_PATH"

entry_offset="$(
    llvm-nm --defined-only "$OBJ_PATH" \
        | awk -v sym="$ENTRY_SYMBOL" '$3 == sym { print $1; found = 1 } END { if (!found) exit 1 }'
)"

entry_pc="$(printf '0x%x' "$((TEXT_BASE + 16#$entry_offset))")"

printf 'fixture: %s\n' "$ASM_PATH"
printf 'text_base: %s\n' "$TEXT_BASE"
printf 'entry_symbol: %s\n' "$ENTRY_SYMBOL"
printf 'entry_pc: %s\n' "$entry_pc"

cargo run \
    --manifest-path "$ROOT_DIR/userspace-harness/Cargo.toml" \
    --bin asm-fixture \
    -- "$BIN_PATH" "$TEXT_BASE" "$entry_pc"
