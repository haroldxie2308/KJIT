#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 2 ]; then
    echo "usage: compile-asm-fixture.sh <fixture.s> <out-dir>" >&2
    exit 2
fi

ASM_PATH="$1"
OUT_DIR="$2"
ENTRY_SYMBOL="${ENTRY_SYMBOL:-toy_translate_entry}"
TEXT_BASE="${TEXT_BASE:-0x4000}"
OBJ_PATH="$OUT_DIR/fixture.o"
BIN_PATH="$OUT_DIR/fixture.text.bin"

if [ "${ASM_PATH##*.}" != "s" ]; then
    echo "only .s assembly fixtures are supported: $ASM_PATH" >&2
    exit 2
fi

mkdir -p "$OUT_DIR"

llvm-mc -triple=aarch64 "$ASM_PATH" -filetype=obj -o "$OBJ_PATH"
llvm-objcopy --only-section=.text -O binary "$OBJ_PATH" "$BIN_PATH"

entry_offset="$(
    llvm-nm --defined-only "$OBJ_PATH" \
        | awk -v sym="$ENTRY_SYMBOL" '$3 == sym { print $1; found = 1 } END { if (!found) exit 1 }'
)"

entry_pc="$(printf '0x%x' "$((TEXT_BASE + 16#$entry_offset))")"

printf 'COMPILED_ASM_PATH=%q\n' "$ASM_PATH"
printf 'COMPILED_OBJ_PATH=%q\n' "$OBJ_PATH"
printf 'COMPILED_BIN_PATH=%q\n' "$BIN_PATH"
printf 'COMPILED_TEXT_BASE=%q\n' "$TEXT_BASE"
printf 'COMPILED_ENTRY_SYMBOL=%q\n' "$ENTRY_SYMBOL"
printf 'COMPILED_ENTRY_PC=%q\n' "$entry_pc"
