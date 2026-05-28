#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 2 ]; then
    echo "usage: compile-asm-fixture.sh <fixture.s> <out-dir>" >&2
    exit 2
fi

ASM_PATH="$1"
OUT_DIR="$2"
HOT_SVC_SYMBOL="${HOT_SVC_SYMBOL:-hot_svc_mark}"
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

if ! hot_svc_offset="$(
    llvm-nm --defined-only "$OBJ_PATH" \
        | awk -v sym="$HOT_SVC_SYMBOL" '$3 == sym { print $1; found = 1 } END { if (!found) exit 1 }'
)"; then
    echo "failed to find hot SVC symbol '$HOT_SVC_SYMBOL' in $ASM_PATH" >&2
    exit 2
fi

hot_svc_pc="$(printf '0x%x' "$((TEXT_BASE + 16#$hot_svc_offset))")"
entry_pc="$(printf '0x%x' "$((TEXT_BASE + 16#$hot_svc_offset + 4))")"

printf 'COMPILED_ASM_PATH=%q\n' "$ASM_PATH"
printf 'COMPILED_OBJ_PATH=%q\n' "$OBJ_PATH"
printf 'COMPILED_BIN_PATH=%q\n' "$BIN_PATH"
printf 'COMPILED_TEXT_BASE=%q\n' "$TEXT_BASE"
printf 'COMPILED_HOT_SVC_SYMBOL=%q\n' "$HOT_SVC_SYMBOL"
printf 'COMPILED_HOT_SVC_PC=%q\n' "$hot_svc_pc"
printf 'COMPILED_ENTRY_PC=%q\n' "$entry_pc"
