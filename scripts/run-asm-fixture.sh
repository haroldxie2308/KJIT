#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEFAULT_ASM_PATH="$ROOT_DIR/tests/arm64/toy_cfg.s"
ASM_PATH="${1:-${ASM_PATH:-}}"
ENTRY_SYMBOL="${ENTRY_SYMBOL:-toy_translate_entry}"
TEXT_BASE="${TEXT_BASE:-0x4000}"
TRACE_TUI_FLAGS="${TRACE_TUI_FLAGS---check --dump}"
TRACE_TUI_SELECT="${TRACE_TUI_SELECT:-0}"
OUT_DIR="$ROOT_DIR/tmp/asm-fixture"
OBJ_PATH="$OUT_DIR/fixture.o"
BIN_PATH="$OUT_DIR/fixture.text.bin"

mkdir -p "$OUT_DIR"

select_asm_fixture() {
    local fixtures=()
    while IFS= read -r path; do
        fixtures+=("$path")
    done < <(find "$ROOT_DIR/tests/arm64" -type f -name '*.s' | sort)

    if [ "${#fixtures[@]}" -eq 0 ]; then
        echo "no .s fixtures found under $ROOT_DIR/tests/arm64" >&2
        exit 2
    fi

    if [ "${#fixtures[@]}" -eq 1 ]; then
        printf '%s\n' "${fixtures[0]}"
        return
    fi

    if [ ! -t 0 ]; then
        echo "multiple .s fixtures found; set ASM_PATH or pass a fixture path:" >&2
        printf '  %s\n' "${fixtures[@]}" >&2
        exit 2
    fi

    echo "Select an AArch64 .s fixture:"
    local index
    for index in "${!fixtures[@]}"; do
        printf '  %2d) %s\n' "$((index + 1))" "${fixtures[$index]}"
    done

    local choice
    while true; do
        printf 'fixture> '
        read -r choice
        if [[ "$choice" =~ ^[0-9]+$ ]] \
            && [ "$choice" -ge 1 ] \
            && [ "$choice" -le "${#fixtures[@]}" ]; then
            printf '%s\n' "${fixtures[$((choice - 1))]}"
            return
        fi
        echo "enter a number from 1 to ${#fixtures[@]}"
    done
}

if [ -z "$ASM_PATH" ]; then
    if [ "$TRACE_TUI_SELECT" = "1" ]; then
        ASM_PATH="$(select_asm_fixture)"
    else
        ASM_PATH="$DEFAULT_ASM_PATH"
    fi
fi

if [ "${ASM_PATH##*.}" != "s" ]; then
    echo "only .s assembly fixtures are supported: $ASM_PATH" >&2
    exit 2
fi

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
    --bin trace-tui \
    -- $TRACE_TUI_FLAGS "$BIN_PATH" "$TEXT_BASE" "$entry_pc"
