#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ASM_PATH="${1:-${ASM_PATH:-}}"
OUT_DIR="$ROOT_DIR/tmp/trace-tui"

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
    ASM_PATH="$(select_asm_fixture)"
fi

eval "$(bash "$ROOT_DIR/scripts/compile-asm-fixture.sh" "$ASM_PATH" "$OUT_DIR")"

printf 'fixture: %s\n' "$COMPILED_ASM_PATH"
printf 'text_base: %s\n' "$COMPILED_TEXT_BASE"
printf 'entry_symbol: %s\n' "$COMPILED_ENTRY_SYMBOL"
printf 'entry_pc: %s\n' "$COMPILED_ENTRY_PC"

cargo run \
    --manifest-path "$ROOT_DIR/harness/Cargo.toml" \
    --bin trace-tui \
    -- "$COMPILED_BIN_PATH" "$COMPILED_TEXT_BASE" "$COMPILED_ENTRY_PC"
