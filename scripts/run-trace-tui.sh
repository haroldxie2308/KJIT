#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ASM_PATH="${1:-${ASM_PATH:-}}"
OUT_DIR="$ROOT_DIR/tmp/trace-tui"
if [ -z "${KJIT_OPENTUI_LIB_PATH:-}" ]; then
    for candidate in \
        "$ROOT_DIR/../opentui/packages/core/node_modules/@opentui/core-darwin-arm64/libopentui.dylib" \
        "$ROOT_DIR/../opentui/node_modules/@opentui/core-darwin-arm64/libopentui.dylib"
    do
        if [ -f "$candidate" ]; then
            export KJIT_OPENTUI_LIB_PATH="$candidate"
            break
        fi
    done
fi

select_asm_fixture() {
    local fixtures=()
    while IFS= read -r path; do
        fixtures+=("$path")
    done < <(find "$ROOT_DIR/tests/arm64" -type f -name '*.s' | sort)

    if [ "${#fixtures[@]}" -eq 0 ]; then
        echo "no .s fixtures found under $ROOT_DIR/tests/arm64" >&2
        exit 2
    fi

    if [ ! -t 0 ]; then
        echo "set ASM_PATH or pass a fixture path:" >&2
        printf '  %s\n' "${fixtures[@]}" >&2
        exit 2
    fi

    echo "Select an AArch64 .s fixture:" >&2
    local index
    for index in "${!fixtures[@]}"; do
        printf '  %2d) %s\n' "$((index + 1))" "${fixtures[$index]}" >&2
    done

    local choice
    while true; do
        printf 'fixture> ' >&2
        read -r choice
        if [[ "$choice" =~ ^[0-9]+$ ]] \
            && [ "$choice" -ge 1 ] \
            && [ "$choice" -le "${#fixtures[@]}" ]; then
            printf '%s\n' "${fixtures[$((choice - 1))]}"
            return
        fi
        echo "enter a number from 1 to ${#fixtures[@]}" >&2
    done
}

if [ -z "$ASM_PATH" ]; then
    ASM_PATH="$(select_asm_fixture)"
fi

eval "$(bash "$ROOT_DIR/scripts/compile-asm-fixture.sh" "$ASM_PATH" "$OUT_DIR")"

printf 'fixture: %s\n' "$COMPILED_ASM_PATH"
printf 'text_base: %s\n' "$COMPILED_TEXT_BASE"
printf 'hot_svc_symbol: %s\n' "$COMPILED_HOT_SVC_SYMBOL"
printf 'hot_svc_pc: %s\n' "$COMPILED_HOT_SVC_PC"
printf 'entry_pc: %s\n' "$COMPILED_ENTRY_PC"

cargo run \
    --manifest-path "$ROOT_DIR/harness/Cargo.toml" \
    --bin trace-tui \
    -- --check "$COMPILED_BIN_PATH" "$COMPILED_TEXT_BASE" "$COMPILED_ENTRY_PC"
