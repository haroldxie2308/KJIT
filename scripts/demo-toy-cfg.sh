#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BASE_PC="${BASE_PC:-0x4000}"
ASM_PATH="${1:-$ROOT_DIR/tests/arm64/toy_cfg.s}"
OUT_DIR="$ROOT_DIR/tmp/toy-cfg-demo"
OBJ_PATH="$OUT_DIR/toy_cfg.o"
BIN_PATH="$OUT_DIR/toy_cfg.bin"

mkdir -p "$OUT_DIR"

llvm-mc -triple=aarch64 "$ASM_PATH" -filetype=obj -o "$OBJ_PATH"
llvm-objcopy -O binary "$OBJ_PATH" "$BIN_PATH"

printf 'fixture: %s\n' "$ASM_PATH"
printf 'base_pc: %s\n' "$BASE_PC"

cargo run --manifest-path "$ROOT_DIR/harness/Cargo.toml" --bin dump-cfg -- "$BIN_PATH" "$BASE_PC"
