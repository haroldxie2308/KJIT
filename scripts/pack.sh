#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEFAULT_OUT_DIR="$ROOT_DIR/tmp/pack"
STAMP="$(date +%Y%m%d-%H%M%S)"
OUT_PATH="${1:-${OUT:-$DEFAULT_OUT_DIR/kjit-tracked-$STAMP.tar.gz}}"

mkdir -p "$(dirname "$OUT_PATH")"

tracked_files=()
while IFS=$'\t' read -r meta path; do
    mode="${meta%% *}"
    if [ "$mode" = "160000" ]; then
        continue
    fi
    tracked_files+=("$path")
done < <(git -C "$ROOT_DIR" ls-files --stage)

tar -C "$ROOT_DIR" -czf "$OUT_PATH" "${tracked_files[@]}"

printf '%s\n' "$OUT_PATH"
