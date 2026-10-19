#!/usr/bin/env bash
# Runs a23-summarize.py over the 14 boots in boots/<k?-b?>/serial.log -> ../<HHMM>-a23.csv (one row per measured run), tables.md (run from the data directory)
set -euo pipefail
args=()
for d in boots/k*-b*; do n=$(basename "$d"); k=${n:1:1}; b=${n##*-b}; args+=("K$k:B$b=$d/serial.log"); done
python3 -I tools/a23-summarize.py --csv "$1" --tables tables.md "${args[@]}" > /dev/null
