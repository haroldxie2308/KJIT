#!/usr/bin/env bash
# Runs a22-summarize.py over the 16 boots in boots/<k?-b?>/serial.log -> runs-raw.csv, tables.md, then runs.csv (= ../<HHMM>-a22-measure.csv; run from the data directory)
set -euo pipefail
args=()
for d in boots/k*-b*; do n=$(basename "$d"); k=${n:1:1}; b=${n##*-b}; args+=("K$k:B$b=$d/serial.log"); done
python3 -I tools/a22-summarize.py --csv runs-raw.csv --tables tables.md "${args[@]}" > /dev/null
python3 -I tools/add-sweep.py runs-raw.csv runs.csv && rm runs-raw.csv
