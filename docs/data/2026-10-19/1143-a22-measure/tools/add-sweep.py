#!/usr/bin/env python3
"""add-sweep.py IN.csv OUT.csv: prepend the `sweep` column (extra = KPTI-on boots 7-12, main = the rest)."""
import csv
import sys

rows = list(csv.DictReader(open(sys.argv[1])))
with open(sys.argv[2], "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=["sweep"] + list(rows[0]))
    w.writeheader()
    for r in rows:
        w.writerow({"sweep": "extra" if int(r["kpti"]) == 1 and int(r["boot"]) >= 7 else "main", **r})
