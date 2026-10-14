#!/usr/bin/env python3
"""Pooled and per-cell paired differences of 1356-a20-paths.csv with a 95% cluster bootstrap CI of the median
(resample boots, then triples within a boot; 5000 draws, seed 1). Usage: a20-bootstrap.py RUNS.csv"""
import collections
import csv
import random
import statistics
import sys

rows = list(csv.DictReader(open(sys.argv[1])))
idx = {(r["kpti"], r["boot"], r["cell"], r["rep"], r["state"]): float(r["cpu_us_per_req"]) for r in rows}
trip = collections.defaultdict(list)
for (k, b, c, rep, s), v in idx.items():
    if s == "a20":
        o, m = idx.get((k, b, c, rep, "off")), idx.get((k, b, c, rep, "main"))
        if o is not None and m is not None:
            trip[(k, c)].append((b, v - m, v - o, m - o))
random.seed(1)


def ci(items):
    byb = collections.defaultdict(list)
    for b, d in items:
        byb[b].append(d)
    bs = list(byb)
    meds = []
    for _ in range(5000):
        s = []
        for b in random.choices(bs, k=len(bs)):
            s += random.choices(byb[b], k=len(byb[b]))
        meds.append(statistics.median(s))
    meds.sort()
    return meds[125], meds[4875]


for k in ("1", "0"):
    print(f"## KPTI {'forced on' if k == '1' else 'off'}")
    for name, i in (("a20 - main", 1), ("a20 - off", 2), ("main - off", 3)):
        items = [(t[0], t[i]) for (kk, c), ts in trip.items() if kk == k for t in ts]
        lo, hi = ci(items)
        print(f"- pooled over cells, {name}: median {statistics.median(d for _, d in items):+.3f} us, "
              f"95% CI [{lo:+.3f}..{hi:+.3f}], {len(items)} triples")
    for (kk, c), ts in trip.items():
        if kk != k:
            continue
        for name, i in (("a20 - main", 1), ("a20 - off", 2)):
            items = [(t[0], t[i]) for t in ts]
            lo, hi = ci(items)
            print(f"- {c}, {name}: median {statistics.median(d for _, d in items):+.3f} us, 95% CI [{lo:+.3f}..{hi:+.3f}]")
    print()
