#!/usr/bin/env python3
"""A17 (16:45 sweep CSV, docs/data/2026-10-13/1645-conditions.csv) against this win map, same cells,
on - off server CPU per request (sched), median [Q1..Q3] over pairs and boots+.
  compare-a17.py A17.csv WINMAP.csv
"""
import csv, statistics, sys
from collections import defaultdict

def quart(xs):
    xs = sorted(xs)
    if len(xs) < 2: return xs[0], xs[0], xs[0]
    q = statistics.quantiles(xs, n=4, method="inclusive")
    return q[0], statistics.median(xs), q[2]

def pairs(rows, setting_f, label_f, cell_f, state_f, cpu_f, rep_f):
    by = defaultdict(dict)
    for r in rows:
        by[(setting_f(r), cell_f(r), label_f(r), rep_f(r))][state_f(r)] = cpu_f(r)
    out = defaultdict(lambda: defaultdict(list))
    for (s, c, lab, rep), st in by.items():
        if "off" in st and "on" in st:
            out[(s, c)][lab].append(st["on"] - st["off"])
    return out

a17 = list(csv.DictReader(open(sys.argv[1])))
a17 = [r for r in a17 if r["setting"] in ("k0", "k1")]
p17 = pairs(a17, lambda r: r["setting"], lambda r: r["label"], lambda r: r["cell"], lambda r: r["state"], lambda r: float(r["us_per_req"]), lambda r: r["rep"])
wm = list(csv.DictReader(open(sys.argv[2])))
pwm = pairs(wm, lambda r: "k1" if r["kpti"] == "1" else "k0", lambda r: r["boot_label"], lambda r: r["cell"], lambda r: r["kjit"], lambda r: float(r["cpu_us_per_req"]), lambda r: r["rep"])
def fmt(d):
    if not d: return ""
    allg = [g for v in d.values() for g in v]
    q1, m, q3 = quart(allg)
    bp = sum(1 for v in d.values() if statistics.median(v) > 0)
    return "%+.3f [%+.3f..%+.3f] (%d/%d)" % (m, q1, q3, bp, len(d)), m
cells = []
for r in wm:
    if r["cell"] not in cells: cells.append(r["cell"])
print("| cell | A17 KPTI off (k0) | main KPTI off | change | A17 KPTI on (k1) | main KPTI on | change |")
print("|---|---|---|---|---|---|---|")
for c in cells:
    row = [c]
    for s in ("k0", "k1"):
        a, w = p17.get((s, c)), pwm.get((s, c))
        fa, fw = fmt(a), fmt(w)
        row.append(fa[0] if fa else "")
        row.append(fw[0] if fw else "")
        row.append("%+.3f" % (fw[1] - fa[1]) if fa and fw else "")
    print("| " + " | ".join(row) + " |")
