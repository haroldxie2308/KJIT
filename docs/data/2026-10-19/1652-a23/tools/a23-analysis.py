#!/usr/bin/env python3
"""A23 measurement analysis: win rule and block rates.

  a23-analysis.py RUNS.csv > analysis.md

RUNS.csv: one row per measured run (a23-summarize.py --csv). A triple = the off, main and a23 runs of one boot, cell and rep.
Server CPU per request in us (`cpu_us_per_req`). Bootstrap: resample boots with replacement, then the triples inside each
drawn boot with replacement, 5000 draws, 95% percentile interval of the median (a fresh seed-1 stream per statistic).
WIN (14 Oct 18:42 rule) = CI upper < 0 and >= 75% of boots negative; LOSS = CI lower > 0; else tie.
Sections: (1) a23 - off, a23 - main, main - off per KPTI setting, cell and pooled, win verdict for the first two; (2) block rate
(voluntary context switches per 1000 requests) per state. Standard library only.
"""
import csv
import random
import statistics
import sys

DRAWS = 5000


def quart(vals):
    vals = sorted(vals)
    q = statistics.quantiles(vals, n=4, method="inclusive")
    return q[1], q[0], q[2]


def load(path):
    rows = [r for r in csv.DictReader(open(path))]
    idx = {}
    for r in rows:
        idx[(int(r["kpti"]), int(r["boot"]), r["cell"], int(r["rep"]), r["state"])] = r
    trip = []
    for (k, b, c, rep, st), r in idx.items():
        if st != "a23":
            continue
        o, a = idx.get((k, b, c, rep, "off")), idx.get((k, b, c, rep, "main"))
        if o and a:
            trip.append({"kpti": k, "boot": b, "cell": c, "rep": rep, "test": r["test"], "srv": r["srv"],
                         "off": float(o["cpu_us_per_req"]), "main": float(a["cpu_us_per_req"]), "a23": float(r["cpu_us_per_req"])})
    return rows, trip


def ci(by_boot, rng, scale=1.0):
    boots = list(by_boot)
    meds = []
    for _ in range(DRAWS):
        s = []
        for b in (rng.choice(boots) for _ in boots):
            v = by_boot[b]
            s.extend(rng.choice(v) for _ in v)
        meds.append(statistics.median(s))
    meds.sort()
    return meds[int(0.025 * DRAWS)] * scale, meds[int(0.975 * DRAWS) - 1] * scale


def diff(trip, a, b):
    by = {}
    for t in trip:
        by.setdefault((t["kpti"], t["boot"]), []).append(t[a] - t[b])
    return by


def stat(trip, a, b, rng=None):
    rng = random.Random(1)   # one fresh seed-1 stream per statistic: the numbers do not depend on the order of the calls
    by = diff(trip, a, b)
    allv = [d for v in by.values() for d in v]
    m, q1, q3 = quart(allv)
    lo, hi = ci(by, rng)
    nb = sum(1 for v in by.values() if statistics.median(v) < 0)
    nt = sum(1 for d in allv if d < 0)
    return dict(n=len(allv), m=m, q1=q1, q3=q3, lo=lo, hi=hi, nb=nb, B=len(by), nt=nt, by=by, allv=allv)


def fmt(s):
    return f"{s['m']:+.3f} [{s['q1']:+.3f}..{s['q3']:+.3f}] | [{s['lo']:+.3f}..{s['hi']:+.3f}] | {s['nb']}/{s['B']} | {s['nt']}/{s['n']}"


def verdict(s):
    if s["hi"] < 0 and s["nb"] / s["B"] >= 0.75:
        return "WIN"
    if s["lo"] > 0:
        return "LOSS"
    return "tie"


def sections(name, trip, rng, out):
    out.append(f"## {name}")
    out.append("")
    out.append("Paired differences in us of server CPU per request (median [Q1..Q3] | 95% boot-cluster-bootstrap CI of the median | boots negative | triples negative).")
    out.append("")
    for kpti in (0, 1):
        sub = [t for t in trip if t["kpti"] == kpti]
        if not sub:
            continue
        cells = []
        for t in sub:
            if t["cell"] not in cells:
                cells.append(t["cell"])
        out.append(f"### KPTI {'forced on' if kpti else 'off'}")
        out.append("")
        out.append("| cell | difference | triples | median [Q1..Q3] | 95% CI | boots neg | triples neg | verdict |")
        out.append("|---|---|---|---|---|---|---|---|")
        for scope, picked in [(c, [t for t in sub if t["cell"] == c]) for c in cells] + [("pooled", sub)]:
            for a, b in (("a23", "off"), ("a23", "main"), ("main", "off")):
                s = stat(picked, a, b, rng)
                v = verdict(s) if (a, b) in (("a23", "off"), ("a23", "main")) else ""
                out.append(f"| {scope} | {a} - {b} | {s['n']} | {fmt(s).replace(' | ', ' | ', 1)} | {v} |")
        out.append("")


def block_rates(rows, out):
    out.append("## Block rate: voluntary context switches per 1000 requests (server tasks), median [Q1..Q3] over runs")
    out.append("")
    out.append("| KPTI | cell | off | main | a23 |")
    out.append("|---|---|---|---|---|")
    for kpti in (0, 1):
        sub = [r for r in rows if int(r["kpti"]) == kpti]
        cells = []
        for r in sub:
            if r["cell"] not in cells:
                cells.append(r["cell"])
        for c in cells:
            cols = []
            for st in ("off", "main", "a23"):
                v = [int(r["nvol"]) / int(r["requests"]) * 1000 for r in sub if r["cell"] == c and r["state"] == st]
                m, q1, q3 = quart(v)
                cols.append(f"{m:.2f} [{q1:.2f}..{q3:.2f}] (n={len(v)})")
            out.append(f"| {kpti} | {c} | " + " | ".join(cols) + " |")
    out.append("")


def main():
    rows, trip = load(sys.argv[1])
    rng = random.Random(1)
    out = [f"A23 measurement analysis of {sys.argv[1]}; bootstrap {DRAWS} draws, seed 1.", ""]
    sections("All boots", trip, rng, out)
    block_rates(rows, out)
    print("\n".join(out))


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    main()
