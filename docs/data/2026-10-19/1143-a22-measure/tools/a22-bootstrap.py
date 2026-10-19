#!/usr/bin/env python3
"""A22 measurement: cluster bootstrap of the paired differences a22 - a21, a22 - off, a21 - off.

  a22-bootstrap.py RUNS.csv [DRAWS] > bootstrap.md

RUNS.csv: one row per measured run (a22-summarize.py --csv). A triple = the off, a21 and a22 runs of one boot, cell
and rep (us of server CPU per request, `cpu_us_per_req`). Per KPTI setting and per cell, and pooled over the cells of a
setting: the median triple difference [Q1..Q3], the 95% cluster-bootstrap interval of that median (resample boots with
replacement, then the triples inside each drawn boot with replacement; DRAWS draws, default 5000, seed 1), the boots
whose own median difference is negative, and the triples with a negative difference. Standard library only.
"""
import csv
import random
import statistics
import sys

DRAWS = int(sys.argv[2]) if len(sys.argv) > 2 else 5000
PAIRS = (("a22", "a21"), ("a22", "off"), ("a21", "off"))


def quart(vals):
    vals = sorted(vals)
    if len(vals) < 2:
        return vals[0], vals[0], vals[0]
    q = statistics.quantiles(vals, n=4, method="inclusive")
    return q[1], q[0], q[2]


def load(path):
    idx = {}
    for r in csv.DictReader(open(path)):
        idx[(int(r["kpti"]), int(r["boot"]), r["cell"], int(r["rep"]), r["state"])] = float(r["cpu_us_per_req"])
    triples = []
    for (k, b, c, rep, st), v in idx.items():
        if st != "a22":
            continue
        off, a21 = idx.get((k, b, c, rep, "off")), idx.get((k, b, c, rep, "a21"))
        if off is not None and a21 is not None:
            triples.append((k, b, c, rep, {"a22": v, "a21": a21, "off": off}))
    return triples


def interval(by_boot, rng):
    """95% cluster-bootstrap interval of the pooled median; by_boot: {boot: [diff, ...]}."""
    boots = list(by_boot)
    meds = []
    for _ in range(DRAWS):
        sample = []
        for b in (rng.choice(boots) for _ in boots):
            vals = by_boot[b]
            sample.extend(rng.choice(vals) for _ in vals)
        meds.append(statistics.median(sample))
    meds.sort()
    return meds[int(0.025 * DRAWS)], meds[int(0.975 * DRAWS) - 1]


def row(label, triples, a, b, rng):
    by_boot = {}
    for k, boot, c, rep, v in triples:
        by_boot.setdefault((k, boot), []).append(v[a] - v[b])
    allv = [d for vals in by_boot.values() for d in vals]
    if not allv:
        return None
    m, q1, q3 = quart(allv)
    lo, hi = interval(by_boot, rng)
    neg_boots = sum(1 for vals in by_boot.values() if statistics.median(vals) < 0)
    neg = sum(1 for d in allv if d < 0)
    return (f"| {label} | {a} - {b} | {len(allv)} | {m:+.3f} [{q1:+.3f}..{q3:+.3f}] | [{lo:+.3f}..{hi:+.3f}] | "
            f"{neg_boots}/{len(by_boot)} | {neg}/{len(allv)} |")


def main():
    triples = load(sys.argv[1])
    rng = random.Random(1)
    out = [f"Cluster bootstrap, {DRAWS} draws, seed 1; us of server CPU per request. neg boots = boots whose median "
           "difference is negative; neg triples = triples with a negative difference.", ""]
    for kpti in (1, 0):
        sub = [t for t in triples if t[0] == kpti]
        if not sub:
            continue
        out += [f"## KPTI {'forced on' if kpti else 'off'}", "",
                "| scope | difference | triples | median [Q1..Q3] | 95% CI | neg boots | neg triples |",
                "|---|---|---|---|---|---|---|"]
        cells = sorted({t[2] for t in sub})
        for scope, picked in [(c, [t for t in sub if t[2] == c]) for c in cells] + [("pooled", sub)]:
            for a, b in PAIRS:
                text = row(scope, picked, a, b, rng)
                if text:
                    out.append(text)
        out.append("")
    print("\n".join(out))


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    main()
