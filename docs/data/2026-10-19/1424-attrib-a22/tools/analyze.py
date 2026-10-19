"""EXPERIMENT (exp/attrib-a22). Tables of the study from the serial logs.

  python3 analyze.py RUNS_DIR OUTDIR            writes OUTDIR/{runs.csv,boots.csv,tables.md}

Pairs are formed inside one (boot, cell, rep): state S minus the `off` run of the same group (or any other named
state). Medians, quartiles [Q1..Q3], boots whose per-boot median is positive / boots, and the number of pairs.
"""
import sys

import numpy as np
import pandas as pd

from parse import load_runs

pd.set_option("display.width", 250)
KEY = ["label", "cfg", "rep"]
CELLS = {"ug": "unix GET -d 1", "us": "unix SET -d 1", "up": "unix PING_MBULK", "ug3": "unix GET -d 1, 3 threads -c 60", "ugp16": "unix GET -d 1 -P 16", "usp16": "unix SET -d 1 -P 16", "ugp4": "unix GET -d 1 -P 4"}
K_IPI_US = 6.9  # us of server CPU per remote wake-up IPI (wake-cost.pl, micro boots: 6.8-6.9)


def pair(runs, a, b, col, sel=None):
    r = runs if sel is None else runs[sel]
    ra = r[r.state == a].set_index(KEY)[col]
    rb = r[r.state == b].set_index(KEY)[col]
    d = (ra - rb).dropna().rename("d").reset_index()
    return d


def summ(d, digits=3):
    if d.empty:
        return None
    v = d["d"].values
    q1, med, q3 = np.percentile(v, [25, 50, 75])
    pb = d.groupby("label")["d"].median()
    return dict(n=len(v), med=med, q1=q1, q3=q3, pos=int((pb > 0).sum()), boots=len(pb), neg=int((pb < 0).sum()))


def fmt(s, d=3, pos=True):
    if s is None:
        return "-"
    f = f"{{:+.{d}f}}"
    out = f"{f.format(s['med'])} [{f.format(s['q1'])}..{f.format(s['q3'])}]"
    if pos:
        out += f" ({s['pos']}/{s['boots']}, n={s['n']})"
    return out


def med(runs, state, col, cfg, sel=None):
    r = runs if sel is None else runs[sel]
    r = r[(r.state == state) & (r.cfg == cfg)][col].dropna()
    return float(np.median(r)) if len(r) else np.nan


def pair_table(runs, specs, cfgs, col="cpu_us", d=3):
    rows = []
    for name, (a, b) in specs.items():
        row = {"pair": name}
        for cfg in cfgs:
            row[cfg] = fmt(summ(pair(runs[runs.cfg == cfg], a, b, col)), d)
        rows.append(row)
    return pd.DataFrame(rows).set_index("pair")


def md(df):
    cols = list(df.columns)
    lines = ["| " + " | ".join([df.index.name or ""] + cols) + " |", "|" + "---|" * (len(cols) + 1)]
    for i, r in df.iterrows():
        lines.append("| " + " | ".join([str(i)] + [str(r[c]) for c in cols]) + " |")
    return "\n".join(lines)


def main(runs_dir, outdir):
    runs, boots = load_runs(runs_dir)
    import os
    os.makedirs(outdir, exist_ok=True)
    runs.to_csv(f"{outdir}/runs.csv", index=False)
    boots.to_csv(f"{outdir}/boots.csv", index=False)
    out = []
    P = out.append
    for kpti in (0, 1):
        kr = runs[runs.kpti == kpti]
        if kr.empty:
            continue
        P(f"\n## KPTI {'forced on' if kpti else 'off'}\n")
        # headline gap: plain module
        for typ, title in (("H", "plain module (uninstrumented 879cf18)"), ("A", "instrumented module"), ("D", "instrumented module, D boots")):
            r = kr[kr.type == typ]
            if r.empty or "on" not in set(r.state):
                continue
            cfgs = [c for c in CELLS if c in set(r.cfg)]
            P(f"\n### on - off, {title}, us of server CPU per request, median [Q1..Q3] (boots positive / boots, pairs)\n")
            P(md(pair_table(r, {"on - off": ("on", "off")}, cfgs)))
    return runs, boots, out


if __name__ == "__main__":
    runs, boots, out = main(sys.argv[1], sys.argv[2])
    print("\n".join(out))
