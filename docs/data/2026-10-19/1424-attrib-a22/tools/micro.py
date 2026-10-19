"""EXPERIMENT (exp/attrib-a22). Hot-loop unit costs from the micro boots (micro-a22.sh).

  python3 micro.py RUNS_DIR OUTDIR     RUNS_DIR/ub-at22-M-*/serial.log (and ub-at22-micro-k0-b0)
Writes OUTDIR/micro.csv (one row per svc_bench / entry_cost / wake line) and OUTDIR/micro.md (slopes).
"""
import glob
import os
import re
import sys

import numpy as np
import pandas as pd


def main(runs_dir, outdir):
    rows = []
    for p in sorted(glob.glob(os.path.join(runs_dir, "ub-at22-M-*/serial.log")) + glob.glob(os.path.join(runs_dir, "ub-at22-micro-*/serial.log"))):
        label = os.path.basename(os.path.dirname(p))[3:]
        kpti = 0
        round_ = {}
        for l in open(p, errors="replace"):
            l = l.strip()
            if l.startswith("mic: cmdline") and "kpti=1" in l:
                kpti = 1
            m = re.match(r"mic (\w+)/(\w+) result .*median_ns_per_iter=([\d.]+) median_ns_per_syscall=([\d.]+)", l)
            if m:
                cfg, mode = m.group(1), m.group(2)
                rows.append(dict(label=label, kpti=kpti, kind="svc_bench", cfg=cfg, mode=mode, ns_per_iter=float(m.group(3)),
                                 ns_per_syscall=float(m.group(4)), round=0))
            m = re.match(r"mic entry_cost (\w+) (\w+) calls=(\d+) result .*median_ns_per_outer=([\d.]+)", l)
            if m:
                rows.append(dict(label=label, kpti=kpti, kind="entry_cost", cfg=m.group(1), mode=f"{m.group(2)}_calls{m.group(3)}",
                                 ns_per_iter=float(m.group(4)), ns_per_syscall=np.nan, round=0))
            m = re.match(r"mic wake wake variant=(\w+) round=(\d+) .*parent_us_per_iter=([\d.]+) ipi_per_iter=([\d.]+)", l)
            if m:
                rows.append(dict(label=label, kpti=kpti, kind="wake", cfg=m.group(1), mode="writer_us", ns_per_iter=float(m.group(3)) * 1000,
                                 ns_per_syscall=float(m.group(4)), round=int(m.group(2))))
            m = re.match(r"mic wake wakechild variant=(\w+) child_us_per_wake=([\d.]+)", l)
            if m:
                rows.append(dict(label=label, kpti=kpti, kind="wake", cfg=m.group(1), mode="sleeper_us", ns_per_iter=float(m.group(2)) * 1000,
                                 ns_per_syscall=np.nan, round=0))
    df = pd.DataFrame(rows)
    os.makedirs(outdir, exist_ok=True)
    df.to_csv(f"{outdir}/micro.csv", index=False)
    out = ["# Micro boots: hot-loop unit costs (ns), median over the 3 rounds\n"]
    sv = df[df.kind == "svc_bench"]
    for lab, g in sv.groupby("label"):
        out.append(f"\n## {lab} (KPTI {'on' if g.kpti.iloc[0] else 'off'})\n")
        tab = {}
        for mode in ("getppid", "raw_zn"):
            m = g[g["mode"] == mode].groupby("cfg").ns_per_iter.median()
            per = 1 if mode == "getppid" else 2
            base = m["on"]
            tab[mode] = {
                "off, ns per syscall": m["off"] / per, "on, ns per syscall": base / per, "off - on": (m["off"] - base) / per,
                "svcn - on (entry/exit saved)": (m["svcn"] - base) / per,
            }
            for name, key, n in (("trampoline round trip into a stub (x_rep_tramp)", "amptr", (32, 128)),
                                 ("whole fragment run: trampoline + prologue + body + epilogue (x_rep_call)", "ampcall", (32, 128)),
                                 ("whole hook body: can_run, lookup, run, stats (x_rep_run)", "amprun", (16, 64))):
                a, b = m[f"{key}{n[0]}"], m[f"{key}{n[1]}"]
                tab[mode][name + ", ns per repetition"] = (b - a) / (n[1] - n[0]) / per
            for name, key, n in (("kjit_can_run", "ampcr", 256), ("kjit_lookup", "amplk", 64), ("SRCU lock+unlock", "ampsr", 64),
                                 ("msr pan pair", "amppan", 64), ("relaxed atomic add", "ampat", 64)):
                tab[mode][name + ", ns per repetition"] = (m[f"{key}{n}"] - base) / n / per
        out.append(pd.DataFrame(tab).round(2).to_markdown())
        ec = g  # entry_cost
    ec = df[df.kind == "entry_cost"]
    if len(ec):
        out.append("\n## entry_cost (ns per outer iteration)\n")
        out.append(ec.pivot_table(index=["label", "mode"], columns="cfg", values="ns_per_iter").round(1).to_markdown())
    wk = df[df.kind == "wake"]
    if len(wk):
        out.append("\n## wake cost (pipe ping-pong, us)\n")
        out.append(wk.pivot_table(index=["label", "cfg"], columns="mode", values="ns_per_iter", aggfunc="median").div(1000).round(2).to_markdown())
    open(f"{outdir}/micro.md", "w").write("\n".join(out))
    print("\n".join(out))


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
