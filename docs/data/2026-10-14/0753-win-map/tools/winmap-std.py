#!/usr/bin/env python3
"""ub-standard.sh cross-check: UB protocol cells, server CPU from utime+stime ticks (10 ms).

  winmap-std.py --runs RUNS_DIR --tag wm [--csv OUT] [--tables OUT]

Reads RUNS_DIR/ub-std-<TAG>-k<0|1>-b<N>/{serial.log,host.txt} ("ubstd run" lines). CPU per request =
(utime_ticks + stime_ticks) * 10000 / requests, us. A pair = the off and on run of one boot, pin, size, test and rep.
"""
import argparse, csv, glob, os, re, statistics, sys
from collections import defaultdict
KV = re.compile(r"(\w+)=(\S+)")

def quart(xs):
    xs = sorted(xs)
    if len(xs) < 2: return xs[0], xs[0], xs[0]
    q = statistics.quantiles(xs, n=4, method="inclusive")
    return q[0], statistics.median(xs), q[2]

ap = argparse.ArgumentParser()
ap.add_argument("--runs", required=True); ap.add_argument("--tag", required=True)
ap.add_argument("--csv"); ap.add_argument("--tables")
a = ap.parse_args()
rows = []
for d in sorted(glob.glob(os.path.join(a.runs, "ub-std-%s-k[01]-b*" % a.tag))):
    m = re.match(r".*/ub-std-%s-k([01])-b(\d+)$" % re.escape(a.tag), d)
    kpti, boot = int(m.group(1)), int(m.group(2))
    host = open(os.path.join(d, "host.txt")).read()
    mm = re.search(r"waited_s=(\d+) load1_before=([\d.]+)", host)
    for line in open(os.path.join(d, "serial.log"), errors="replace"):
        line = line.rstrip("\r\n")
        if line.startswith("ubstd run "):
            kv = dict(KV.findall(line)); n = int(kv["requests"])
            kv.update(kpti=kpti, boot=boot, boot_label="std-k%d-b%d" % (kpti, boot), host_load1_before=mm.group(2), host_waited_s=mm.group(1))
            kv["cpu_ticks_us_per_req"] = (int(kv["utime_ticks"]) + int(kv["stime_ticks"])) * 10000.0 / n
            kv["syscalls_per_req"] = int(kv["hook_calls"]) / n
            kv["in_kernel_per_req"] = int(kv["syscalls_in_kernel"]) / n
            kv["entries_per_req"] = int(kv["fragment_entries"]) / n
            rows.append(kv)
if a.csv:
    cols = ["boot_label", "boot", "kpti", "pin", "size", "rep", "state", "test", "requests", "rps", "wall_cs", "utime_ticks", "stime_ticks",
            "cpu_ticks_us_per_req", "hook_calls", "syscalls_in_kernel", "fragment_entries", "exit_unsupported", "translate_ok", "host_load1_before", "host_waited_s"]
    with open(a.csv, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["kjit" if c == "state" else "value_bytes" if c == "size" else "req_per_s" if c == "rps" else c for c in cols])
        for r in rows:
            w.writerow([("%.5f" % r[c]) if isinstance(r.get(c), float) else r.get(c, "") for c in cols])
by = defaultdict(dict)
for r in rows:
    by[(r["kpti"], r["pin"], r["size"], r["test"], r["boot"], r["rep"])][r["state"]] = r
cells = defaultdict(lambda: defaultdict(list))
meta = defaultdict(list)
for (kpti, pin, size, test, boot, rep), st in sorted(by.items()):
    if "off" in st and "on" in st:
        cells[(kpti, pin, size, test)][boot].append(st["on"]["cpu_ticks_us_per_req"] - st["off"]["cpu_ticks_us_per_req"])
        meta[(kpti, pin, size, test)].append(st)
out = ["| KPTI | pin | -d | test | pairs | boots+ | off | on | on - off [Q1..Q3] | syscalls/req | entries/req |", "|---|---|---|---|---|---|---|---|---|---|---|"]
for k in sorted(cells):
    g = [x for v in cells[k].values() for x in v]
    q1, m, q3 = quart(g)
    bp = sum(1 for v in cells[k].values() if statistics.median(v) > 0)
    offs = [s["off"]["cpu_ticks_us_per_req"] for s in meta[k]]; ons = [s["on"]["cpu_ticks_us_per_req"] for s in meta[k]]
    out.append("| %s | %s | %s | %s | %d | %d/%d | %.3f | %.3f | %+.3f [%+.3f..%+.3f] | %.3f | %.3f |" % (
        "on" if k[0] else "off", k[1], k[2], k[3], len(g), bp, len(cells[k]), statistics.median(offs), statistics.median(ons), m, q1, q3,
        statistics.median(s["on"]["syscalls_per_req"] for s in meta[k]), statistics.median(s["on"]["entries_per_req"] for s in meta[k])))
text = "\n".join(out)
if a.tables: open(a.tables, "w").write(text + "\n")
else: print(text)
