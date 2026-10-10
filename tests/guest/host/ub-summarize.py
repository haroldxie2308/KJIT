#!/usr/bin/env python3
"""Summaries of the userspace-bypass comparison runs (ub-bench.sh, a11-baseline.sh).

  ub-summarize.py sys  SERIAL_LOG...    table: per mode/size, ns per syscall off vs on
  ub-summarize.py code SERIAL_LOG...    per variant: least-squares slope/intercept off vs on
  ub-summarize.py redis LABEL=SERIAL_LOG...   per label: mean req/s and counters per point/test

Standard library only. Reads the "ub off|on ..." lines of ub-bench.sh and the
"a11 point=..." lines of a11-baseline.sh from the guest's serial log. With several
logs of one label the per-config values are medians over the logs.
"""
import re
import statistics
import sys


def kv(line):
    return {k: v for k, v in re.findall(r"(\w+)=(\S+)", line)}


def load_ub(paths):
    """Rows of the "ub off|on ..." lines. Besides the key=value pairs each row has
    state (off|on), kind (result|counters|kjit|rep), log (path) and line (1-based
    line number); a "rep N" line (one timed repeat) also has rep (N)."""
    rows = []
    for p in paths:
        for lineno, line in enumerate(open(p, errors="replace"), 1):
            m = re.search(r"\bub (off|on) (result|counters|kjit|rep (\d+)) (.*)", line)
            if m:
                d = kv(m.group(4))
                d["state"], d["kind"] = m.group(1), m.group(2).split()[0]
                if m.group(3) is not None:
                    d["rep"] = m.group(3)
                d["log"], d["line"] = p, lineno
                rows.append(d)
    return rows


def sys_table(paths):
    rows = load_ub(paths)
    res = {}
    kj = {}
    for r in rows:
        if r["kind"] == "result":
            res.setdefault((r["mode"], int(r["size"])), {"off": [], "on": []})[r["state"]].append(
                float(r["median_ns_per_syscall"]))
        elif r["kind"] == "kjit":
            kj.setdefault((r["mode"], int(r["size"])), []).append(
                (float(r["in_kernel_frac"]), float(r["runtime_entries_per_syscall"])))
    print("mode size | off ns/syscall | on ns/syscall | speedup (off/on) | in-kernel frac | runtime entries/syscall | n")
    for key in sorted(res):
        off, on = res[key]["off"], res[key]["on"]
        fo, fn = statistics.median(off), statistics.median(on)
        k = kj.get(key, [])
        frac = statistics.median(x[0] for x in k) if k else float("nan")
        ent = statistics.median(x[1] for x in k) if k else float("nan")
        print(f"{key[0]:9s} {key[1]:3d} | {fo:8.1f} | {fn:8.1f} | {fo / fn:5.3f} | {frac:.3f} | {ent:.3f} | {len(off)}/{len(on)}")


def fit(xs, ys):
    n = len(xs)
    mx, my = sum(xs) / n, sum(ys) / n
    sxx = sum((x - mx) ** 2 for x in xs)
    b = sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / sxx
    a = my - b * mx
    ss_tot = sum((y - my) ** 2 for y in ys)
    ss_res = sum((y - (a + b * x)) ** 2 for x, y in zip(xs, ys))
    return a, b, 1 - ss_res / ss_tot if ss_tot else 1.0


def code_table(paths):
    rows = [r for r in load_ub(paths) if r["kind"] == "result"]
    data = {}
    for r in rows:
        ipo = float(r["insn_per_outer"])
        data.setdefault(r["variant"], {}).setdefault(r["state"], {}).setdefault(int(r["n"]), []).append(
            (float(r["median_ns_per_outer"]), ipo))
    print("variant | n: off ns / on ns / on-off ratio | off slope ns/n (R2) | on slope | slope ratio | off icpt | on icpt | ns per insn off / on")
    for v in sorted(data):
        off = {n: statistics.median(x[0] for x in l) for n, l in data[v]["off"].items()}
        on = {n: statistics.median(x[0] for x in l) for n, l in data[v]["on"].items()}
        ins = {n: statistics.median(x[1] for x in l) for n, l in data[v]["off"].items()}
        ns = sorted(off)
        ao, bo, ro = fit(ns, [off[n] for n in ns])
        an, bn, rn = fit(ns, [on[n] for n in ns])
        per = " ".join(f"{n}:{off[n]:.0f}/{on[n]:.0f}/{on[n] / off[n]:.2f}" for n in ns)
        insn_per_n = (ins[ns[-1]] - ins[ns[0]]) / (ns[-1] - ns[0])
        print(f"{v:7s} | {per} | {bo:.4f} ({ro:.4f}) | {bn:.4f} ({rn:.4f}) | {bn / bo:.3f} | {ao:.0f} | {an:.0f} | {bo / insn_per_n:.3f} / {bn / insn_per_n:.3f}")


def redis_table(args):
    out = {}
    for a in args:
        label, path = a.split("=", 1)
        for line in open(path, errors="replace"):
            if not line.startswith("a11 point="):
                continue
            d = kv(line)
            out.setdefault((label, d["point"], d["test"]), []).append(d)
    print("label point test | n | req/s mean (min..max) | us/req | in-kernel syscalls/req | runtime entries/req | hook calls/req")
    for key in sorted(out):
        l = out[key]
        rps = [float(d["rps"]) for d in l]
        req = float(l[0]["requests"])
        def per(c):
            return statistics.mean(float(d[c]) for d in l) / req
        print(f"{key[0]:14s} {key[1]:5s} {key[2]:3s} | {len(l)} | {statistics.mean(rps):9.0f} ({min(rps):.0f}..{max(rps):.0f}) | {statistics.mean(1e6 / r for r in rps):6.3f} | {per('syscalls_in_kernel'):.3f} | {per('fragment_entries'):.3f} | {per('hook_calls'):.3f}")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    {"sys": sys_table, "code": code_table, "redis": redis_table}[sys.argv[1]](sys.argv[2:])
