#!/usr/bin/env python3
"""Low client counts (redis-benchmark -c 1, -c 10) against two modules and KJIT off: server CPU from sum_exec_runtime.

  ub-c1.py [--csv FILE] MODULE:BOOT=SERIAL_LOG...

One log per boot, from a guest run of c1-sweep.sh (branch exp/c1) with STATES='off on': its "cond run" lines.
MODULE is any label (the first one seen is the baseline, the second the module under test: a17, a19), BOOT the
boot number; boots of different modules with the same BOOT are a pair (run back to back). Server CPU per request =
sum over the server's tasks of se.sum_exec_runtime (/proc/PID/task/*/sched) over the run / requests, in us (tick
sampling of utime/stime undercounts at low load). Prints, per cell (markdown):
  - the medians of KJIT off (every boot) and of each module's KJIT-on runs;
  - the paired differences tested-on - baseline-on (same boot number, same rep), tested-on - off and baseline-on - off
    (same boot, same rep: off and on alternate inside a rep), each as median [Q1..Q3] over all pairs (us per request,
    negative = the first term costs less) and "x/y" = boots with a positive per-boot median.
--csv writes one row per measured run (docs/data/README.md conventions: kjit off|on).

Standard library only.
"""
import csv
import os
import re
import statistics
import sys

KEYS = ("cell test n c p d thr rep order state rps wall_cs sched_ms nvol ninv ctxt hook_calls syscalls_in_kernel "
        "fragment_entries exit_svc exit_bl exit_blr exit_br exit_ret exit_mem exit_unsupported exit_budget "
        "run_declined svc_declined translate_ok invalidated_fragments").split()


def kv(line):
    return dict(re.findall(r"(\w+)=(\S+)", line))


def load(args):
    rows = []
    for a in args:
        head, path = a.split("=", 1)
        module, boot = head.split(":")
        host = os.path.join(os.path.dirname(path), "host.txt")
        m = re.search(r"load1_before=(\S+)", open(host).read()) if os.path.exists(host) else None
        for line in open(path, errors="replace"):
            if "cond run " not in line:
                continue
            d = kv(line.split("cond run ", 1)[1])
            r = {"module": module, "boot": int(boot), "load1_before": m.group(1) if m else ""}
            for k in KEYS:
                r[k] = d.get(k, "")
            r["kjit"] = d["state"]
            n = int(d["n"])
            r["cpu_us_per_req"] = round(float(d["sched_ms"]) * 1000 / n, 4)
            rows.append(r)
    return rows


def quart(vals):
    vals = sorted(vals)
    if len(vals) < 2:
        return vals[0], vals[0], vals[0]
    q = statistics.quantiles(vals, n=4, method="inclusive")
    return q[1], q[0], q[2]


def med_q(vals, spec):
    m, lo, hi = quart(vals)
    return f"{m:{spec}} [{lo:{spec}}..{hi:{spec}}]"


def pairs_text(pairs, spec="+.3f"):
    if not pairs:
        return "-"
    by_boot = {}
    for b, d in pairs:
        by_boot.setdefault(b, []).append(d)
    pos = sum(1 for v in by_boot.values() if statistics.median(v) > 0)
    return f"{med_q([d for _, d in pairs], spec)} ({pos}/{len(by_boot)})"


def main():
    args = sys.argv[1:]
    csv_path = None
    if args and args[0] == "--csv":
        csv_path, args = args[1], args[2:]
    rows = load(args)
    if csv_path:
        with open(csv_path, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0]))
            w.writeheader()
            w.writerows(rows)
    modules = []
    for r in rows:
        if r["module"] not in modules:
            modules.append(r["module"])
    base, test_m = modules[0], modules[1]
    idx = {(r["module"], r["boot"], r["cell"], r["rep"], r["kjit"]): r for r in rows}
    cells = sorted({r["cell"] for r in rows})

    print("Server CPU per request, us (sum_exec_runtime), median [Q1..Q3] over all runs of the cell")
    print(f"| cell | KJIT off | {base} on | {test_m} on |")
    print("|---|---|---|---|")
    for cell in cells:
        def vals(module, kjit):
            return [r["cpu_us_per_req"] for r in rows if (r["cell"], r["kjit"]) == (cell, kjit)
                    and (module is None or r["module"] == module)]
        print(f"| {cell} | {med_q(vals(None, 'off'), '.2f')} | {med_q(vals(base, 'on'), '.2f')} | "
              f"{med_q(vals(test_m, 'on'), '.2f')} |")
    print()
    print("Paired differences, us per request (negative = the first term costs less), median [Q1..Q3] over all pairs "
          "(boots with a positive per-boot median / boots)")
    print(f"| cell | {test_m} on - {base} on | {test_m} on - off | {base} on - off |")
    print("|---|---|---|---|")
    for cell in cells:
        vs_base, vs_off, base_off = [], [], []
        for (m, b, c, rep, state), r in idx.items():
            if (c, state) != (cell, "on"):
                continue
            off = idx.get((m, b, c, rep, "off"))
            if m == test_m:
                if off:
                    vs_off.append((b, r["cpu_us_per_req"] - off["cpu_us_per_req"]))
                other = idx.get((base, b, c, rep, "on"))
                if other:
                    vs_base.append((b, r["cpu_us_per_req"] - other["cpu_us_per_req"]))
            elif m == base and off:
                base_off.append((b, r["cpu_us_per_req"] - off["cpu_us_per_req"]))
        print(f"| {cell} | {pairs_text(vs_base)} | {pairs_text(vs_off)} | {pairs_text(base_off)} |")
    print()
    for m in modules:
        on = [r for r in rows if r["module"] == m and r["kjit"] == "on"]
        off = [r for r in rows if r["module"] == m and r["kjit"] == "off"]
        print(f"{m}: {len(on)} on-runs (fragment entries in {sum(1 for r in on if r['fragment_entries'] not in ('', '0'))}), "
              f"{len(off)} off-runs (with fragment entries: {sum(1 for r in off if r['fragment_entries'] not in ('', '0'))})")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    main()
