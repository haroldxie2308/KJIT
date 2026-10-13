#!/usr/bin/env python3
"""Two modules and KJIT off on the same redis cells (guest side tests/guest/cond-sweep.sh of branch exp/conditions).

  cond-modules.py [--csv FILE] MODULE:BOOT=SERIAL_LOG...

One log per boot. MODULE is any label (the first one seen is the baseline, the second the module under
test: main, a18), BOOT the boot number; a boot is the "cond run" lines of cond-sweep.sh in the log, KJIT
off and on paired in the boot (rep i: off,on or on,off). Server CPU per request = sum of
se.sum_exec_runtime of the server's tasks (sched_ms) / requests, in us. Prints, per cell (markdown):
  - the medians of KJIT off (every boot), the baseline's and the tested module's KJIT-on runs;
  - the paired differences tested-on - baseline-on (same boot number, same rep), tested-on - off and
    baseline-on - off (same boot, same rep) as median [Q1..Q3] over all pairs (us per request), and
    "x/y" = boots with a positive per-boot median;
  - per request, for the on-runs of each module: hook calls, syscalls in the kernel, fragment entries,
    Unsupported exits, FP/SIMD entries (medians), and the stopping words ("cond unsup" lines).
--csv writes one row per measured run.
Standard library only.
"""
import csv
import re
import statistics
import sys

COUNTERS = ("hook_calls syscalls_in_kernel fragment_entries exit_svc exit_bl exit_blr exit_br exit_ret "
            "exit_mem exit_unsupported exit_budget run_declined svc_declined fpsimd_entries translate_ok "
            "invalidated_fragments").split()


def kv(line):
    return dict(re.findall(r"(\w+)=(\S+)", line))


def load(args):
    rows, unsup = [], {}
    for a in args:
        head, path = a.split("=", 1)
        module, boot = head.split(":")
        for line in open(path, errors="replace"):
            if "cond run " in line and "state=" in line:
                d = kv(line.split("cond run ", 1)[1])
                n = int(d["n"])
                r = {"module": module, "boot": int(boot), "cell": d["cell"], "srv": d["srv"], "test": d["test"],
                     "requests": n, "clients": int(d["c"]), "pipeline": int(d["p"]), "value_bytes": int(d["d"]),
                     "threads": int(d["thr"]), "rep": int(d["rep"]), "order": d["order"], "kjit": d["state"],
                     "req_per_s": float(d["rps"]), "wall_cs": int(d["wall_cs"]), "ticks_u": int(d["ticks_u"]),
                     "ticks_s": int(d["ticks_s"]), "sched_ms": float(d["sched_ms"]), "nvol": int(d["nvol"]),
                     "ninv": int(d["ninv"]), "c0_busy": int(d["c0_busy"]), "c0_idle": int(d["c0_idle"]),
                     "ipi_c0": int(d["ipi_c0"]), "ipi_other": int(d["ipi_other"])}
                r["cpu_us_per_req"] = round(r["sched_ms"] * 1000 / n, 4)
                for c in COUNTERS:
                    r[c] = int(d[c])
                rows.append(r)
            elif "cond unsup cell=" in line:
                m = re.search(r"cond unsup cell=(\S+) (.*)", line)
                unsup.setdefault((module, m.group(1)), []).append((int(boot), m.group(2).strip()))
    return rows, unsup


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
    rows, unsup = load(args)
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
    cells = []
    for r in rows:
        if r["cell"] not in cells:
            cells.append(r["cell"])
    boots = {m: sorted({r["boot"] for r in rows if r["module"] == m}) for m in modules}
    print(f"{' '.join(f'{m} {len(boots[m])} boots' for m in modules)}")
    print()
    print("Server CPU per request, us (sum of se.sum_exec_runtime of the server's tasks / requests), median [Q1..Q3] over all runs")
    print(f"| cell | KJIT off | {base} on | {test_m} on |")
    print("|---|---|---|---|")
    for cell in cells:
        def vals(module, kjit):
            return [r["cpu_us_per_req"] for r in rows if (r["cell"], r["kjit"]) == (cell, kjit)
                    and (module is None or r["module"] == module)]
        print(f"| {cell} | {med_q(vals(None, 'off'), '.3f')} | {med_q(vals(base, 'on'), '.3f')} | "
              f"{med_q(vals(test_m, 'on'), '.3f')} |")
    print()
    print("Paired differences, us per request (negative = the first term costs less), median [Q1..Q3] over all pairs "
          "(boots with a positive per-boot median / boots)")
    print(f"| cell | {test_m} on - {base} on | {test_m} on - off | {base} on - off | {test_m} on / off |")
    print("|---|---|---|---|---|")
    for cell in cells:
        vs_base, vs_off, base_off, ratio = [], [], [], []
        for (m, b, c, rep, state), r in idx.items():
            if c != cell or state != "on":
                continue
            off = idx.get((m, b, c, rep, "off"))
            if m == test_m:
                if off:
                    vs_off.append((b, r["cpu_us_per_req"] - off["cpu_us_per_req"]))
                    ratio.append((b, r["cpu_us_per_req"] / off["cpu_us_per_req"]))
                other = idx.get((base, b, c, rep, "on"))
                if other:
                    vs_base.append((b, r["cpu_us_per_req"] - other["cpu_us_per_req"]))
            elif m == base and off:
                base_off.append((b, r["cpu_us_per_req"] - off["cpu_us_per_req"]))
        rt = med_q([x for _, x in ratio], ".3f") if ratio else "-"
        print(f"| {cell} | {pairs_text(vs_base)} | {pairs_text(vs_off)} | {pairs_text(base_off)} | {rt} |")
    print()
    print("Per request, KJIT-on runs, median over runs")
    print("| cell | module | hook calls | in-kernel syscalls | fragment entries | FP/SIMD entries | Unsupported exits | Mem exits | run_declined |")
    print("|---|---|---|---|---|---|---|---|---|")
    for cell in cells:
        for m in modules:
            on = [r for r in rows if (r["module"], r["cell"], r["kjit"]) == (m, cell, "on")]
            if not on:
                continue

            def per(c):
                return statistics.median(r[c] / r["requests"] for r in on)
            print(f"| {cell} | {m} | {per('hook_calls'):.3f} | {per('syscalls_in_kernel'):.3f} | "
                  f"{per('fragment_entries'):.3f} | {per('fpsimd_entries'):.3f} | {per('exit_unsupported'):.4f} | "
                  f"{per('exit_mem'):.4f} | {per('run_declined'):.4f} |")
    print()
    print("Stopping words of the cell (warm-ups included), word(exits/entry_stops), first boot of each module")
    for cell in cells:
        for m in modules:
            got = sorted(unsup.get((m, cell), []))
            if got:
                print(f"- {cell} {m}: {got[0][1]}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    main()
