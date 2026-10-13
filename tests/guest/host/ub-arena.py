#!/usr/bin/env python3
"""Packed image arena (A17) against the module without it and against KJIT off: redis under the UB protocol.

  ub-arena.py [--csv FILE] MODULE:KPTI:BOOT=SERIAL_LOG...

One log per boot. MODULE is any label (the first one seen is the baseline, the second the module
under test: main, a17), KPTI is 0 or 1, BOOT the boot number; a boot is the "ubstd run" lines of
tests/guest/ub-standard.sh in the log. Boots of different modules with the same KPTI and BOOT are a
pair (run back to back). Server CPU per request = (user + system ticks of the server over the run) /
requests. Prints, per KPTI setting, size and test (markdown):
  - the medians of KJIT off (every boot), the baseline's and the tested module's KJIT-on runs;
  - the paired differences tested-on - baseline-on (the same boot number, the same rep) and tested-on -
    off, baseline-on - off (the same boot, the same rep, off and on alternate inside a rep), each
    as median [Q1..Q3] over all pairs (us per request, negative = the first costs less), and
    "x/y" = boots with a positive per-boot median;
  - the arena gauges after the runs (tested module; arena_chunks_pmd, A19, is "-" for a module without it).
--csv writes one row per measured run (docs/data/README.md conventions: kjit off|on, req_per_s).

Standard library only.
"""
import csv
import os
import re
import statistics
import sys

COUNTERS = ("hook_calls syscalls_in_kernel fragment_entries exit_svc exit_bl exit_blr exit_br exit_ret "
            "exit_mem exit_unsupported exit_budget run_declined svc_declined fpsimd_entries translate_ok "
            "invalidated_fragments link_made link_restored link_out_of_range link_class_refused "
            "link_sites_linked link_sites_pending arena_chunks arena_chunks_pmd arena_bytes").split()


def kv(line):
    return dict(re.findall(r"(\w+)=(\S+)", line))


def load(args):
    rows = []
    for a in args:
        head, path = a.split("=", 1)
        module, kpti, boot = head.split(":")
        host = os.path.join(os.path.dirname(path), "host.txt")
        m = re.search(r"load1_before=(\S+)", open(host).read()) if os.path.exists(host) else None
        for line in open(path, errors="replace"):
            if "ubstd run " not in line:
                continue
            d = kv(line.split("ubstd run ", 1)[1])
            r = {"module": module, "kpti": int(kpti), "boot": int(boot), "pin": d["pin"], "size": int(d["size"]),
                 "rep": int(d["rep"]), "test": d["test"], "kjit": d["state"], "requests": int(d["requests"]),
                 "req_per_s": float(d["rps"]), "wall_cs": int(d["wall_cs"]),
                 "utime_ticks": int(d["utime_ticks"]), "stime_ticks": int(d["stime_ticks"]),
                 "clk_tck": int(d["clk_tck"]), "load1_before": m.group(1) if m else ""}
            r["cpu_us_per_req"] = round((r["utime_ticks"] + r["stime_ticks"]) / r["clk_tck"] * 1e6 / r["requests"], 4)
            for c in COUNTERS:
                r[c] = int(d[c]) if c in d else ""
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
    """pairs: list of (boot, diff). Median [Q1..Q3] over all, and boots with a positive per-boot median."""
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
    idx = {(r["module"], r["kpti"], r["boot"], r["size"], r["test"], r["rep"], r["kjit"]): r for r in rows}

    for kpti in sorted({r["kpti"] for r in rows}):
        sel = [r for r in rows if r["kpti"] == kpti]
        sizes = sorted({r["size"] for r in sel})
        boots = {m: sorted({r["boot"] for r in sel if r["module"] == m}) for m in modules}
        print(f"### KPTI {'forced on' if kpti else 'off'}: {' '.join(f'{m} {len(boots[m])} boots' for m in modules)}")
        print()
        print("Server CPU per request, us, median [Q1..Q3] over all runs of the cell")
        print(f"| -d | test | KJIT off | {base} on | {test_m} on |")
        print("|---|---|---|---|---|")
        for size in sizes:
            for test in ("set", "get"):
                def vals(module, kjit):
                    return [r["cpu_us_per_req"] for r in sel if (r["size"], r["test"], r["kjit"]) == (size, test, kjit)
                            and (module is None or r["module"] == module)]
                print(f"| {size} | {test.upper()} | {med_q(vals(None, 'off'), '.2f')} | "
                      f"{med_q(vals(base, 'on'), '.2f')} | {med_q(vals(test_m, 'on'), '.2f')} |")
        print()
        print("Paired differences, us per request (negative = the first term costs less), median [Q1..Q3] over all pairs "
              "(boots with a positive per-boot median / boots)")
        print(f"| -d | test | {test_m} on - {base} on | {test_m} on - off | {base} on - off | {test_m} on / off |")
        print("|---|---|---|---|---|---|")
        for size in sizes:
            for test in ("set", "get"):
                vs_base, vs_off, base_off, ratio = [], [], [], []
                for (m, k, b, s, t, rep, state), r in idx.items():
                    if (k, s, t, state) != (kpti, size, test, "on"):
                        continue
                    off = idx.get((m, k, b, s, t, rep, "off"))
                    if m == test_m:
                        if off:
                            vs_off.append((b, r["cpu_us_per_req"] - off["cpu_us_per_req"]))
                            ratio.append((b, r["cpu_us_per_req"] / off["cpu_us_per_req"]))
                        other = idx.get((base, k, b, s, t, rep, "on"))
                        if other:
                            vs_base.append((b, r["cpu_us_per_req"] - other["cpu_us_per_req"]))
                    elif m == base and off:
                        base_off.append((b, r["cpu_us_per_req"] - off["cpu_us_per_req"]))
                rt = med_q([x for _, x in ratio], ".3f") if ratio else "-"
                print(f"| {size} | {test.upper()} | {pairs_text(vs_base)} | {pairs_text(vs_off)} | "
                      f"{pairs_text(base_off)} | {rt} |")
        print()
        print(f"{test_m} KJIT on, after the runs (gauges), median [min..max] over runs; fragment entries per request")
        print("| -d | test | arena_chunks | arena_chunks_pmd | arena_bytes | fragment entries/req | translate_ok sum | invalidated sum |")
        print("|---|---|---|---|---|---|---|---|")
        for size in sizes:
            for test in ("set", "get"):
                on = [r for r in sel if (r["module"], r["size"], r["test"], r["kjit"]) == (test_m, size, test, "on")]
                if not on or on[0]["arena_bytes"] == "":
                    continue
                ch = [r["arena_chunks"] for r in on]
                by = [r["arena_bytes"] for r in on]
                pm = [r["arena_chunks_pmd"] for r in on if r["arena_chunks_pmd"] != ""]
                pm_text = f"{statistics.median(pm):.0f} [{min(pm)}..{max(pm)}]" if pm else "-"
                print(f"| {size} | {test.upper()} | {statistics.median(ch):.0f} [{min(ch)}..{max(ch)}] | {pm_text} | "
                      f"{statistics.median(by):.0f} [{min(by)}..{max(by)}] | "
                      f"{statistics.median(r['fragment_entries'] / r['requests'] for r in on):.3f} | "
                      f"{sum(r['translate_ok'] for r in on)} | {sum(r['invalidated_fragments'] for r in on)} |")
        print()
        for m in modules:
            on = [r for r in sel if r["module"] == m and r["kjit"] == "on"]
            off = [r for r in sel if r["module"] == m and r["kjit"] == "off"]
            print(f"{m}: {len(on)} on-runs, translate_ok grew in {sum(1 for r in on if r['translate_ok'])} "
                  f"(sum {sum(r['translate_ok'] for r in on)}), off-runs with fragment entries: "
                  f"{sum(1 for r in off if r['fragment_entries'])}")
        print()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    main()
