#!/usr/bin/env python3
"""Direct BL links (A16) against the module without them: redis under the UB protocol.

  ub-links.py [--csv FILE] MODULE:BOOT=SERIAL_LOG...

One log per boot, MODULE is any label (main, a16), BOOT its boot number; a boot is the
"ubstd run" lines of tests/guest/ub-standard.sh in the log. Boots of different modules
with the same BOOT are a pair (run back to back, same session). Prints, per size and
test, the server CPU per request (user + system ticks of the server over the run / requests)
of every module's KJIT-on runs, the per-pair ratio second module / first module, the
on/off ratio inside each module, and the link counters per request. --csv writes one row
per measured run (docs/data/README.md conventions: kjit off|on, req_per_s).

Standard library only.
"""
import csv
import os
import re
import statistics
import sys

LINK_COUNTERS = ["link_made", "link_restored", "link_out_of_range", "link_class_refused"]
GAUGES = ["link_sites_linked", "link_sites_pending"]
COUNTERS = ("hook_calls syscalls_in_kernel fragment_entries exit_svc exit_bl exit_blr exit_br exit_ret "
            "exit_mem exit_unsupported exit_budget run_declined svc_declined fpsimd_entries translate_ok "
            "invalidated_fragments").split()


def kv(line):
    return dict(re.findall(r"(\w+)=(\S+)", line))


def load(args):
    rows = []
    for a in args:
        head, path = a.split("=", 1)
        module, boot = head.split(":")
        host = os.path.join(os.path.dirname(path), "host.txt")
        m = re.search(r"load1_before=(\S+)", open(host).read()) if os.path.exists(host) else None
        load1 = m.group(1) if m else ""
        for line in open(path, errors="replace"):
            if "ubstd run " not in line:
                continue
            d = kv(line.split("ubstd run ", 1)[1])
            r = {"module": module, "boot": int(boot), "pin": d["pin"], "size": int(d["size"]),
                 "rep": int(d["rep"]), "test": d["test"], "kjit": d["state"], "requests": int(d["requests"]),
                 "req_per_s": float(d["rps"]), "wall_cs": int(d["wall_cs"]),
                 "utime_ticks": int(d["utime_ticks"]), "stime_ticks": int(d["stime_ticks"]),
                 "clk_tck": int(d["clk_tck"]), "load1_before": load1}
            r["cpu_us_per_req"] = round((r["utime_ticks"] + r["stime_ticks"]) / r["clk_tck"] * 1e6 / r["requests"], 4)
            for c in COUNTERS + LINK_COUNTERS + GAUGES:
                r[c] = int(d[c]) if c in d else ""
            rows.append(r)
    return rows


def q(vals, spec):
    vals = sorted(vals)
    return f"{statistics.median(vals):{spec}} [{vals[0]:{spec}}..{vals[-1]:{spec}}]"


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
    sizes = sorted({r["size"] for r in rows})
    boots = sorted({r["boot"] for r in rows})

    def cell(module, boot, size, test, kjit, field):
        vals = [r[field] for r in rows if (r["module"], r["boot"], r["size"], r["test"], r["kjit"]) ==
                (module, boot, size, test, kjit)]
        return statistics.mean(vals)

    print(f"Server CPU per request, us; KJIT on, mean of the reps within a boot, median over {len(boots)} boots [min..max]")
    print(f"| -d | test | {base} off | {base} on | {test_m} off | {test_m} on | {base} on/off | {test_m} on/off | "
          f"{test_m} on / {base} on (pairs) | {test_m} on - {base} on, us (pairs) |")
    print("|---|---|---|---|---|---|---|---|---|---|")
    for size in sizes:
        for test in ("set", "get"):
            g = lambda m, k: [cell(m, b, size, test, k, "cpu_us_per_req") for b in boots]
            bo, bn, to, tn = g(base, "off"), g(base, "on"), g(test_m, "off"), g(test_m, "on")
            print(f"| {size} | {test.upper()} | {q(bo, '.2f')} | {q(bn, '.2f')} | {q(to, '.2f')} | {q(tn, '.2f')} | "
                  f"{q([n / o for n, o in zip(bn, bo)], '.3f')} | {q([n / o for n, o in zip(tn, to)], '.3f')} | "
                  f"{q([t / b for t, b in zip(tn, bn)], '.3f')} | {q([t - b for t, b in zip(tn, bn)], '+.3f')} |")
    print()
    print(f"Throughput, requests/s (KJIT on), median over boots [min..max]; client-bound at small sizes, not the metric")
    print(f"| -d | test | {base} on | {test_m} on |")
    print("|---|---|---|---|")
    for size in sizes:
        for test in ("set", "get"):
            g = lambda m: [cell(m, b, size, test, "on", "req_per_s") for b in boots]
            print(f"| {size} | {test.upper()} | {q(g(base), '.0f')} | {q(g(test_m), '.0f')} |")
    print()
    print(f"{test_m} KJIT on, link counters per request (sum over the runs of a boot / requests, median over boots) and the "
          "gauges after the runs (median)")
    print("| -d | test | fragment entries/req | link_made/req | link_restored/req | out_of_range | class_refused | linked | pending |")
    print("|---|---|---|---|---|---|---|---|---|")
    for size in sizes:
        for test in ("set", "get"):
            sel = [r for r in rows if r["module"] == test_m and r["size"] == size and r["test"] == test and r["kjit"] == "on"]
            per = lambda f: statistics.median(r[f] / r["requests"] for r in sel)
            tot = lambda f: sum(r[f] for r in sel)
            print(f"| {size} | {test.upper()} | {per('fragment_entries'):.3f} | {per('link_made'):.2e} | "
                  f"{per('link_restored'):.2e} | {tot('link_out_of_range')} | {tot('link_class_refused')} | "
                  f"{statistics.median(r['link_sites_linked'] for r in sel):.0f} | "
                  f"{statistics.median(r['link_sites_pending'] for r in sel):.0f} |")
    print()
    for m in modules:
        on = [r for r in rows if r["module"] == m and r["kjit"] == "on"]
        off = [r for r in rows if r["module"] == m and r["kjit"] == "off"]
        print(f"{m}: {len(on)} on-runs, translate_ok grew in {sum(1 for r in on if r['translate_ok'])} "
              f"(sum {sum(r['translate_ok'] for r in on)}), off-runs with fragment entries: "
              f"{sum(1 for r in off if r['fragment_entries'])}, invalidated_fragments sum {sum(r['invalidated_fragments'] for r in on)}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    main()
