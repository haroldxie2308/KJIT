#!/usr/bin/env python3
"""Summarise measurement boots: analyze.py OUTDIR [--slots]"""
import glob, os, re, statistics, sys
from collections import defaultdict

out = sys.argv[1]
N = 200000
NAMES = {0: "V0 direct", 1: "V1 hash", 2: "V2a 2-way 2048x2", 3: "V2b 2-way 4096x2",
         4: "V3a victim 256", 5: "V3b victim 512"}
TEMPLATE_WORDS = {0: 9, 1: 10, 2: 18, 3: 18, 4: 20, 5: 20}
TABLE_BYTES = {0: 32768, 1: 32768, 2: 32768, 3: 65536, 4: 32768 + 2048, 5: 32768 + 4096}

runs = defaultdict(list)       # (variant, point, test) -> list of dict
micro = defaultdict(list)      # (variant, kind, calls, enabled) -> per-boot median ns per outer
slots = defaultdict(list)      # (variant, point, test) -> list of listing lines
waits = []
for path in sorted(glob.glob(os.path.join(out, "boot-*.serial.log"))):
    m = re.search(r"boot-(\d+)-v(\d)", path)
    boot, variant = int(m.group(1)), int(m.group(2))
    text = open(path, errors="replace").read().replace("\r", "")
    got = re.search(r"meas: variant=(\d+)", text)
    if not got or int(got.group(1)) != variant:
        print("WARNING: variant mismatch in", path, got and got.group(1))
    if "kjit-init: run exit=0" not in text:
        print("WARNING: run did not exit 0:", path)
    for line in text.splitlines():
        if line.startswith("a11 point="):
            d = dict(tok.split("=", 1) for tok in line.split()[1:] if "=" in tok)
            d["boot"] = boot
            runs[(variant, d["point"], d["test"])].append(d)
        elif line.startswith("result variant="):
            d = dict(tok.split("=", 1) for tok in line.split()[1:] if "=" in tok)
            micro[(variant, d["variant"], int(d["calls"]), int(d["enabled"]))].append(
                float(d["median_ns_per_outer"]))
        elif line.startswith("a11slots "):
            toks = line.split()
            kv = dict(t.split("=", 1) for t in toks[1:4] if "=" in t)
            slots[(variant, kv["point"], kv["test"])].append(line)

for path in sorted(glob.glob(os.path.join(out, "boot-*.wait"))):
    waits.append(open(path).read().strip().replace("\n", " | "))


def f(x, nd=1):
    return f"{x:.{nd}f}"


def mean(xs):
    return statistics.mean(xs) if xs else float("nan")


print("== boots (waits)")
for w in waits:
    print(" ", w)

print("\n== redis req/s (mean, min..max over runs), ratio to KJIT off of the same variant's boots")
rows = {}
for v in sorted({k[0] for k in runs}):
    for test in ("set", "get"):
        off = [float(r["rps"]) for r in runs[(v, "off", test)]]
        on = [float(r["rps"]) for r in runs[(v, "1024", test)]]
        rows[(v, test)] = (off, on)
        print(f"  {NAMES[v]:18s} {test.upper()}: off {mean(off):9.0f} ({min(off):.0f}..{max(off):.0f}, n={len(off)})"
              f"  on {mean(on):9.0f} ({min(on):.0f}..{max(on):.0f}, n={len(on)})  ratio {mean(on) / mean(off):.3f}")

print("\n== per request counters at chain_budget 1024 (mean over runs)")
keys = ["fragment_entries", "fpsimd_entries", "exit_bl", "exit_blr", "exit_br", "exit_ret", "exit_svc",
        "ibtc_miss_cold", "ibtc_miss_conflict", "ibtc_miss_other", "ibtc_fpsimd_boundary",
        "ibtc_insert", "ibtc_replace", "syscalls_in_kernel", "hook_calls", "exit_budget", "chain_cap"]
for test in ("set", "get"):
    print(f"  -- {test.upper()}")
    print("  " + f"{'variant':18s}" + "".join(f"{k.replace('ibtc_', '').replace('exit_', 'x_')[:11]:>12s}" for k in keys))
    for v in sorted({k[0] for k in runs}):
        rs = runs[(v, "1024", test)]
        vals = [mean([float(r[k]) / N for r in rs]) for k in keys]
        print("  " + f"{NAMES[v]:18s}" + "".join(f"{x:12.3f}" for x in vals))
    for v in sorted({k[0] for k in runs}):
        rs = runs[(v, "1024", test)]
        res = [int(r["miss_residual"]) for r in rs]
        print(f"     {NAMES[v]:18s} miss_residual max abs {max(abs(x) for x in res)}; fpsimd_run_max_ns max {max(int(r['fpsimd_run_max_ns']) for r in rs)}")

print("\n== entry_cost (ns per outer iteration, median over boots of the per-boot median of 7)")
print("  variant            kind  calls  transfers   off      on   (on-off)/transfers")
for v in sorted({k[0] for k in micro}):
    for kind in ("gpr", "fp"):
        for calls in (16, 128, 256):
            off = micro.get((v, kind, calls, 0), [])
            on = micro.get((v, kind, calls, 1), [])
            if not off or not on:
                continue
            t = 2 * calls + 1
            print(f"  {NAMES[v]:18s} {kind:4s} {calls:5d} {t:9d} {statistics.median(off):8.1f} {statistics.median(on):8.1f}"
                  f"   {(statistics.median(on) - statistics.median(off)) / t:6.2f} ns  (n={len(on)})")

if "--slots" in sys.argv:
    print("\n== ibtc_slots top listings (pass 1 SET at 1024, first boot per variant)")
    for v in sorted({k[0] for k in slots}):
        lst = slots.get((v, "1024", "set"), [])
        print(" ", NAMES[v], f"({len(lst)} lines over all passes)")
        for line in lst[:60]:
            print("   ", line)
print("\n== table memory per mm (two tables)")
for v in sorted(NAMES):
    print(f"  {NAMES[v]:18s} template {TEMPLATE_WORDS[v]:2d} words, table {TABLE_BYTES[v]:6d} B, per mm {2 * TABLE_BYTES[v]:6d} B")
