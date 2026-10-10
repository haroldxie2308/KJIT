#!/usr/bin/env python3
import glob, re, statistics, sys, os
out = sys.argv[1]
NAMES = {0: "V0 direct", 1: "V1 hash", 2: "V2a 2-way 2048x2", 3: "V2b 2-way 4096x2",
         4: "V3a victim 256", 5: "V3b victim 512"}
calls = 100000 * 256
data = {}
stats = {}
for path in sorted(glob.glob(os.path.join(out, "boot-*.serial.log"))):
    v = int(re.search(r"-v(\d)\.", path).group(1))
    text = open(path, errors="replace").read().replace("\r", "")
    for m in re.finditer(r"aliascost enabled=(\d) rep=\d ns_total=(\d+)", text):
        data.setdefault(v, {0: [], 1: []})[int(m.group(1))].append(int(m.group(2)))
    for key in ("fragment_entries", "chain_cap", "exit_budget", "ibtc_insert", "ibtc_replace"):
        m = re.search(rf"^{key} (\d+)", text, re.M)
        if m:
            stats.setdefault(v, {}).setdefault(key, []).append(int(m.group(1)))
print("alias_loop 100000 x 256 calls (blr alternating between callees 16 KiB apart + ret + back-edge), 2 boots per variant, 7 runs each")
print(f"{'variant':18s} {'off ns/call':>12s} {'on ns/call':>11s} {'(on-off)/call':>14s}   notes")
for v in sorted(data):
    off = statistics.median(data[v][0]) / calls
    on = statistics.median(data[v][1]) / calls
    s = stats.get(v, {})
    note = " ".join(f"{k}={sum(x) // len(x)}" for k, x in s.items())
    print(f"{NAMES[v]:18s} {off:12.2f} {on:11.2f} {on - off:14.2f}   {note}")
