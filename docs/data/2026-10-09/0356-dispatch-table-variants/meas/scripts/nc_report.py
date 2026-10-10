#!/usr/bin/env python3
"""V0 with the miss classification compiled out (v0nc) against V0: paired boots."""
import glob, re, statistics, sys
out = sys.argv[1]
res = {}
for path in sorted(glob.glob(out + "/boot-*.serial.log")):
    name = re.search(r"boot-\d+-v(\w+)\.serial", path).group(1)
    text = open(path, errors="replace").read().replace("\r", "")
    for line in text.splitlines():
        if line.startswith("a11 point=1024"):
            d = dict(t.split("=", 1) for t in line.split()[1:] if "=" in t)
            res.setdefault(name, {}).setdefault(d["test"], []).append(float(d["rps"]))
        if line.startswith("a11 point=off"):
            d = dict(t.split("=", 1) for t in line.split()[1:] if "=" in t)
            res.setdefault(name, {}).setdefault("off-" + d["test"], []).append(float(d["rps"]))
for name, d in res.items():
    print(name, {k: f"{statistics.mean(v):.0f} ({min(v):.0f}..{max(v):.0f}, n={len(v)})" for k, v in sorted(d.items())})
