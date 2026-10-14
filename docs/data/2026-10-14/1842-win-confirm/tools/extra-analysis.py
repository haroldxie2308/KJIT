#!/usr/bin/env python3
"""Per-boot medians and block rates of the unix PING_MBULK / GET cells (KPTI on), and the post-hoc
subset of boots whose server block rate is the same off and on (|on - off| <= 3 per 1000 requests).
  extra-analysis.py 1842-win-confirm.csv
"""
import csv, random, statistics as st, sys
from collections import defaultdict
rows = list(csv.DictReader(open(sys.argv[1])))
by = defaultdict(dict)
for r in rows:
    by[(r["kpti"], r["cell"], r["boot_label"], r["rep"])][r["kjit"]] = r
blk = lambda r: int(r["voluntary_switches"]) / int(r["requests"]) * 1000
def ci(pb):
    labs, out, rnd = list(pb), [], random.Random(1)
    for _ in range(5000):
        pool = []
        for _ in labs:
            v = pb[rnd.choice(labs)]
            pool += [rnd.choice(v) for _ in v]
        out.append(st.median(pool))
    out.sort()
    return out[125], out[4874]
for cell in ["unix_pingm_c50_p1", "unix_get_c50_p1_d1"]:
    g, d, off, on = defaultdict(list), defaultdict(list), defaultdict(list), defaultdict(list)
    for (k, c, b, rep), p in by.items():
        if k == "1" and c == cell and "off" in p and "on" in p:
            g[b].append(float(p["on"]["cpu_us_per_req"]) - float(p["off"]["cpu_us_per_req"]))
            d[b].append(blk(p["on"]) - blk(p["off"]))
            off[b].append(blk(p["off"])); on[b].append(blk(p["on"]))
    print("## %s, KPTI forced on\n\n| boot | median pair gap (us) | blocks/kreq off | blocks/kreq on |\n|---|---|---|---|" % cell)
    for b in sorted(g, key=lambda x: int(x.split("-b")[1])):
        print("| %s | %+.3f | %.1f | %.1f |" % (b, st.median(g[b]), st.median(off[b]), st.median(on[b])))
    keep = {b: v for b, v in g.items() if abs(st.median(d[b])) <= 3}
    allv = [x for v in keep.values() for x in v]
    lo, hi = ci(keep)
    print("\nPost hoc, boots with equal block rate (%d): %d pairs, median %+.3f, 95%% CI [%+.3f..%+.3f], pairs negative %d/%d, boots negative %d/%d\n" % (
        len(keep), len(allv), st.median(allv), lo, hi, sum(1 for x in allv if x < 0), len(allv), sum(1 for v in keep.values() if st.median(v) < 0), len(keep)))
