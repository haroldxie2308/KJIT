#!/usr/bin/env python3
"""journal-tables.py RUNS.csv: the tables of the journal entry (a23 - main, a23 - off, main - off per cell and pooled, KPTI off then on), same bootstrap as a23-analysis.py."""
import importlib.util
import random
import sys
from pathlib import Path

spec = importlib.util.spec_from_file_location("an", Path(__file__).with_name("a23-analysis.py"))
an = importlib.util.module_from_spec(spec)
spec.loader.exec_module(an)
rows, trip = an.load(sys.argv[1])
rng = random.Random(1)
NAMES = {"unix_get_c50_p1_d1": "unix GET -d 1", "unix_set_c50_p1_d1": "unix SET -d 1", "unix_pingm_c50_p1": "unix PING_MBULK",
         "get_c50_p1_d1": "TCP GET -d 1"}


def cellfmt(s):
    return f"{s['m']:+.3f} [{s['q1']:+.3f}..{s['q3']:+.3f}] [{s['lo']:+.3f}..{s['hi']:+.3f}] ({s['nb']}/{s['B']}, {s['nt']}/{s['n']})"


for kpti, title in ((0, "KPTI off, 8 boots"), (1, "KPTI forced on, 6 boots")):
    sub = [t for t in trip if t["kpti"] == kpti]
    print(f"{title}:")
    print()
    print("| cell | triples | a23 - off | verdict | a23 - main | verdict | main - off |")
    print("|---|---|---|---|---|---|---|")
    for scope, picked in [(NAMES[c], [t for t in sub if t["cell"] == c]) for c in NAMES] + [("pooled", sub)]:
        s1, s2, s3 = (an.stat(picked, a, b, rng) for a, b in (("a23", "off"), ("a23", "main"), ("main", "off")))
        print(f"| {scope} | {s1['n']} | {cellfmt(s1)} | {an.verdict(s1)} | {cellfmt(s2)} | {an.verdict(s2)} | {cellfmt(s3)} |")
    print()
