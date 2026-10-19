#!/usr/bin/env python3
"""journal-tables.py RUNS.csv: the three tables of the journal entry (A21 entry's format), same bootstrap as a22-analysis.py."""
import importlib.util
import random
import sys
from pathlib import Path

spec = importlib.util.spec_from_file_location("an", Path(__file__).with_name("a22-analysis.py"))
an = importlib.util.module_from_spec(spec)
spec.loader.exec_module(an)
rows, trip = an.load(sys.argv[1])
rng = random.Random(1)
NAMES = {"unix_get_c50_p1_d1": "unix GET -d 1", "unix_set_c50_p1_d1": "unix SET -d 1", "unix_pingm_c50_p1": "unix PING_MBULK",
         "get_c50_p1_d1": "TCP GET -d 1", "set_c50_p1_d1": "TCP SET -d 1"}


def cellfmt(s):
    return f"{s['m']:+.3f} [{s['q1']:+.3f}..{s['q3']:+.3f}] [{s['lo']:+.3f}..{s['hi']:+.3f}] ({s['nb']}/{s['B']}, {s['nt']}/{s['n']})"


def table(title, sub, cells):
    print(title)
    print()
    print("| cell | triples | a22 - a21 | a22 - off | a21 - off | verdict a22 - off |")
    print("|---|---|---|---|---|---|")
    for scope, picked in [(NAMES[c], [t for t in sub if t["cell"] == c]) for c in cells] + [("pooled", sub)]:
        s1, s2, s3 = (an.stat(picked, a, b, rng) for a, b in (("a22", "a21"), ("a22", "off"), ("a21", "off")))
        print(f"| {scope} | {s1['n']} | {cellfmt(s1)} | {cellfmt(s2)} | {cellfmt(s3)} | {an.verdict(s2)} |")
    print()


order = ["unix_get_c50_p1_d1", "unix_set_c50_p1_d1", "unix_pingm_c50_p1", "get_c50_p1_d1", "set_c50_p1_d1"]
main = [t for t in trip if not (t["kpti"] == 1 and t["boot"] >= 7)]
table("KPTI forced on, 6 boots:", [t for t in main if t["kpti"] == 1], order)
table("KPTI off, 4 boots:", [t for t in main if t["kpti"] == 0], order[:2])
table("KPTI forced on, unix GET -d 1 and unix PING_MBULK, 12 boots:",
      [t for t in trip if t["kpti"] == 1 and t["cell"] in (order[0], order[2])], [order[0], order[2]])
