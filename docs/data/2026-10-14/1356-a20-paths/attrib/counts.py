"""Dynamic hot-path words per request by lowering class, from the E1 request-gap counts of the
2026-10-13 15:25 lowering TSVs and a retranslation of every executed instruction.

  python3 counts.py BEFORE-SET.tsv BEFORE-GET.tsv AFTER-SET.tsv AFTER-GET.tsv

A16 links 99% of the BL executions (2026-10-11 22:37 / 2026-10-13 15:25). A linked BL executes its budget
check, the link write and the slot's `b`; the dispatch template and, from A20 on, the target move are skipped.
(The 15:25 tool counted the 9 template words for every BL, the overcount fixed here.) Per BL row:
  dispatch_lookup: count * lookup * (1 - LINKED)
  dispatch_target: before A20 (target move ahead of the slot) count * dt; A20 count * dt * (1 - LINKED)
  link_slot: count (the `b` or the `nop` is one executed word either way)
"""
import csv
import sys

COLS = ["user_op", "user_synth", "user_access", "fill", "spill", "helper_other", "budget", "align", "range",
        "window_access", "link_slot", "dispatch_target", "dispatch_lookup"]
N = 100000
LINKED = 0.99


def one(path, a20):
    tot = {c: 0.0 for c in COLS}
    native = 0
    bl = 0
    for r in csv.DictReader(open(path), delimiter="\t"):
        if r["supported"] != "1":
            continue
        n = int(r["count"])
        native += n
        is_bl = r["text"].split()[0] == "bl"
        bl += n if is_bl else 0
        for c in COLS:
            w = n * int(r[c])
            if is_bl and c == "dispatch_lookup":
                w *= 1 - LINKED
            if is_bl and c == "dispatch_target" and a20:
                w *= 1 - LINKED
            tot[c] += w
    return {k: v / N for k, v in tot.items()}, native / N, bl / N


def main():
    res = {}
    for key, path, a20 in (("before SET", sys.argv[1], False), ("before GET", sys.argv[2], False),
                           ("after SET", sys.argv[3], True), ("after GET", sys.argv[4], True)):
        res[key] = one(path, a20)
    print("| class | before SET | after SET | change | before GET | after GET | change |")
    print("|---|---|---|---|---|---|---|")
    for c in COLS + ["total"]:
        cells = []
        for t in ("SET", "GET"):
            b = sum(res[f"before {t}"][0].values()) if c == "total" else res[f"before {t}"][0][c]
            a = sum(res[f"after {t}"][0].values()) if c == "total" else res[f"after {t}"][0][c]
            cells += [f"{b:.1f}", f"{a:.1f}", f"{a - b:+.1f}"]
        print(f"| {c} | " + " | ".join(cells) + " |")
    for t in ("SET", "GET"):
        words, native, bl = res[f"after {t}"]
        print(f"{t}: original instructions {native:.0f}/req, BL {bl:.1f}/req")


main()
