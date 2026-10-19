#!/usr/bin/env python3
"""A22 measurement: three states (off, a21, a22) paired inside each boot.

  a22-summarize.py --csv RUNS.csv --tables TABLES.md K<kpti>:B<boot>=SERIAL_LOG...

One log per boot (the "cond run" lines of a22-sweep.sh). Server CPU per request = sum of se.sum_exec_runtime of
the server's tasks (sched_ms) / requests, in us. A triple = the off, a21 and a22 runs of one boot, cell and rep.
Prints, per KPTI setting and cell, the paired differences a22 - a21, a22 - off and a21 - off as median
[Q1..Q3] over the triples (us per request), the number of triples with a negative a22 - a21, and "x/y" = boots
whose per-boot median is positive. --csv writes one row per measured run. Standard library only.
"""
import csv
import re
import statistics
import sys

COUNTERS = ("hook_calls syscalls_in_kernel fragment_entries exit_svc exit_bl exit_blr exit_br exit_ret "
            "exit_mem exit_unsupported exit_budget run_declined svc_declined fpsimd_entries translate_ok "
            "invalidated_fragments chains chain_cap translate_exists released_fragments ibtc_insert ibtc_miss_cold "
            "ibtc_miss_conflict ibtc_miss_other link_made link_out_of_range auto_req_exit_target auto_req_svc_resume").split()
ABS = "abs_translate_ok abs_released abs_arena_bytes abs_links_linked abs_links_pending".split()


def kv(line):
    return dict(re.findall(r"(\w+)=(\S+)", line))


def load(args):
    rows = []
    for a in args:
        head, path = a.split("=", 1)
        kpti, boot = re.fullmatch(r"K(\d):B(\d+)", head).groups()
        for line in open(path, errors="replace"):
            if "cond run " in line and "state=" in line:
                d = kv(line.split("cond run ", 1)[1])
                n = int(d["n"])
                r = {"kpti": int(kpti), "boot": int(boot), "cell": d["cell"], "srv": d["srv"], "test": d["test"],
                     "requests": n, "clients": int(d["c"]), "pipeline": int(d["p"]), "value_bytes": int(d["d"]),
                     "threads": int(d["thr"]), "rep": int(d["rep"]), "order": d["order"], "state": d["state"],
                     "req_per_s": float(d["rps"]), "wall_cs": int(d["wall_cs"]), "ticks_u": int(d["ticks_u"]),
                     "ticks_s": int(d["ticks_s"]), "sched_ms": float(d["sched_ms"]), "nvol": int(d["nvol"]),
                     "ninv": int(d["ninv"]), "c0_busy": int(d["c0_busy"]), "c0_idle": int(d["c0_idle"]),
                     "ipi_c0": int(d["ipi_c0"]), "ipi_other": int(d["ipi_other"])}
                r["cpu_us_per_req"] = round(r["sched_ms"] * 1000 / n, 4)
                for c in COUNTERS:
                    r[c] = int(d[c])
                for c in ABS:
                    r[c] = int(d[c])
                rows.append(r)
    return rows


def quart(vals):
    vals = sorted(vals)
    if len(vals) < 2:
        return vals[0], vals[0], vals[0]
    q = statistics.quantiles(vals, n=4, method="inclusive")
    return q[1], q[0], q[2]


def med_q(vals, spec="+.3f"):
    m, lo, hi = quart(vals)
    return f"{m:{spec}} [{lo:{spec}}..{hi:{spec}}]"


def pairs_text(pairs):
    if not pairs:
        return "-"
    by_boot = {}
    for b, d in pairs:
        by_boot.setdefault(b, []).append(d)
    pos = sum(1 for v in by_boot.values() if statistics.median(v) > 0)
    neg = sum(1 for _, d in pairs if d < 0)
    return f"{med_q([d for _, d in pairs])} ({pos}/{len(by_boot)} boots+, {neg}/{len(pairs)} pairs<0)"


def main():
    args = sys.argv[1:]
    csv_path = tables_path = None
    while args and args[0].startswith("--"):
        if args[0] == "--csv":
            csv_path, args = args[1], args[2:]
        elif args[0] == "--tables":
            tables_path, args = args[1], args[2:]
        else:
            sys.exit(__doc__)
    rows = load(args)
    if csv_path:
        with open(csv_path, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0]))
            w.writeheader()
            w.writerows(rows)
    out = []
    p = out.append
    idx = {(r["kpti"], r["boot"], r["cell"], r["rep"], r["state"]): r for r in rows}
    for kpti in (1, 0):
        sub = [r for r in rows if r["kpti"] == kpti]
        if not sub:
            continue
        cells = []
        for r in sub:
            if r["cell"] not in cells:
                cells.append(r["cell"])
        boots = sorted({r["boot"] for r in sub})
        p(f"## KPTI {'forced on' if kpti else 'off'}: {len(boots)} boots ({', '.join(map(str, boots))})")
        p("")
        p("Server CPU per request, us (median [Q1..Q3] over runs)")
        p("| cell | triples | off | a21 | a22 |")
        p("|---|---|---|---|---|")
        diffs = {}
        for cell in cells:
            def vals(state):
                return [r["cpu_us_per_req"] for r in sub if (r["cell"], r["state"]) == (cell, state)]
            trip = []
            for (k, b, c, rep, st), r in idx.items():
                if k == kpti and c == cell and st == "a22":
                    off, main_ = idx.get((k, b, c, rep, "off")), idx.get((k, b, c, rep, "a21"))
                    if off and main_:
                        trip.append((b, r["cpu_us_per_req"], main_["cpu_us_per_req"], off["cpu_us_per_req"]))
            diffs[cell] = trip
            p(f"| {cell} | {len(trip)} | {med_q(vals('off'), '.3f')} | {med_q(vals('a21'), '.3f')} | {med_q(vals('a22'), '.3f')} |")
        p("")
        p("Paired differences inside a boot, us per request (median [Q1..Q3] over triples; boots+ = boots whose median "
          "triple is positive; negative = the first term is cheaper)")
        p("| cell | a22 - a21 | a22 - off | a21 - off |")
        p("|---|---|---|---|")
        for cell in cells:
            t = diffs[cell]
            p(f"| {cell} | {pairs_text([(b, a - m) for b, a, m, o in t])} | {pairs_text([(b, a - o) for b, a, m, o in t])} "
              f"| {pairs_text([(b, m - o) for b, a, m, o in t])} |")
        p("")
        p("Per request, median over runs (counters of the loaded module); round trips = fragment_entries - hook_calls "
          "(entries after the first of a hook call); exits = svc/bl/blr/br/ret/mem/unsupported/budget; ibtc misses = "
          "cold+conflict+other; fragments = translate_ok since the module was loaded (warm-ups included, the cell's server); "
          "freed = released_fragments; links = link slots patched / waiting (gauges, all mms)")
        p("| cell | state | fragments | freed | links | in-kernel syscalls | fragment entries | chains | exits bl/blr/br/ret | "
          "exits svc/mem/unsup/budget | ibtc misses | translate_ok (run) | arena KiB |")
        p("|---|---|---|---|---|---|---|---|---|---|---|---|---|")
        for cell in cells:
            for st in ("a21", "a22"):
                on = [r for r in sub if (r["cell"], r["state"]) == (cell, st)]
                if on:
                    def per(c):
                        return statistics.median(r[c] / r["requests"] for r in on)

                    def med(c):
                        return statistics.median(r[c] for r in on)
                    miss = statistics.median((r["ibtc_miss_cold"] + r["ibtc_miss_conflict"] + r["ibtc_miss_other"]) / r["requests"] for r in on)
                    p(f"| {cell} | {st} | {med('abs_translate_ok'):.0f} | {med('abs_released'):.0f} | "
                      f"{med('abs_links_linked'):.0f}/{med('abs_links_pending'):.0f} | {per('syscalls_in_kernel'):.3f} | "
                      f"{per('fragment_entries'):.4f} | {per('chains'):.4f} | "
                      f"{per('exit_bl'):.4f}/{per('exit_blr'):.4f}/{per('exit_br'):.4f}/{per('exit_ret'):.4f} | "
                      f"{per('exit_svc'):.4f}/{per('exit_mem'):.4f}/{per('exit_unsupported'):.4f}/{per('exit_budget'):.4f} | "
                      f"{miss:.5f} | {per('translate_ok'):.6f} | {med('abs_arena_bytes') / 1024:.0f} |")
        p("")
    text = "\n".join(out)
    if tables_path:
        open(tables_path, "w").write(text + "\n")
    print(text)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    main()
