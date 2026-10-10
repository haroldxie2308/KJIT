#!/usr/bin/env python3
"""Dispatch-table conflict variants (journal 2026-10-09, "Dispatch-table conflict
variants: index hash, 2-way, victim table").

  extract_ibtc_variants.py BOOT.serial.log... --out FILE.json

Inputs: the serial logs of the measurement boots, one per boot, named
boot-NN-v<label>.serial.log with boot-NN-v<label>.wait next to them (label = the
ibtc_variant number, "0nc" = variant 0 with the miss classification compiled out).
Three kinds of boot exist (the directory name becomes the `series` column):
meas (a11-baseline.sh redis runs + entry_cost), meas-alias (alias_loop) and meas-nc.

Tables:
  boots              one row per boot: series, boot, variant, waits/loads/duration from the .wait file
  redis_runs         every "a11 point=..." line (one redis-benchmark run: point off|1024, pass, test set|get)
  entry_cost_reps    every "rep N variant=gpr|fp ..." line of entry_cost (one timed repeat)
  entry_cost_counters  the "counters" line that follows each KJIT-on result line of entry_cost
  alias_loop_reps    every "aliascost enabled=E rep=N ns_total=T" line (T: wall time of
                     alias_loop 100000 x 256 calls, whole process)
  alias_loop_stats   the five stats lines printed after the alias_loop reps

Standard library only.
"""
import os
import re

import kjit_data as kd

NAME = re.compile(r"boot-(\d+)-v(\w+)\.serial\.log$")
STAT_KEYS = ["fragment_entries", "chain_cap", "exit_budget", "ibtc_insert", "ibtc_replace"]
STAT_LINE = re.compile(r"^(fragment_entries|chain_cap|exit_budget|ibtc_insert|ibtc_replace) (\d+)$")


def wait_file(log, boot, variant):
    """boot-NN-vV.wait: "boot=.. variant=.. waited_s=.. polls=.. load1_at_start=.. qemu_others=.. date=.."
    then "boot=.. variant=.. rc=.. load1_at_end=.. duration_s=..". Strict."""
    path = log.replace(".serial.log", ".wait")
    lines = list(kd.read_lines(path))
    if len(lines) != 2:
        kd.fail(path, None, f"expected 2 lines, found {len(lines)}")
    a = dict(kd.kv_pairs(path, lines[0][0], lines[0][1]))
    b = dict(kd.kv_pairs(path, lines[1][0], lines[1][1]))
    want_a = ["boot", "variant", "waited_s", "polls", "load1_at_start", "qemu_others", "date"]
    want_b = ["boot", "variant", "rc", "load1_at_end", "duration_s"]
    for got, want, ln in ((a, want_a, lines[0][0]), (b, want_b, lines[1][0])):
        if list(got) != want:
            kd.fail(path, ln, f"expected keys {want}, found {list(got)}")
        if got["boot"] != boot or got["variant"] != variant:
            kd.fail(path, ln, f"boot/variant {got['boot']}/{got['variant']} differ from the file name {boot}/{variant}")
    n = lambda lineno, d, k: kd.number(path, lineno, k, d[k])
    return {"waited_s": n(lines[0][0], a, "waited_s"), "polls": n(lines[0][0], a, "polls"),
            "load1_at_start": n(lines[0][0], a, "load1_at_start"), "qemu_others": n(lines[0][0], a, "qemu_others"),
            "date": a["date"], "rc": n(lines[1][0], b, "rc"), "load1_at_end": n(lines[1][0], b, "load1_at_end"),
            "duration_s": n(lines[1][0], b, "duration_s")}


def build(logs):
    boots = kd.Table("boots", ["series", "boot", "variant", "waited_s", "polls", "load1_at_start", "qemu_others",
                               "date", "rc", "load1_at_end", "duration_s"])
    redis = None
    redis_schema = kd.UniformKV("a11 point")
    reps = kd.Table("entry_cost_reps", ["series", "boot", "variant", "kind", "calls", "enabled", "rep", "outer",
                                        "ns_per_outer", "ns_per_call"])
    counters = None
    counters_schema = kd.UniformKV("entry_cost counters")
    alias = kd.Table("alias_loop_reps", ["series", "boot", "variant", "enabled", "rep", "ns_total"])
    alias_stats = kd.Table("alias_loop_stats", ["series", "boot", "variant"] + STAT_KEYS)
    redis_rows, counter_rows = [], []

    for log in logs:
        m = NAME.search(log)
        if not m:
            kd.fail(log, None, "file name is not boot-NN-v<label>.serial.log")
        boot, variant = m.group(1), m.group(2)
        series = os.path.basename(os.path.dirname(os.path.abspath(log)))
        w = wait_file(log, boot, variant)
        if w["rc"] != 0:
            kd.fail(log.replace(".serial.log", ".wait"), 2, f"boot ended with rc={w['rc']}")
        boots.add(series=series, boot=int(boot), variant=variant, **w)
        ctx = dict(series=series, boot=int(boot), variant=variant)

        exited = meas_variant = None
        last_result = None
        alias_seen, stats = 0, {}
        for lineno, text in kd.read_lines(log):
            if text.startswith("kjit-init: run exit="):
                exited = text.split("=", 1)[1]
            elif text.startswith("meas: variant="):
                meas_variant = text.split("=", 1)[1]
            elif text.startswith("a11 point="):
                pairs = kd.kv_pairs(log, lineno, text[len("a11 "):])
                redis_schema.check(log, lineno, pairs)
                redis_rows.append((ctx, log, lineno, pairs))
            elif text.startswith("rep "):
                parts = text.split(" ", 2)
                d = dict(kd.kv_pairs(log, lineno, parts[2]))
                want = ["variant", "enabled", "outer", "calls", "ns_per_outer", "ns_per_call"]
                if list(d) != want:
                    kd.fail(log, lineno, f"rep line keys {list(d)} != {want}")
                reps.add(**ctx, kind=d["variant"], calls=kd.number(log, lineno, "calls", d["calls"]),
                         enabled=kd.number(log, lineno, "enabled", d["enabled"]),
                         rep=kd.number(log, lineno, "rep", parts[1]),
                         outer=kd.number(log, lineno, "outer", d["outer"]),
                         ns_per_outer=kd.number(log, lineno, "ns_per_outer", d["ns_per_outer"]),
                         ns_per_call=kd.number(log, lineno, "ns_per_call", d["ns_per_call"]))
            elif text.startswith("result variant="):
                d = dict(kd.kv_pairs(log, lineno, text[len("result "):]))
                for need in ("variant", "enabled", "calls"):
                    if need not in d:
                        kd.fail(log, lineno, f"result line lacks {need}")
                last_result = (d["variant"], d["enabled"], d["calls"])
            elif text.startswith("counters variant="):
                if last_result is None or last_result[0] != text.split()[1].split("=")[1] or last_result[1] != "1":
                    kd.fail(log, lineno, "counters line does not follow the KJIT-on result line of its variant")
                pairs = kd.kv_pairs(log, lineno, text[len("counters "):])
                counters_schema.check(log, lineno, pairs)
                counter_rows.append((ctx, log, lineno, pairs, last_result[2]))
            elif text.startswith("aliascost "):
                d = dict(kd.kv_pairs(log, lineno, text[len("aliascost "):]))
                if list(d) != ["enabled", "rep", "ns_total"]:
                    kd.fail(log, lineno, f"aliascost keys {list(d)}")
                alias.add(**ctx, enabled=kd.number(log, lineno, "enabled", d["enabled"]),
                          rep=kd.number(log, lineno, "rep", d["rep"]),
                          ns_total=kd.number(log, lineno, "ns_total", d["ns_total"]))
                alias_seen += 1
            elif alias_seen:
                sm = STAT_LINE.match(text)
                if sm:
                    if sm.group(1) in stats:
                        kd.fail(log, lineno, f"duplicate stats line {sm.group(1)}")
                    stats[sm.group(1)] = kd.number(log, lineno, sm.group(1), sm.group(2))
        if exited != "0":
            kd.fail(log, None, f"no 'kjit-init: run exit=0' line (found {exited!r})")
        if meas_variant is None or not variant.startswith(meas_variant):
            kd.fail(log, None, f"'meas: variant=' line {meas_variant!r} does not match file name variant {variant!r}")
        if alias_seen:
            if sorted(stats) != sorted(STAT_KEYS):
                kd.fail(log, None, f"alias_loop stats lines found {sorted(stats)}, expected {sorted(STAT_KEYS)}")
            alias_stats.add(**ctx, **stats)

    if redis_rows:
        keys = redis_schema.keys
        redis = kd.Table("redis_runs", ["series", "boot", "variant"] + keys)
        for ctx, log, lineno, pairs in redis_rows:
            vals = {k: (v if k in ("point", "test") else kd.number(log, lineno, k, v)) for k, v in pairs}
            if vals["point"] not in ("off", "1024"):
                kd.fail(log, lineno, f"unexpected point {vals['point']!r} (off or chain_budget 1024 expected)")
            redis.add(**ctx, **vals)
    if counter_rows:
        keys = [k for k in counters_schema.keys if k != "variant"]
        counters = kd.Table("entry_cost_counters", ["series", "boot", "variant", "kind", "calls"] + keys)
        for ctx, log, lineno, pairs, calls in counter_rows:
            d = dict(pairs)
            counters.add(**ctx, kind=d["variant"], calls=kd.number(log, lineno, "calls", calls),
                         **{k: kd.number(log, lineno, k, d[k]) for k in keys})
    tables = [t for t in (boots, redis, reps, counters, alias, alias_stats) if t is not None and len(t)]
    meta = {"extracted_by": "tests/guest/host/extract_ibtc_variants.py",
            "source": "serial logs of the measurement boots (meas, meas-alias, meas-nc)",
            "variants": "0 direct, 1 hash, 2 2-way 2048x2, 3 2-way 4096x2, 4 victim 256, 5 victim 512, 0nc = 0 without miss classification"}
    return meta, tables


if __name__ == "__main__":
    kd.run_cli(__doc__, build, "json")
