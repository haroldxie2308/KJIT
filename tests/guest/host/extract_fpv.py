#!/usr/bin/env python3
"""FP/SIMD bracket experiment (journal 2026-10-09, "FP/SIMD bracket: preemptible
kernel-mode NEON experiment").

  extract_fpv.py FPV_LOG... --out FILE.json

Inputs: the logs written by fpv-run.sh (branch exp/fp-bracket-neon, <build root>/fpv/):
bench-*.log and lat-*.log (fpv-bench.sh: redis-benchmark SET/GET per bracket variant,
lat-* with the lat_probe beside every run) and entry-*.log (fpv-entry.sh: entry_cost
per variant). A bench/lat log names its guest run directory ("guest-run: ... run-dir=");
that directory's kjit-run.sh gives the redis-benchmark arguments of the run
(FPV_BENCH_ARGS), so it must still exist.

Points: off = KJIT off, v0 = fpvariant 0 (A11 bracket), A = 1, B = 2, B2 = 3.

Tables:
  runs             one row per log: step, profile, host load average (1/5/15 min) before and after
  redis_runs       every "fpv point=..." line (one redis-benchmark run): counters are deltas over the
                   run, fpsimd_run_max_ns is cumulative per boot; lat_* columns are empty
                   in runs without the lat_probe (fpv_probe 0)
  bracket_hist     every "fpv-hist" line, one row per non-empty bucket of the legacy bracket's
                   duration histogram (bucket_lo_ns = lower bound of a log2 bucket)
  entry_cost       every "fpv-entry" line (median of 7 timed repetitions of entry_cost, one per round)
  entry_cost_counters  the counters of each KJIT-on "fpv-entry" line

Standard library only.
"""
import os
import re

import kjit_data as kd

RUN_HEAD = re.compile(r"^fpv-run: step=(\w+) args=(.*) profile=(\S+) "
                      r"host_load_before=([\d.]+), ([\d.]+), ([\d.]+)$")
RUN_DONE = re.compile(r"^fpv-run: step=(\w+) done host_load_after=([\d.]+), ([\d.]+), ([\d.]+)$")
RUN_DIR = re.compile(r"^guest-run: profile=\S+ run-dir=(\S+)$")
LAT_KEYS = ["lat_p50_us", "lat_p99_us", "lat_p999_us", "lat_max_us", "lat_gt100us", "lat_gt1ms", "lat_gt5ms"]
POINTS = ("off", "v0", "A", "B", "B2")


def run_script_settings(log, run_dir):
    """FPV_PROBE and FPV_BENCH_ARGS from <run_dir>/kjit-run.sh."""
    path = os.path.join(run_dir, "kjit-run.sh")
    text = "\n".join(t for _, t in kd.read_lines(path))
    m = re.search(r"FPV_PROBE=(\d) FPV_BENCH_ARGS='([^']*)' sh /opt/kjit-tests/fpv-bench\.sh ", text)
    if not m:
        kd.fail(path, None, f"no 'FPV_PROBE=.. FPV_BENCH_ARGS=.. sh .../fpv-bench.sh' command (named by {log})")
    return int(m.group(1)), m.group(2)


def build(logs):
    runs = kd.Table("runs", ["log", "step", "rounds", "points_in_order", "profile", "fpv_probe", "redis_benchmark_args",
                             "host_load1_before", "host_load5_before", "host_load15_before",
                             "host_load1_after", "host_load5_after", "host_load15_after"])
    redis_schema = kd.UniformKV("fpv point")
    redis_rows = []
    hist = kd.Table("bracket_hist", ["log", "point", "pass", "test", "bucket_lo_ns", "count"])
    entry = kd.Table("entry_cost", ["log", "point", "kind", "calls", "round", "ns_per_outer"])
    entry_ctr_schema = kd.UniformKV("fpv-entry counters")
    entry_ctr_rows = []

    for log in logs:
        name = os.path.basename(log)
        head = done = run_dir = None
        for lineno, text in kd.read_lines(log):
            m = RUN_HEAD.match(text)
            if m:
                head = (lineno, m)
                continue
            m = RUN_DONE.match(text)
            if m:
                done = (lineno, m)
                continue
            m = RUN_DIR.match(text)
            if m:
                run_dir = m.group(1)
                continue
            if text.startswith("fpv point="):
                pairs = kd.kv_pairs(log, lineno, text[len("fpv "):])
                base = [(k, v) for k, v in pairs if k not in LAT_KEYS]
                lat = [k for k, _ in pairs if k in LAT_KEYS]
                if lat not in ([], LAT_KEYS):
                    kd.fail(log, lineno, f"lat_* keys {lat} are neither absent nor the full set {LAT_KEYS}")
                redis_schema.check(log, lineno, base)
                redis_rows.append((name, log, lineno, pairs))
            elif text.startswith("fpv-hist "):
                toks = text.split()
                d = dict(kd.kv_pairs(log, lineno, " ".join(toks[1:4])))
                if list(d) != ["point", "pass", "test"] or len(toks) < 5:
                    kd.fail(log, lineno, "fpv-hist line is not 'point= pass= test= bucket:count...'")
                for tok in toks[4:]:
                    lo, sep, cnt = tok.partition(":")
                    if not sep:
                        kd.fail(log, lineno, f"expected bucket:count, got {tok!r}")
                    hist.add(log=name, point=d["point"], **{"pass": kd.number(log, lineno, "pass", d["pass"])},
                             test=d["test"], bucket_lo_ns=kd.number(log, lineno, "bucket", lo),
                             count=kd.number(log, lineno, "count", cnt))
            elif text.startswith("fpv-entry "):
                pairs = kd.kv_pairs(log, lineno, text[len("fpv-entry "):])
                d = dict(pairs)
                head_keys = ["point", "kind", "calls", "round", "ns_per_outer"]
                if [k for k, _ in pairs[:5]] != head_keys:
                    kd.fail(log, lineno, f"fpv-entry line must start with {head_keys}")
                if d["point"] not in POINTS:
                    kd.fail(log, lineno, f"unknown point {d['point']!r}")
                num = lambda k: kd.number(log, lineno, k, d[k])
                entry.add(log=name, point=d["point"], kind=d["kind"], calls=num("calls"), round=num("round"),
                          ns_per_outer=num("ns_per_outer"))
                rest = pairs[5:]
                if d["point"] == "off":
                    if rest:
                        kd.fail(log, lineno, "KJIT-off fpv-entry line has counters")
                else:
                    if not rest:
                        kd.fail(log, lineno, "KJIT-on fpv-entry line has no counters")
                    entry_ctr_schema.check(log, lineno, rest)
                    entry_ctr_rows.append((name, log, lineno, d["point"], d["kind"], num("calls"), num("round"), rest))

        if head is None or done is None:
            kd.fail(log, None, "no 'fpv-run: step=.. args=..' header or 'done' line")
        hl, hm = head
        dl, dm = done
        if hm.group(1) != dm.group(1):
            kd.fail(log, dl, f"done line is for step {dm.group(1)}, header for {hm.group(1)}")
        step = hm.group(1)
        if step not in ("bench", "lat", "entry"):
            kd.fail(log, hl, f"step {step!r} is not bench, lat or entry")
        args = hm.group(2).split()
        rounds, points = kd.number(log, hl, "rounds", args[0]), " ".join(args[1:])
        probe = bench_args = None
        if step in ("bench", "lat"):
            if run_dir is None:
                kd.fail(log, None, "no 'guest-run: ... run-dir=' line")
            probe, bench_args = run_script_settings(log, run_dir)
            if probe != (1 if step == "lat" else 0):
                kd.fail(log, hl, f"step {step} but the run script says FPV_PROBE={probe}")
        runs.add(log=name, step=step, rounds=rounds, points_in_order=points, profile=hm.group(3),
                 fpv_probe=probe, redis_benchmark_args=bench_args,
                 host_load1_before=kd.number(log, hl, "load", hm.group(4)),
                 host_load5_before=kd.number(log, hl, "load", hm.group(5)),
                 host_load15_before=kd.number(log, hl, "load", hm.group(6)),
                 host_load1_after=kd.number(log, dl, "load", dm.group(2)),
                 host_load5_after=kd.number(log, dl, "load", dm.group(3)),
                 host_load15_after=kd.number(log, dl, "load", dm.group(4)))

    tables = [runs]
    if redis_rows:
        keys = redis_schema.keys
        columns = ["log"] + [k for k in keys if k not in LAT_KEYS] + LAT_KEYS
        redis = kd.Table("redis_runs", columns)
        probe_of = {r[0]: r[5] for r in runs.rows}
        for name, log, lineno, pairs in redis_rows:
            d = dict(pairs)
            lat_present = [k in d for k in LAT_KEYS]
            if any(lat_present) and not all(lat_present):
                kd.fail(log, lineno, "line has only some of the lat_* keys")
            if any(lat_present) != bool(probe_of[name]):
                kd.fail(log, lineno, f"lat_* keys present={any(lat_present)} but FPV_PROBE={probe_of[name]}")
            row = {"log": name}
            for k in columns[1:]:
                if k in d:
                    row[k] = d[k] if k in ("point", "test") else kd.number(log, lineno, k, d[k])
                else:
                    row[k] = None
            if row["point"] not in POINTS:
                kd.fail(log, lineno, f"unknown point {row['point']!r}")
            redis.add(**row)
        tables.append(redis)
    if len(hist):
        tables.append(hist)
    if len(entry):
        tables.append(entry)
        keys = [k for k in entry_ctr_schema.keys]
        ctr = kd.Table("entry_cost_counters", ["log", "point", "kind", "calls", "round"] + keys)
        for name, log, lineno, point, kind, calls, rnd, rest in entry_ctr_rows:
            d = dict(rest)
            ctr.add(log=name, point=point, kind=kind, calls=calls, round=rnd,
                    **{k: (d[k] if k == "variant" else kd.number(log, lineno, k, d[k])) for k in keys})
        tables.append(ctr)
    meta = {"extracted_by": "tests/guest/host/extract_fpv.py", "source": "fpv-run.sh logs (branch exp/fp-bracket-neon)",
            "points": "off = KJIT off, v0 = fpvariant 0, A = 1, B = 2, B2 = 3"}
    return meta, tables


if __name__ == "__main__":
    kd.run_cli(__doc__, build, "json")
