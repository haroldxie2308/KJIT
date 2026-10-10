#!/usr/bin/env python3
"""Redis campaigns (journal 2026-09-27: "K4: redis under KJIT", "A8 implementation",
"A9b implementation", "A10: chain budget and counter reads").

  extract_k4_campaign.py RUN_DIR... --out FILE.json

Inputs are either campaign directories written by scripts/redis-campaign.sh
(k4-<profile>-<time>/ with campaign.log, suite-off.log, suite-on.log and
suite-on/suite/stats.{before,after}) or the run directory of a single k4-bench.sh boot
(<runs>/<run>/serial.log). Tables (present when the inputs have the lines):

  campaigns          one row per input directory: kind campaign|k4-bench, profile, iterations and
                     requests per benchmark test (campaigns), the command the benchmark guest ran
                     (kjit-run.sh of the guest run directory)
  suites             redis test suite per campaign: mode off|on (KJIT), ok/err/skip/ignore, runtest exit
  suite_kjit_stats   KJIT module counters around the KJIT-on suite: counter, before, after (the
                     delta is what the suite did; fpsimd_run_max_ns and chain_max are not deltas;
                     a chain_hist_* bucket the kernel had not printed yet before the suite has
                     an empty `before`)
  bench_phases       one row per benchmark phase (default | pipelined | clients256) and iteration:
                     in-kernel syscalls, hook calls, fragment entries, exits, FP/SIMD counters
  bench_tests        every redis-benchmark test line: req_per_s and p50_ms
  bench_chain_hist   "entries per hook call" histogram of a phase (lo..hi entries: hook calls)
  bench_unsupported_top  the most frequent unsupported instruction words of a phase
  checks             adversarial tests and the off/on dataset consistency check per iteration

A phase line group the log does not have (fields added by later modules: fpsimd counters,
histogram) is empty for the whole log; a log that has it for some phases only is an error.
The campaign's K2 micro tests and the adversarial tests' own counters are not extracted.
Standard library only.
"""
import os
import re

import kjit_data as kd

PHASES = ("default", "pipelined", "clients256")
BENCH_HEAD = re.compile(r"^k4-bench: (default|pipelined|clients256) \((.*)\):$")
BENCH_TEST = re.compile(r"^k4:     (.+): ([\d.]+) requests per second, p50=([\d.]+) msec$")
ITERATION = re.compile(r"^k4: iteration (\d+)$")
ALL_PASS = re.compile(r"^k4: ALL PASS \((\d+) iterations, (\d+) requests per benchmark test\)$")
LINE1 = re.compile(r"^k4:   (\w+): in_kernel=(\d+)/(\d+) syscalls \(([\d.]+)%\) entries=(\d+) chains=(\d+) "
                   r"chain_cap=(\d+) translated=(\d+) \(entry_unsupported=(\d+) compile=(\d+) verify=(\d+) "
                   r"capped=(\d+) neg=(\d+)\) invalidated=(\d+) released=(\d+)$")
LINE2 = re.compile(r"^k4:   (\w+): exits svc=(\d+) bl=(\d+) blr=(\d+) br=(\d+) ret=(\d+) mem=(\d+) "
                   r"unsupported=(\d+) budget=(\d+) invalid=(\d+) svc_declined=(\d+)$")
LINE3 = re.compile(r"^k4:   (\w+): fpsimd entries=(\d+) restores=(\d+) exit_mem=(\d+) refused_sve_sme=(\d+)$")
HIST = re.compile(r"^k4:   (\w+): entries per hook call: (.*) \(chain_max since load (\d+)\)$")
TOP = re.compile(r"^k4:   (\w+): unsupported_top \(word\(exits/entry_stops\)\): ?(.*)$")
ADV = re.compile(r"^k4-adv: (\w+) (PASS|FAIL)\b")
CONSISTENCY = re.compile(r"^k4-bench: consistency (PASS|FAIL)\b")
SUITE_OK = re.compile(r"^k4-suite: ok=(\d+) err=(\d+) skip=(\d+) ignore=(\d+)$")
SUITE_DONE = re.compile(r"^k4-suite: done \(runtest exit (\d+)\)$")
SUITE_HEAD = re.compile(r"^k4-suite: kjit=([01]) runtest (.*)$")

PHASE_COLS = ["in_kernel_syscalls", "hook_calls", "in_kernel_pct", "fragment_entries", "chains", "chain_cap",
              "translated", "entry_unsupported", "compile_failed", "verify_rejected", "capped", "neg_hits",
              "invalidated", "released", "exit_svc", "exit_bl", "exit_blr", "exit_br", "exit_ret", "exit_mem",
              "exit_unsupported", "exit_budget", "exit_invalid", "svc_declined", "fpsimd_entries",
              "fpsimd_restores", "fpsimd_exit_mem", "fpsimd_refused_sve_sme", "chain_max_since_load"]


def read_stats(path):
    out = []
    for lineno, text in kd.read_lines(path):
        name, sep, value = text.partition(" ")
        if not sep:
            kd.fail(path, lineno, "expected '<counter> <value>'")
        out.append((name, kd.number(path, lineno, name, value)))
    if not out:
        kd.fail(path, None, "empty stats file")
    return out


def build(run_dirs):
    campaigns = kd.Table("campaigns", ["campaign", "kind", "profile", "iterations", "requests_per_benchmark_test",
                                       "guest_command"])
    suites = kd.Table("suites", ["campaign", "mode", "runtest_args", "ok", "err", "skip", "ignore", "runtest_exit"])
    stats = kd.Table("suite_kjit_stats", ["campaign", "counter", "before", "after"])
    phases = kd.Table("bench_phases", ["campaign", "iteration", "phase", "benchmark_args"] + PHASE_COLS)
    tests = kd.Table("bench_tests", ["campaign", "iteration", "phase", "test", "req_per_s", "p50_ms"])
    hist = kd.Table("bench_chain_hist", ["campaign", "iteration", "phase", "entries_lo", "entries_hi", "hook_calls"])
    top = kd.Table("bench_unsupported_top", ["campaign", "iteration", "phase", "word", "exits", "entry_stops"])
    checks = kd.Table("checks", ["campaign", "iteration", "kind", "name", "result"])

    for run_dir in run_dirs:
        name = os.path.basename(os.path.normpath(run_dir))
        campaign_log = os.path.join(run_dir, "campaign.log")
        is_campaign = os.path.exists(campaign_log)
        log = campaign_log if is_campaign else os.path.join(run_dir, "serial.log")
        m = re.match(r"^(?:k4-)?(kjit-guest(?:-debug)?)-\d{8}-\d{6}$", name)
        if not m or name.startswith("k4-") != is_campaign:
            kd.fail(run_dir, None, "directory name is not k4-<profile>-<date>-<time> (campaign) or "
                                   "<profile>-<date>-<time> (k4-bench run)")
        profile = m.group(1)
        script = os.path.join(run_dir, "campaign" if is_campaign else "", "kjit-run.sh")
        script_lines = [t for _, t in kd.read_lines(script)]
        if len(script_lines) != 3 or script_lines[:2] != ["#!/bin/sh", "set -e"]:
            kd.fail(script, None, "expected '#!/bin/sh', 'set -e' and one command line")
        guest_command = script_lines[2]

        iteration = None
        phase = args = None
        iterations_marked, all_pass = 0, None
        phase_rows = {}
        for lineno, text in kd.read_lines(log):
            m = ITERATION.match(text)
            if m:
                iteration = kd.number(log, lineno, "iteration", m.group(1))
                iterations_marked += 1
                continue
            m = ALL_PASS.match(text)
            if m:
                all_pass = (kd.number(log, lineno, "iterations", m.group(1)),
                            kd.number(log, lineno, "requests", m.group(2)))
                continue
            m = BENCH_HEAD.match(text)
            if m:
                phase, args = m.group(1), m.group(2)
                key = (iteration, phase)
                if key in phase_rows:
                    kd.fail(log, lineno, f"phase {phase} of iteration {iteration} appears twice")
                phase_rows[key] = {"line": lineno, "args": args}
                continue
            m = BENCH_TEST.match(text)
            if not m and text.startswith("k4:     "):
                kd.fail(log, lineno, f"unparsable benchmark test line: {text!r}")
            if m:
                if phase is None:
                    kd.fail(log, lineno, "benchmark test line before any 'k4-bench: <phase>' header")
                tests.add(campaign=name, iteration=iteration, phase=phase, test=m.group(1),
                          req_per_s=kd.number(log, lineno, "req/s", m.group(2)),
                          p50_ms=kd.number(log, lineno, "p50", m.group(3)))
                continue
            m = CONSISTENCY.match(text)
            if not m and text.startswith("k4-bench: consistency"):
                kd.fail(log, lineno, f"unparsable consistency line: {text!r}")
            if m:
                checks.add(campaign=name, iteration=iteration, kind="consistency", name="dataset_off_on",
                           result=m.group(1))
                continue
            m = ADV.match(text)
            if not m and text.startswith("k4-adv: ") and text != "k4-adv: ALL PASS":
                kd.fail(log, lineno, f"unparsable adversarial test line: {text[:80]!r}")
            if m and m.group(1) != "ALL":
                checks.add(campaign=name, iteration=iteration, kind="adversarial", name=m.group(1),
                           result=m.group(2))
                continue
            # k4:   <phase>: ... lines of the benchmark phases (other names are adversarial tests)
            m = LINE1.match(text) or LINE2.match(text) or LINE3.match(text) or HIST.match(text) or TOP.match(text)
            if not m or m.group(1) not in PHASES:
                if text.startswith("k4:   ") and re.match(r"^k4:   (default|pipelined|clients256): ", text) \
                        and not re.match(r"^k4:   \w+: hot: ", text):
                    kd.fail(log, lineno, f"unparsable benchmark phase line: {text!r}")
                continue
            ph = m.group(1)
            row = phase_rows.get((iteration, ph))
            if row is None:
                kd.fail(log, lineno, f"counter line of phase {ph} without its 'k4-bench: {ph}' header")
            n = lambda i, f: kd.number(log, lineno, f, m.group(i))
            if m.re is LINE1:
                row["l1"] = dict(in_kernel_syscalls=n(2, "in_kernel"), hook_calls=n(3, "syscalls"),
                                 in_kernel_pct=n(4, "pct"), fragment_entries=n(5, "entries"), chains=n(6, "chains"),
                                 chain_cap=n(7, "chain_cap"), translated=n(8, "translated"),
                                 entry_unsupported=n(9, "entry_unsupported"), compile_failed=n(10, "compile"),
                                 verify_rejected=n(11, "verify"), capped=n(12, "capped"), neg_hits=n(13, "neg"),
                                 invalidated=n(14, "invalidated"), released=n(15, "released"))
            elif m.re is LINE2:
                row["l2"] = dict(exit_svc=n(2, "svc"), exit_bl=n(3, "bl"), exit_blr=n(4, "blr"), exit_br=n(5, "br"),
                                 exit_ret=n(6, "ret"), exit_mem=n(7, "mem"), exit_unsupported=n(8, "unsupported"),
                                 exit_budget=n(9, "budget"), exit_invalid=n(10, "invalid"),
                                 svc_declined=n(11, "svc_declined"))
            elif m.re is LINE3:
                row["l3"] = dict(fpsimd_entries=n(2, "fpsimd entries"), fpsimd_restores=n(3, "restores"),
                                 fpsimd_exit_mem=n(4, "exit_mem"), fpsimd_refused_sve_sme=n(5, "refused"))
            elif m.re is HIST:
                row["chain_max"] = n(3, "chain_max")
                row["hist_line"] = lineno
                for tok in m.group(2).split():
                    rng, sep, cnt = tok.partition(":")
                    lo, dash, hi = rng.partition("-")
                    if not sep or not dash:
                        kd.fail(log, lineno, f"expected lo-hi:count, got {tok!r}")
                    hist.add(campaign=name, iteration=iteration, phase=ph, entries_lo=kd.number(log, lineno, "lo", lo),
                             entries_hi=kd.number(log, lineno, "hi", hi), hook_calls=kd.number(log, lineno, "count", cnt))
            else:  # TOP
                row["top"] = True
                for tok in m.group(2).split():
                    mm = re.match(r"^(0x[0-9a-f]+)\((\d+)/(\d+)\)$", tok)
                    if not mm:
                        kd.fail(log, lineno, f"expected 0xWORD(exits/entry_stops), got {tok!r}")
                    top.add(campaign=name, iteration=iteration, phase=ph, word=mm.group(1),
                            exits=kd.number(log, lineno, "exits", mm.group(2)),
                            entry_stops=kd.number(log, lineno, "entry_stops", mm.group(3)))

        if not phase_rows:
            kd.fail(log, None, "no 'k4-bench: <phase>' benchmark in the log")
        has_l3 = {("l3" in r) for r in phase_rows.values()}
        has_hist = {("chain_max" in r) for r in phase_rows.values()}
        if len(has_l3) != 1 or len(has_hist) != 1:
            kd.fail(log, None, "some benchmark phases have the fpsimd or histogram line and some do not")
        for (it, ph), row in phase_rows.items():
            for need in ("l1", "l2", "top"):
                if need not in row:
                    kd.fail(log, row["line"], f"phase {ph} lacks its {need} line")
            vals = dict(row["l1"], **row["l2"])
            vals.update(row.get("l3", dict(fpsimd_entries=None, fpsimd_restores=None, fpsimd_exit_mem=None,
                                           fpsimd_refused_sve_sme=None)))
            vals["chain_max_since_load"] = row.get("chain_max")
            phases.add(campaign=name, iteration=it, phase=ph, benchmark_args=row["args"], **vals)

        if not is_campaign:
            campaigns.add(campaign=name, kind="k4-bench", profile=profile, iterations=None,
                          requests_per_benchmark_test=None, guest_command=guest_command)
        if is_campaign:
            if all_pass is None:
                kd.fail(log, None, "no 'k4: ALL PASS (N iterations, M requests per benchmark test)' line")
            if all_pass[0] != iterations_marked:
                kd.fail(log, None, f"ALL PASS says {all_pass[0]} iterations, {iterations_marked} 'k4: iteration' lines")
            campaigns.add(campaign=name, kind="campaign", profile=profile, iterations=all_pass[0],
                          requests_per_benchmark_test=all_pass[1], guest_command=guest_command)
            logs = {mode: os.path.join(run_dir, f"suite-{mode}.log") for mode in ("off", "on")}
            present = [os.path.exists(p) for p in logs.values()]
            if any(present) and not all(present):
                kd.fail(run_dir, None, "only one of suite-off.log and suite-on.log exists")
            for mode, path in logs.items():
                if not all(present):
                    break
                head = ok = done = None
                for lineno, text in kd.read_lines(path):
                    m = SUITE_HEAD.match(text)
                    if m:
                        head = (lineno, m)
                    m = SUITE_OK.match(text)
                    if m:
                        ok = (lineno, m)
                    m = SUITE_DONE.match(text)
                    if m:
                        done = (lineno, m)
                if not (head and ok and done):
                    kd.fail(path, None, "missing k4-suite header, ok=... or done line")
                if head[1].group(1) != ("1" if mode == "on" else "0"):
                    kd.fail(path, head[0], f"suite-{mode}.log ran with kjit={head[1].group(1)}")
                g = ok[1]
                suites.add(campaign=name, mode=mode, runtest_args=head[1].group(2),
                           ok=kd.number(path, ok[0], "ok", g.group(1)), err=kd.number(path, ok[0], "err", g.group(2)),
                           skip=kd.number(path, ok[0], "skip", g.group(3)),
                           ignore=kd.number(path, ok[0], "ignore", g.group(4)),
                           runtest_exit=kd.number(path, done[0], "exit", done[1].group(1)))
            if all(present):
                before = read_stats(os.path.join(run_dir, "suite-on", "suite", "stats.before"))
                after = read_stats(os.path.join(run_dir, "suite-on", "suite", "stats.after"))
                after_path = os.path.join(run_dir, "suite-on", "suite", "stats.after")
                b = dict(before)
                a_names = [k for k, _ in after]
                if [k for k in a_names if k in b] != [k for k, _ in before]:
                    kd.fail(after_path, None, "stats.before has counters that stats.after lacks, or in another order")
                for k, a in after:
                    # The kernel prints a chain_hist_* bucket only once it is non-zero, so stats.before
                    # may lack it (before is then empty); every other counter is always printed.
                    if k not in b and not k.startswith("chain_hist_"):
                        kd.fail(after_path, None, f"counter {k} is not in stats.before")
                    stats.add(campaign=name, counter=k, before=b.get(k), after=a)

    tables = [t for t in (campaigns, suites, stats, phases, tests, hist, top, checks) if len(t)]
    meta = {"extracted_by": "tests/guest/host/extract_k4_campaign.py",
            "source": "redis-campaign.sh output directories and k4-bench.sh run directories"}
    return meta, tables


if __name__ == "__main__":
    kd.run_cli(__doc__, build, "json")
