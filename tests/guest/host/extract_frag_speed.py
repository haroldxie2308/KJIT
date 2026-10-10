#!/usr/bin/env python3
"""Fragment-code speed experiments (journal 2026-10-10, "Why translated fragment
code is slower than native" and "The EL1 RMW-chain cost is PSTATE.SSBS = 0 at EL1").

  extract_frag_speed.py RUN_DIR_OR_SERIAL_LOG... --out FILE.json

Inputs are the runs written by ub-run.sh (<runs>/ub-<label>/serial.log with the
host.txt next to it): ub-bench.sh code runs, exp_el1/exp_el0 microbenchmark runs and
the SSBS fact runs. Tables of the JSON file (a table is present when some log has
its lines):

  runs             one row per run: label, kernel command line, host load, guest command
  exp_ops          every "expN <op> ps_per_op ..." line: level el1|el0, op, occurrence
                   (n-th line of that op in that log and level: a log may run an op twice)
  code_speed_reps  every "ub off|on rep N" line (one timed repeat of code_speed), with the
                   insn_per_outer of the result line that closes the repeats
  code_speed_kjit  every "ub on kjit" line (in-kernel fraction, runtime entries per outer)
  facts            "ub:" header lines, sysfs vulnerability lines, kernel command line,
                   cpuinfo, dmesg and the exp ids/dssbs/ssbs lines, as run/source/key/value

Parsing of the "ub ..." lines is ub-summarize.py's (load_ub). Standard library only.
"""
import os
import re
import statistics

import kjit_data as kd

EXP_OP = re.compile(r"^(exp[01]) (exp_\w+) ps_per_op median=(\d+) min=(\d+) "
                    r"\(outer=(\d+) trips_per_outer=(\d+) ops=(\d+)\)$")
UB_HEADER = re.compile(r"^ub: ([\w ]+?): (.*)$")
VULN = re.compile(r"^VULN (\w+): (.*)$")
FACT_KV = re.compile(r"^FACT (cmdline|spec_store_bypass): (.*)$")
DMESG = re.compile(r"^(?:FACT dmesg|DMESG) \[\s*([\d.]+)\] (.*)$")
CPUINFO = re.compile(r"^CPUINFO ([^\t:]+)\t: (.*)$")
LEVEL = {"exp1": "el1", "exp0": "el0"}


def host_info(run_dir):
    """host.txt of ub-run.sh: five lines, strict."""
    path = os.path.join(run_dir, "host.txt")
    lines = list(kd.read_lines(path))
    if len(lines) != 5:
        kd.fail(path, None, f"expected 5 lines, found {len(lines)}")

    def first(lineno, prefix):
        text = lines[lineno][1]
        if not text.startswith(prefix):
            kd.fail(path, lines[lineno][0], f"expected a line starting with {prefix!r}")
        return text[len(prefix):]

    def pairs(lineno, keys):
        got = dict(kd.kv_pairs(path, lines[lineno][0], lines[lineno][1]))
        if list(got) != keys:
            kd.fail(path, lines[lineno][0], f"expected keys {keys}, found {list(got)}")
        return got

    l1 = pairs(0, ["label", "kpti", "profile"])
    append = first(1, "append=")
    l3 = pairs(2, ["waited_s", "load1_before"])
    cmd = first(3, "cmd=")
    l5 = pairs(4, ["load1_after", "guest_run_status"])
    ln = lambda i, k, d: kd.number(path, lines[i][0], k, d[k])
    return {
        "label": l1["label"], "kpti": ln(0, "kpti", l1), "profile": l1["profile"],
        "kernel_append": append, "waited_s": ln(2, "waited_s", l3), "host_load1_before": ln(2, "load1_before", l3),
        "host_load1_after": ln(4, "load1_after", l5), "guest_run_status": ln(4, "guest_run_status", l5), "cmd": cmd,
    }


def build(args):
    logs = []
    for a in args:
        logs.append(os.path.join(a, "serial.log") if os.path.isdir(a) else a)
    ubs = kd.ub_summarize()

    runs = kd.Table("runs", ["run", "kpti", "profile", "kernel_append", "waited_s", "host_load1_before",
                             "host_load1_after", "guest_run_status", "cmd", "log"])
    exp_ops = kd.Table("exp_ops", ["run", "level", "op", "occurrence", "median_ps_per_op", "min_ps_per_op",
                                   "outer", "trips_per_outer", "ops"])
    reps = kd.Table("code_speed_reps", ["run", "variant", "n", "kjit", "rep", "outer", "ns_per_outer",
                                        "insn_per_outer"])
    kjit = kd.Table("code_speed_kjit", ["run", "variant", "n", "in_kernel_frac", "runtime_entries_per_outer"])
    facts = kd.Table("facts", ["run", "source", "key", "value"])

    for log in logs:
        h = host_info(os.path.dirname(log))
        run = h["label"]
        runs.add(run=run, kpti=h["kpti"], profile=h["profile"], kernel_append=h["kernel_append"],
                 waited_s=h["waited_s"], host_load1_before=h["host_load1_before"],
                 host_load1_after=h["host_load1_after"], guest_run_status=h["guest_run_status"], cmd=h["cmd"],
                 log=os.path.basename(os.path.dirname(log)) + "/" + os.path.basename(log))

        occurrence = {}
        for lineno, text in kd.read_lines(log):
            m = EXP_OP.match(text)
            if m:
                level = LEVEL[m.group(1)]
                op = m.group(2)
                occurrence[(level, op)] = occurrence.get((level, op), 0) + 1
                f = ("median_ps_per_op", "min_ps_per_op", "outer", "trips_per_outer", "ops")
                v = [kd.number(log, lineno, f[i], m.group(3 + i)) for i in range(5)]
                exp_ops.add(run=run, level=level, op=op, occurrence=occurrence[(level, op)],
                            median_ps_per_op=v[0], min_ps_per_op=v[1], outer=v[2], trips_per_outer=v[3], ops=v[4])
                continue
            if text.startswith(("exp1 ", "exp0 ")):
                level_prefix, rest = text.split(" ", 1)
                if rest.startswith("exp_"):
                    kd.fail(log, lineno, f"unparsable exp op line: {text!r}")
                source = "exp_" + LEVEL[level_prefix]
                if "=" not in rest.split()[0]:
                    label, _, rest = rest.partition(" ")
                    source += "_" + label
                for k, v in kd.kv_pairs(log, lineno, rest):
                    facts.add(run=run, source=source, key=k, value=v)
                continue
            m = UB_HEADER.match(text)
            if m:
                facts.add(run=run, source="ub_header", key=m.group(1), value=m.group(2))
                continue
            m = VULN.match(text) or FACT_KV.match(text)
            if m:
                source = "cmdline" if m.group(1) == "cmdline" else "sysfs_vulnerability"
                facts.add(run=run, source=source, key=m.group(1), value=m.group(2))
                continue
            if text.startswith("CMDLINE "):
                facts.add(run=run, source="cmdline", key="cmdline", value=text[len("CMDLINE "):])
                continue
            m = DMESG.match(text)
            if m:
                facts.add(run=run, source="dmesg", key=m.group(1), value=m.group(2))
                continue
            if text.startswith("CPUINFO "):
                m = CPUINFO.match(text)
                if not m:
                    kd.fail(log, lineno, f"unparsable CPUINFO line: {text!r}")
                facts.add(run=run, source="cpuinfo", key=m.group(1), value=m.group(2))

        # ub-bench.sh code lines, parsed by ub-summarize.py's load_ub.
        pending = {}
        kjit_keys = None
        for r in ubs.load_ub([log]):
            where = (log, r["line"])
            try:
                if r["kind"] == "rep":
                    key = (r["variant"], r["n"], r["enabled"])
                    if (r["state"] == "on") != (r["enabled"] == "1"):
                        kd.fail(*where, f"state {r['state']} contradicts enabled={r['enabled']}")
                    pending.setdefault(key, []).append((r["rep"], kd.number(*where, "outer", r["outer"]),
                                                       kd.number(*where, "ns_per_outer", r["ns_per_outer"]),
                                                       r["line"]))
                elif r["kind"] == "result":
                    key = (r["variant"], r["n"], r["enabled"])
                    got = pending.pop(key, None)
                    if not got:
                        kd.fail(*where, f"result line without its rep lines (variant={key[0]} n={key[1]} enabled={key[2]})")
                    count = kd.number(*where, "reps", r["reps"])
                    if len(got) != count:
                        kd.fail(*where, f"result says reps={count}, {len(got)} rep lines precede it")
                    insn = kd.number(*where, "insn_per_outer", r["insn_per_outer"])
                    median = kd.number(*where, "median_ns_per_outer", r["median_ns_per_outer"])
                    if abs(statistics.median(x[2] for x in got) - median) > 0.0051:
                        kd.fail(*where, f"median of the rep lines {statistics.median(x[2] for x in got)} != "
                                        f"median_ns_per_outer={median}")
                    for rep, outer, ns, _ in got:
                        if kd.number(*where, "outer", r["outer"]) != outer:
                            kd.fail(*where, "outer differs between rep lines and result line")
                        reps.add(run=run, variant=key[0], n=kd.number(*where, "n", key[1]),
                                 kjit=r["state"], rep=int(rep), outer=outer, ns_per_outer=ns, insn_per_outer=insn)
                elif r["kind"] == "kjit":
                    keys = list(r)
                    if kjit_keys is None:
                        kjit_keys = keys
                    elif keys != kjit_keys:
                        kd.fail(*where, f"kjit line keys {keys} differ from the first one {kjit_keys}")
                    for need in ("variant", "n", "in_kernel_frac", "runtime_entries_per_outer"):
                        if need not in r:
                            kd.fail(*where, f"kjit line lacks {need}")
                    kjit.add(run=run, variant=r["variant"], n=kd.number(*where, "n", r["n"]),
                             in_kernel_frac=kd.number(*where, "in_kernel_frac", r["in_kernel_frac"]),
                             runtime_entries_per_outer=kd.number(*where, "runtime_entries_per_outer",
                                                                 r["runtime_entries_per_outer"]))
            except KeyError as e:
                kd.fail(*where, f"ub {r['kind']} line lacks key {e}")
        if pending:
            k = min(pending, key=lambda key: pending[key][0][3])
            kd.fail(log, pending[k][0][3], f"rep lines without a closing result line (variant={k[0]} n={k[1]} enabled={k[2]})")

    tables = [t for t in (runs, exp_ops, reps, kjit, facts) if len(t)]
    if not (len(exp_ops) or len(reps) or len(facts)):
        kd.fail(logs[0], None, "no exp, ub or fact lines in any log")
    meta = {"extracted_by": "tests/guest/host/extract_frag_speed.py", "source": "serial logs of ub-run.sh runs",
            "inputs": [os.path.basename(os.path.dirname(l)) for l in logs]}
    return meta, tables


if __name__ == "__main__":
    kd.run_cli(__doc__, build, "json")
