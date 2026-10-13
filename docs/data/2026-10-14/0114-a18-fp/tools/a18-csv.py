#!/usr/bin/env python3
"""One CSV for the A18 measurement: every measured run of both parts.

  a18-csv.py OUT.csv RUNS_DIR

RUNS_DIR holds ub-<module>-std-k1-b<N>/serial.log (ub-standard.sh, the UB protocol) and
ub-cond-<module>-k1-b<N>/serial.log (cond-sweep.sh) of the boots. Columns: part (std | aof), module, kpti, boot, cell,
srv, test, size (-d), clients, pipeline, rep, kjit (off | on), requests, req_per_s,
cpu_us_per_req + cpu_metric (std: utime+stime ticks of the server, 10 ms; aof: sum of se.sum_exec_runtime), load1_before
(host.txt of the boot), and the KJIT debugfs counter deltas of the run.
Standard library only; the loaders are those of tests/guest/host/ub-arena.py and cond-modules.py (same directory).
"""
import csv
import glob
import importlib.util
import os
import re
import sys

here = os.path.dirname(os.path.abspath(__file__))


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


root = os.path.abspath(os.path.join(here, "..", "..", ".."))
out_path, runs = sys.argv[1], sys.argv[2]
ub_arena = load_module("ub_arena", os.path.join(os.environ["A18_TREE"], "tests/guest/host/ub-arena.py"))
cond = load_module("cond_modules", os.path.join(here, "cond-modules.py"))

std_args, cond_args = [], []
for path in sorted(glob.glob(os.path.join(runs, "ub-*-std-k1-b*", "serial.log"))):
    m = re.search(r"ub-(\w+)-std-k1-b(\d+)", path)
    std_args.append(f"{m.group(1)}:1:{m.group(2)}={path}")
for path in sorted(glob.glob(os.path.join(runs, "ub-cond-*-k1-b*", "serial.log"))):
    m = re.search(r"ub-cond-(\w+)-k1-b(\d+)", path)
    cond_args.append(f"{m.group(1)}:{m.group(2)}={path}")

counters = ["hook_calls", "syscalls_in_kernel", "fragment_entries", "exit_svc", "exit_bl", "exit_blr", "exit_br",
            "exit_ret", "exit_mem", "exit_unsupported", "exit_budget", "run_declined", "svc_declined",
            "fpsimd_entries", "translate_ok", "invalidated_fragments"]
cols = ["part", "module", "kpti", "boot", "cell", "srv", "test", "size", "clients", "pipeline", "rep", "kjit",
        "requests", "req_per_s", "cpu_us_per_req", "cpu_metric", "load1_before"] + counters
rows = []
for r in ub_arena.load(std_args):
    rows.append({"part": "std", "module": r["module"], "kpti": r["kpti"], "boot": r["boot"],
                 "cell": f"{r['test']}_d{r['size']}", "srv": "base", "test": r["test"], "size": r["size"],
                 "clients": 50, "pipeline": 1, "rep": r["rep"], "kjit": r["kjit"], "requests": r["requests"],
                 "req_per_s": r["req_per_s"], "cpu_us_per_req": r["cpu_us_per_req"], "cpu_metric": "ticks",
                 "load1_before": r["load1_before"], **{c: r[c] for c in counters}})
crow, _ = cond.load(cond_args)
for r in crow:
    host = os.path.join(runs, f"ub-cond-{r['module']}-k1-b{r['boot']}", "host.txt")
    m = re.search(r"load1_before=(\S+)", open(host).read()) if os.path.exists(host) else None
    rows.append({"part": "aof", "module": r["module"], "kpti": 1, "boot": r["boot"], "cell": r["cell"],
                 "srv": r["srv"], "test": r["test"], "size": r["value_bytes"], "clients": r["clients"],
                 "pipeline": r["pipeline"], "rep": r["rep"], "kjit": r["kjit"], "requests": r["requests"],
                 "req_per_s": r["req_per_s"], "cpu_us_per_req": r["cpu_us_per_req"], "cpu_metric": "sched",
                 "load1_before": m.group(1) if m else "", **{c: r[c] for c in counters}})
with open(out_path, "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=cols)
    w.writeheader()
    w.writerows(rows)
print(f"{len(rows)} rows", file=sys.stderr)
