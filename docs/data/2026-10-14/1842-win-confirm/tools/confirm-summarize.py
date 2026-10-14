#!/usr/bin/env python3
"""Win confirmation of main (A20): KJIT on minus off, server CPU per request, paired inside each boot.

  confirm-summarize.py --runs RUNS_DIR --tag wc [--csv OUT] [--boots-csv OUT] [--sys-csv OUT] [--tables OUT]

Reads RUNS_DIR/ub-cond-<TAG>-k<0|1>-b<N>/{serial.log,host.txt} (tests/guest/host/cond-sweep.sh boots).
Server CPU per request = sum over the server's tasks of se.sum_exec_runtime (sched_ms) * 1000 / n.
A pair = the off run and the on run of one boot, cell and rep (the guest script alternates off,on / on,off);
gap = on - off, us per request. Per cell: median and quartiles over pairs; boots+ = boots whose median pair
gap is positive; CI = 95% percentile interval of the median pair gap from a cluster bootstrap (resample the
boots, then the pairs inside each, 5000 draws, seed 1); verdict: win = CI upper < 0, tie = CI contains 0,
lose = CI lower > 0.
"""
import argparse
import csv
import glob
import os
import random
import re
import statistics
import sys
from collections import defaultdict

COUNTERS = ["hook_calls", "syscalls_in_kernel", "fragment_entries", "exit_svc", "exit_bl", "exit_blr", "exit_br",
            "exit_ret", "exit_mem", "exit_unsupported", "exit_budget", "run_declined", "svc_declined",
            "fpsimd_entries", "translate_ok", "invalidated_fragments"]
KV = re.compile(r"(\w+)=(\S+)")


def quart(xs):
    xs = sorted(xs)
    if len(xs) < 2:
        return xs[0], xs[0], xs[0]
    q = statistics.quantiles(xs, n=4, method="inclusive")
    return q[0], statistics.median(xs), q[2]


def parse(runs_dir, tag):
    rows, boots, sysrows = [], {}, []
    pat = re.compile(r"^ub-cond-%s-(k[01])-b(\d+)$" % re.escape(tag))
    for d in sorted(glob.glob(os.path.join(runs_dir, "ub-cond-%s-*" % tag))):
        m = pat.match(os.path.basename(d))
        if not m:
            continue
        setting, boot = m.group(1), int(m.group(2))
        label = "%s-b%d" % (setting, boot)
        if not os.path.exists(os.path.join(d, "host.txt")):
            continue
        host = open(os.path.join(d, "host.txt")).read()
        mm = re.search(r"waited_s=(\d+) load1_before=([\d.]+)", host)
        waited, load = int(mm.group(1)), float(mm.group(2))
        la = re.search(r"load1_after=([\d.]+)", host)
        append = re.search(r"^append=(.*)$", host, re.M).group(1)
        n_run, done, forced = 0, False, 0
        for line in open(os.path.join(d, "serial.log"), errors="replace"):
            line = line.rstrip("\r\n")
            if "kernel page table isolation forced ON" in line:
                forced += 1
            if line.startswith("cond run "):
                kv = dict(KV.findall(line))
                kv.update(setting=setting, boot=boot, label=label, load1_before=load, waited_s=waited)
                rows.append(kv)
                n_run += 1
            elif line.startswith("cond: done"):
                done = True
            elif re.match(r"^ub (off|on) result ", line):
                kv = dict(KV.findall(line))
                sysrows.append(dict(setting=setting, boot=boot, label=label, kjit=line.split()[1], mode=kv["mode"],
                                    size=kv["size"], ns_per_syscall=kv["median_ns_per_syscall"]))
        boots[label] = dict(setting=setting, boot=boot, kernel_append=append, kpti_forced_on_lines=forced,
                            host_waited_s=waited, host_load1_before=load, host_load1_after=la.group(1) if la else "",
                            runs=n_run, finished=int(done))
    return rows, boots, sysrows


def derive(r):
    n = int(r["n"])
    r["kpti"] = 1 if r["setting"] == "k1" else 0
    r["transport"] = "unix" if r["cell"].startswith("unix_") else "tcp"
    r["cpu_us_per_req"] = float(r["sched_ms"]) * 1000.0 / n
    r["ticks_cpu_us_per_req"] = (int(r["ticks_u"]) + int(r["ticks_s"])) * 10000.0 / n
    r["ticks_u_us_per_req"] = int(r["ticks_u"]) * 10000.0 / n
    for c in COUNTERS:
        r[c + "_per_req"] = int(r[c]) / n
    r["blocks_per_kreq"] = int(r["nvol"]) * 1000.0 / n
    r["wake_ipi_per_kreq"] = int(r["ipi_other"]) * 1000.0 / n


def pairs_of(rows):
    by = defaultdict(dict)
    for r in rows:
        by[(r["kpti"], r["cell"], r["label"], r["rep"])][r["state"]] = r
    out = defaultdict(list)
    for (kpti, cell, label, rep), st in sorted(by.items()):
        if "off" in st and "on" in st:
            out[(kpti, cell)].append((label, int(rep), st["off"], st["on"]))
    return out


def boot_ci(pairs, gapf, draws=5000, seed=1):
    byb = defaultdict(list)
    for lab, _, off, on in pairs:
        byb[lab].append(gapf(off, on))
    labs = list(byb)
    rnd = random.Random(seed)
    meds = []
    for _ in range(draws):
        pool = []
        for _ in labs:
            v = byb[rnd.choice(labs)]
            pool.extend(rnd.choice(v) for _ in v)
        meds.append(statistics.median(pool))
    meds.sort()
    return meds[int(0.025 * draws)], meds[int(0.975 * draws) - 1]


WAKE_US_PER_IPI = 6.2
WAKE_US_PER_BLOCK = 9.1


def g_corr(off, on):
    n_off, n_on = int(off["n"]), int(on["n"])
    dipi = int(on["ipi_other"]) / n_on - int(off["ipi_other"]) / n_off
    dblk = int(on["nvol"]) / n_on - int(off["nvol"]) / n_off
    return on["cpu_us_per_req"] - off["cpu_us_per_req"] - WAKE_US_PER_IPI * dipi - WAKE_US_PER_BLOCK * dblk


def stats(pairs):
    g_sched = lambda off, on: on["cpu_us_per_req"] - off["cpu_us_per_req"]
    g_tick = lambda off, on: on["ticks_cpu_us_per_req"] - off["ticks_cpu_us_per_req"]
    gaps = [g_sched(o, n) for _, _, o, n in pairs]
    tg = [g_tick(o, n) for _, _, o, n in pairs]
    byb = defaultdict(list)
    for (lab, _, _, _), g in zip(pairs, gaps):
        byb[lab].append(g)
    bmed = {b: statistics.median(v) for b, v in byb.items()}
    q1, med, q3 = quart(gaps)
    lo, hi = boot_ci(pairs, g_sched)
    cg = [g_corr(o, n) for _, _, o, n in pairs]
    clo, chi = boot_ci(pairs, g_corr)
    cq1, cmed, cq3 = quart(cg)
    boots_neg = sum(1 for v in bmed.values() if v < 0)
    if hi < 0:
        verdict = "WIN" if boots_neg >= 0.75 * len(bmed) else "neg, <75% boots"
    elif lo > 0:
        verdict = "LOSE"
    else:
        verdict = "TIE"
    ons = [on for *_, on in pairs]
    offs = [off for _, _, off, _ in pairs]
    m = lambda rs, k: statistics.median(r[k] for r in rs)
    return dict(pairs=len(pairs), boots=len(bmed), boots_pos=sum(1 for v in bmed.values() if v > 0),
                boots_neg=boots_neg, pairs_neg=sum(1 for g in gaps if g < 0), gap=med, q1=q1, q3=q3, lo=lo, hi=hi,
                verdict=verdict, cgap=cmed, cq1=cq1, cq3=cq3, clo=clo, chi=chi,
                tick_gap=statistics.median(tg), off=m(offs, "cpu_us_per_req"), on=m(ons, "cpu_us_per_req"),
                sys=m(ons, "hook_calls_per_req"), ink=m(ons, "syscalls_in_kernel_per_req"),
                ent=m(ons, "fragment_entries_per_req"), fp=m(ons, "fpsimd_entries_per_req"),
                unsup=m(ons, "exit_unsupported_per_req"), decl=m(ons, "run_declined_per_req"),
                blk_off=m(offs, "blocks_per_kreq"), blk_on=m(ons, "blocks_per_kreq"),
                ipi_off=m(offs, "wake_ipi_per_kreq"), ipi_on=m(ons, "wake_ipi_per_kreq"),
                rps_off=m(offs, "rps") if False else statistics.median(float(r["rps"]) for r in offs),
                rps_on=statistics.median(float(r["rps"]) for r in ons),
                translate=sum(int(r["translate_ok"]) for r in ons), bmed=bmed)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", required=True)
    ap.add_argument("--tag", required=True)
    ap.add_argument("--csv")
    ap.add_argument("--boots-csv")
    ap.add_argument("--sys-csv")
    ap.add_argument("--tables")
    a = ap.parse_args()
    rows, boots, sysrows = parse(a.runs, a.tag)
    for r in rows:
        derive(r)
    for b in boots.values():
        if not b["finished"]:
            print("WARNING: boot %s%d did not finish" % (b["setting"], b["boot"]), file=sys.stderr)
    if a.csv:
        cols = (["label", "boot", "kpti", "cell", "srv", "transport", "test", "n", "c", "p", "d", "thr", "rep", "order", "state",
                 "rps", "wall_cs", "cpu_us_per_req", "ticks_cpu_us_per_req", "ticks_u_us_per_req", "sched_ms", "ticks_u",
                 "ticks_s", "nvol", "ninv", "c0_busy", "c0_idle", "ipi_c0", "ipi_other", "load1_before", "waited_s"] + COUNTERS)
        names = {"state": "kjit", "label": "boot_label", "boot": "boot", "srv": "server_profile", "n": "requests",
                 "c": "clients", "p": "pipeline", "d": "value_bytes", "thr": "benchmark_threads", "rps": "req_per_s",
                 "wall_cs": "wall_cs", "sched_ms": "sched_exec_ms", "ticks_u": "utime_ticks", "ticks_s": "stime_ticks",
                 "nvol": "voluntary_switches", "ninv": "involuntary_switches", "c0_busy": "cpu0_busy_ticks",
                 "c0_idle": "cpu0_idle_ticks", "ipi_c0": "ipi_cpu0", "ipi_other": "ipi_cpus1_3", "load1_before": "host_load1_before",
                 "waited_s": "host_waited_s", "order": "rep_order"}
        with open(a.csv, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow([names.get(c, c) for c in cols])
            for r in rows:
                w.writerow([("%.5f" % r[c]) if isinstance(r.get(c), float) else r.get(c, "") for c in cols])
    if a.boots_csv:
        with open(a.boots_csv, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["boot_label", "kpti", "kernel_append", "kpti_forced_on_lines", "host_waited_s", "host_load1_before",
                        "host_load1_after", "runs", "finished"])
            for lab, b in sorted(boots.items()):
                w.writerow([lab, 1 if b["setting"] == "k1" else 0, b["kernel_append"], b["kpti_forced_on_lines"],
                            b["host_waited_s"], b["host_load1_before"], b["host_load1_after"], b["runs"], b["finished"]])
    if a.sys_csv:
        with open(a.sys_csv, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["boot_label", "kpti", "kjit", "mode", "size", "ns_per_syscall"])
            for r in sysrows:
                w.writerow([r["label"], 1 if r["setting"] == "k1" else 0, r["kjit"], r["mode"], r["size"], r["ns_per_syscall"]])
    pt = pairs_of(rows)
    out = []
    # boots table
    out.append("### Boots\n")
    out.append("| boot | kernel append | KPTI forced-ON lines | host load1 before | host wait (s) | runs |")
    out.append("|---|---|---|---|---|---|")
    for lab, b in sorted(boots.items(), key=lambda kv: (kv[1]["setting"], kv[1]["boot"])):
        out.append("| %s | `%s` | %d | %.2f | %d | %d |" % (lab, b["kernel_append"].replace("console=ttyAMA0 panic=-1 nokaslr ", ""),
                                                          b["kpti_forced_on_lines"], b["host_load1_before"], b["host_waited_s"], b["runs"]))
    out.append("")
    by_sys = defaultdict(lambda: defaultdict(list))
    for r in sysrows:
        if r["size"] == "1" and r["mode"] == "getppid":
            by_sys[r["setting"]][r["kjit"]].append(float(r["ns_per_syscall"]))
    out.append("### Null syscall (getppid, ns; median over boots [min..max])\n")
    out.append("| setting | boots | KJIT off (native) | KJIT on (in kernel) | sigma (saving) |")
    out.append("|---|---|---|---|---|")
    for s in sorted(by_sys):
        o, n = by_sys[s]["off"], by_sys[s]["on"]
        out.append("| %s | %d | %.1f [%.1f..%.1f] | %.1f [%.1f..%.1f] | %.1f |" % (
            s, len(o), statistics.median(o), min(o), max(o), statistics.median(n), min(n), max(n), statistics.median(o) - statistics.median(n)))
    out.append("")
    cell_order = []
    for r in rows:
        if r["cell"] not in cell_order:
            cell_order.append(r["cell"])
    for kpti, name in ((1, "KPTI forced on (k1)"), (0, "KPTI off (k0)")):
        out.append("### %s: server CPU per request, KJIT on minus off\n" % name)
        out.append("sched = `sum_exec_runtime`; gap = on - off per pair (us per request), median [Q1..Q3]; CI = 95% cluster bootstrap over boots; "
                   "boots- = boots with a negative median pair gap; pairs- = pairs with gap < 0; tick gap = same gap from utime+stime ticks; "
                   "sys/req = hook calls, in-kernel/req, entries/req = fragment entries per request of the on runs; unsup = Unsupported exits per request; "
                   "blocks = server voluntary switches per 1000 requests off -> on.\n")
        out.append("| cell | pairs | boots- | pairs- | off | on | on - off [Q1..Q3] | 95% CI | verdict | corrected [Q1..Q3] | corrected 95% CI | tick gap | sys/req | entries/req | unsup/req | blocks/kreq off -> on | wake IPI/kreq off -> on | per-boot medians |")
        out.append("|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|")
        for c in cell_order:
            if (kpti, c) not in pt:
                continue
            s = stats(pt[(kpti, c)])
            bm = " ".join("%+.2f" % v for _, v in sorted(s["bmed"].items()))
            out.append("| %s | %d | %d/%d | %d/%d | %.3f | %.3f | %+.3f [%+.3f..%+.3f] | [%+.3f..%+.3f] | %s | %+.3f [%+.3f..%+.3f] | [%+.3f..%+.3f] | %+.3f | %.3f | %.3f | %.4f | %.1f -> %.1f | %.1f -> %.1f | %s |" % (
                c, s["pairs"], s["boots_neg"], s["boots"], s["pairs_neg"], s["pairs"], s["off"], s["on"], s["gap"], s["q1"], s["q3"], s["lo"], s["hi"],
                s["verdict"], s["cgap"], s["cq1"], s["cq3"], s["clo"], s["chi"], s["tick_gap"], s["sys"], s["ent"], s["unsup"],
                s["blk_off"], s["blk_on"], s["ipi_off"], s["ipi_on"], bm))
        out.append("")
    text = "\n".join(out)
    if a.tables:
        open(a.tables, "w").write(text + "\n")
    else:
        print(text)


if __name__ == "__main__":
    main()
