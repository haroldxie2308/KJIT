"""EXPERIMENT (exp/attrib-a22). Parses the serial logs of attrib-a22.sh / micro-a22.sh boots into tidy tables.

  from parse import load_runs
  runs, timers, boots = load_runs(RUNS_DIR)    # RUNS_DIR/ub-at22-*/serial.log

runs: one row per measured run: the `atr` line keys, derived per-request columns, the per-CPU interrupt and
/proc/stat deltas (`atrd` line), the module's timers of the T states (`atrx` line, ticks and us per request).
boots: one row per boot (label, type, kpti, module, host wait/load, x_micro, svc_bench items).
"""
import glob
import os
import re

import numpy as np
import pandas as pd

KV = re.compile(r"(\w+)=(\S+)")


def num(v):
    try:
        return int(v)
    except ValueError:
        try:
            return float(v)
        except ValueError:
            return v


def parse_timers(toks):
    d = {}
    i = 0
    while i < len(toks):
        t = toks[i]
        if t.endswith("_by_nr"):
            j = i + 1
            while j + 2 < len(toks) and toks[j] in ("epoll_pwait", "read", "write", "other"):
                d[f"{t}_{toks[j]}_t"] = int(toks[j + 1])
                d[f"{t}_{toks[j]}_n"] = int(toks[j + 2])
                j += 3
            i = j
        else:
            d[t] = int(toks[i + 1])
            i += 2
    return d


def load_boot(label, path):
    text = open(path, errors="replace").read().splitlines()
    info = {"label": label, "kpti": 1 if any("atr: cmdline:" in l and "kpti=1" in l for l in text) else 0}
    m = re.match(r"at22-([A-Z])-k(\d)-b(\d+)", label)
    if m:
        info["type"], info["boot"] = m.group(1), int(m.group(3))
    runs, atrd, atrx = {}, {}, {}
    micro = []
    for l in text:
        l = l.strip()
        if l.startswith("atr: x_micro"):
            for k, v in re.findall(r"(\w+_ps) (\d+)", l):
                info.setdefault("x_micro_" + k, []).append(int(v))
        elif l.startswith("atr: svc_bench") or l.startswith("atr: x_delay"):
            mm = re.search(r"mode=(\S+) .*median_ns_per_syscall=([\d.]+)", l)
            dd = re.match(r"atr: x_delay (\d+)", l)
            if mm:
                key = f"svc_{mm.group(1)}" + (f"_delay{dd.group(1)}" if dd else "")
                info.setdefault(key, []).append(float(mm.group(2)))
        elif l.startswith("atr seq="):
            d = {k: num(v) for k, v in KV.findall(l)}
            runs[d["seq"]] = d
        elif l.startswith("atrd seq="):
            m2 = re.match(r"atrd seq=(\d+)(.*)", l)
            seq = int(m2.group(1))
            d = {}
            for k, v in KV.findall(m2.group(2)):
                if k.startswith("stat_c"):
                    f = [int(x) for x in v.split(":")]
                    c = k[len("stat_c"):]
                    for name, x in zip(["user", "nice", "sys", "idle", "iowait", "irq", "sirq", "steal"], f):
                        d[f"cpu{c}_{name}"] = x
                else:
                    d[k] = int(v)
            atrd[seq] = d
        elif l.startswith("atrx seq="):
            m2 = re.match(r"atrx seq=(\d+) (.*)", l)
            atrx[int(m2.group(1))] = parse_timers(m2.group(2).split())
    rows = []
    for seq, d in runs.items():
        r = dict(d)
        r.update({k: v for k, v in atrd.get(seq, {}).items()})
        if seq in atrx:
            r.update({"x_" + k: v for k, v in atrx[seq].items()})
        r["label"] = label
        r["kpti"] = info["kpti"]
        r["type"] = info.get("type")
        r["boot"] = info.get("boot")
        rows.append(r)
    return info, rows


def derive(runs):
    n = runs["n"]
    runs["cpu_us"] = runs["sched_ms"] * 1000.0 / n
    runs["user_us"] = runs["ticks_u"] * 1e4 / n
    runs["sys_us"] = runs["ticks_s"] * 1e4 / n
    runs["nvol_k"] = runs["nvol"] * 1000.0 / n
    runs["ninv_k"] = runs["ninv"] * 1000.0 / n
    for c in ("0", "1", "2", "3"):
        for k in ("IPI0", "IPI1"):
            col = f"int_{k}_c{c}"
            if col not in runs.columns:
                runs[col] = 0
    runs = runs.fillna({c: 0 for c in runs.columns if c.startswith("int_") or c.startswith("cpu")})
    # IPIs received on the client CPUs (1-3) = wake-ups of load generator threads sent by the server (IPI1 = function call,
    # the remote wake-up queue; IPI0 = reschedule), IPIs received on CPU 0 = wake-ups of the server by the clients.
    runs["ipi_cl_k"] = sum(runs[f"int_{k}_c{c}"] for k in ("IPI0", "IPI1") for c in ("1", "2", "3")) * 1000.0 / n
    runs["ipi_c0_k"] = sum(runs[f"int_{k}_c0"] for k in ("IPI0", "IPI1")) * 1000.0 / n
    tot = sum(runs[f"cpu0_{x}"] for x in ("user", "nice", "sys", "idle", "iowait", "irq", "sirq", "steal"))
    runs["c0_idle_frac"] = runs["cpu0_idle"] / tot.replace(0, np.nan)
    for c in ["hook_calls", "syscalls_in_kernel", "fragment_entries", "fpsimd_entries", "chains", "exit_svc", "exit_bl",
              "exit_blr", "exit_br", "exit_ret", "exit_mem", "exit_unsupported", "exit_budget", "run_declined",
              "svc_declined", "ibtc_miss_cold", "ibtc_miss_conflict", "ibtc_miss_other", "ibtc_fpsimd_boundary"]:
        if c in runs.columns:
            runs[c + "_pr"] = runs[c] / n
    return runs


def timers_us(runs, boots):
    """Add `t_*_us` (per request, raw) and `c_*_us` (corrected for the timers' own cost) columns to the T-state rows."""
    mic = boots.set_index("label")
    for lab, g in runs.groupby("label"):
        idx = g.index[g["x_hook_t"].notna()] if "x_hook_t" in g else []
        if len(idx) == 0:
            continue
        m = mic.loc[lab]
        L = np.median(m["x_micro_cntvct_read_ps"]) / 1000.0  # ns per counter read
        P = np.median(m["x_micro_percpu_inc_ps"]) / 1000.0  # ns per this_cpu_add/inc
        hz = g.loc[idx, "x_cntfrq"].iloc[0]
        tick_ns = 1e9 / hz
        n = runs.loc[idx, "n"]
        r = runs.loc[idx]
        for k in ("hook", "fnofp", "ffp", "brk", "gsys", "gusr", "idle"):
            runs.loc[idx, f"t_{k}_us"] = r[f"x_{k}_t"] * tick_ns / 1000.0 / n
            runs.loc[idx, f"t_{k}_pr"] = r[f"x_{k}_n"] / n
        # corrected (ns -> us per request)
        nh, np_, nf, nb, ngs, ngu = (r["x_hook_n"], r["x_fnofp_n"], r["x_ffp_n"], r["x_brk_n"], r["x_gsys_n"], r["x_gusr_n"])
        raw = lambda k: r[f"x_{k}_t"] * tick_ns
        # ops inside a run's x_call after its second counter read: x_obs of the run (2 per-CPU updates) and, in the
        # instr2 module, the x_obs of the prep/chain window (2 more); the hook's POST x_obs (2) lies in the gap window
        xp = 4 if "x_prep_t" in r.columns else 2
        plain = raw("fnofp") - np_ * L
        fp = raw("ffp") - nf * L
        bracket = raw("brk") - raw("ffp") - nb * (2 * L + xp * P)
        logic = raw("hook") - raw("fnofp") - np_ * (L + xp * P) - raw("brk") - nh * (4 * P + L)
        gsys = raw("gsys") - ngs * (L + xp * P)
        gusr = raw("gusr") - ngu * (L + xp * P)
        for k, v in (("plain", plain), ("fp", fp), ("bracket", bracket), ("logic", logic), ("gsys", gsys), ("gusr", gusr)):
            runs.loc[idx, f"c_{k}_us"] = v / 1000.0 / n
        # phases of the hook call (instr2 only): each window contains one counter read and the 4 per-CPU updates of two x_obs
        if "x_prep_t" in r.columns:
            for k in ("prep", "chain", "post"):
                v = r[f"x_{k}_t"] * tick_ns - r[f"x_{k}_n"] * (L + 4 * P)
                runs.loc[idx, f"c_{k}_us"] = v / 1000.0 / n
                runs.loc[idx, f"c_{k}_pr"] = r[f"x_{k}_n"] / n
    return runs


def load_runs(runs_dir, pattern="ub-at22-*"):
    rows, infos = [], []
    for p in sorted(glob.glob(os.path.join(runs_dir, pattern, "serial.log"))):
        label = os.path.basename(os.path.dirname(p))[len("ub-"):]
        info, r = load_boot(label, p)
        host = os.path.join(os.path.dirname(p), "host.txt")
        if os.path.exists(host):
            h = open(host).read()
            m = re.search(r"load1_before=(\S+)", h)
            info["load1_before"] = float(m.group(1)) if m else np.nan
            m = re.search(r"load1_after=(\S+)", h)
            info["load1_after"] = float(m.group(1)) if m else np.nan
        infos.append(info)
        rows.extend(r)
    runs = pd.DataFrame(rows)
    boots = pd.DataFrame(infos)
    if len(runs):
        runs = derive(runs)
        runs = timers_us(runs, boots)
    return runs, boots
