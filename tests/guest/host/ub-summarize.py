#!/usr/bin/env python3
"""Summaries of the userspace-bypass comparison runs (ub-bench.sh, a11-baseline.sh).

  ub-summarize.py sys  SERIAL_LOG...    table: per mode/size, ns per syscall off vs on
  ub-summarize.py code SERIAL_LOG...    per variant: least-squares slope/intercept off vs on
  ub-summarize.py redis LABEL=SERIAL_LOG...   per label: mean req/s and counters per point/test
  ub-summarize.py std [--csv PREFIX] LABEL=SERIAL_LOG...   ub-standard.sh sweeps (host/ub-standard.sh)

Standard library only. Reads the "ub off|on ..." lines of ub-bench.sh and the
"a11 point=..." lines of a11-baseline.sh and the "ubstd run ..." lines of ub-standard.sh
from the guest's serial log. With several logs of one label the per-config values are
medians over the logs. For `std` the label of a log must end in -k<0|1>-b<boot> (KPTI
setting, boot number; the labels host/ub-standard.sh uses).
"""
import os
import re
import statistics
import sys


def kv(line):
    return {k: v for k, v in re.findall(r"(\w+)=(\S+)", line)}


def load_ub(paths):
    rows = []
    for p in paths:
        for line in open(p, errors="replace"):
            m = re.search(r"\bub (off|on) (result|counters|kjit) (.*)", line)
            if m:
                d = kv(m.group(3))
                d["state"], d["kind"] = m.group(1), m.group(2)
                d["log"] = p
                rows.append(d)
    return rows


def sys_table(paths):
    rows = load_ub(paths)
    res = {}
    kj = {}
    for r in rows:
        if r["kind"] == "result":
            res.setdefault((r["mode"], int(r["size"])), {"off": [], "on": []})[r["state"]].append(
                float(r["median_ns_per_syscall"]))
        elif r["kind"] == "kjit":
            kj.setdefault((r["mode"], int(r["size"])), []).append(
                (float(r["in_kernel_frac"]), float(r["runtime_entries_per_syscall"])))
    print("mode size | off ns/syscall | on ns/syscall | speedup (off/on) | in-kernel frac | runtime entries/syscall | n")
    for key in sorted(res):
        off, on = res[key]["off"], res[key]["on"]
        fo, fn = statistics.median(off), statistics.median(on)
        k = kj.get(key, [])
        frac = statistics.median(x[0] for x in k) if k else float("nan")
        ent = statistics.median(x[1] for x in k) if k else float("nan")
        print(f"{key[0]:9s} {key[1]:3d} | {fo:8.1f} | {fn:8.1f} | {fo / fn:5.3f} | {frac:.3f} | {ent:.3f} | {len(off)}/{len(on)}")


def fit(xs, ys):
    n = len(xs)
    mx, my = sum(xs) / n, sum(ys) / n
    sxx = sum((x - mx) ** 2 for x in xs)
    b = sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / sxx
    a = my - b * mx
    ss_tot = sum((y - my) ** 2 for y in ys)
    ss_res = sum((y - (a + b * x)) ** 2 for x, y in zip(xs, ys))
    return a, b, 1 - ss_res / ss_tot if ss_tot else 1.0


def code_table(paths):
    # Only code_speed results (entry_cost results, from "ub-bench.sh entry", have no insn_per_outer).
    rows = [r for r in load_ub(paths) if r["kind"] == "result" and "insn_per_outer" in r]
    data = {}
    for r in rows:
        ipo = float(r["insn_per_outer"])
        data.setdefault(r["variant"], {}).setdefault(r["state"], {}).setdefault(int(r["n"]), []).append(
            (float(r["median_ns_per_outer"]), ipo))
    print("variant | n: off ns / on ns / on-off ratio | off slope ns/n (R2) | on slope | slope ratio | off icpt | on icpt | ns per insn off / on")
    for v in sorted(data):
        off = {n: statistics.median(x[0] for x in l) for n, l in data[v]["off"].items()}
        on = {n: statistics.median(x[0] for x in l) for n, l in data[v]["on"].items()}
        ins = {n: statistics.median(x[1] for x in l) for n, l in data[v]["off"].items()}
        ns = sorted(off)
        ao, bo, ro = fit(ns, [off[n] for n in ns])
        an, bn, rn = fit(ns, [on[n] for n in ns])
        per = " ".join(f"{n}:{off[n]:.0f}/{on[n]:.0f}/{on[n] / off[n]:.2f}" for n in ns)
        insn_per_n = (ins[ns[-1]] - ins[ns[0]]) / (ns[-1] - ns[0])
        print(f"{v:7s} | {per} | {bo:.4f} ({ro:.4f}) | {bn:.4f} ({rn:.4f}) | {bn / bo:.3f} | {ao:.0f} | {an:.0f} | {bo / insn_per_n:.3f} / {bn / insn_per_n:.3f}")


def redis_table(args):
    out = {}
    for a in args:
        label, path = a.split("=", 1)
        for line in open(path, errors="replace"):
            if not line.startswith("a11 point="):
                continue
            d = kv(line)
            out.setdefault((label, d["point"], d["test"]), []).append(d)
    print("label point test | n | req/s mean (min..max) | us/req | in-kernel syscalls/req | runtime entries/req | hook calls/req")
    for key in sorted(out):
        l = out[key]
        rps = [float(d["rps"]) for d in l]
        req = float(l[0]["requests"])
        def per(c):
            return statistics.mean(float(d[c]) for d in l) / req
        print(f"{key[0]:14s} {key[1]:5s} {key[2]:3s} | {len(l)} | {statistics.mean(rps):9.0f} ({min(rps):.0f}..{max(rps):.0f}) | {statistics.mean(1e6 / r for r in rps):6.3f} | {per('syscalls_in_kernel'):.3f} | {per('fragment_entries'):.3f} | {per('hook_calls'):.3f}")


def quartiles(vals):
    """(Q1, median, Q3) of a list, inclusive method; a single value is all three."""
    if len(vals) == 1:
        return vals[0], vals[0], vals[0]
    q = statistics.quantiles(vals, n=4, method="inclusive")
    return q[0], q[1], q[2]


def fmt_q(vals, spec):
    q1, med, q3 = quartiles(vals)
    return f"{med:{spec}} [{q1:{spec}}..{q3:{spec}}]"


STD_COUNTERS = ("hook_calls syscalls_in_kernel fragment_entries exit_svc exit_bl exit_blr exit_br exit_ret "
                "exit_mem exit_unsupported exit_budget run_declined svc_declined fpsimd_entries translate_ok "
                "invalidated_fragments").split()


def load_std(args):
    """Rows of ub-standard.sh runs (one dict per "ubstd run" line) and of the null-syscall
    results of ub-bench.sh sys, with the KPTI setting and boot of the log's label."""
    runs, sysrows = [], []
    for a in args:
        label, path = a.split("=", 1)
        m = re.search(r"-k([01])-b(\d+)$", label)
        if not m:
            sys.exit(f"label {label!r} does not end in -k<0|1>-b<boot>")
        kpti, boot = int(m.group(1)), int(m.group(2))
        for line in open(path, errors="replace"):
            if "ubstd run " in line:
                d = kv(line.split("ubstd run ", 1)[1])
                r = {"kpti": kpti, "boot": boot, "label": label, "pin": d["pin"], "size": int(d["size"]),
                     "rep": int(d["rep"]), "state": d["state"], "test": d["test"], "requests": int(d["requests"]),
                     "rps": float(d["rps"]), "wall_cs": int(d["wall_cs"]), "utime_ticks": int(d["utime_ticks"]),
                     "stime_ticks": int(d["stime_ticks"]), "clk_tck": int(d["clk_tck"])}
                r["cpu_us_per_req"] = (r["utime_ticks"] + r["stime_ticks"]) / r["clk_tck"] * 1e6 / r["requests"]
                r["server_busy"] = (r["utime_ticks"] + r["stime_ticks"]) / r["clk_tck"] / (r["wall_cs"] / 100)
                for c in STD_COUNTERS:
                    r[c] = int(d[c])
                runs.append(r)
            m = re.search(r"\bub (off|on) result (.*)", line)
            if m:
                d = kv(m.group(2))
                sysrows.append({"kpti": kpti, "boot": boot, "label": label, "state": m.group(1), "mode": d["mode"],
                                "size": int(d["size"]), "iters": int(d["iters"]), "reps": int(d["reps"]),
                                "syscalls_per_iter": int(d["syscalls_per_iter"]),
                                "median_ns_per_syscall": float(d["median_ns_per_syscall"])})
    return runs, sysrows


def write_csv(path, rows):
    import csv
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)


def std_table(args):
    csv_prefix = None
    if args and args[0] == "--csv":
        csv_prefix, args = args[1], args[2:]
    runs, sysrows = load_std(args)
    if csv_prefix:
        # Column names as docs/data/README.md: kjit off|on, req_per_s, load1_before from host.txt.
        load = {}
        for a in args:
            label, path = a.split("=", 1)
            host = os.path.join(os.path.dirname(path), "host.txt")
            m = re.search(r"load1_before=(\S+)", open(host).read()) if os.path.exists(host) else None
            load[label] = m.group(1) if m else ""
        ren = {"state": "kjit", "rps": "req_per_s"}
        write_csv(csv_prefix + ".csv", [{ren.get(k, k): v for k, v in dict(r, load1_before=load[r["label"]]).items()}
                                         for r in runs])
        write_csv(csv_prefix + "-sys.csv", [{ren.get(k, k): v for k, v in dict(r, load1_before=load[r["label"]]).items()}
                                            for r in sysrows])

    # cell[(kpti, pin, size, test, state)][boot] -> runs (a boot has REPS of them: mean within the boot)
    cell = {}
    for r in runs:
        cell.setdefault((r["kpti"], r["pin"], r["size"], r["test"], r["state"]), {}).setdefault(r["boot"], []).append(r)

    def per_boot(key, field, fn=None):
        out = {}
        for b, rs in cell[key].items():
            vals = [fn(r) if fn else r[field] for r in rs]
            out[b] = statistics.mean(vals)
        return out

    def ratio(kpti, pin, size, test, field):
        off = per_boot((kpti, pin, size, test, "off"), field)
        on = per_boot((kpti, pin, size, test, "on"), field)
        return [on[b] / off[b] for b in sorted(off) if b in on]

    def med(kpti, pin, size, test, state, field, fn=None):
        return statistics.median(per_boot((kpti, pin, size, test, state), field, fn).values())

    def per_req(c):
        return lambda r: r[c] / r["requests"]

    kptis = sorted({r["kpti"] for r in runs})
    sizes = sorted({r["size"] for r in runs if r["pin"] == "pinned"})
    boots = {k: sorted({r["boot"] for r in runs if r["kpti"] == k}) for k in kptis}
    name = {0: "KPTI off", 1: "KPTI forced on"}

    print("## Null syscall round trip (ub-bench.sh sys, getppid), ns; median over boots [Q1..Q3]")
    print("| KPTI | boots | KJIT off (native) | KJIT on (in kernel) | native - in kernel |")
    print("|---|---|---|---|---|")
    ceil = {}
    for k in kptis:
        sel = lambda st: [r["median_ns_per_syscall"] for r in sysrows
                          if r["kpti"] == k and r["mode"] == "getppid" and r["state"] == st]
        off, on = sel("off"), sel("on")
        ceil[k] = (statistics.median(off), statistics.median(on))
        print(f"| {name[k]} | {len(off)} | {fmt_q(off, '.1f')} | {fmt_q(on, '.1f')} | {ceil[k][0] - ceil[k][1]:.1f} |")
    print()

    for k in kptis:
        pin = "pinned"
        print(f"## {name[k]}, server pinned to CPU 0, client on CPUs 1-3 ({len(boots[k])} boots; median over boots [Q1..Q3])")
        print()
        print("Throughput, requests/s (on/off per boot, then the median of the ratios):")
        print()
        print("| -d | SET off | SET on | SET on/off | GET off | GET on | GET on/off |")
        print("|---|---|---|---|---|---|---|")
        for d in sizes:
            row = [f"{d}"]
            for t in ("set", "get"):
                row.append(fmt_q(list(per_boot((k, pin, d, t, "off"), "rps").values()), ".0f"))
                row.append(fmt_q(list(per_boot((k, pin, d, t, "on"), "rps").values()), ".0f"))
                row.append(fmt_q(ratio(k, pin, d, t, "rps"), ".3f"))
            print("| " + " | ".join(row) + " |")
        print()
        print("Server CPU per request, us (user + system ticks of the server over the run), and server busy fraction:")
        print()
        print("| -d | SET off | SET on | SET on/off | busy off/on | GET off | GET on | GET on/off | busy off/on |")
        print("|---|---|---|---|---|---|---|---|---|")
        for d in sizes:
            row = [f"{d}"]
            for t in ("set", "get"):
                row.append(fmt_q(list(per_boot((k, pin, d, t, "off"), "cpu_us_per_req").values()), ".2f"))
                row.append(fmt_q(list(per_boot((k, pin, d, t, "on"), "cpu_us_per_req").values()), ".2f"))
                row.append(fmt_q(ratio(k, pin, d, t, "cpu_us_per_req"), ".3f"))
                row.append(f"{med(k, pin, d, t, 'off', 'server_busy'):.2f}/{med(k, pin, d, t, 'on', 'server_busy'):.2f}")
            print("| " + " | ".join(row) + " |")
        print()
        print("KJIT on, counters per request (medians over boots): syscalls = hook calls, in-kernel fraction, runtime entries "
              "(fragment entries), Unsupported exits, FP/SIMD entries, translations during the measured run:")
        print()
        print("| -d | test | syscalls/req | in-kernel | runtime entries/req | Unsupported exits/req | FP/SIMD entries/req | translate_ok in run |")
        print("|---|---|---|---|---|---|---|---|")
        for d in sizes:
            for t in ("set", "get"):
                key = (k, pin, d, t, "on")
                hc = med(*key, "hook_calls", per_req("hook_calls"))
                ik = med(*key, "syscalls_in_kernel", lambda r: r["syscalls_in_kernel"] / r["hook_calls"])
                en = med(*key, "fragment_entries", per_req("fragment_entries"))
                un = med(*key, "exit_unsupported", per_req("exit_unsupported"))
                fp = med(*key, "fpsimd_entries", per_req("fpsimd_entries"))
                tr = sum(r["translate_ok"] for rs in cell[key].values() for r in rs)
                print(f"| {d} | {t.upper()} | {hc:.3f} | {ik:.4f} | {en:.2f} | {un:.4f} | {fp:.3f} | {tr} |")
        print()
        # Ceiling: the null-syscall cost times the syscalls per request, against the server CPU per request.
        rtt_off, rtt_on = ceil[k]
        print(f"Ceiling ({name[k]}): saving per request = null-syscall round trip x syscalls/req. Round trip native "
              f"{rtt_off:.1f} ns, in kernel {rtt_on:.1f} ns. Full = native round trip x syscalls (transition cost removed "
              "entirely); achievable = (native - in kernel) x syscalls. The server is the bottleneck in both states "
              "(busy 0.9+), so the ceiling gain is saving / (server CPU off - saving) and is read against the measured "
              "throughput gain (on/off - 1, quantized, see the notes) and the measured CPU change (on/off - 1).")
        print()
        print("| -d | test | syscalls/req | full saving ns | achievable saving ns | server CPU off us | full / CPU off | ceiling gain full | ceiling gain achievable | measured throughput gain | measured CPU change |")
        print("|---|---|---|---|---|---|---|---|---|---|---|")
        for d in sizes:
            for t in ("set", "get"):
                sc = med(k, pin, d, t, "on", "hook_calls", per_req("hook_calls"))
                full, ach = rtt_off * sc, (rtt_off - rtt_on) * sc
                cpu = med(k, pin, d, t, "off", "cpu_us_per_req")
                gf = full / 1000 / (cpu - full / 1000)
                ga = ach / 1000 / (cpu - ach / 1000)
                mg = statistics.median(ratio(k, pin, d, t, "rps")) - 1
                mc = statistics.median(ratio(k, pin, d, t, "cpu_us_per_req")) - 1
                print(f"| {d} | {t.upper()} | {sc:.3f} | {full:.0f} | {ach:.0f} | {cpu:.2f} | {full / 1000 / cpu:.1%} | {gf:+.1%} | {ga:+.1%} | {mg:+.1%} | {mc:+.1%} |")
        print()

    up = sorted({r["size"] for r in runs if r["pin"] == "unpinned"})
    if up:
        print("## Pinned against unpinned, same boots (median over boots [Q1..Q3])")
        print()
        print("| KPTI | -d | test | pin | off req/s | on req/s | on/off | CPU off us | CPU on us | CPU on/off | busy off/on |")
        print("|---|---|---|---|---|---|---|---|---|---|---|")
        for k in kptis:
            for d in up:
                for t in ("set", "get"):
                    for pin in ("pinned", "unpinned"):
                        if (k, pin, d, t, "off") not in cell:
                            continue
                        o = lambda st, f: fmt_q(list(per_boot((k, pin, d, t, st), f).values()), ".0f" if f == "rps" else ".2f")
                        print(f"| {name[k]} | {d} | {t.upper()} | {pin} | {o('off', 'rps')} | {o('on', 'rps')} | "
                              f"{fmt_q(ratio(k, pin, d, t, 'rps'), '.3f')} | {o('off', 'cpu_us_per_req')} | {o('on', 'cpu_us_per_req')} | "
                              f"{fmt_q(ratio(k, pin, d, t, 'cpu_us_per_req'), '.3f')} | "
                              f"{med(k, pin, d, t, 'off', 'server_busy'):.2f}/{med(k, pin, d, t, 'on', 'server_busy'):.2f} |")
        print()

    on_runs = [r for r in runs if r["state"] == "on"]
    grew = [r for r in on_runs if r["translate_ok"] > 0]
    print(f"## Settled translation: {len(on_runs)} measured KJIT-on runs, {len(grew)} with translate_ok growing "
          f"(sum of deltas {sum(r['translate_ok'] for r in on_runs)}); KJIT-off runs with fragment entries: "
          f"{sum(1 for r in runs if r['state'] == 'off' and r['fragment_entries'])}; runs: {len(runs)}")
    for r in grew:
        print(f"  grew: {r['label']} {r['pin']} -d {r['size']} {r['test']}: translate_ok +{r['translate_ok']}")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    {"sys": sys_table, "code": code_table, "redis": redis_table, "std": std_table}[sys.argv[1]](sys.argv[2:])
