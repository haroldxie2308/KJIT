"""Figure 9: redis progress across milestones, one panel per measurement method (journal 2026-10-11 16:23 explains why they stay apart)."""
from common import *


def paired(d, off_col, on_col, keys, rps="rps", off="off", on="on"):
    """Per-pair on/off ratio of `rps`, pairing the KJIT-off and KJIT-on run of the same (boot, pass, test)."""
    a = d[d[off_col] == off].set_index(keys)[rps]
    b = d[d[on_col] == on].set_index(keys)[rps]
    return (b / a).dropna().rename("ratio").reset_index()


def throughput_series():
    """On/off throughput of the a11-baseline protocol (client-bound at native). Returns {label: {test: (median, lo, hi, points)}}."""
    out = {}

    def add(label, test, ratios=None, mid=None, lo=None, hi=None):
        if ratios is not None:
            r = np.asarray(ratios)
            out.setdefault(label, {})[test] = (float(np.median(r)), r.min(), r.max(), r)
        else:
            out.setdefault(label, {})[test] = (mid, lo, hi, None)

    # A11 integration (10-05 11:47): journal-table means, chain_budget 1024; range = on min..max over the table's off mean
    _, t = json_tables("2026-10-05/1147-a11-integration-remeasure.json")
    p = t["redis_per_point"].set_index("point")
    for test in ("set", "get"):
        off = p.loc["off", f"{test}_req_per_s_mean"]
        add("A11\n10-05", test, mid=p.loc["1024", f"{test}_req_per_s_mean"] / off,
            lo=p.loc["1024", f"{test}_req_per_s_min"] / off, hi=p.loc["1024", f"{test}_req_per_s_max"] / off)
    # A11c (10-09 22:11): journal-table
    c = csv("2026-10-09/2211-a11c-victim-table.csv")
    c = c[c.variant == "A11c"].set_index("test")
    for test in ("set", "get"):
        r = c.loc[test.upper()]
        add("A11c\n10-09", test, mid=r.ratio_on_over_off, lo=r.req_per_s_min / r.kjit_off_req_per_s, hi=r.req_per_s_max / r.kjit_off_req_per_s)
    # A13 (10-10 11:09): paired by run directory and pass
    a13 = csv("2026-10-10/1109-a13-redis.csv")
    r = paired(a13, "state", "state", ["run_dir", "pass", "test"], rps="req_per_s")
    for test in ("set", "get"):
        add("A13\n10-10", test, ratios=r[r.test == test].ratio)
    # A12 (10-10 11:51): the A12 worktree rows, paired by boot and pass
    a12 = csv("2026-10-10/1149-a12-redis.csv")
    a12 = a12[a12.commit == "6802ee6+A12-worktree"]
    r = paired(a12, "point", "point", ["boot", "pass", "test"], rps="req_per_s", on="1024")
    for test in ("set", "get"):
        add("A12\n10-10", test, ratios=r[r.test == test].ratio)
    # merged main (10-11 00:37)
    mn = csv("2026-10-11/0037-main-redis.csv")
    r = paired(mn, "point", "point", ["boot", "pass", "test"], rps="req_per_s", on="1024")
    for test in ("set", "get"):
        add("main A12+A13\n10-11 00:37", test, ratios=r[r.test == test].ratio)
    # main and A14, same session (10-11 03:54)
    a14 = csv("2026-10-11/0354-a14-redis.csv")
    for mod, label in (("main", "main\n03:54 session"), ("a14", "A14\n03:54")):
        r = paired(a14[a14.module == mod], "point", "point", ["boot", "pass", "test"], on="1024")
        for test in ("set", "get"):
            add(label, test, ratios=r[r.test == test].ratio)
    return out


def cpu_series():
    """Server CPU per request on/off, a11-baseline-like setup, utime+stime ticks (03:03 and 03:54 entries)."""
    out = {}
    cpu = csv("2026-10-11/0354-a14-cpu.csv")
    for mod, label in (("main", "main\n03:54 session"), ("a14", "A14\n03:54")):
        for test in ("set", "get"):
            g = cpu[(cpu.module == mod) & (cpu.test == test)]
            r = g[g.point == "1024"].set_index("boot").server_cpu_us_per_request / g[g.point == "off"].set_index("boot").server_cpu_us_per_request
            # boots differ between points (same boot id for both points): pair by boot
            r = r.dropna()
            out.setdefault(label, {})[test] = (float(r.median()), r.min(), r.max(), r.values)
    x = csv("2026-10-11/0303-dispatch-study-redis.csv")
    for test in ("set", "get"):
        g = x[x.test == test]
        m0 = g[g.colors.astype(str) == "0"].server_cpu_us_per_request.median()
        mo = g[g.colors.astype(str) == "off"].server_cpu_us_per_request.median()
        out.setdefault("main (as 03:03 colours 0)\n10-11 03:03", {})[test] = (m0 / mo, None, None, None)
    return out


def ub_series():
    """UB protocol (16:21), A14, server pinned, --threads 2, small values: per-boot on/off throughput and CPU ratios."""
    d = csv("2026-10-11/1621-ub-standard.csv")
    d = d[(d.pin == "pinned") & (d["size"] <= 8)]
    keys = ["kpti", "boot", "size", "test"]
    out = {}
    for k in (0, 1):
        g = d[d.kpti == k]
        off, on = g[g.kjit == "off"].set_index(keys), g[g.kjit == "on"].set_index(keys)
        tp, cp = (on.req_per_s / off.req_per_s), (on.cpu_us_per_req / off.cpu_us_per_req)
        for test in ("set", "get"):
            for name, ser in (("tput", tp), ("cpu", cp)):
                s = ser.xs(test, level="test")
                out.setdefault((name, k), {})[test] = (float(s.median()), s.min(), s.max(), s.values)
    return out


def draw(a, x0, series, order, ref=None):
    for i, label in enumerate(order):
        for test, color, dx, mk in (("set", BLUE, -0.12, "o"), ("get", ORANGE, 0.12, "s")):
            med, lo, hi, pts = series[label][test]
            x = x0 + i + dx
            if pts is not None:
                a.scatter(np.full(len(pts), x) + (np.arange(len(pts)) % 5 - 2) * 0.012, pts, s=8, color=color, alpha=0.4, lw=0, marker=mk, zorder=3)
                a.plot([x - 0.08, x + 0.08], [med, med], color=color, lw=2.2, zorder=4)
            else:
                if lo is not None:
                    a.plot([x, x], [lo, hi], color=color, lw=1.2, zorder=3)
                a.scatter([x], [med], s=26, facecolor="white", edgecolor=color, linewidth=1.5, marker=mk, zorder=4)


def build():
    thr, cpu, ub = throughput_series(), cpu_series(), ub_series()
    fig, ax = figure(
        12, 5.8,
        "Redis progress by method: the client-bound view says A14 is at native; the server-bound view says it is not",
        "Left: throughput on/off in the a11-baseline protocol (native server 75% busy, so extra server CPU hides). Right: server CPU per request on/off, the metric that holds under load.",
        "Data: 2026-10-05/1147 and 2026-10-09/2211 (journal tables, open markers: mean, range = on min..max / off mean), 2026-10-10/1109-a13-redis.csv, 1149-a12-redis.csv, "
        "2026-10-11/0037-main-redis.csv, 0354-a14-redis.csv (a11-baseline.sh, 3 passes x 200000, 50 clients, unpinned; dots = (boot, pass) pairs, bar = median), "
        "0354-a14-cpu.csv and 0303-dispatch-study-redis.csv (server CPU = utime+stime ticks, 500000 requests; the 03:03 point is the median of its runs), 1621-ub-standard.csv "
        "(UB protocol: pinned, --threads 2, KPTI off/on, -d 1..8, dots = (boot, size) pairs). Journal: 10-05 11:47, 10-09 22:11, 10-10 11:09 and 11:51, 10-11 00:37, 03:03, 03:54, 16:21, 16:23 (Correction). "
        "No server-CPU measurement of the same method exists for A11-A13, so the CPU panel starts at main. The two protocols are not one series.",
        nrows=1, ncols=2, gridspec_kw={"width_ratios": [1.5, 1]})
    order = list(thr.keys())
    a = ax[0, 0]
    draw(a, 0, thr, order)
    a.axhline(1.0, color=INK2, lw=0.8, ls="--")
    n = len(order)
    a.axvline(n - 0.5, color=GRID, lw=1.5)
    a.text(-0.5, 1.13, "a11-baseline protocol: unpinned, native server 75% busy", fontsize=8, color=INK2, va="top")
    a.text(n - 0.4, 1.13, "UB protocol, A14\n(server 90%+ busy)", fontsize=8, color=INK2, va="top")
    ubx = n + 0.2
    for j, k in enumerate((0, 1)):
        draw(a, ubx + j, {"kpti": ub[("tput", k)]}, ["kpti"])
    a.set_xticks(list(range(n)) + [ubx, ubx + 1])
    a.set_xticklabels(order + ["KPTI\noff", "KPTI\non"], fontsize=7.5)
    a.set_ylabel("throughput, KJIT on / off")
    a.set_ylim(0.2, 1.15)
    a.set_xlim(-0.6, ubx + 1.6)
    a.set_title("Throughput on/off")
    a.grid(axis="x", visible=False)
    a.scatter([], [], color=BLUE, marker="o", label="SET")
    a.scatter([], [], color=ORANGE, marker="s", label="GET")
    a.legend(loc="lower left", fontsize=8)

    b = ax[0, 1]
    corder = ["main (as 03:03 colours 0)\n10-11 03:03", "main\n03:54 session", "A14\n03:54"]
    draw(b, 0, cpu, corder)
    m = len(corder)
    b.axvline(m - 0.5, color=GRID, lw=1.5)
    b.text(-0.5, 3.15, "a11-baseline-like setup, ticks", fontsize=8, color=INK2, va="top")
    b.text(m - 0.4, 3.15, "UB protocol, A14", fontsize=8, color=INK2, va="top")
    cx = m + 0.2
    for j, k in enumerate((0, 1)):
        draw(b, cx + j, {"kpti": ub[("cpu", k)]}, ["kpti"])
    b.axhline(1.0, color=INK2, lw=0.8, ls="--")
    b.set_xticks(list(range(m)) + [cx, cx + 1])
    b.set_xticklabels(["main\n03:03", "main\n03:54", "A14\n03:54", "KPTI\noff", "KPTI\non"], fontsize=7.5)
    b.set_ylabel("server CPU per request, KJIT on / off")
    b.set_ylim(0.8, 3.2)
    b.set_xlim(-0.6, cx + 1.6)
    b.set_title("Server CPU on/off")
    b.grid(axis="x", visible=False)
    return save(fig, "fig09_progress")


if __name__ == "__main__":
    build()
