"""Figure 8: variant studies. 8a dispatch-table conflict variants (2026-10-09 03:56), 8b FP/SIMD bracket variants
(2026-10-09 02:31), 8c the SSBS read-modify-write chain (2026-10-10 09:41)."""
from common import *

IBTC = [("0", "V0 direct\n(9 words)"), ("1", "V1 index\nhash"), ("2", "V2a 2-way\n2048x2"), ("3", "V2b 2-way\n4096x2"),
        ("4", "V3a victim\n256"), ("5", "V3b victim\n512")]


def build_ibtc():
    _, t = json_tables("2026-10-09/0356-dispatch-table-variants.json")
    r = t["redis_runs"]
    r = r[r.series == "meas"]       # the 'meas-nc' series is variant 0 without miss classification
    off = r[r.point == "off"].groupby("test").rps.median()
    on = r[r.point != "off"].copy()
    on["ratio"] = on.rps / on.test.map(off)
    on["conf"] = on.ibtc_miss_conflict / on.requests
    on["x"] = on.variant.map({v: i for i, (v, _) in enumerate(IBTC)})
    fig, ax = figure(
        11.5, 4.9,
        "Dispatch-table conflicts: a 2-way 4096x2 table or a victim table removes them; hash or 2-way 2048x2 alone do not",
        "Conflict misses per SET request fall from 18.6 to 0; throughput recovers from 0.47 to 0.62 of KJIT off (SET), 0.57 to 0.69 (GET).",
        "Data: docs/data/2026-10-09/0356-dispatch-table-variants.json (table redis_runs, series meas, 18 runs per cell = 6 boots x 3 passes, 200000 requests, 50 clients; "
        "ratio = run req/s over the median of the KJIT-off runs of the same test). Journal: 2026-10-09 03:56 (Dispatch-table conflict variants; branch not merged). "
        "Dots = runs, line = median. The entry's table quotes 3 boots per cell, so its medians differ slightly (V0 SET 0.486 there, 0.466 here).",
        nrows=1, ncols=2)
    for c, (col, ylabel, ylim) in enumerate((("conf", "conflict misses per request", (0, 20)), ("ratio", "throughput / KJIT off", (0.3, 0.8)))):
        a = ax[0, c]
        for test, color, dx in (("set", BLUE, -0.1), ("get", ORANGE, 0.1)):
            g = on[on.test == test]
            a.scatter(g.x + dx + (np.arange(len(g)) % 6 - 2.5) * 0.012, g[col], s=8, color=color, alpha=0.4, lw=0, zorder=3)
            m = g.groupby("x")[col].median()
            a.plot(m.index + dx, m.values, color=color, marker="o", ms=4, label=test.upper(), zorder=4)
        a.set_xticks(range(len(IBTC)))
        a.set_xticklabels([l for _, l in IBTC], fontsize=7.5)
        a.set_ylabel(ylabel)
        a.set_ylim(*ylim)
        a.grid(axis="x", visible=False)
    ax[0, 0].legend(loc="upper right")
    return save(fig, "fig08a_dispatch_table_variants")


FP = [("off", "KJIT off"), ("v0", "v0: today's\nnon-preemptible"), ("A", "A: preemptible,\nFP-entered runs"), ("B", "B: every run\nof an FP mm"), ("B2", "B2: one bracket\nper hook call")]


def build_fp():
    _, t = json_tables("2026-10-09/0231-fpsimd-bracket-neon.json")
    r = t["redis_runs"]
    r = r[r.log.str.startswith("bench-")]     # the lat-* logs run a latency probe, one of them with -P 16: not throughput runs
    ec = t["entry_cost"]
    ec = ec[ec.calls == "16"] if ec.calls.dtype == object else ec[ec.calls == 16]
    pos = {p: i for i, (p, _) in enumerate(FP)}
    fig, ax = figure(
        11.5, 4.9,
        "FP/SIMD bracket variants: preemptible brackets are feasible, throughput differences are within noise",
        "Redis throughput is the same across v0/A/B/B2 within the +-10% per-cell spread; the entry cost of the new brackets is 35-50 ns per bracketed hook call.",
        "Data: docs/data/2026-10-09/0231-fpsimd-bracket-neon.json (redis_runs of the three bench-* logs: 150 runs, 5 rounds with point order rotated; lat-* logs excluded: latency probe, one with -P 16, 200000 requests; entry_cost: ns per outer iteration, K=16 calls per syscall, one dot per round). "
        "Journal: 2026-10-09 02:31 (FP/SIMD bracket: preemptible kernel-mode NEON experiment; branch not merged). Host load1 6-22 (other agents' builds) throughout. "
        "Dots = runs / rounds, marker = median.",
        nrows=1, ncols=2)
    a = ax[0, 0]
    for test, color, dx in (("set", BLUE, -0.12), ("get", ORANGE, 0.12)):
        g = r[r.test == test]
        x = g.point.map(pos)
        a.scatter(x + dx + (np.arange(len(g)) % 5 - 2) * 0.012, g.rps / 1000, s=9, color=color, alpha=0.4, lw=0, zorder=3)
        m = (g.rps / 1000).groupby(x).median()
        a.plot(m.index + dx, m.values, color=color, marker="o", ms=4, label=test.upper(), zorder=4)
    a.set_xticks(range(len(FP)))
    a.set_xticklabels([l for _, l in FP], fontsize=7.5)
    a.set_ylabel("redis throughput (kreq/s)")
    a.set_ylim(0, None)
    a.legend(loc="lower right")
    a.grid(axis="x", visible=False)
    b = ax[0, 1]
    for kind, color, dx in (("gpr", BLUE, -0.12), ("fp", ORANGE, 0.12)):
        g = ec[ec.kind == kind]
        x = g.point.map(pos)
        b.scatter(x + dx + (np.arange(len(g)) % 5 - 2) * 0.012, g.ns_per_outer, s=9, color=color, alpha=0.4, lw=0, zorder=3)
        m = g.ns_per_outer.groupby(x).median()
        b.plot(m.index + dx, m.values, color=color, marker="o", ms=4, label=f"{kind.upper()} callee", zorder=4)
    b.set_xticks(range(len(FP)))
    b.set_xticklabels([l for _, l in FP], fontsize=7.5)
    b.set_ylabel("ns per syscall iteration (16 calls)")
    b.set_ylim(0, None)
    b.legend(loc="lower right")
    b.grid(axis="x", visible=False)
    return save(fig, "fig08b_fpsimd_bracket_variants")


SSB = [("exp_loop", "empty loop trip"), ("exp_fwd", "ldr; str chain"), ("exp_rmw1", "budget unit RMW"), ("exp_calls_all", "calls, all emitted costs")]
# (label, colour, level, runs, op suffix)
SSB_COND = [("EL1 default (SSBS = 0)", RED, "el1", ("ssbDef1", "ssbDef2"), "", "o"),
            ("EL1 msr ssbs,#0", ORANGE, "el1", ("ssbDef1", "ssbDef2"), "_s0", "s"),
            ("EL1 msr ssbs,#1", BLUE, "el1", ("ssbDef1", "ssbDef2"), "_s1", "^"),
            ("EL1 DSSBS = 1 on all CPUs", AQUA, "el1", ("dssbs1", "dssbs2"), "", "v"),
            ("EL0 default (SSBS = 1)", VIOLET, "el0", ("ssbDef1", "ssbDef2"), "", "D"),
            ("EL0 msr ssbs,#0", MAGENTA, "el0", ("ssbDef1", "ssbDef2"), "_s0", "P")]


def build_ssbs():
    _, t = json_tables("2026-10-10/0941-ssbs-rmw-chain.json")
    e = t["exp_ops"]
    fig, ax = figure(
        11.5, 4.9,
        "EL1 read-modify-write chains are slow because PSTATE.SSBS = 0 at EL1; setting SSBS = 1 matches EL0",
        "A bare ldr;str chain costs 1.5 ns with SSBS = 0 (EL1 default, or EL0 with SSBS cleared) and 0.33 ns with SSBS = 1; empty loops and PAN pairs are unaffected.",
        "Data: docs/data/2026-10-10/0941-ssbs-rmw-chain.json (table exp_ops: median ps per op of 7 repeats; one dot per boot, 2 boots per condition; "
        "s0 / s1 = the loop wrapped in msr ssbs,#0 / #1). Journal: 2026-10-10 09:41 (The EL1 RMW chain = PSTATE.SSBS; branch not merged). "
        "SSBS = 1 inside fragments weakens kernel-mode Spectre-v4 posture (not analysed in the entry).")
    a = ax[0, 0]
    w = 0.13
    for k, (label, color, level, runs, suf, mk) in enumerate(SSB_COND):
        for i, (op, _) in enumerate(SSB):
            g = e[(e.level == level) & e.run.isin(runs) & (e.op == op + suf)]
            assert len(g) == len(runs), (label, op, len(g))
            x = i + (k - 2.5) * w
            a.scatter(np.full(len(g), x), g.median_ps_per_op / 1000, s=10, color=color, marker=mk, alpha=0.5, lw=0, zorder=3)
            a.scatter([x], [(g.median_ps_per_op / 1000).median()], s=28, color=color, marker=mk, zorder=4)
        a.scatter([], [], color=color, marker=mk, s=28, label=label)
    a.set_xticks(range(len(SSB)))
    a.set_xticklabels([l for _, l in SSB])
    a.set_ylabel("ns per operation")
    a.set_ylim(0, None)
    a.grid(axis="x", visible=False)
    a.legend(loc="upper left", fontsize=8)
    return save(fig, "fig08c_ssbs_rmw_chain")


def build():
    return [build_ibtc(), build_fp(), build_ssbs()]


if __name__ == "__main__":
    build()
