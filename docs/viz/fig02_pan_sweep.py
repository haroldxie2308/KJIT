"""Figure 2: PAN ablation across value sizes (journal 2026-10-11 19:31, PAN sweep)."""
from common import *

STATES = (("off", MUTED, "KJIT off"), ("on", BLUE, "KJIT on"), ("pan", ORANGE, "KJIT on+PAN (windows removed)"))


def build():
    d = csv("2026-10-11/1931-pan-sweep.csv")
    w = csv("2026-10-11/1931-pan-sweep-windows.csv")
    sizes = sorted(d["size"].unique())
    fig, ax = figure(
        11.5, 7.4,
        "PAN windows are the large-value penalty: removing them brings 16 KiB from 3.7x to 1.5x of off",
        "Below 512 B the PAN-clear saves nothing measurable; the saving grows with the SIMD ldp/stp windows (about 8 ns each), "
        "i.e. with value size.",
        "Data: docs/data/2026-10-11/1931-pan-sweep.csv (720 measured runs; per run cpu_us = server utime+stime ticks / 1M requests; 8 reps per size, "
        "the three states interleaved in one boot), 1931-pan-sweep-windows.csv (windows per request, counted from a TCG trace, not timed). "
        "Journal: 2026-10-11 19:31 (PAN ablation across value sizes; experiment branch, on+PAN is not a product configuration). "
        "Dots = individual runs, lines = median. KPTI off, server pinned to CPU 0.",
        nrows=2, ncols=2, sharex=True, gridspec_kw={"height_ratios": [1.5, 1]})

    for c, test in enumerate(("set", "get")):
        a = ax[0, c]
        for i, (state, color, label) in enumerate(STATES):
            t = d[(d.test == test) & (d.state == state)]
            a.scatter(t["size"] * (0.9 + 0.1 * i), t.cpu_us, s=6, color=color, alpha=0.35, lw=0, zorder=3)
            m = t.groupby("size").cpu_us.median()
            a.plot(m.index, m.values, color=color, label=label, zorder=4)
        a.set_title(test.upper())
        a.set_ylim(0, 17)
        if c == 0:
            a.set_ylabel("server CPU per request (us)")
            a.legend(loc="upper left")
        b = ax[1, c]
        t = w[w.test == test].sort_values("size_bytes")
        b.plot(t.size_bytes, t.simd_windows_per_req, color=VIOLET, label="SIMD&FP windows (ldp/stp q pairs, ld1, ldr...)")
        b.plot(t.size_bytes, t.lse_windows_per_req, color=AQUA, label="LSE windows (ldadd, swp, cas)")
        b.set_yscale("log")
        b.set_ylim(5, 2000)
        b.set_xlabel("redis-benchmark -d (value bytes)")
        if c == 0:
            b.set_ylabel("PAN windows per request (counted)")
            b.legend(loc="upper left")
        log_size_axis(b, sizes)
        b.grid(True, which="major")
    return save(fig, "fig02_pan_sweep")


if __name__ == "__main__":
    build()
