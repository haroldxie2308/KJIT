"""Figure 3: redis CPU gap by setup (journal 2026-10-11 19:31, Redis CPU gap)."""
from common import *

# display order: (cfg, label). Labels restate the cfg key; groups follow the entry's table.
CONFIGS = [
    ("p_t2_c50_d1", "pinned, --threads 2, -c 50, -d 1  (16:21 setup)"),
    ("p_t2_c50_d3", "pinned, --threads 2, -c 50, -d 3"),
    ("u_t2_c50_d1", "unpinned, --threads 2, -c 50, -d 1"),
    ("u_t2_c50_d3", "unpinned, --threads 2, -c 50, -d 3"),
    ("p_t2_c50_d1_n400k", "pinned, --threads 2, -c 50, -d 1, -n 400k"),
    ("p_t2_c200_d1", "pinned, --threads 2, -c 200, -d 1"),
    ("p_t2_c10_d1", "pinned, --threads 2, -c 10, -d 1"),
    ("p_t2_c50_d1_cl1", "pinned, --threads 2, -c 50, client on CPU 1 only"),
    ("p_t0_c50_d1", "pinned, no --threads, -c 50, -d 1"),
    ("p_t0_c50_d3", "pinned, no --threads, -c 50, -d 3"),
    ("u_t0_c50_d1", "unpinned, no --threads, -c 50, -d 1"),
    ("u_t0_c50_d3", "unpinned, no --threads, -c 50, -d 3"),
    ("u_t0_c50_d3_n400k", "unpinned, no --threads, -c 50, -d 3, -n 400k  (12:42 setup)"),
]
WAKE = [("remote", "writer, reader blocked on another CPU"), ("local", "writer, reader blocked on same CPU"),
        ("spin", "writer, reader polling (nobody woken)"), ("child_remote", "sleeper, remote wake"),
        ("child_local", "sleeper, local wake")]


def build():
    d = csv("2026-10-11/1931-cpu-gap.csv")
    wk = csv("2026-10-11/1931-cpu-gap-wake.csv")
    idx = ["boot", "cfg", "rep", "test"]
    off = d[d.state == "off"].set_index(idx).cpu_ticks_us
    on = d[d.state == "on"].set_index(idx).cpu_ticks_us
    gap = (on - off).rename("gap").reset_index()

    fig, ax = figure(
        12, 7.4,
        "Redis CPU gap is set by --threads (whether the client can outrun the server), not by pinning, -d or -n",
        "With --threads 2 the gap is 1.2-1.8 us per request, without it 0.9-1.0 us, pinned or not; the cause is the cost of cross-CPU wake-ups (IPIs) in this VM.",
        "Data: docs/data/2026-10-11/1931-cpu-gap.csv (gap = server CPU per request, KJIT on minus off, from ticks; one point per (boot, rep) pair, 12 pairs per configuration and test, "
        "4 boots), 1931-cpu-gap-wake.csv (wake-cost micro-benchmark, one point per round). Journal: 2026-10-11 19:31 (Redis CPU gap: 1.0 vs 1.5 us). "
        "Dots = pairs, bar = median with inter-quartile range. The wake micro-benchmark: a remote wake costs the waker 8.7 us and the sleeper 9.3 us of runtime (GICv2 emulated in QEMU userspace).",
        nrows=1, ncols=3, gridspec_kw={"width_ratios": [1.6, 1.6, 1.4]})
    ymap = {c: i for i, (c, _) in enumerate(CONFIGS)}
    for k, test in enumerate(("set", "get")):
        a = ax[0, k]
        for cfg, label in CONFIGS:
            y = ymap[cfg]
            g = gap[(gap.cfg == cfg) & (gap.test == test)].gap
            color = BLUE if "_t2_" in cfg else ORANGE
            jit = (np.arange(len(g)) % 4 - 1.5) * 0.045
            a.scatter(g, y + jit, s=9, color=color, alpha=0.4, lw=0, zorder=3)
            q1, m, q3 = quartiles(g)
            a.plot([q1, q3], [y, y], color=color, lw=3.2, solid_capstyle="butt", zorder=4)
            a.plot([m], [y], marker="|", color=INK, ms=11, mew=1.8, zorder=5)
        a.set_yticks(range(len(CONFIGS)))
        a.set_yticklabels([l for _, l in CONFIGS] if k == 0 else [], fontsize=7.5)
        a.set_ylim(len(CONFIGS) - 0.5, -0.5)
        a.set_xlim(0, 3.0)
        a.set_title(test.upper() + ": KJIT on - off (us per request)")
        a.axhline(7.5, color=GRID, lw=1.2)
        a.grid(axis="y", visible=False)
    ax[0, 0].text(2.95, 0.2, "--threads 2", color=BLUE, fontsize=8.5, ha="right", fontweight="bold")
    ax[0, 0].text(2.95, 8.2, "no --threads", color=ORANGE, fontsize=8.5, ha="right", fontweight="bold")
    ax[0, 0].text(1.4, 7.05, "client on one CPU: cannot\noutrun the server, gap =\nno --threads level", fontsize=7, color=INK2, va="center")

    a = ax[0, 2]
    for i, (v, label) in enumerate(WAKE):
        x = wk[wk.variant == v].cpu_us_per_iter
        color = BLUE if "remote" in v else (MUTED if v == "spin" else AQUA)
        a.scatter(x, i + (np.arange(len(x)) % 3 - 1) * 0.05, s=10, color=color, alpha=0.5, lw=0, zorder=3)
        a.plot([x.median()], [i], marker="|", color=INK, ms=11, mew=1.8, zorder=5)
        a.text(x.median() + 0.5, i - 0.28, f"{x.median():.1f}", fontsize=7.5, color=INK2, va="center")
    a.set_yticks(range(len(WAKE)))
    a.set_yticklabels([l for _, l in WAKE], fontsize=7.5)
    a.yaxis.tick_right()
    a.set_ylim(len(WAKE) - 0.5, -0.5)
    a.set_xlim(0, 18)
    a.set_title("Wake cost micro-benchmark (us)")
    a.grid(axis="y", visible=False)
    a.spines["right"].set_visible(True)
    return save(fig, "fig03_cpu_gap")


if __name__ == "__main__":
    build()
