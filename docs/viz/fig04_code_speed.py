"""Figure 4: translated code speed across versions (journal 2026-10-10 09:05, 11:51; 2026-10-11 00:37, 03:54).

04a: slope ratio fragment/native per variant and version.
04b: end-to-end time per syscall iteration, off vs on, on merged main (00:37 entry).
"""
from common import *

VARIANTS = ["strlen", "copy", "hash", "copy16", "calls", "callsi", "calls2", "simd32"]
UNIT = {"strlen": "per byte", "copy": "per byte", "hash": "per byte", "copy16": "per 16 B", "calls": "per call",
        "callsi": "per call", "calls2": "per nested call", "simd32": "per 32 B"}
# (key, label, colour, marker)
VERSIONS = [("a518d03", "before A12 (a518d03, 4 boots)", MUTED, "o"),
            ("6802ee6", "before A12 (6802ee6, 2 boots)", MUTED, "D"),
            ("A12", "A12 (2 boots)", BLUE, "o"),
            ("main", "merged main A12+A13 (2 boots)", ORANGE, "o"),
            ("A14", "A14 (2 boots)", AQUA, "o")]


def load():
    """One frame of every rep: columns ver, boot, variant, state, n, ns_per_outer."""
    _, t = json_tables("2026-10-10/0905-fragment-code-slowdown.json")
    pre = t["code_speed_reps"].rename(columns={"run": "boot", "kjit": "state"})
    pre["ver"] = "a518d03"
    a12 = csv("2026-10-10/1149-a12-code-speed.csv")
    a12["ver"] = a12.commit.map({"6802ee6": "6802ee6", "6802ee6+A12-worktree": "A12"})
    a12 = a12[a12.ver.notna()]
    main = csv("2026-10-11/0037-main-code-speed.csv"); main["ver"] = "main"
    a14 = csv("2026-10-11/0354-a14-code-speed.csv"); a14["ver"] = "A14"
    cols = ["ver", "boot", "variant", "state", "n", "ns_per_outer"]
    return pd.concat([x[cols] for x in (pre, a12, main, a14)], ignore_index=True)


def fits(d, by):
    """Least-squares ns = icpt + slope * n per group and state, fitted on the median over reps at each n
    (robust to the occasional outlier rep, e.g. main hash n=1024 on: 1569 ns against 1021); one row per group."""
    rows = []
    for key, g in d.groupby(by + ["state"], sort=True):
        m = g.groupby("n").ns_per_outer.median()
        slope, icpt = np.polyfit(m.index, m.values, 1)
        rows.append((*key, slope, icpt))
    f = pd.DataFrame(rows, columns=by + ["state", "slope", "icpt"])
    f = f.pivot(index=by, columns="state", values=["slope", "icpt"])
    f.columns = [f"{a}_{b}" for a, b in f.columns]
    f = f.reset_index()
    f["ratio"] = f.slope_on / f.slope_off
    f["saving"] = f.icpt_off - f.icpt_on
    return f


def build_ratio(d):
    f = fits(d, ["ver", "boot", "variant"])
    fig, ax = figure(
        11.5, 5.4,
        "Translated code speed: integer byte loops went from 2-7x native to native at A12; SIMD q copies stay 35x",
        "Slope ratio = ns per unit of work in the fragment / native. The register budget counter (A12) removed the per-instruction cost; "
        "A13 and A14 left it unchanged (calls 1.5x, copy16 1.5x).",
        "Data: docs/data/2026-10-10/0905-fragment-code-slowdown.json (code_speed_reps, a518d03), 2026-10-10/1149-a12-code-speed.csv (6802ee6 base and A12), "
        "2026-10-11/0037-main-code-speed.csv, 2026-10-11/0354-a14-code-speed.csv. Journal: 2026-10-10 09:05 and 11:51, 2026-10-11 00:37 and 03:54. "
        "Each dot = one boot (median ns per outer iteration at each n, fitted linearly against n; 7 reps per n); bar = median over boots. simd32 ratios move with its tiny native slope (0.014 ns).")
    a = ax[0, 0]
    w = 0.14
    for k, (ver, label, color, mk) in enumerate(VERSIONS):
        off = (k - 2) * w
        for i, v in enumerate(VARIANTS):
            r = f[(f.ver == ver) & (f.variant == v)].ratio
            a.scatter(np.full(len(r), i + off) + (np.arange(len(r)) - (len(r) - 1) / 2) * 0.012, r, s=14, color=color, marker=mk, alpha=0.7, lw=0, zorder=3)
            a.plot([i + off - 0.05, i + off + 0.05], [r.median()] * 2, color=color, lw=2.2, zorder=4)
        a.scatter([], [], color=color, marker=mk, s=18, label=label)
    a.axhline(1.0, color=INK2, lw=0.8, ls="--")
    a.text(7.55, 1.0, "native", fontsize=7.5, color=INK2, va="bottom", ha="right")
    a.set_yscale("log")
    a.set_yticks([0.9, 1, 1.5, 2, 3, 4, 6, 10, 20, 40])
    a.set_yticklabels(["0.9", "1", "1.5", "2", "3", "4", "6", "10", "20", "40"])
    a.minorticks_off()
    a.set_xticks(range(len(VARIANTS)))
    a.set_xticklabels([f"{v}\n({UNIT[v]})" for v in VARIANTS], fontsize=8)
    a.set_ylabel("slope ratio, fragment / native")
    a.grid(axis="x", visible=False)
    a.legend(loc="upper left", fontsize=8)
    return save(fig, "fig04a_code_speed_ratio")


def build_end_to_end(d):
    m = d[d.ver == "main"]
    f = fits(m, ["variant"])
    pooled = f.set_index("variant")
    order = [v for v in VARIANTS if v != "callsi"]   # the 00:37 table omits callsi
    fig, ax = figure(
        11.5, 6.6,
        "End to end on merged main: each syscall saves about 75-80 ns; loses beyond ~69 calls or ~51 bytes of q-register copy",
        "Time per outer iteration (one syscall plus n units of work). Integer loops win at every n; call-heavy and SIMD-copy work erodes the saving.",
        "Data: docs/data/2026-10-11/0037-main-code-speed.csv. Journal: 2026-10-11 00:37 (Merged main: code speed and redis). Dots = median over reps and boots at each n; "
        "lines = least-squares fit of the per-n medians over both boots (7 reps per n; robust to one outlier rep). Saving = native intercept - fragment intercept; break-even n = saving / (fragment slope - native slope), "
        "marked only where it falls within 2x the measured range (the entry's copy figure of ~16k bytes is a slope gap within noise).",
        nrows=2, ncols=4, sharey=False)
    for k, v in enumerate(order):
        a = ax[k // 4, k % 4]
        g = m[m.variant == v]
        p = pooled.loc[v]
        nmax = g.n.max()
        xs = np.array([0, nmax * 1.0])
        for state, color, label in (("off", MUTED, "native"), ("on", ORANGE, "fragment (KJIT on)")):
            pts = g[g.state == state].groupby("n").ns_per_outer.median()
            a.scatter(pts.index, pts.values, s=14, color=color, zorder=3)
            a.plot(xs, p[f"icpt_{state}"] + p[f"slope_{state}"] * xs, color=color, lw=1.6, label=label)
        txt = f"saving {p.saving:.0f} ns at n=0"
        dslope = p.slope_on - p.slope_off
        if dslope > 0 and 0 < p.saving / dslope <= 2 * nmax:
            be = p.saving / dslope
            a.axvline(be, color=INK2, lw=0.8, ls=":")
            txt += f"\nbreak-even n = {be:.0f}"
            if be > nmax:
                txt += " (extrapolated)"
        else:
            txt += "\nno break-even in range"
        a.set_title(f"{v} ({UNIT[v]})", fontsize=9)
        a.text(0.04, 0.96, txt, transform=a.transAxes, fontsize=7.5, color=INK2, va="top", bbox=dict(fc="white", ec="none", alpha=0.85, pad=1.5))
        a.set_xlim(0, max(nmax, be if dslope > 0 and 0 < p.saving / dslope <= 2 * nmax else 0) * 1.05)
        a.set_ylim(0, None)
        a.set_xlabel("n (units of work)", fontsize=8)
        if k % 4 == 0:
            a.set_ylabel("ns per iteration")
        if k == 0:
            a.legend(loc="lower right", fontsize=7.5)
    ax[1, 3].axis("off")
    return save(fig, "fig04b_code_speed_end_to_end")


def build():
    d = load()
    return [build_ratio(d), build_end_to_end(d)]


if __name__ == "__main__":
    build()
