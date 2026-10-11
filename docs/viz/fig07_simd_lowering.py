"""Figure 7: SIMD&FP access lowering alternatives (journal 2026-10-11 01:47)."""
from common import *

LOOPS = [("qcopy", 32), ("memcpy_loop", 64), ("memmove_back", 64), ("memset_loop", 64), ("strlen_loop", 32), ("memchr_loop", 32)]
# bytes per loop trip: the loop definitions of the entry's glibc table, not measurements
MODES = [("nat", "native (plain access)", MUTED, "D"),
         ("c0", "C0 today: one window per access", BLUE, "o"),
         ("c1", "C1 one window per straight-line run", ORANGE, "s"),
         ("c2r", "C2 window per call (EL1 upper bound)", AQUA, "^"),
         ("c2run", "C2 PAN cleared for the whole run", VIOLET, "v"),
         ("c3", "C3 no PAN: 64-bit LDTR/STTR pieces", MAGENTA, "P")]
FIT_N = (256, 1024, 4096)


def build():
    raw = csv("2026-10-11/0147-simd-lowering.csv")
    der = csv("2026-10-11/0147-simd-lowering-derived.csv")
    slope = der[(der.metric == "loop_slope_ns_per_trip")]
    el1 = raw[(raw.level == "el1") & raw.n.isin(FIT_N)]

    # per-boot slope (ns per trip) of the median ps per outer vs n
    rows = []
    for (b, sh, m), g in el1.groupby(["boot", "shape", "mode"]):
        g = g.groupby("n").median_ps_per_outer.median()
        if len(g) == len(FIT_N) and sh in dict(LOOPS):
            rows.append((b, sh, m, np.polyfit(g.index, g.values / 1000.0, 1)[0] * dict(LOOPS)[sh]))
    ps = pd.DataFrame(rows, columns=["boot", "shape", "mode", "ns_trip"])
    # guard: the per-boot fits must reproduce the entry's derived slopes (loud failure if not)
    ref = slope[slope.level == "el1"].set_index(["shape", "mode"]).value
    med = ps.groupby(["shape", "mode"]).ns_trip.median()
    bad = [(k, med[k], ref[k]) for k in med.index if abs(med[k] / ref[k] - 1) > 0.05]
    assert not bad, f"per-boot fits disagree with 0147-simd-lowering-derived.csv: {bad}"

    # geometric mean of the ratio to EL0 native over the six loops (derived file's value_over_reference)
    gm = {}
    for m, *_ in MODES:
        v = slope[(slope.level == "el1") & (slope["mode"] == m) & slope["shape"].isin([l for l, _ in LOOPS])].value_over_reference
        if m == "nat":
            v = slope[(slope.level == "el0") & (slope["mode"] == "nat") & slope["shape"].isin([l for l, _ in LOOPS])].value_over_reference
        assert len(v) == len(LOOPS), (m, len(v))
        gm[m] = float(np.exp(np.log(v).mean()))

    fig, ax = figure(
        11.5, 5.8,
        "SIMD&FP lowering: only a run-scoped or per-call PAN window gets glibc loops near native; C0 today costs 18-57x",
        "ns per loop trip at EL1 (slope over n = 256/1024/4096 bytes). C3 (no PAN) is 1.5-2.9x native; C2 run-scoped 1.1-1.6x but weakens the PAN backstop for the whole run.",
        "Data: docs/data/2026-10-11/0147-simd-lowering.csv (per-boot medians of ps per outer iteration; slopes fitted per boot, 7 EL1 boots), "
        "0147-simd-lowering-derived.csv (entry's slopes and ratios to EL0 native; right panel = geometric mean over the six loops). Journal: 2026-10-11 01:47 (experiment branch, not merged). "
        "Dots = individual boots, marker = median. Bytes per trip: qcopy 32, memcpy 64, memmove 64, memset 64, strlen 32, memchr 32.",
        nrows=1, ncols=2, gridspec_kw={"width_ratios": [3, 1]})
    a = ax[0, 0]
    w = 0.12
    for k, (m, label, color, mk) in enumerate(MODES):
        for i, (sh, _) in enumerate(LOOPS):
            g = ps[(ps["shape"] == sh) & (ps["mode"] == m)]
            x = i + (k - 2.5) * w
            a.scatter(np.full(len(g), x), g.ns_trip, s=8, color=color, marker=mk, alpha=0.4, lw=0, zorder=3)
            a.scatter([x], [g.ns_trip.median()], s=22, color=color, marker=mk, zorder=4)
        a.scatter([], [], color=color, marker=mk, s=22, label=label)
    a.set_yscale("log")
    a.set_yticks([0.3, 0.5, 1, 2, 5, 10, 20, 50])
    a.set_yticklabels(["0.3", "0.5", "1", "2", "5", "10", "20", "50"])
    a.minorticks_off()
    a.set_xticks(range(len(LOOPS)))
    a.set_xticklabels([f"{s.replace('_loop', '').replace('_back', ' back')}\n({b} B/trip)" for s, b in LOOPS], fontsize=8)
    a.set_ylabel("ns per glibc loop trip (EL1)")
    a.grid(axis="x", visible=False)
    a.legend(loc="upper right", fontsize=7.5, ncol=1)
    a.set_ylim(0.25, 90)

    b = ax[0, 1]
    for k, (m, label, color, mk) in enumerate(MODES):
        b.barh(k, gm[m], color=color, height=0.62, zorder=3)
        b.text(gm[m] * 1.08, k, f"{gm[m]:.1f}x", va="center", fontsize=8)
    b.axvline(1, color=INK2, lw=0.8, ls="--")
    b.set_xscale("log")
    b.set_xlim(0.8, 80)
    b.set_xticks([1, 2, 5, 10, 30])
    b.set_xticklabels(["1", "2", "5", "10", "30"])
    b.minorticks_off()
    b.set_yticks([])
    b.set_ylim(len(MODES) - 0.5, -0.5)
    b.set_title("geometric mean vs native")
    b.grid(axis="y", visible=False)
    return save(fig, "fig07_simd_lowering")


if __name__ == "__main__":
    build()
