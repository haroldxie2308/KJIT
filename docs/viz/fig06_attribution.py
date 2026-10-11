"""Figure 6: redis loss attribution before/after A14 (journal 2026-10-11 01:54 and 12:42)."""
import re
from common import *

# (key, label, colour, regex on the row's item name). Fixed order = stack order, bottom to top.
GROUPS = [
    ("pan", "PAN windows", BLUE, r"PAN windows"),
    ("tmpl", "Dispatch template words", ORANGE, r"template words"),
    ("stall", "Dispatch stalls (call + return targets)", AQUA, r"stall at"),
    ("mid", "Other native-equivalent instructions mid-block", YELLOW, r"mid-block"),
    ("small", "Budget checks, reg-virt, alignment, prologue/epilogue", MAGENTA, r"Budget|Reg-virt|Alignment|prologue"),
    ("rt", "Runtime entries + FP/SIMD bracket", VIOLET, r"Runtime entries|FP/SIMD bracket"),
    ("sys", "Syscall path, net (saved round trips)", RED, r"Syscall path"),
    ("tim", "Timer instrumentation, native idle slack", MUTED, r"Instrumentation|Timers of|Native server idle"),
]


def rows(file, test):
    d = csv(file)
    a = d[(d.group == "attribution") & (d.test == test) & (d.metric == "insitu_ns_per_req")].copy()
    a["value"] = pd.to_numeric(a.value)
    a["sampled"] = a.tag.str.contains("sampled")
    out = {}
    for key, _, _, rx in GROUPS:
        g = a[a["item"].str.contains(rx, regex=True)]
        assert len(g), (file, test, key)
        assert g.sampled.nunique() == 1, f"group {key} mixes sampled and timed rows"
        out[key] = (g.value.sum(), bool(g.sampled.iloc[0]))
    # every row is in exactly one group
    assert sum(a["item"].str.contains(rx, regex=True).sum() for *_, rx in GROUPS) == len(a)
    return out


def total(file, test, item):
    d = csv(file)
    s = d[(d.group == "summary") & (d.test == test) & (d["item"] == item)]
    return float(pd.to_numeric(s.value).iloc[0]) * 1000.0     # us -> ns


def build():
    f0, f1 = "2026-10-11/0154-redis-attrib.csv", "2026-10-11/1240-attrib-a14.csv"
    bars = []
    for test in ("set", "get"):
        bars.append((test, "before A14\n(01:54, wall loss L)", rows(f0, test), total(f0, test, "L")))
        bars.append((test, "after A14\n(12:42, server-CPU gap G)", rows(f1, test), total(f1, test, "G")))

    fig, ax = figure(
        11.5, 7.0,
        "Redis loss before vs after A14: stalls and mid-block time vanish, PAN windows and runtime entries remain",
        "Stacked in-situ ns per request (positive costs up, savings and slack down); the black mark is the measured total (L before, G after). "
        "Hatched = sampled shares, solid = timed.",
        "Data: docs/data/2026-10-11/0154-redis-attrib.csv and 1240-attrib-a14.csv (group attribution, metric insitu_ns_per_req; totals from group summary). Journal: 2026-10-11 01:54 and 12:42. "
        "Before: wall-time loss L in the client-bound a11-baseline setup (includes -973/-1021 ns of native idle slack and the timers' own cost); after: paired server-CPU gap G "
        "(timers-off boots). Sampled rows are shares of sampled fragment time, not additive costs: the 12:42 PAN ablation removed 0.00 us of CPU although windows sample at 486 ns "
        "(the time reappears in the other fragment classes). No spread is shown: these are derived medians; quartiles of G are in the entry.")
    a = ax[0, 0]
    xs = []
    for i, (test, lab, g, tot) in enumerate(bars):
        x = i + (0.35 if i >= 2 else 0)
        xs.append(x)
        pos = neg = 0.0
        for key, _, color, _ in GROUPS:
            v, sampled = g[key]
            bottom = pos if v >= 0 else neg
            a.bar(x, v, bottom=bottom, width=0.62, color=color, edgecolor="white" if sampled else color, linewidth=0,
                  hatch="//////" if sampled else None, zorder=3)
            a.plot([x - 0.31, x + 0.31], [bottom + v] * 2, color="white", lw=1.2, zorder=4)
            if v >= 0:
                pos += v
            else:
                neg += v
        a.plot([x - 0.38, x + 0.38], [tot, tot], color=INK, lw=2.2, zorder=5)
        a.text(x + 0.42, tot, f"{tot:.0f}", fontsize=8, va="center", fontweight="bold")
    a.axhline(0, color=INK2, lw=0.8)
    a.set_xticks(xs)
    a.set_xticklabels([f"{b[0].upper()}\n{b[1]}" for b in bars], fontsize=8)
    a.set_ylabel("in-situ ns per request")
    a.grid(axis="x", visible=False)
    a.set_xlim(-0.6, 4.2)
    handles = [plt.Rectangle((0, 0), 1, 1, color=c, label=l) for _, l, c, _ in GROUPS][::-1]
    handles += [plt.Rectangle((0, 0), 1, 1, fc=MUTED, ec="white", hatch="//////", label="hatched: sampled (S)"),
                plt.Rectangle((0, 0), 1, 1, fc=MUTED, ec=MUTED, label="solid: timed (T)"),
                plt.Line2D([0], [0], color=INK, lw=2.2, label="measured total (L / G)")]
    a.legend(handles=handles, loc="center left", bbox_to_anchor=(1.01, 0.5), fontsize=8)
    return save(fig, "fig06_attribution")


if __name__ == "__main__":
    build()
