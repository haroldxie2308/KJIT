"""Figure 5: dispatch stall = I-cache placement (journal 2026-10-11 03:03)."""
from common import *

STRIDES = (4096, 8192, 16384, 32768)
RAMP = {4096: "#86b6ef", 8192: "#3987e5", 16384: "#1c5cab", 32768: "#0d366b"}    # sequential blue, steps 250/400/550/700
ORDER = ["off", "0", "2", "4", "16", "64", "256", "1024", "pack"]
LABEL = {"off": "KJIT\noff", "0": "as\nmain", "pack": "packed"}


def build():
    d = csv("2026-10-11/0303-dispatch-study.csv")
    k = d[(d["where"] == "el1") & (d.kernel == "sites") & (d.extra == "knee") & d.placement.str.match(r"^stride\d+$")].copy()
    k["stride"] = k.placement.str[6:].astype(int)
    k["ns_pair"] = k.ns_per_transfer * 2          # call + return
    k["blocks"] = k.n + 2                         # n call sites + leaf + entry block
    r = csv("2026-10-11/0303-dispatch-study-redis.csv")

    fig, ax = figure(
        11.5, 7.6,
        "Dispatch stall is I-cache placement: the cliff sits at 6 x (32 KiB / stride) fragments, colouring or packing removes it",
        "Page-aligned fragments put every hot block in the same few L1I sets; redis server CPU falls from 6.4 us to 3.6-3.9 us per SET once start offsets are spread.",
        "Data: docs/data/2026-10-11/0303-dispatch-study.csv (top: suite extra/knee, EL1, hand-written call kernel, ns per call+return = 2 x ns_per_transfer, "
        "one dot per boot, 2 boots), 0303-dispatch-study-redis.csv (bottom: server CPU = utime+stime ticks / 500k requests, one dot per run; colours = distinct fragment start offsets). "
        "Journal: 2026-10-11 03:03 (Dispatch stall: cause and alternatives; experiment branch, not merged). Dotted lines: predicted cliff 6 x 32 KiB / stride blocks. "
        "Native redis is client-limited, so the throughput panel saturates near 1.0; the CPU panel is the cost.",
        nrows=2, ncols=2, gridspec_kw={"height_ratios": [1, 1.1]})

    for c, (low, title) in enumerate((("nat", "native bl / ret in the fragment layout"), ("d0", "lowered (A11 dispatch template)"))):
        a = ax[0, c]
        for s in STRIDES:
            g = k[(k.lowering == low) & (k.stride == s)]
            a.scatter(g.blocks, g.ns_pair, s=7, color=RAMP[s], alpha=0.5, lw=0)
            m = g.groupby("blocks").ns_pair.median()
            a.plot(m.index, m.values, color=RAMP[s], lw=1.6, label=f"stride {s // 1024} KiB")
            a.axvline(6 * 32768 // s, color=RAMP[s], lw=0.9, ls=":")
        a.set_title(title)
        a.set_xlabel("fragments (blocks) in the cyclic call chain")
        a.set_ylim(0, 12.5)
        a.set_xlim(0, 66)
        if c == 0:
            a.set_ylabel("ns per call + return")
            a.legend(loc="lower right", fontsize=8)

    # redis: server CPU and throughput relative to native
    pos = {c: i for i, c in enumerate(ORDER)}
    r = r.assign(x=r.colors.astype(str).map(pos))
    base_rps = r[r.colors.astype(str) == "off"].groupby("test").rps.median()
    r["rel_rps"] = r.rps / r.test.map(base_rps)
    for c, (col, ylabel, ttl) in enumerate((("server_cpu_us_per_request", "server CPU per request (us)", "Redis server CPU vs colours"),
                                            ("rel_rps", "throughput / native median", "Redis throughput vs colours"))):
        a = ax[1, c]
        for test, color, dx in (("set", BLUE, -0.12), ("get", ORANGE, 0.12)):
            t = r[r.test == test]
            a.scatter(t.x + dx + (np.arange(len(t)) % 5 - 2) * 0.015, t[col], s=7, color=color, alpha=0.4, lw=0, zorder=3)
            m = t.groupby("x")[col].median()
            a.plot(m.index, m.values, color=color, marker="o", ms=4, label=test.upper(), zorder=4)
        a.set_xticks(range(len(ORDER)))
        a.set_xticklabels([LABEL.get(o, o) for o in ORDER], fontsize=8)
        a.set_xlabel("fragment start-offset colours (--> more spread)")
        a.set_ylabel(ylabel)
        a.set_title(ttl)
        if c == 0:
            a.set_ylim(0, 7.2)
            a.legend(loc="upper right")
        else:
            a.set_ylim(0.4, 1.15)
            a.axhline(1.0, color=INK2, lw=0.8, ls="--")
    return save(fig, "fig05_dispatch_stall")


if __name__ == "__main__":
    build()
