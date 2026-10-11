"""Figure 1: redis under UB's benchmark protocol (journal 2026-10-11 16:21)."""
import numpy as np
from common import *

UB_GET_GAIN = (0.044, 0.108)   # UB's published GET throughput gain, quoted in the 16:21 entry (OSDI '23, 6.2)


def build():
    d = csv("2026-10-11/1621-ub-standard.csv")
    d = d[d.pin == "pinned"]
    sys_ = csv("2026-10-11/1621-ub-standard-sys.csv")
    sys_ = sys_[sys_["mode"] == "getppid"]
    sizes = sorted(d["size"].unique())

    # per (kpti, boot, size, test): off and on side by side
    idx = ["kpti", "boot", "size", "test"]
    off = d[d.kjit == "off"].set_index(idx)
    on = d[d.kjit == "on"].set_index(idx)
    r = pd.DataFrame({
        "tput": on.req_per_s / off.req_per_s,
        "cpu": on.cpu_us_per_req / off.cpu_us_per_req,
        "cpu_off": off.cpu_us_per_req,
        "sys_per_req": on.hook_calls / on.requests,
    }).reset_index()

    fig, ax = figure(
        11.5, 7.2,
        "Redis under UB's protocol: KJIT on is slower than off at every value size",
        "Throughput falls to 0.28-0.75 of native and server CPU per request rises 1.4-3.6x; UB's published GET gain is not reached "
        "and the transition-removal ceiling is only +6..18%.",
        "Data: docs/data/2026-10-11/1621-ub-standard.csv (per-boot on/off ratios, server pinned to CPU 0, --threads 2, one run per cell per boot, 5 boots), "
        "1621-ub-standard-sys.csv (null-syscall round trip, for the ceiling). Journal: 2026-10-11 16:21. Dots = individual boots, "
        "lines = median over boots. Ceiling band (GET) = saving of removing the syscall transition (achievable: native - in-kernel round trip; full: native "
        "round trip) x syscalls per request, as in the entry's ceiling table. Throughput is quantized in 250 ms steps by --threads (D11); the CPU row is the exact one.",
        nrows=2, ncols=2, sharex=True)

    for c, kpti in enumerate((0, 1)):
        s = sys_[sys_.kpti == kpti]
        nat = s[s.kjit == "off"].median_ns_per_syscall.median()
        ink = s[s.kjit == "on"].median_ns_per_syscall.median()
        g = r[(r.kpti == kpti) & (r.test == "get")].groupby("size")
        sav_full = nat * g.sys_per_req.median() / 1000          # us per request
        sav_ach = (nat - ink) * g.sys_per_req.median() / 1000
        cpu_off = g.cpu_off.median()
        # throughput ceiling gain = saving / (cpu_off - saving); CPU ratio ceiling = 1 - saving / cpu_off
        t_lo, t_hi = 1 + sav_ach / (cpu_off - sav_ach), 1 + sav_full / (cpu_off - sav_full)
        c_hi, c_lo = 1 - sav_ach / cpu_off, 1 - sav_full / cpu_off

        for row, (key, ylabel) in enumerate((("tput", "throughput on / off"), ("cpu", "server CPU per request on / off"))):
            a = ax[row, c]
            if row == 0:
                a.axhspan(1 + UB_GET_GAIN[0], 1 + UB_GET_GAIN[1], color=MUTED, alpha=0.35, lw=0)
                a.fill_between(sizes, t_lo.values, t_hi.values, color=AQUA, alpha=0.18, lw=0)
                a.set_ylim(0.2, 1.25)
                a.set_title(("KPTI off" if kpti == 0 else "KPTI forced on") + " (round trip native %.0f ns, in kernel %.0f ns)" % (nat, ink), fontsize=9.5)
            else:
                a.fill_between(sizes, c_lo.values, c_hi.values, color=AQUA, alpha=0.18, lw=0)
                a.set_ylim(0.8, 4.0)
            a.axhline(1.0, color=INK2, lw=0.8, ls="--")
            for test, color, dx, mk in (("set", BLUE, 0.92, "o"), ("get", ORANGE, 1.08, "s")):
                t = r[(r.kpti == kpti) & (r.test == test)]
                a.scatter(t["size"] * dx, t[key], s=9, color=color, alpha=0.45, marker=mk, lw=0, zorder=3)
                m = t.groupby("size")[key].median()
                a.plot(m.index, m.values, color=color, lw=1.8, label=test.upper(), zorder=4)
            log_size_axis(a, sizes)
            if c == 0:
                a.set_ylabel(ylabel)
            if row == 1:
                a.set_xlabel("redis-benchmark -d (value bytes)")

    # legend and direct labels
    h = [plt.Line2D([], [], color=BLUE, marker="o", lw=1.8, ms=4, label="SET"),
         plt.Line2D([], [], color=ORANGE, marker="s", lw=1.8, ms=4, label="GET"),
         plt.Rectangle((0, 0), 1, 1, color=MUTED, alpha=0.35, lw=0, label="UB published GET band"),
         plt.Rectangle((0, 0), 1, 1, color=AQUA, alpha=0.25, lw=0, label="KJIT ceiling, GET (achievable..full)")]
    ax[0, 0].legend(handles=h, loc="lower left", ncol=2, fontsize=7.5)
    ax[0, 0].text(16384, 1.0, "no change ", fontsize=7, color=INK2, va="bottom", ha="right")
    return save(fig, "fig01_redis_ub")


if __name__ == "__main__":
    build()
