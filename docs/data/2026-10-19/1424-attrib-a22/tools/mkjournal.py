"""EXPERIMENT (exp/attrib-a22). Builds the journal entry text from tables.md and runs.csv. usage: mkjournal.py HHMM > entry.md"""
import re
import sys

import numpy as np
import pandas as pd

HHMM = sys.argv[1]
HH, MM = HHMM[:2], HHMM[2:]
D = f"../data/2026-10-19/{HHMM}-attrib-a22"
T = open("tables.md").read()


def sec(title, strip_header=True):
    m = re.search(r"^## " + re.escape(title) + r".*?\n\n(.*?)(?=\n## |\n# |\Z)", T, re.S | re.M)
    assert m, title
    return m.group(1).strip()


runs = pd.read_csv("runs.csv")
# block-rate table
rows = []
for kpti in (0, 1):
    for cfg, nm in (("ug", "unix GET -d 1"), ("us", "unix SET -d 1"), ("up", "unix PING_MBULK")):
        r = {"KPTI": "forced on" if kpti else "off", "cell": nm}
        for st in ("off", "on"):
            k = runs[(runs.kpti == kpti) & (runs.cfg == cfg) & (runs.state == st)]
            r[f"{st}: blocks/1000"] = f"{k.nvol_k.median():.2f}"
            r[f"{st}: wake IPIs/1000"] = f"{k.ipi_cl_k.median():.2f}"
            r[f"{st}: CPU 0 idle"] = f"{k.c0_idle_frac.median():.3f}"
        for st in ("offS", "onS"):
            k = runs[(runs.kpti == kpti) & (runs.cfg == cfg) & (runs.state == st)]
            r[f"{st}: blocks/1000"] = f"{k.nvol_k.median():.2f}"
        rows.append(r)
blk = pd.DataFrame(rows)
blk_md = "| " + " | ".join(blk.columns) + " |\n|" + "---|" * len(blk.columns) + "\n" + "\n".join("| " + " | ".join(str(v) for v in r) + " |" for r in blk.values)

# dose-response table (all 24 injected states)
import sys as _s
_s.path.insert(0, "tools")
from analyze import pair, summ

rows = []
for kpti in (0, 1):
    for cfg in ("ug", "us", "up"):
        k = runs[(runs.kpti == kpti) & (runs.cfg == cfg) & (runs.type == "D")]
        hk = k[k.state == "on"].hook_calls_pr.median()
        for a, b, d in (("offD100", "off", 100), ("offD300", "off", 300), ("onD100", "on", 100), ("onD300", "on", 300)):
            s = summ(pair(k, a, b, "cpu_us"))
            sn = summ(pair(k, a, b, "nvol_k"))
            si = summ(pair(k, a, b, "ipi_cl_k"))
            inj = d * 0.325 * hk / 1000
            rows.append({"KPTI": "on" if kpti else "off", "cell": cfg, "pair": f"{a} - {b}", "injected": f"{inj:+.3f}",
                         "cpu delta": f"{s['med']:+.3f}", "realized fraction": f"{s['med'] / inj:.2f}",
                         "blocks/1000": f"{sn['med']:+.2f}", "wake IPIs/1000": f"{si['med']:+.2f}"})
dr = pd.DataFrame(rows)
dr_md = "| " + " | ".join(dr.columns) + " |\n|" + "---|" * len(dr.columns) + "\n" + "\n".join("| " + " | ".join(str(v) for v in r) + " |" for r in dr.values)
fr = dr["realized fraction"].astype(float)
frac_all = f"{fr.median():.2f} (range {fr.min():.2f}..{fr.max():.2f}, {len(fr)} states)"
frac_off = fr[dr.pair.str.startswith("off")].median()

text = f"""## {HH}:{MM} +0800 — Redis overhead attribution on A22

Commit: 879cf18 (measured tree; instrumentation diff in the data dir)

Data: [runs]({D}.csv) (one row per measured run: 1122 runs of 13 attribution boots (2 more boots are micro boots) `boot_label` = `at22-<type>-k<kpti>-b<n>`; types H = uninstrumented module, off/on only; P = same module, pipelined cells; A = instrumented, all states; D, N = instrumented, delay / statistics states; `cell` ug|us|up|ug3|ugp16|usp16|ugp4, `state`, timers `x_*` in CNTVCT ticks, derived `c_*_us_per_req` corrected for the timers' own cost),
[boots]({D}-boots.csv) (module md5s are in `module-md5.txt`, host load, x_micro, svc_bench and x_delay calibration items), [micro]({D}-micro.csv) (hot-loop items of the two micro boots);
raw logs in `docs/data/2026-10-19/{HHMM}-attrib-a22/` (`boots/<label>/` serial.log, host.txt, guest-run.out, fragment list and final counters; `tables.md` = every generated table, `micro.md`; `kjit_glue-experiment.diff` = the instrumentation (`kjit_glue.c`, `runtime/stats.rs`, applies to 879cf18); `tools/` = guest scripts `attrib-a22.sh` / `micro-a22.sh`, drivers `boot.sh` / `drive*.sh`, `parse.py`, `analyze.py`, `report.py`, `micro.py`, `export.py`, `mkjournal.py`; `hung-attempts/`; `progress.txt`, `drive.log`).

Question: where does the remaining KJIT-on minus KJIT-off server CPU per redis request go on main after A22, KPTI off first (still a loss, +0.06 us in the 11:43 entry), KPTI forced on as the comparison; and what are the next levers.

### Answer

Server CPU per request, UB protocol (server on CPU 0, `nojit` clients on CPUs 1-3, `--threads 2 -c 50 -P 1`, unix socket, `sum_exec_runtime`), KJIT on minus off, paired inside boots, `-d 1`:
**KPTI off: GET +0.048 [+0.033..+0.056], SET +0.078 [+0.072..+0.092], PING_MBULK +0.043 [+0.035..+0.059]** (uninstrumented 879cf18 module, 2 boots, 16 pairs per cell, 2/2 boots positive in every cell; pooled over all 7 boots with both states, instrumented included: +0.043 / +0.081 / +0.049, 7/7 boots positive, bootstrap CIs [+0.027..+0.053] / [+0.066..+0.106] / [+0.039..+0.060]).
KPTI forced on: GET -0.070, SET -0.036, PING -0.105 (1 boot, 8 pairs; pooled over 5 boots -0.070 [-0.094..-0.058], -0.031 [-0.046..+0.007], -0.117 [-0.140..-0.097]). **Verified** as measured numbers.

1. **Where the KPTI-off GET gap comes from (intrinsic, KPTI off, GET; SET and PING in the tables below).** In-kernel syscalls avoided -0.217 (2.16 x 100 ns, hot unit); the fixed path of the runtime costs +0.262 (hook logic proper +0.142, FP/SIMD bracket +0.073, run entry/exit +0.047);
   the translated body costs +0.103 above native code at steady state (the -P 16 gap, where syscalls and the fixed path are 1/16 as frequent); sum +0.148 against +0.048 measured; with the in-situ saving (`svcn - on` = 0.308 for GET) the sum is +0.057. The budget closes to within 0.1, no better: whether the difference is the closed loop of the benchmark giving back part of any server-side cost (below) or a larger real saving per syscall (the cold start of native code after a return to EL0) is **not separated**.
   **The translated code is no longer the main term; the fixed path (hook, bracket, run entry/exit, statistics) is larger than the whole syscall saving.** Scheduling is not the cause at KPTI off (below).
2. **Fixed per-run path.** 14.8 ns per fragment run hot (trampoline 8.1 ns, of which the `msr pan` pair 7.7; prologue + epilogue 6.8), 40.6 ns for a whole hook body with one run, SRCU 9.5 ns on top (paid by off as well). In situ per request: 2.16 hook calls, 3.16 runs, **one non-SVC exit per request: the `BR` into the FP/SIMD fragment (`exit_br` 1.000, `ibtc_fpsimd_boundary` 1.000); every other exit is <= 0.0013 per request**. In situ the hook logic costs 142 ns per request, of which about 47 ns is the single chain exit; the other 95 ns is 44 ns per hook call against 26 ns hot (1.7x). The FP excursion (bracket 73 + chain exit 47 + the extra run 15) is about 135 ns per request.
3. **Block rate: a protocol effect, not a KJIT cost.** With KPTI forced on the server blocks more with KJIT on (GET 15.4 -> 18.6, SET 10.3 -> 15.2, PING 18.9 -> 22.9 per 1000 requests) because it is faster; with KPTI off it blocks *less* (11.1 -> 8.1, 8.3 -> 7.3, 16.9 -> 13.2) because it is slower. A native server made slower by a known delay (`x_delay`) shows the same movement (offD300: -4.5 blocks/1000 on GET), and a KJIT server slowed to the native CPU per request (KPTI on, GET: `onD100` / `onD300` interpolated to equal CPU) has -0.7 / -1.2 blocks per 1000 against off instead of +2.8 (PING -2.9 instead of +3.5); the SET cell is not resolved by this (below). Extra wake-up IPIs to the load generator: -0.000 / +0.017 / +0.002 us per request at KPTI off. With a SCHED_IDLE spinner on CPU 0 (the vCPU never idles) the KPTI-off gap stays (onS - offS +0.033 / +0.044 / +0.049, against +0.042 / +0.097 / +0.051 without it in the same boots). **The scheduling share of the KPTI-off gap is 0 +- 0.03 (no value above +0.017).**
   The closed loop also damps server-side changes: a delay injected into a native server shows up in CPU per request at a median fraction {frac_all} (native base {frac_off:.2f}), so an A23 saving is expected at roughly half its intrinsic size (the statistics ablation realized 0.35-0.85 of its prediction).
4. **A23 ranking (KPTI off, GET, realized = intrinsic x ~0.45 unless measured).** (a) statistics off the hot path (per-CPU `hook_calls`, 17 runtime atomics, 2 CNTVCT reads of the bracket): intrinsic 0.068, **measured -0.024 GET / -0.024 SET / -0.054 PING** (KPTI on -0.058 / -0.051 / -0.056); (b) no FP boundary exit (sticky bracket for entries that reach it): intrinsic 0.062, est. -0.028; (c) PAN once per hook call: 0.009, est. -0.004; (d) hook-path trims: ~0.02, est. -0.01; (e) C6 + C7: 301 words = 0.0135, est. -0.006; C8: 653 words = 0.029 if the load is free, est. -0.013.
   **No single change flips KPTI-off GET (+0.043).** (a) alone leaves +0.02 (measured); **(a) + (b) is estimated at -0.009 +- 0.03 (marginal); adding (c) + (d) gives -0.023.** PING flips with (a) alone (+0.049 - 0.054). SET (+0.081) also needs the translated body (C6-C8 and beyond). Only (a) is measured; (b)-(e) are estimates.

### Decomposition of on - off, us per request

Lines 2-4 are timers of the `onT` state (CNTVCT around the hook, every run and the bracket, corrected for their own cost; `onT` itself costs +0.43..+0.56 against `on` at KPTI off, so only differences of its own segments are used), line 1 is the in-kernel syscall count times the hot unit of the micro boot (101 ns per syscall at KPTI off; at KPTI on plus the null-syscall difference 207.3 - 133.3 ns, **assumed** because the KPTI-on micro boot was dropped), line 5 is the gap of the plain module with `-P 16` (KPTI off, GET and SET cells; PING uses GET's).

KPTI off:

{sec("KPTI off: decomposition of on - off")}

KPTI forced on:

{sec("KPTI forced on: decomposition of on - off")}

Reading: **line 1** is verified as a unit and counted per request (in-situ `svcn - on`, line 1b, is the same quantity measured with the fragments still running; it varies 0.11..0.44 between cells because `svcn` also changes the server's speed and so the loop's batching; hot-unit values are used for the sum). **Lines 2-3** verified as timers (+-0.02 from the correction constants).
**Line 2** contains the one chain exit per request (the BR into the FP fragment; chain window 83 ns, about 47 ns without the bracket's front half), so the dispatch / miss / chain round trips are about 0.047 of the 0.142. **Line 4** is a hot unit times the counted entries (**assumed** in situ). **Line 5** is the translated body above native at steady state: with `-P 16` the in-kernel syscalls are 0.129 per request and fixed path and saving shrink to a net of about +0.003 (estimated from the 4 units), so the gap is the code (GET 0.391 -> 0.494, SET 0.462 -> 0.616 us per request); at `-P 4` it is +0.117. It is a KPTI-off measurement used in both tables; the pipelined cells were not run with KPTI on.
The tick-based estimate of the native EL0 time (utime of off minus on, the 15:25 method) says 0.70 us (GET) for 0.72 us of fragment code, i.e. no excess; it is not used (see below). Line 7 (IPIs) is `(ipi on - off) x 6.9 us`, 6.9 us being the remote-wake price of the micro boots (6.8-7.6).

Paired state differences of the instrumented boots (KPTI off, then on); `svcn` = every SVC executes at EL0 after the fragments ran in the kernel, `decl1/2` = the hook runs `kjit_can_run` (+ `kjit_lookup`) and returns to EL0, `offT/onT` = timers, `offS/onS` = a SCHED_IDLE spinner on CPU 0:

{sec("KPTI off: instrumented-module pairs")}

{sec("KPTI forced on: instrumented-module pairs")}

`decl2 - off` is +0.016 / +0.014 / +0.009 at KPTI off (+0.025 / +0.008 / +0.015 on): the hook with KJIT enabled but all code native costs nothing measurable, as at A17.

Timer lines of `onT` (median [Q1..Q3] over runs, KPTI off), and the three phases of a hook call:

{sec("KPTI off: timer lines of onT")}

Runtime exits per request, state `on`, KPTI off (KPTI on the same to 0.002):

{sec("KPTI off: runtime counters per request")}

### The fixed path

Hot loops (micro boot `M-k0-b1`, `svc_bench getppid`, 3 rounds, rounds agree within 1 ns; `micro-k0-b0` with the previous instrumented module agrees within 1.5 ns), ns per repetition of one operation on a copy of `pt_regs` (a pure syscall loop): trampoline into a stub 8.07, whole fragment run 14.81, whole hook body (`kjit_rs_after_syscall` with one run) 40.61, `kjit_can_run` 1.01, `kjit_lookup` 4.17, SRCU lock+unlock 9.52, `msr pan` pair 7.72, relaxed atomic add 1.96. Null syscall 133.3 ns off, 69.2 on (64.1 saved), `svcn - on` 100.5 (entry/exit alone); with KPTI the null syscall is 207.3 ns. So per in-kernel syscall the hot path saves 101 ns and pays 36 ns (hook body without its run) + 9.5 SRCU (also paid by off) + the run.
The FP excursion hot (`entry_cost`, one syscall plus one call into an FP callee): on - off = +25.9 ns against -69.1 for the integer callee, so the boundary exit plus bracket plus FP callee cost 95 ns more than an integer callee.

In situ, amplifiers (N extra repetitions of one pure operation per hook call / run / bracket; the slope of server CPU is the in-situ price), KPTI off:

{sec("KPTI off: amplifiers")}

Reading: the amplifiers agree with the hot loops (can_run 1.1-1.5 ns, SRCU 9.6-11.5, PAN pair 8.1-9.2, trampoline 8.5-9.7); the bracket is 42-51 ns without its two statistic CNTVCT reads (the timers measure 71-73 ns **with** them: `kjit_call_fragment_fpsimd` reads the counter twice for `fpsimd_run_max_ns`, 25 ns); the chain exit's label search and publish are 1-5 ns (not the cost of the boundary exit). The timers' hook logic of 142 ns per request is 66 ns per hook call, against 26 ns hot (hook body 40.6 minus the run 14.8) plus the chain: the in-situ premium (cold code and data, FFI calls, stats atomics) is about 60 ns per request and is not isolated (no PMU).
Of the three phases (per hook call): prep 28 ns (can_run, lookup, accessors, budget read), post 44 ns (SVC exit handling: counters, `can_run`, `note_chain`; includes the bracket's back half on the FP call), chain 83 ns once per request (BR exit handling plus the bracket's front half).

Statistics ablation (`x_nostats`: 1 = the runtime's counter updates, 2 = the per-CPU `hook_calls` add, 4 = the bracket's two CNTVCT reads; paired with `on`, 4 pairs per cell, 1 boot per KPTI setting):

KPTI off:

{sec("KPTI off: statistics ablation")}

KPTI forced on:

{sec("KPTI forced on: statistics ablation")}

All together (bit 7) removes 0.024-0.054 per request at KPTI off and 0.051-0.058 at KPTI on, 35-85% of the 0.068 the hot units predict; the single bits are within the noise of 4 pairs (+-0.02).

### Block rate, wake-ups and the protocol

Medians over all runs of the state (all boots), per 1000 requests; the spinner states `offS`/`onS` keep CPU 0 from idling:

{blk_md}

KPTI forced on, the block rate rises with KJIT on in all three cells (+3.2, +4.9, +4.0 per 1000), 11:43 had the same (+2.1, +4.0, +4.2). Wake-up IPIs sent to the load generator (received on CPUs 1-3) rise by +2.3, +2.2, +1.4 per 1000 (x 6.9 us = +0.016, +0.015, +0.009 us per request); CPU 0 idles 8-10 points more.

**Is it inherent to a faster server?** `x_delay=N` is a busy loop of N iterations (0.325 ns each, calibrated by `svc_bench`: 1000 iterations = 331 ns at KPTI off) at the start of every hook call, in either state: a known slow-down of a native (`off`) or KJIT server (`on`). Paired with its own base (4 reps, 1 boot per KPTI setting; "injected" = N x 0.325 ns x hook calls per request of the `on` state, **assumed** equal for off):

{dr_md}

- A native server slowed by 0.07 / 0.21 us per request blocks 1.8 / 4.5 per 1000 less on GET at KPTI off (3.4 / 8.7 less at KPTI on): block rate follows the server's speed in this closed loop, whatever the code. The KPTI-on increase of the block rate with KJIT on is the same relation read the other way.
- **Equal-speed check, KPTI on (D-k1-b6 alone, 4 pairs).** GET: `on - off` is -0.053 us with +2.8 blocks/1000, `onD100 - off` +0.035 with -3.0; interpolated to equal CPU per request (t = 0.60) the block difference is -0.7 per 1000 (`onD300`: -1.2). PING: `on - off` -0.110 / +3.5, `onD300 - off` +0.096 / -8.5, interpolated -2.9. In those two cells the block excess disappears at equal speed: a response to speed, not a KJIT cost. **SET is not resolved:** in that boot `on - off` is +0.022 (pooled over boots -0.031) with +3.7 blocks, there is no sign change to interpolate at; the `onD` states of SET do reduce the blocks (-3.0 / -5.4), but a block excess of +3.7 with an `on` server that is not faster than `off` is not explained by speed. (At KPTI off the `onD` states of SET go the other way, +1.6 / +2.5 blocks and +7.3 / +14.7 wake IPIs per 1000: the clients start to sleep.)
- **Protocol-independent checks run:** (i) the injected-delay family above; (ii) the spinner states (no idle vCPU on CPU 0): the gap onS - offS is +0.033 / +0.044 / +0.049 at KPTI off (4 boots) and -0.049 / -0.028 / -0.096 at KPTI on (3 boots), the same sign and about the same size as without the spinner in the same boots (+0.042, +0.097, +0.051 and -0.063, -0.019, -0.110); (iii) pipelined cells (`-P 16`, `-P 4`; GET off 2.0 M requests/s with CPU 0 24% idle, SET off 10% idle, SET on 1.33 M requests/s): the gap there is +0.103 (GET -P 16) / +0.154 (SET -P 16) / +0.117 (GET -P 4), the code alone. `-c 60 --threads 3` does not saturate the server either (CPU 0 idle 21%, gap +0.156 with 5.7 more wake IPIs per 1000).
- **What an extra block costs.** The micro boots price a remote wake-up at 6.8-7.6 us to the waker (14.35 vs 6.70 us for a write that wakes nobody, M-k0-b1; 13.34 vs 6.56 in the earlier micro boot) and 8.5-8.8 us of CPU to the woken task; at 8.5 us the KPTI-on block excess would cost +0.027 (GET), +0.042 (SET), +0.034 (PING) us per request plus the IPIs (+0.016, +0.015, +0.009), +0.04..+0.06 in all (**assumed** unit costs). The dose-response gives no usable per-block price (0 and 11 us per block in the two KPTI-on GET estimates; the events that change with a block also change the event-loop cycles per request), so the in-situ price is **unknown**.
  At KPTI off the block rate falls with KJIT on (-3.0, -1.0, -3.7 per 1000), so the term is zero or negative there: about -0.026 (GET), +0.008 (SET), -0.029 (PING) with the IPIs, at 8.5 us per block (**assumed**).

Summary of the protocol: realized fraction of an injected delay {frac_all}. (1) At KPTI off the intrinsic sum of the decomposition is +0.13..+0.20 us per request with the hot-unit saving (+0.06..+0.1 with the in-situ saving) against +0.043..+0.081 measured, i.e. no more than half of the server-side cost reaches `sum_exec_runtime` if the hot-unit saving is right. (2) An A23 saving is expected at about half its intrinsic size (the statistics ablation: 0.034 realized of 0.068 predicted at KPTI off, 0.055 at KPTI on). (3) `sum_exec_runtime` per request is not a clean reading of a server-side change in this regime, which is why the A23 table gives intrinsic and realized sizes. At KPTI on the measured win (-0.07..-0.12 GET/PING) is larger than the intrinsic sum (-0.03), the opposite of a give-back; the decomposition does not explain that (A17's KPTI-on budget had the same sign of residual, +0.12..+0.20).

### A23 candidates, ranked by benefit / risk (KPTI off; us per request)

| # | candidate | intrinsic | realized, KPTI off GET (SET / PING) | basis | risk |
|---|---|---|---|---|---|
| 1 | statistics off the hot path: `hook_calls` per-CPU add (4 ns), about 17 runtime atomics per request (counted from `exec.rs`: 5 per hook call, ~6 more for the chain; `note_chain`: `fetch_max` + histogram), the bracket's two CNTVCT reads; keep the counters the guest tests read behind a static key or accumulate per hook call and flush once | 0.068 (hot units 9 + 34 + 25 ns x counts) | **-0.024 (-0.024 / -0.054)**, KPTI on -0.058 / -0.051 / -0.056 | **ablation measured** (1 boot, 4 pairs, +-0.02) | none for correctness; the K2/K3/campaign scripts parse the counters |
| 2 | no FP boundary exit: a sticky bracket for entries that reached the boundary (the run starts inside the bracket on the table that includes FP fragments): removes the `exit_br` round trip (chain exit ~47 ns without the bracket's front half, one run entry/exit 15 ns) | 0.062 | -0.028 (est.) | timers (chain 83 ns incl. the bracket's front half, ~36 ns by halving the 73), hot `entry_cost` (95 ns FP excursion); **not ablated** | medium: a policy in `run_chain`, the FP state contract is unchanged (the plain fragment runs inside the bracket); B2 "bracket every run" costs 1.2 extra brackets and breaks even |
| 3 | `msr pan` clear/set once per hook call instead of per run (A15 contract) | 0.009 (1.16 pairs) | -0.004 (est.) | amplifier 8.1-9.2 ns | low, contract change |
| 4 | hook-path trims: one FFI call for base/fpsimd/table instead of three, `Running` kept across the SVC exit check, prep 28 ns and post 44 ns in situ against ~12 and ~15 hot | ~0.02 | -0.01 (est.) | timers vs hot units, **no ablation** | low |
| 5 | C6 (RET on x30, 166 words SET), C7 (no budget on forward BL, 135 words) | 0.0135 | -0.006 | words x 0.045 ns | C6 a second template shape (3), C7 weakens verifier independence (4) |
| 6 | C8 (constants as one literal load, 653 words SET) | 0.029 if free | -0.013 | words x 0.045 ns; load latency unmeasured | verifier class (5) |
| - | SRCU -> `srcu_read_lock_fast`-style read side | 0.02 | **0** on the gap (off pays it too); lowers both | amplifier 9.5-11.5 ns x 2.16 | kernel patch 0001, rebuild; not a gap lever |
| - | scheduling | - | none: protocol | block-rate section | - |

The translated body is the largest single intrinsic term left after the fixed path (+0.103 GET, +0.154 SET at steady state, 35-45% of the native code time at `-P 16`); at 0.045 ns per word that is 2300 / 3400 words, and C6 + C7 + C8 reach 954 words of SET (0.043). Larger structural levers (dispatch lookup 1793 words per SET request, RET 1490 of them; user-access synthesis 2100 words) are outside this list.
Single change: none. Pairs: **1 + 2** (-0.024 measured plus -0.028 estimated, GET +0.043 -> -0.009, +-0.03). PING flips with 1 alone. SET needs 1 + 2 + 4 + 5/6.

### Method

Protocol of the 11:43 entry: kjit-guest, 4 vCPUs, M1/HVF, `rodata=off` on both KPTI settings, redis-server 7.0.15 pinned to CPU 0 (unix socket and TCP port open), `redis-benchmark -s <sock> -t get|set|ping_mbulk -n 1000000 -c 50 -P 1 -d 1 --threads 2 -q` under `nojit` on CPUs 1-3, `chain_budget` 1024, on = `enable=1 auto=1`, off = `enable=0 auto=0` on the loaded module. States of a boot are paired inside (boot, cell, rep); the state order rotates by one per rep and by a boot offset; one unrecorded 100000-request run follows every state change and a 1000000-request warm-up every cell. Headline gap: the uninstrumented module built from the worktree at 879cf18 (md5 `839d58ae`, `llvm-objdump` of its code identical to the 11:43 `mod-a22` build, whose md5 differs by build path). Attribution: instrumented modules (`kjit_glue-experiment.diff`, 15:25 method ported: timers, `svcn`, `decl1/2`, amplifiers; new: `x_rep_tramp/call/run` on copies of `pt_regs` in the micro boots, hook phase timers `prep/chain/post`, `x_rep_link/clookup`, `x_delay`, `x_nostats`; dropped: the check-word NOPs and `emul`, A22 left almost no check words and `emul` was 0 at A17). Every knob is off at load; the instrumented `on - off` is close to the plain one (A boots GET +0.042, SET +0.057, PING +0.051; D boots +0.038 / +0.122 / +0.050; N boots +0.029 / +0.093 / +0.060; plain +0.048 / +0.078 / +0.043), SET being up to 0.04 higher.
Modules: `instr` (`9a11eefe`) A-k0-b1, A-k1-b1; `instr2` (`077411cf`, + chain timers, link amplifiers) A-k0-b2/b3, A-k1-b2, D boots; `instr3` (`54fa7465`, + `x_nostats`) N boots and the micro boot; `micro-k0-b0` ran an earlier build (`4a7f09b5`, no `x_delay`).
Boots (labels `at22-...`, own ports 13122 / 2355, one guest at a time, each started at host load1 3.0-4.0 with no other qemu): A-k0-b1..b3 and A-k1-b1..b2 (instrumented, 17-19 states, 3 cells, 2 reps), H-k0-b1..b2 and H-k1-b1 (plain, 4 cells, 8 reps), P-k0-b9 (plain, `-P 16` GET and SET, `-P 4` GET, 8 reps), D-k0-b4 and D-k1-b6 (delay states, 4 reps), N-k0-b7 and N-k1-b8 (statistics states, 4 reps), M-k0-b1 and micro-k0-b0 (micro). 13 attribution boots + 2 micro boots (M-k0-b1 with the final module, micro-k0-b0 with the earlier one). Not counted: the first attempt of A-k1-b2 hung before the first serial byte (host load1 rose to 7 during the hang) and was killed by me after 21 minutes (`hung-attempts/`); it ran again successfully. Smoke and debug boots (2 smoke, 2 `amprun` debug, 3 failed micro attempts: `svc_bench` refuses `decl1/2`; `amprun` under auto mode died with SIGILL, so the micro boot uses `auto=0`) are deleted.
The micro boot of KPTI on and a `-P 16` boot with KPTI on were dropped to stay near the 16-boot budget.

### Not verified

- **Tick-based native time.** The 15:25 method (off utime minus on utime) gives the native EL0 code as 0.70 / 0.76 / 0.64 us against fragment code of 0.72 / 0.85 / 0.56 (KPTI off), i.e. translated = native, but the `-P 16` gap says +0.10 / +0.15. Ticks that land in the masked tail of a kernel exit are counted as user time, which would overstate native time after each of ~2.2 syscalls per request; **assumed** to explain the difference (a P1-versus-P16 fit gives about 50 ns per return to EL0 that the pipelined code does not pay; the in-situ `svcn - on` is 143 / 212 / 51 ns per in-kernel syscall for GET / SET / PING against 101 hot, so it does not confirm it). Not isolated: no PMU in the guest.
- Line 1 at KPTI on is the hot unit plus the null-syscall difference, not measured; the in-situ `svcn - on` is 0.231 / 0.367 / 0.264, lower than 0.375 / 0.387 / 0.377. Line 5 was not measured with KPTI on, and PING_MBULK has no pipelined cell.
- The timers perturb heavily (`onT - on` +0.43..+0.56 us at KPTI off, with 17 more wake IPIs per 1000); their corrections use hot unit costs (CNTVCT read 12.5 ns, per-CPU update 4.2 ns). Hook logic and bracket are good to +-0.02, the phase split less. Only 3 / 2 boots (KPTI off / on), 2 reps each.
- The in-situ premium of the hook logic (66 ns per hook call against 26 hot) is not explained (cold code, FFI, stats lines, TLB: no PMU).
- Realized fractions of A23 items 2-6 are estimates (0.45 from the delay family; the statistics ablation realized 0.34-0.8 of its prediction). The sticky bracket was not implemented or ablated. The delay family has 1 boot and 4 reps per KPTI setting, the SET cell at KPTI off shows a realized fraction of 2.1-2.2 for `onD` (clients start to sleep: +7.3 / +14.7 wake IPIs per 1000), so the family is not a single linear response.
- The stock-kernel baseline (module not loaded) was not measured: `off` keeps the hook registered and pays SRCU and the indirect call on every syscall (0.02-0.03 us per request by the amplifier; 0.055 at A17), so KJIT on against a stock kernel would be about that much worse.
- Per-block price; whether the closed-loop give-back holds with other clients, `-d 1024`, `-c 1/10`, TCP, AOF, the debug kernel or real hardware; `ug3` (3 client threads) shows +0.156 and was not decomposed.
- Host activity beyond the load1 <= 4 gate at boot start was not controlled (load1 after a boot 3.2-6.4).

### Reproduce

Worktree `exp/attrib-a22` (base 879cf18): `git apply {D}/kjit_glue-experiment.diff`; modules with `tools/modbuild1.sh <name>` (kjit-guest into `$KJIT_BUILD_ROOT/mod-attrib-a22/<name>/kjit-guest`; the plain module is the unpatched tree); boots with `tools/drive.sh` (A, H), `drive3.sh` (P, D, N, M), `drive4.sh` (A-k1-b2 retry), each boot through `tools/boot.sh LABEL KPTI MODULE_KO "sh /kjit/attrib-a22.sh /tmp/atr REPS 1000000 100000 ROT 'CELL ...' 'STATE ...'"`; tables with `cd tools && python3 report.py $KJIT_BUILD_ROOT/runs ..` and `python3 micro.py $KJIT_BUILD_ROOT/runs ..`; the entry with `python3 tools/mkjournal.py HHMM` in the data directory; CSVs with `tools/export.py`.
"""
print(text)
