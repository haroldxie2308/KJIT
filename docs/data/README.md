# Measurement data

Structured numbers of the measurement entries in `docs/journal/`, next to the raw logs they
came from. `AGENTS.md`, "Documentation Rules", is the rule; this file is the layout.

## Layout

`docs/data/<date>/<HHMM>-<slug>.csv` or `.json`: date and `HHMM` are those of the journal
entry (`## HH:MM +ZZZZ`), and the entry links the file on a `Data:` line. The raw logs are in
`docs/data/<date>/<HHMM>-<slug>/`, one subdirectory per run directory under its original name
(text files only: serial logs, host.txt, counters, redis-benchmark/suite output; no binaries,
no redis server data `srv/`, `*.aof`, `*.rdb`). A JSON file's `meta.raw` names that directory.

- **CSV** when the entry has one kind of observation: header row, one row per observation.
- **JSON** when it has several kinds with different columns (a redis run, a timed repeat, a
  log fact are not rows of one table):
  `{"meta": {...}, "tables": {"<name>": {"columns": [...], "rows": [[...], ...]}}}`, one row per
  line. Load a table with `pd.DataFrame(t["rows"], columns=t["columns"])`.

## Conventions

- One row per observation: every benchmark run, every timed repeat, every boot. Aggregates
  (mean, median, ratio) are not stored unless the journal table is the only record of them
  (`source=journal-table` files); they are computed from the rows.
- Units are in the column names (`ns_per_outer`, `req_per_s`, `ps_per_op`, `us_per_req`,
  `kreq_per_s` = thousands of requests per second); `_pct` is a percentage, `_per_req` a counter
  delta divided by the number of requests.
- Varying conditions are columns: `run`/`boot`/`log` (which boot), `variant`, `point`
  (`off` = KJIT off, else the chain budget or the bracket variant), `kpti`, `kjit`
  (`off`|`on`), `test` (`set`|`get`), `level` (`el1`|`el0`), `kernel_append` (kernel command
  line), `profile`, `series`. Host load is in the `runs`/`boots` tables.
- A counter column keeps the name the guest program printed (`fragment_entries`, `exit_ret`,
  `ibtc_miss_conflict`, ...). Redis counters are deltas over one benchmark run, except
  `fpsimd_run_max_ns`, which is cumulative per boot.
- An empty cell (CSV) or `null` (JSON) means the column does not apply to that row (e.g.
  `lat_*` in a run without the latency probe, `req_per_s_min` of a reference row). Nothing is
  filled with a default.
- `source=journal-table` marks a row transcribed from a markdown table of the journal entry
  (raw logs gone). Cells are copied; nothing is computed, estimated or corrected. A
  composite cell is split into its parts; a cell with one value in a "SET / GET" column is
  stored for both; a `105.9k` cell is stored as 105900 (the journal's rounding); a cell
  that follows no single pattern (`2.19-2.22`) is kept as a `*_text` column.

## Files

Class: `logs` = taken from the raw logs (in the sibling directory); `table` = transcribed from
the entry's own markdown table because the logs are gone (`source=journal-table`, no raw
directory).

| Entry (journal) | File | Class |
|---|---|---|
| 2026-09-27 10:20 K4: redis under KJIT (debug, 10 iterations) | `2026-09-27/1020-k4-redis-under-kjit.json` | logs |
| 2026-09-27 12:07 A8 implementation (campaigns) | `2026-09-27/1207-a8-redis-campaign.json` | logs |
| 2026-09-27 16:16 A9b implementation (campaigns) | `2026-09-27/1616-a9b-redis-campaign.json` | logs |
| 2026-09-27 19:01 A10: chain budget and counter reads (campaigns; `kjit-guest-20260927-163604` is the `chain_budget=65536` k4-bench) | `2026-09-27/1901-a10-redis-campaign.json` | logs |
| 2026-10-02 17:14 A11 Step 0: baseline | `2026-10-02/1714-a11-step0-baseline.json` | table |
| 2026-10-05 11:47 A11 integration | `2026-10-05/1147-a11-integration-remeasure.json` | table |
| 2026-10-09 00:47 Dispatch-table miss classification | `2026-10-09/0047-dispatch-miss-classification.csv` | table |
| 2026-10-09 02:31 FP/SIMD bracket: preemptible NEON (`fpv/` logs; `runs/` the guest run directories they name; the entry_cost runs have none left) | `2026-10-09/0231-fpsimd-bracket-neon.json` | logs |
| 2026-10-09 03:56 Dispatch-table conflict variants (`meas`, `meas-alias`, `meas-nc` boots) | `2026-10-09/0356-dispatch-table-variants.json` | logs |
| 2026-10-09 19:59 Userspace Bypass design evaluation (E1 gap table) | `2026-10-09/1959-ub-eval-e1-gaps.csv` | table |
| 2026-10-09 21:41 Why KJIT does not reach UB's speedups | `2026-10-09/2141-ub-speedups-measure.json` | table |
| 2026-10-09 22:11 A11c implemented | `2026-10-09/2211-a11c-victim-table.csv` | table |
| 2026-10-10 09:05 Fragment-code slowdown: root cause | `2026-10-10/0905-fragment-code-slowdown.json` | logs |
| 2026-10-10 09:41 EL1 RMW chain = PSTATE.SSBS | `2026-10-10/0941-ssbs-rmw-chain.json` | logs |
| 2026-10-10 11:09 A13 implemented: preemptible FP/SIMD bracket | `2026-10-10/1109-a13-{entry-cost,redis,preempt-stress,latency,stale-binding}.csv` | logs |
| 2026-10-10 11:51 A12 implemented: budget counter in x18 | `2026-10-10/1149-a12-{code-speed,entry-cost,redis}.csv` | logs |
| 2026-10-11 00:37 Merged main (A12 + A13): code speed and redis | `2026-10-11/0037-main-{code-speed,redis}.csv` | logs |
| 2026-10-11 01:47 SIMD&FP access lowering alternatives | `2026-10-11/0147-simd-lowering*.csv` | logs |
| 2026-10-11 01:54 Redis per-request loss attribution | `2026-10-11/0154-redis-attrib*.csv` | logs |
| 2026-10-11 03:03 Dispatch stall: cause and alternatives | `2026-10-11/0303-dispatch-study*.csv` | logs |
| 2026-10-11 03:54 A14 implemented: fragment image colouring | `2026-10-11/0354-a14-*.csv` | logs |
| 2026-10-11 12:42 Redis loss attribution on A14 | `2026-10-11/1240-attrib-a14*.csv` | logs |
| 2026-10-11 16:21 Redis under UB's benchmark protocol (`std-a-k<kpti>-b<boot>` boots; `-sys.csv`: null syscall) | `2026-10-11/1621-ub-standard.csv` | logs |
| 2026-10-11 19:31 PAN ablation across value sizes | `2026-10-11/1931-pan-sweep*.csv` | logs |
| 2026-10-11 19:31 Redis CPU gap: 1.0 vs 1.5 us (`-wake.csv`: wake-cost micro-benchmark) | `2026-10-11/1931-cpu-gap*.csv` | logs |
| 2026-10-11 22:37 Direct BL and RAS-predicted RET in redis | `2026-10-11/2237-dispatch-ablation*.csv` | logs |
| 2026-10-11 23:18 A15 implemented: run-scoped PAN clear (`-redis-std.csv`: main vs A15 module, same session; `-gates.csv`: harness/fuzz/module/guest gates) | `2026-10-11/2318-a15-{redis-std,code-speed,gates}.csv` | logs |
| 2026-10-12 00:31 A16 implemented: direct BL links (`-links.csv`: redis under the UB protocol, main module vs A16 module, 4 boots each, interleaved; `-gates.csv`: guest gates on both profiles; `-links/` also holds the `a16-diag` boot with cumulative link counters) | `2026-10-12/0031-a16-{links,gates}.csv` | logs |
| 2026-10-12 04:15 ROX vs RWX fragment images (`-pairs.csv`: paired differences; `-kb.csv`: kernel micro-benchmarks; `-place.csv`: image VA/PFN histograms; `-ptes.csv`, `-linear-map.csv`: page-table evidence; `-install.csv`: install cost; campaigns a-f, boots `rox-<campaign>-b<N>`) | `2026-10-12/0415-rox-rwx*.csv` | logs |
| 2026-10-13 02:20 A17 implemented: packed image arena (`-a17-arena.csv`: redis under the UB protocol, KPTI off and forced on, main module vs A17 module, 5 boots each per KPTI setting, interleaved; boots `ub-<module>-std-k<kpti>-b<N>`, tables = `tests/guest/host/ub-arena.py` output; `-gates.csv`: guest gates on both profiles, `arena_churn_version` v1 = first version of the test, v2 = final) | `2026-10-13/0220-a17-arena{,-gates}.csv` | logs |
| 2026-10-13 15:25 Redis overhead attribution on A17 (`-attrib-a17.csv`: one row per measured run of 15 attribution boots, states off/on/svcn/decl1/decl2/nomod/onT/offT/svcnT/amp*/nop*/onZ/emul, the timers of the T states as `t_*` columns, KPTI off and forced on; `-boots.csv`: per boot host wait/load and the micro items of the boot; `-micro.csv`: code_speed, svc_bench, entry_cost and wake-cost rows of the micro boots; `-ref.csv`: ub-standard.sh boots of the A17 module and of the instrumented module with every knob off; raw logs in `-attrib-a17/`: serial.log, host.txt, fragment lists and final counters per boot, the driver scripts, `progress.txt`, the per-instruction lowering of the E1 traces `attrib-lowering-{set,get}.tsv`, and the module diff) | `2026-10-13/1525-attrib-a17{,-boots,-micro,-ref}.csv` | logs |
| 2026-10-13 16:45 Redis operating conditions for KJIT (A17) (`.csv`: one row per measured redis run, `setting` k0 = KPTI off, k1 = `kpti=1`, dbg = `kjit-guest-debug`, mitoff = `mitigations=off`, `tag` = the cell set of the boot; `-sys.csv`: null/small-I/O syscall round trip per boot, KJIT off and on, settings also `nobhb`, `ssbd`, `nopauth`; raw logs `-conditions/<boot>/` incl. `cond-count-k0-b1` = native syscalls per request, `cond-d2-dbgkpti-b1` = the debug kernel with `kpti=1`, which does not boot; `tables.md`, `model.md` = `tests/guest/host/cond-summarize.py` / `cond-model.py` output) | `2026-10-13/1645-conditions{,-sys}.csv` | logs |
| 2026-10-13 22:54 Arena chunk mapped by one PMD block (`.csv`: one row per measured redis run, `campaign` main = off/k4/pmd, ctl = off/k4a/pmd, full = default `rodata`, state k4 = A17 4 KiB chunk, k4a = 4 KiB 2 MiB-aligned control, pmd = PMD block; `-chunks.csv`: page-table dump lines; `-kb.csv`: svc_bench with fragments installed; `-micro.csv`: code_speed / svc_bench rows of the `main` boots; raw logs `-huge-arena/<boot>/`, `tables-*.md` = `tests/guest/host/huge-summarize.py` output, `module.diff`, the kernel patch) | `2026-10-13/2254-huge-arena{,-chunks,-kb,-micro}.csv` | logs |
| 2026-10-13 23:55 Redis -c 1 overhead (`.csv`: one row per measured redis run, `boot` = `c1-<tag>-b<N>`, `state` = `off`, `on` and the ablation / probe modifiers (`+spin`, `+time`, `+decline`, `+epoll_native`, `+svc22`, `+nofpinv`, `+pf=N`, `+guard=M`), `k_*` = every KJIT counter that moved, `quality` non-empty = left out of the tables; `-boots.csv`: module md5, states, cells, host wait and load per boot; `-xstats.csv`: the module timers of the `+time` states (CNTVCT ticks, 24 MHz) by what ended the previous hook call, syscall, age (hook calls since the task last switched out), fragment runs and FP/SIMD bracket parts; `-cold.csv`: `cold_calls` runs, not used for conclusions; raw logs, `hostmon.log` and the module diff in `-c1/<boot>/`) | `2026-10-13/2355-c1{,-boots,-xstats,-cold}.csv` | logs |
| 2026-10-14 01:14 A18 implemented: scalar floating point (`.csv`: one row per measured redis run, `part` std = `ub-standard.sh` (-d 1 and 1024, SET and GET), aof = `cond-sweep.sh` (AOF always over unix socket and TCP, unix SET), KPTI forced on, main module vs A18 module, 3 boots each, interleaved; `-gates.csv`: guest gates of the first and the final run on both profiles; raw logs `0114-a18-fp/`: boots `ub-<module>-std-k1-b<N>` and `ub-cond-<module>-k1-b<N>`, `gates/`, `logs/`, `tools/` incl. the driver `meas.sh`, `tables-std.md` = `ub-arena.py` output, `tables-aof.md` = `tools/cond-modules.py` output) | `2026-10-14/0114-a18-fp{,-gates}.csv` | logs |
| 2026-10-14 03:55 A19 implemented: PMD-mapped arena chunks (`.csv`: redis under the UB protocol, KPTI off and forced on, a17 = main module vs a19, 4 boots each per KPTI setting, interleaved, boots `ub-<module>-std-k<kpti>-b<N>`; `-c1.csv`: `-c 1` / `-c 10` GET and SET, KPTI off, `cpu_us_per_req` from `sum_exec_runtime`, boots `ub-c1-<module>-b<N>`; `-gates.csv`: guest gates on both profiles; tables = `tests/guest/host/ub-arena.py` / `ub-c1.py` output; `gates/`, `experiments/` (alias probe and failure knob, removed), `mutation/`) | `2026-10-14/0348-a19-pmd{,-c1,-gates}.csv` | logs |
| 2026-10-14 07:53 Win map of main (A17-A19) against KJIT-off (`.csv`: one row per measured redis run of 22 `cond-sweep.sh` boots, `kpti` 0|1, `kjit` off|on, `cpu_us_per_req` from `sum_exec_runtime`, `ticks_cpu_us_per_req` from utime+stime ticks, boots `ub-cond-wm-k<kpti>-b<N>` (b1-6 / k0 b1-4 full cell sets, k1 b7-10 and k0 b5-8 near-zero cells, k1 b11-14 request-count check with cells `*_n500k` / `*_n2m`); `-std.csv`: `ub-standard.sh` cross-check, 8 boots `ub-std-wm-k<kpti>-b<N>`, tick-sampled; `-boots.csv`: host load before and after each boot; `-sys.csv`: null syscall per boot; raw logs `0753-win-map/<boot>/`, `tables.md`, `tables-std.md`, `compare-a17.md`, `model.md` / `model-a17-same-cells.md` = `cond-model.py` output, `tools/` drivers and table scripts, `tools/tooling-changes.diff`) | `2026-10-14/0753-win-map{,-std,-boots,-sys}.csv` | logs |
| 2026-10-14 14:46 Return continuations and a shadow return stack (experiment) (`.csv`: one row per measured redis run of the four-state sweep (`off`, `m0` today, `m1` continuations, `m2` continuations + ring), boots `ub-rc-rc-k<kpti>-b<N>` (k1 b1-6 six cells, k0 b1-3 unix GET/SET), `cpu_us_per_req` from `sum_exec_runtime`, `frags_live` / `code_live` = live fragments and code bytes after the run; `-push.csv`: the push-only ablation (states m0..m3, boots `ub-rc-push-k1-b<N>`); `-units.csv`: the units build (budget units per request, boots `ub-rc-units-k0-b<N>`); `-boots.csv`; `-words.csv`: hot-path words per request from the attrib TSVs per test, mode and ring hit rate; raw logs `1446-ret-cont/<boot>/` (also `ub-rc-gate-m*` = K2 per mode, `ub-retcont-smoke1`, `ub-rc-diag-k0-b1`), `tables.md`, `tables-push.md`, `tables-units.md`, `words.txt`, `attrib/` (BL/BLR/RET rows of the attrib TSVs), `harness/` (test summaries), `ret-cont.diff` = the experiment as a patch on dc1b962) | `2026-10-14/1446-ret-cont{,-push,-units,-boots,-words}.csv` | logs |
| 2026-10-14 13:56 A20 implemented: shorter transfer and SP-check paths (`.csv`: one row per measured redis run of 10 `a20-sweep.sh` boots `ub-a20-k<kpti>-b<N>` (k1 b1-6, k0 b1-4), `state` off|main|a20 paired inside the boot (main = module of dc1b962, a20 = this tree; swapped by rmmod/insmod), `order` the state order of the rep, `cpu_us_per_req` from `sum_exec_runtime`; raw logs `1356-a20-paths/boots/<boot>/` (serial.log, host.txt, guest-run.out), `tables.md` and `bootstrap.md` = `tools/a20-summarize.py` / `a20-bootstrap.py` output, `tools/` the drivers and guest sweep, `attrib/` the word counts (`attrib-from-tsv.rs` = `harness/src/bin/attrib.rs` of exp/attrib-a17 reading the lowering TSV, `counts.py`, `before-*.tsv` = dc1b962, `after-*.tsv` = A20, `counts.md`), `gates/` the harness, native, fuzz and guest gate logs, `midblock_probe.s` the contract-issue probe) | `2026-10-14/1356-a20-paths.csv` | logs |
| 2026-10-14 15:20 A20 final tree: entry labels, and what they cost in redis (`.csv`: one row per measured run of 10 `a20-sweep.sh` boots `ub-a20f-k<kpti>-b<N>` (k1 b1-6, k0 b1-4), `state` off|main|a20 paired inside the boot, extra columns over the 13:56 file: `chains`, `ibtc_miss_*`, `link_*`, `translate_exists`, `released_fragments`, `abs_*` = absolute values at the end of the run since the module was loaded; raw logs `1520-a20-final/boots/<boot>/`, `tables.md`, `bootstrap.md`, `tools/`; gate logs of the final tree in `1356-a20-paths/gates-final/`) | `2026-10-14/1520-a20-final.csv` | logs |
| 2026-10-14 16:02 Hot-path word census on A20 (`.csv`: one row per executed original instruction per test (`set`|`get`, redis request gaps of the 2026-10-13 15:25 trace), `exec_per_req`, hot-path words per request by class (`w_*`), the words each candidate saves standalone (`save_C*`); the directory: `class-table`, `group-table`, `mnemonic-table`, `helper-other`, `fill-spill`, `memory-forms`, `budget-sites`, `sp-check`, `candidates`, `top30*` (exact word sequences), `raw/` = the `census` tool output (per-pc TSV and the emitted words, gzip), `tools/`, `logs/`) | `2026-10-14/1602-word-census.csv` | logs |
| 2026-10-14 18:42 Win confirmation on main (A20) (`.csv`: one row per measured redis run of 16 `cond-sweep.sh` boots `ub-cond-wc-k<kpti>-b<N>` (k1 b1-12: 12 unix-socket cells and TCP PING_MBULK / GET, k0 b1-4: unix PING_MBULK / GET), `kjit` off|on paired in the boot, `rep_order` off,on|on,off, `cpu_us_per_req` from `sum_exec_runtime`; `-boots.csv`: host load before and wait per boot; `-sys.csv`: null syscall per boot; raw logs `1842-win-confirm/boots/<boot>/` (serial.log, host.txt), `tables.md` = `tools/confirm-summarize.py` output, `extra.md` = `tools/extra-analysis.py` output, `tools/` drivers, guest sweep and `cond-sweep-changes.diff`) | `2026-10-14/1842-win-confirm{,-boots,-sys}.csv` | logs |

A new measurement entry adds the data file, the raw-log directory, a row in this table and the
`Data:` line in the entry.

## What is not in the data files

- 2026-10-13 15:25: the module builds (not stored), the E1 traces (14 MB each, in `.kjit/build/attrib/` of an earlier session; only their lowering
  TSVs are stored), the smoke boot of the instrumentation (deleted), the run directories of the boots (kjit.ko copies, qemu state; deleted after the export).
- 2026-10-14 16:02: the redis-server / libc / ld.so / libm ELF files the `census` tool reads (not stored; md5 in `logs/elf-md5.txt`), the intermediate analysis scripts (superseded by `tools/census.py`).
- 2026-10-14 15:20: the module builds (not stored; kjit.ko md5 final tree e6fc23cd... kjit-guest, ca5e2c19... kjit-guest-debug), the `kjit.ko` copies and qemu state of the run directories.
- 2026-10-14 13:56: the module builds (not stored; `kjit.ko` md5 a20 2bffd464..., main cb4a3481...), the smoke boot of the sweep (deleted), the `kjit.ko` copies and qemu state of the run directories, the boots that lost the host to another agent's back-to-back boots (killed while waiting, nothing measured; b4 of k1 ran before the host-grabbing change of `a20-boot.sh`), the E1 traces (the lowering TSVs of 2026-10-13 15:25 stand in for them).
- 2026-10-14 01:14: the module builds' object files (not stored), the first aborted gate runs (an earlier `fp_trap` with one loop shape; `k2-kjit-guest-v1-fp_trap.log` is its K2 log), the full redis test suite (not run).
- 2026-10-14 14:46: the module builds (three modules: sweep, push-only, units build; not stored), the harness test logs beyond their summaries (`harness/`), the E1 traces and the guest libc / ld.so / redis-server ELF files the `attrib` runs read (`.kjit/build/attrib/`, `.kjit/build/guest-rootfs/base.cpio`), a fourth KPTI-off boot (`k0-b4`) that never started (the other agent's guests held the host), the `gate-m0` boot that waited for load <= 6 (rerun with `UB_MAX_LOAD=100`), `make fuzz` output (summary line only in the entry), `ret-cont.diff` leaves out the regenerated K0 golden (`tests/arm64/golden/`) and the docs.
- 2026-10-13 16:45: the discovery and smoke boots of the sweep tooling (one boot per kernel setting for the null
  syscall, a smoke boot per cell type, a smoke boot of the debug profile; superseded by the `s1` and sweep boots), the
  two sweep boots that failed on the first version of the `redis-benchmark` output parser (`MSET (10 keys):` title;
  deleted, re-run), the queue logs of the driver, and the first-run order in which the other agent's guests held the
  host (`host.txt` `waited_s` is the wait inside `ub-run.sh` after the driver's own 0.2 s poll, so it is 0 for most
  boots; the real waits were up to about 40 minutes). The first boots `dens-k0-b1`, `dens-k1-b1` ran an earlier
  version of `cond-sweep.sh` without the `subs=` field and without the null-syscall block.
- 2026-10-13 23:55: the module builds (not stored), the killed boots e6 and the first try of m-b2 (two guests started in the same second as another agent's; nothing measured), the `ub-c1-*` run directories' `kjit.ko` copies.
- 2026-10-13 02:20: the module builds (not stored), the first run of the mutation check against the first version of
  `arena_churn` (the first version did not detect it; it was rewritten with callees of different sizes and the check
  repeated, `arena_churn-mutation-neighbour-granule.log`), the K2/K3 runs of the first version of the test (same pass lines).
- 2026-10-12 04:15: the smoke boot (200000 requests, deleted), the per-run counters other than the listed
  columns (in the serial logs), and the module builds (not stored).
- 2026-09-27 campaign files: matched to the entries by their figures (suite counts, in-kernel
  syscalls of N, fragment entries, translations, chain histogram all agree with the entry).
  Not extracted: the K2 micro-test lines and the adversarial tests' counters of a campaign, the
  suite's unsupported-word ranking, the older campaigns of the same day, and the figures that have
  no log (K4: "302 s vs 251 s", the pipelined SET comparison, the pre-A7d experiment's 4.0M
  Unsupported exits; A10: the 274k/275k, 293k/305k, 62k/71k requests per second; A9b: the
  `fpsimd_run_max_ns` of the K2/K3 suites and the diagnostic build).

- 2026-10-09 03:56: the per-slot conflict listings (`a11slots`, `a11maps` lines, `slots-*.txt`).
- 2026-10-09 02:31: the earlier, superseded fpv logs (`bench-...013723/013912/014058`,
  `lat-...014326/014529/014728`; no run directory left, arguments unknown) and the k2/k3/
  campaign/stress logs (pass/fail runs, not measurements).
- 2026-10-10 09:05: the development runs `ub-exp1`/`ub-exp2` (the journal calls them garbled
  and superseded).
- 2026-10-09 21:41: the "Model of one request" table (derived arithmetic), the raw logs.
- Numbers that appear only in prose (host loads, per-boot waits of the table entries, single
  figures in conclusions) when the entry has no table or log for them.
