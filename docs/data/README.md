# Measurement data

Machine-readable numbers of the measurement entries in `docs/journal/`. Raw logs are not
committed; every file here is produced by a checked-in script (`tests/guest/host/extract_*.py`)
from the raw logs, or, where the logs are gone, from the entry's own markdown table.
`AGENTS.md`, "Documentation Rules", is the rule; this file is the layout and the recipes.

## Layout

`docs/data/<date>/<HHMM>-<slug>.csv` or `.json`: date and `HHMM` are those of the journal
entry (`## HH:MM +ZZZZ`), and the entry links the file on a `Data:` line.

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
  (raw logs gone). The script copies cells; it computes, estimates and corrects nothing. A
  composite cell is split into its parts; a cell with one value in a "SET / GET" column is
  stored for both; a `105.9k` cell is stored as 105900 (the journal's rounding); a cell
  that follows no single pattern (`2.19-2.22`) is kept as a `*_text` column.
- A malformed line, a missing expected line or an unexpected table header makes the script
  fail with `<file>:<line>: <what>`; it never skips or defaults.

## Files

Class: `logs` = generated from the raw logs; `table` = transcribed from the entry's own markdown
table because the logs are gone (`source=journal-table`).

| Entry (journal) | File | Class | Script |
|---|---|---|---|
| 2026-09-27 10:20 K4: redis under KJIT (debug, 10 iterations) | `2026-09-27/1020-k4-redis-under-kjit.json` | logs | `extract_k4_campaign.py` |
| 2026-09-27 12:07 A8 implementation (campaigns) | `2026-09-27/1207-a8-redis-campaign.json` | logs | `extract_k4_campaign.py` |
| 2026-09-27 16:16 A9b implementation (campaigns) | `2026-09-27/1616-a9b-redis-campaign.json` | logs | `extract_k4_campaign.py` |
| 2026-09-27 19:01 A10: chain budget and counter reads (campaigns) | `2026-09-27/1901-a10-redis-campaign.json` | logs | `extract_k4_campaign.py` |
| 2026-10-02 17:14 A11 Step 0: baseline | `2026-10-02/1714-a11-step0-baseline.json` | table | `extract_journal_tables.py --entry a11-step0` |
| 2026-10-05 11:47 A11 integration | `2026-10-05/1147-a11-integration-remeasure.json` | table | `--entry a11-integration` |
| 2026-10-09 00:47 Dispatch-table miss classification | `2026-10-09/0047-dispatch-miss-classification.csv` | table | `--entry miss-class` |
| 2026-10-09 02:31 FP/SIMD bracket: preemptible NEON | `2026-10-09/0231-fpsimd-bracket-neon.json` | logs | `extract_fpv.py` |
| 2026-10-09 03:56 Dispatch-table conflict variants | `2026-10-09/0356-dispatch-table-variants.json` | logs | `extract_ibtc_variants.py` |
| 2026-10-09 19:59 Userspace Bypass design evaluation (E1 gap table) | `2026-10-09/1959-ub-eval-e1-gaps.csv` | table | `--entry ub-eval-e1` |
| 2026-10-09 21:41 Why KJIT does not reach UB's speedups | `2026-10-09/2141-ub-speedups-measure.json` | table | `--entry ub-measure` |
| 2026-10-09 22:11 A11c implemented | `2026-10-09/2211-a11c-victim-table.csv` | table | `--entry a11c` |
| 2026-10-10 09:05 Fragment-code slowdown: root cause | `2026-10-10/0905-fragment-code-slowdown.json` | logs | `extract_frag_speed.py` |
| 2026-10-10 09:41 EL1 RMW chain = PSTATE.SSBS | `2026-10-10/0941-ssbs-rmw-chain.json` | logs | `extract_frag_speed.py` |

The scripts share `tests/guest/host/kjit_data.py` (strict parsing, deterministic writers);
`extract_frag_speed.py` reuses `load_ub` of `ub-summarize.py` for the `ub off|on` lines.
Each script's docstring (`<script> --help`) lists its tables.

## Regenerate

Common shape: `<script> <logs...> --out <file>`. The raw logs were at these places on
2026-10-10 (worktrees and scratch directories are removed over time; the data files are
the record then):

```sh
H=tests/guest/host
WT=/Volumes/CaseSentitiveLocal/KJIT/.claude/worktrees
FS=$WT/frag-speed/.kjit/build/runs                       # ub-run.sh run directories
FPV=$WT/agent-a3568d87c4d834b78/.kjit/build/fpv          # fpv-run.sh logs (branch exp/fp-bracket-neon)
IB=/Volumes/Local/kjit-a4b2                              # measurement boots of exp/ibtc-variants
K4=/Volumes/CaseSentitiveLocal/kjit-build/runs           # redis-campaign.sh output of 2026-09-27 (main build root)

# 2026-09-27 campaigns: the run directory whose figures the entry quotes
python3 $H/extract_k4_campaign.py $K4/k4-kjit-guest-debug-20260927-061921 --out docs/data/2026-09-27/1020-k4-redis-under-kjit.json
python3 $H/extract_k4_campaign.py $K4/k4-kjit-guest-20260927-104253 $K4/k4-kjit-guest-debug-20260927-105719 \
    --out docs/data/2026-09-27/1207-a8-redis-campaign.json
python3 $H/extract_k4_campaign.py $K4/k4-kjit-guest-20260927-145443 $K4/k4-kjit-guest-debug-20260927-150848 \
    --out docs/data/2026-09-27/1616-a9b-redis-campaign.json
python3 $H/extract_k4_campaign.py $K4/k4-kjit-guest-20260927-165035 $K4/k4-kjit-guest-debug-20260927-171337 \
    $K4/kjit-guest-20260927-163604 --out docs/data/2026-09-27/1901-a10-redis-campaign.json   # 163604: chain_budget=65536 k4-bench

# 2026-10-10 09:05 (exp/frag-speed: exp_el1/exp_el0 microbenchmarks and ub-bench.sh code runs)
python3 $H/extract_frag_speed.py $FS/ub-expA1 $FS/ub-expA2 $FS/ub-expA3 $FS/ub-codeB1 $FS/ub-codeB2 \
    $FS/ub-codeB3 $FS/ub-code-base1 --out docs/data/2026-10-10/0905-fragment-code-slowdown.json
# 2026-10-10 09:41 (SSBS facts, default / force-off / DSSBS=1 / msr ssbs runs)
python3 $H/extract_frag_speed.py $FS/ub-facts1 $FS/ub-facts2 $FS/ub-ssbDef1 $FS/ub-ssbDef2 $FS/ub-ssbOff1 \
    $FS/ub-ssbOff2 $FS/ub-dssbs1 $FS/ub-dssbs2 $FS/ub-ssbsp1 $FS/ub-ssbsp2 --out docs/data/2026-10-10/0941-ssbs-rmw-chain.json
# 2026-10-09 03:56 (36 meas boots, 12 meas-alias, 8 meas-nc)
python3 $H/extract_ibtc_variants.py $IB/meas/boot-*.serial.log $IB/meas-alias/boot-*.serial.log \
    $IB/meas-nc/boot-*.serial.log --out docs/data/2026-10-09/0356-dispatch-table-variants.json
# 2026-10-09 02:31 (bench = the 3 five-pass throughput boots, entry = entry_cost, lat = latency probe boots)
python3 $H/extract_fpv.py $FPV/bench-kjit-guest-20261009-0{15035,15328,15623}.log $FPV/entry-kjit-guest-20261009-0136{46,51,55}.log \
    $FPV/lat-kjit-guest-20261009-0{15915,20118,20322,20521}.log --out docs/data/2026-10-09/0231-fpsimd-bracket-neon.json
# journal tables (raw logs gone)
python3 $H/extract_journal_tables.py docs/journal/2026-10-02.md --entry a11-step0 --out docs/data/2026-10-02/1714-a11-step0-baseline.json
python3 $H/extract_journal_tables.py docs/journal/2026-10-05.md --entry a11-integration --out docs/data/2026-10-05/1147-a11-integration-remeasure.json
python3 $H/extract_journal_tables.py docs/journal/2026-10-09.md --entry miss-class --out docs/data/2026-10-09/0047-dispatch-miss-classification.csv
python3 $H/extract_journal_tables.py docs/journal/2026-10-09.md --entry ub-eval-e1 --out docs/data/2026-10-09/1959-ub-eval-e1-gaps.csv
python3 $H/extract_journal_tables.py docs/journal/2026-10-09.md --entry ub-measure --out docs/data/2026-10-09/2141-ub-speedups-measure.json
python3 $H/extract_journal_tables.py docs/journal/2026-10-09.md --entry a11c --out docs/data/2026-10-09/2211-a11c-victim-table.csv
```

A new measurement entry adds its own `extract_*.py` (or a spec to `extract_journal_tables.py`
if only the table survives), the file under `docs/data/`, a row in the table above, and the
`Data:` line in the entry.

## What is not in the files

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
