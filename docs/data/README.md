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

A new measurement entry adds the data file, the raw-log directory, a row in this table and the
`Data:` line in the entry.

## What is not in the data files

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
