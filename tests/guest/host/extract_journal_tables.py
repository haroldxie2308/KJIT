#!/usr/bin/env python3
"""Data files for journal entries whose raw logs are gone but whose measurements
stand in markdown tables of the entry itself.

  extract_journal_tables.py JOURNAL.md --entry ID --out FILE

The tables are parsed from the entry's section of the journal (the section starts at
its exact "## HH:MM +ZZZZ - title" heading and ends at the next "## " heading), checked
against the expected header cells, and transcribed cell by cell: no value is computed,
estimated or taken from the surrounding prose. A composite cell is split into its parts
("234341 (213447..263852)" -> mean, min, max; "4.288 / 4.259" -> SET and GET); a cell that
holds one value in a "SET / GET" column applies to both (the journal leaves the repeated
value out); a cell that does not follow one pattern is kept as text in a *_text column.
Every row carries source=journal-table. Entry ids and their files:

  a11-step0       2026-10-02 17:14  JSON, 6 tables
  a11-integration 2026-10-05 11:47  JSON, 2 tables
  miss-class      2026-10-09 00:47  CSV
  ub-measure      2026-10-09 21:41  JSON, 5 tables (the "Model of one request" table is derived
                                    arithmetic over the measured ones and is not transcribed)
  a11c            2026-10-09 22:11  CSV
  ub-eval-e1      2026-10-09 19:59  CSV (the E1 gap table of Q2)

Standard library only.
"""
import re
from decimal import Decimal

import kjit_data as kd

SEPARATOR = re.compile(r"^\|[-| :]+\|$")


class Row:
    """One table row with parsing helpers that fail with the journal file and line."""

    def __init__(self, path, lineno, cells):
        self.path, self.lineno, self.cells = path, lineno, cells

    def fail(self, message):
        kd.fail(self.path, self.lineno, message)

    def text(self, i):
        return self.cells[i]

    def _number(self, s, field):
        if s.startswith("+"):
            s = s[1:]
        return kd.number(self.path, self.lineno, field, s)

    def num(self, i, field):
        return self._number(self.cells[i], field)

    def num_k(self, i, field):
        """"105.9k" -> 105900 (thousands, exact decimal arithmetic)."""
        s = self.cells[i]
        if not s.endswith("k"):
            self.fail(f"{field}: expected a number ending in k, got {s!r}")
        self._number(s[:-1], field)
        return int(Decimal(s[:-1]) * 1000)

    def unit(self, i, suffix, field):
        """"15.1 ns" / "2.2x": the number before the unit suffix."""
        s = self.cells[i]
        if not s.endswith(suffix):
            self.fail(f"{field}: expected a number followed by {suffix!r}, got {s!r}")
        return self._number(s[:-len(suffix)].rstrip(), field)

    def percent(self, i, field):
        return self.unit(i, "%", field)

    def mean_range(self, i, field):
        m = re.match(r"^(\S+) \((\S+)\.\.(\S+)\)$", self.cells[i])
        if not m:
            self.fail(f"{field}: expected 'mean (min..max)', got {self.cells[i]!r}")
        return tuple(self._number(m.group(k), field) for k in (1, 2, 3))

    def mean_paren(self, i, field):
        """"209980 (3257)" -> (209980, 3257)."""
        m = re.match(r"^(\S+) \((\S+)\)$", self.cells[i])
        if not m:
            self.fail(f"{field}: expected 'a (b)', got {self.cells[i]!r}")
        return self._number(m.group(1), field), self._number(m.group(2), field)

    def plus_minus(self, i, field):
        """"0.95 +- 0.07" -> (0.95, 0.07); a single number has no second part and is an error."""
        m = re.match(r"^(\S+) \+- (\S+)$", self.cells[i])
        if not m:
            self.fail(f"{field}: expected 'a +- b', got {self.cells[i]!r}")
        return self._number(m.group(1), field), self._number(m.group(2), field)

    def pair(self, i, field):
        parts = self.cells[i].split(" / ")
        if len(parts) != 2:
            self.fail(f"{field}: expected 'a / b', got {self.cells[i]!r}")
        return tuple(self._number(p, field) for p in parts)

    def pair_or_single(self, i, field):
        """"a / b", or one number that stands for both."""
        parts = self.cells[i].split(" / ")
        if len(parts) == 1:
            v = self._number(parts[0], field)
            return v, v
        return self.pair(i, field)

    def numbers(self, i, field, count):
        parts = self.cells[i].split()
        if len(parts) != count:
            self.fail(f"{field}: expected {count} numbers, got {self.cells[i]!r}")
        return [self._number(p, field) for p in parts]


def split_cells(path, lineno, text):
    if not (text.startswith("|") and text.endswith("|")):
        kd.fail(path, lineno, f"not a table row: {text!r}")
    return [c.strip() for c in text[1:-1].split("|")]


def section_lines(path, heading):
    lines = list(kd.read_lines(path))
    starts = [i for i, (_, t) in enumerate(lines) if t == heading]
    if len(starts) != 1:
        kd.fail(path, None, f"expected exactly one line {heading!r}, found {len(starts)}")
    out = []
    for lineno, text in lines[starts[0] + 1:]:
        if text.startswith("## "):
            break
        out.append((lineno, text))
    return out


def read_table(path, lines, anchor, header):
    """Rows (Row objects) of the first table after the first line containing anchor."""
    for i, (_, text) in enumerate(lines):
        if anchor in text:
            break
    else:
        kd.fail(path, None, f"anchor text {anchor!r} not found in the entry")
    j = i
    while j < len(lines) and not lines[j][1].startswith("|"):
        j += 1
    if j >= len(lines):
        kd.fail(path, lines[i][0], f"no table after {anchor!r}")
    rows = []
    while j < len(lines) and lines[j][1].startswith("|"):
        rows.append(lines[j])
        j += 1
    got = split_cells(path, rows[0][0], rows[0][1])
    if got != header:
        kd.fail(path, rows[0][0], f"table header {got} differs from the expected {header}")
    if len(rows) < 3 or not SEPARATOR.match(rows[1][1]):
        kd.fail(path, rows[0][0], "table has no separator row or no body")
    out = []
    for lineno, text in rows[2:]:
        cells = split_cells(path, lineno, text)
        if len(cells) != len(header):
            kd.fail(path, lineno, f"{len(cells)} cells, header has {len(header)}")
        out.append(Row(path, lineno, cells))
    return out


# ---------------------------------------------------------------------------------------
# Row transcribers: Row -> dict, or list of dicts (one table row may hold several observations)

def step0_micro(c):
    return dict(variant=c.text(0), calls_k=c.num(1, "calls K"), entries_per_outer=c.num(2, "entries/outer"),
                off_ns_per_outer=c.num(3, "off"), on_ns_per_outer=c.num(4, "on"),
                on_minus_off_ns_per_entry=c.unit(5, " ns", "(on-off)/entries"))


def step0_points(c):
    sm, sa, sb = c.mean_range(1, "SET req/s")
    gm, ga, gb = c.mean_range(2, "GET req/s")
    set_us, get_us = c.pair(3, "SET / GET us/req")
    ent_set, ent_get = c.pair_or_single(4, "entries/req")
    return dict(point=c.text(0), set_req_per_s_mean=sm, set_req_per_s_min=sa, set_req_per_s_max=sb,
                get_req_per_s_mean=gm, get_req_per_s_min=ga, get_req_per_s_max=gb,
                set_us_per_req=set_us, get_us_per_req=get_us, entries_per_req_set=ent_set,
                entries_per_req_get=ent_get, fp_entries_per_req=c.num(5, "FP entries/req"),
                in_kernel_syscalls_per_req=c.num(6, "in-kernel syscalls/req"),
                hook_calls_per_req_text=c.text(7), chain_cap_per_req_text=c.text(8))


def raw_round_cells(header):
    """["test point", "A1 A2 A3", "B1 B2 B3", ...] -> [(round, [pass, ...]), ...]"""
    out = []
    for cell in header[1:]:
        toks = cell.split()
        out.append((toks[0][0], [int(t[1:]) for t in toks]))
    return out


def step0_raw(c):
    test, point = c.text(0).split(" ")
    rows = []
    for col, (rnd, passes) in enumerate(RAW_ROUNDS, 1):
        for p, v in zip(passes, c.numbers(col, "req/s in thousands", len(passes))):
            rows.append(dict(test=test, point=point, boot_round=rnd, pass_=p, kreq_per_s=v))
    return rows


RAW_ROUNDS = raw_round_cells(["test point", "A1 A2 A3", "B1 B2 B3", "C1 C2 C3"])


def step0_sweeps(c):
    test, point = c.text(0).split(" ")
    rows = []
    for sweep in (1, 2):
        for p, v in enumerate(c.numbers(sweep, "req/s in thousands", 3), 1):
            rows.append(dict(test=test, point=point, sweep=sweep, pass_=p, kreq_per_s=v))
    return rows


def step0_fit(c):
    tests = c.text(1).split(" / ")
    if tests not in (["SET"], ["GET"], ["SET", "GET"]):
        c.fail(f"test cell {c.text(1)!r}")
    if len(tests) == 2:
        a, b, r2 = c.pair(2, "a (us)"), c.pair(3, "b (ns/entry)"), c.pair_or_single(4, "R2")
        return [dict(data=c.text(0), test=t, a_us=a[k], b_ns_per_entry=b[k], r2=r2[k], note=None)
                for k, t in enumerate(tests)]
    m = re.match(r"^(\S+)(?: \((.*)\))?$", c.text(4))
    if not m:
        c.fail(f"R2 cell {c.text(4)!r}")
    return [dict(data=c.text(0), test=tests[0], a_us=c.num(2, "a (us)"), b_ns_per_entry=c.num(3, "b (ns/entry)"),
                 r2=c._number(m.group(1), "R2"), note=m.group(2))]


def step0_pred(c):
    sm, sse = c.plus_minus(1, "SET measured")
    gm, gse = c.plus_minus(3, "GET measured")
    return dict(point=c.text(0), set_measured_extra_us_per_req=sm, set_measured_se_us=sse,
                set_predicted_extra_us_per_req=c.num(2, "SET predicted"),
                get_measured_extra_us_per_req=gm, get_measured_se_us=gse,
                get_predicted_extra_us_per_req=c.num(4, "GET predicted"))


def integ_redis(c):
    sm, sa, sb = c.mean_range(1, "SET req/s")
    gm, ga, gb = c.mean_range(2, "GET req/s")
    set_us, get_us = c.pair(3, "SET / GET us/req")
    ent = c.pair_or_single(4, "runtime entries/req")
    fp = c.pair_or_single(5, "FP entries/req")
    return dict(point=c.text(0), set_req_per_s_mean=sm, set_req_per_s_min=sa, set_req_per_s_max=sb,
                get_req_per_s_mean=gm, get_req_per_s_min=ga, get_req_per_s_max=gb,
                set_us_per_req=set_us, get_us_per_req=get_us, runtime_entries_per_req_set=ent[0],
                runtime_entries_per_req_get=ent[1], fp_entries_per_req_set=fp[0], fp_entries_per_req_get=fp[1],
                in_kernel_syscalls_per_req=c.num(6, "in-kernel syscalls/req"),
                hook_calls_per_req=c.num(7, "hook calls/req"), exit_budget_per_req=c.num(8, "exit_budget/req"))


def integ_micro(c):
    return dict(variant=c.text(0), calls_k=c.num(1, "calls K"), transfers_per_outer=c.num(2, "transfers/outer"),
                off_ns_per_outer=c.num(3, "off"), on_ns_per_outer=c.num(4, "on"),
                on_minus_off_ns_per_transfer=c.unit(5, " ns", "(on-off)/transfers"),
                step0_on_minus_off_ns_per_entry=c.unit(6, " ns", "Step 0 (on-off)/entries"))


def miss_class(c):
    m, lo, hi = c.mean_range(1, "req/s")
    return dict(test=c.text(0), req_per_s_mean=m, req_per_s_min=lo, req_per_s_max=hi,
                runtime_entries_per_req=c.num(2, "runtime entries"), miss_cold_per_req=c.num(3, "cold"),
                miss_conflict_per_req=c.num(4, "conflict"), miss_other_per_req=c.num(5, "other"),
                fpsimd_boundary_per_req=c.num(6, "FP/SIMD boundary"))


KPTI = {"KPTI off": "off", "KPTI on": "on"}


def ub_null(c):
    if c.text(0) not in KPTI:
        c.fail(f"row label {c.text(0)!r}")
    m = re.match(r"^(\S+) \((\d+) boots?\)$", c.text(3))
    if not m:
        c.fail(f"module-not-loaded cell {c.text(3)!r}")
    return dict(kpti=KPTI[c.text(0)], kjit_off_ns_per_syscall=c.num(1, "KJIT off"),
                kjit_on_ns_per_syscall=c.num(2, "KJIT on"),
                module_not_loaded_ns_per_syscall=c._number(m.group(1), "module not loaded"),
                module_not_loaded_boots=int(m.group(2)))


def ub_io(c):
    rows = []
    for kpti, cols in (("off", (2, 3, 4)), ("on", (5, 6, 7))):
        rows.append(dict(mode=c.text(0), size_bytes=c.num(1, "size"), kpti=kpti,
                         kjit_off_ns_per_syscall=c.num(cols[0], "off"), kjit_on_ns_per_syscall=c.num(cols[1], "on"),
                         speedup_off_over_on=c.num(cols[2], "speedup")))
    return rows


UB_REDIS_CARRY = {}


def ub_redis(c):
    size = c.text(0)
    if size:
        UB_REDIS_CARRY["size"] = size
    elif "size" not in UB_REDIS_CARRY:
        c.fail("blank value-size cell before any value size")
    if c.text(2) not in ("off", "on"):
        c.fail(f"KPTI cell {c.text(2)!r}")
    off, off_sd = c.mean_paren(3, "off")
    on, on_sd = c.mean_paren(4, "on")
    return dict(value_size=UB_REDIS_CARRY["size"], test=c.text(1), kpti=c.text(2), kjit_off_req_per_s_mean=off,
                kjit_off_req_per_s_sd=off_sd, kjit_on_req_per_s_mean=on, kjit_on_req_per_s_sd=on_sd,
                ratio_on_over_off=c.num(5, "ratio"))


def ub_code(c):
    nat, frag = c.pair(5, "native / fragment ns per instruction")
    return dict(variant=c.text(0), work_unit=c.text(1), native_ns_per_unit=c.num(2, "native ns/unit"),
                fragment_ns_per_unit=c.num(3, "fragment ns/unit"), slowdown=c.unit(4, "x", "slowdown"),
                native_ns_per_insn=nat, fragment_ns_per_insn=frag)


def ub_cpu(c):
    uo, uo_sd = c.plus_minus(1, "off user")
    so, so_sd = c.plus_minus(2, "off system")
    m = re.match(r"^(\S+) \((\d+) runs\)$", c.text(4))
    if not m:
        c.fail(f"KJIT on total cell {c.text(4)!r}")
    return dict(test=c.text(0), kjit_off_user_us_per_req=uo, kjit_off_user_sd_us=uo_sd,
                kjit_off_system_us_per_req=so, kjit_off_system_sd_us=so_sd, kjit_off_total_us_per_req=c.num(3, "off total"),
                kjit_on_total_us_per_req=c._number(m.group(1), "on total"), kjit_on_total_runs=int(m.group(2)),
                kjit_on_user_us_per_req=c.num(5, "on user"))


def a11c(c):
    label = c.text(0)
    m = re.match(r"^(SET|GET) (A11c|V0 \(journal above\))$", label)
    if not m:
        c.fail(f"row label {label!r}")
    own = m.group(2) == "A11c"
    if own:
        mean, lo, hi = c.mean_range(1, "req/s")
        off = c.num(2, "KJIT off")
    else:
        mean, lo, hi, off = c.num_k(1, "req/s"), None, None, c.num_k(2, "KJIT off")
    return dict(test=m.group(1), variant="A11c" if own else "V0",
                origin="this-entry" if own else "referenced-earlier-entry",
                req_per_s_mean=mean, req_per_s_min=lo, req_per_s_max=hi, kjit_off_req_per_s=off,
                ratio_on_over_off=c.num(3, "ratio"), runtime_entries_per_req=c.num(4, "runtime entries"),
                miss_cold_per_req=c.num(5, "cold"), miss_conflict_per_req=c.num(6, "conflict"),
                miss_other_per_req=c.num(7, "other"), fpsimd_boundary_per_req=c.num(8, "FP/SIMD boundary"))


def ub_eval_e1(c):
    m = re.match(r"^(\S+) \((\S+)\)$", c.text(3))
    if not m:
        c.fail(f"transfers cell {c.text(3)!r}")
    return dict(pair=c.text(0), share_of_syscalls_pct=c.percent(1, "share of syscalls"),
                median_insns_per_gap=c.num(2, "median insns"), transfers_per_gap=c._number(m.group(1), "transfers"),
                indirect_transfers_per_gap=c._number(m.group(2), "indirect transfers"))


# ---------------------------------------------------------------------------------------
# Entry registry. columns lists the output columns in order ("pass_" is written as "pass").

ENTRIES = {
    "a11-step0": dict(
        journal="2026-10-02.md", out="json",
        heading="## 17:14 +0800 — A11 Step 0: baseline of fragment entry cost",
        tables=[
            dict(name="microbench_ns_per_outer", anchor="### Microbenchmark: cost of one fragment entry", fn=step0_micro,
                 header=["variant", "calls K", "entries/outer", "off", "on", "(on-off)/entries"],
                 columns=["variant", "calls_k", "entries_per_outer", "off_ns_per_outer", "on_ns_per_outer",
                          "on_minus_off_ns_per_entry"]),
            dict(name="redis_per_point", anchor="### redis-benchmark: per point", fn=step0_points,
                 header=["point", "SET req/s mean (min..max)", "GET req/s mean (min..max)", "SET / GET us/req",
                         "entries/req (SET / GET)", "FP entries/req", "in-kernel syscalls/req", "hook calls/req",
                         "chain_cap/req"],
                 columns=["point", "set_req_per_s_mean", "set_req_per_s_min", "set_req_per_s_max",
                          "get_req_per_s_mean", "get_req_per_s_min", "get_req_per_s_max", "set_us_per_req",
                          "get_us_per_req", "entries_per_req_set", "entries_per_req_get", "fp_entries_per_req",
                          "in_kernel_syscalls_per_req", "hook_calls_per_req_text", "chain_cap_per_req_text"]),
            dict(name="redis_runs_fresh_server", anchor="Raw req/s in thousands", fn=step0_raw,
                 header=["test point", "A1 A2 A3", "B1 B2 B3", "C1 C2 C3"],
                 columns=["test", "point", "boot_round", "pass", "kreq_per_s"]),
            dict(name="redis_runs_single_server_sweeps", anchor="Single-server sweeps", fn=step0_sweeps,
                 header=["test point", "sweep 1", "sweep 2"],
                 columns=["test", "point", "sweep", "pass", "kreq_per_s"]),
            dict(name="fit_us_per_req_vs_entries_per_req", anchor="### Fit: time per request", fn=step0_fit,
                 header=["data", "test", "a (us)", "b (ns/entry)", "R2"],
                 columns=["data", "test", "a_us", "b_ns_per_entry", "r2", "note"]),
            dict(name="prediction_vs_measured_extra_us_per_req", anchor="Microbenchmark prediction applied", fn=step0_pred,
                 header=["point", "SET measured", "SET predicted", "GET measured", "GET predicted"],
                 columns=["point", "set_measured_extra_us_per_req", "set_measured_se_us",
                          "set_predicted_extra_us_per_req", "get_measured_extra_us_per_req", "get_measured_se_us",
                          "get_predicted_extra_us_per_req"]),
        ]),
    "a11-integration": dict(
        journal="2026-10-05.md", out="json",
        heading="## 11:47 +0800 — A11 integration: merged tree validated and re-measured against Step 0",
        tables=[
            dict(name="redis_per_point", anchor="Redis (req/s mean over 9 runs", fn=integ_redis,
                 header=["point", "SET req/s", "GET req/s", "SET / GET us/req", "runtime entries/req (SET / GET)",
                         "FP entries/req", "in-kernel syscalls/req", "hook calls/req", "exit_budget/req"],
                 columns=["point", "set_req_per_s_mean", "set_req_per_s_min", "set_req_per_s_max",
                          "get_req_per_s_mean", "get_req_per_s_min", "get_req_per_s_max", "set_us_per_req",
                          "get_us_per_req", "runtime_entries_per_req_set", "runtime_entries_per_req_get",
                          "fp_entries_per_req_set", "fp_entries_per_req_get", "in_kernel_syscalls_per_req",
                          "hook_calls_per_req", "exit_budget_per_req"]),
            dict(name="microbench_ns_per_outer", anchor="Microbenchmark (`entry_cost`;", fn=integ_micro,
                 header=["variant", "calls K", "transfers/outer (2K+1)", "off", "on", "(on-off)/transfers",
                         "Step 0 (on-off)/entries"],
                 columns=["variant", "calls_k", "transfers_per_outer", "off_ns_per_outer", "on_ns_per_outer",
                          "on_minus_off_ns_per_transfer", "step0_on_minus_off_ns_per_entry"]),
        ]),
    "miss-class": dict(
        journal="2026-10-09.md", out="csv",
        heading="## 00:47 +0800 — Dispatch-table miss classification",
        tables=[
            dict(name="miss_classification", anchor="Results (per request, chain_budget 1024", fn=miss_class,
                 header=["test", "req/s", "runtime entries", "cold", "conflict", "other", "FP/SIMD boundary"],
                 columns=["test", "req_per_s_mean", "req_per_s_min", "req_per_s_max", "runtime_entries_per_req",
                          "miss_cold_per_req", "miss_conflict_per_req", "miss_other_per_req",
                          "fpsimd_boundary_per_req"]),
        ]),
    "ub-measure": dict(
        journal="2026-10-09.md", out="json",
        note='The "Model of one request" table is derived arithmetic over the measured tables and is not transcribed.',
        heading="## 21:41 +0800 — Why KJIT does not reach Userspace Bypass's speedups",
        tables=[
            dict(name="null_syscall_ns_per_syscall", anchor="### 1. Null syscall", fn=ub_null,
                 header=["", "KJIT off", "KJIT on (in kernel)", "module not loaded"],
                 columns=["kpti", "kjit_off_ns_per_syscall", "kjit_on_ns_per_syscall",
                          "module_not_loaded_ns_per_syscall", "module_not_loaded_boots"]),
            dict(name="io_microbenchmark_ns_per_syscall", anchor="### 2. I/O micro-benchmark", fn=ub_io,
                 header=["mode (syscalls per iteration)", "size", "off", "on", "speedup", "off (KPTI)", "on (KPTI)",
                         "speedup (KPTI)"],
                 columns=["mode", "size_bytes", "kpti", "kjit_off_ns_per_syscall", "kjit_on_ns_per_syscall",
                          "speedup_off_over_on"]),
            dict(name="redis_req_per_s", anchor="### 3. Redis", fn=ub_redis,
                 header=["value size", "test", "KPTI", "off", "on", "ratio"],
                 columns=["value_size", "test", "kpti", "kjit_off_req_per_s_mean", "kjit_off_req_per_s_sd",
                          "kjit_on_req_per_s_mean", "kjit_on_req_per_s_sd", "ratio_on_over_off"]),
            dict(name="code_speed_slopes", anchor="### 4. Speed of translated code", fn=ub_code,
                 header=["variant", "work per unit of n", "native ns/unit", "fragment ns/unit", "slowdown",
                         "native / fragment ns per instruction"],
                 columns=["variant", "work_unit", "native_ns_per_unit", "fragment_ns_per_unit", "slowdown",
                          "native_ns_per_insn", "fragment_ns_per_insn"]),
            dict(name="server_cpu_us_per_req", anchor="### 5. Where the server's time goes", fn=ub_cpu,
                 header=["", "KJIT off user", "off system", "off total", "KJIT on total", "on user"],
                 columns=["test", "kjit_off_user_us_per_req", "kjit_off_user_sd_us", "kjit_off_system_us_per_req",
                          "kjit_off_system_sd_us", "kjit_off_total_us_per_req", "kjit_on_total_us_per_req",
                          "kjit_on_total_runs", "kjit_on_user_us_per_req"]),
        ]),
    "a11c": dict(
        journal="2026-10-09.md", out="csv",
        heading="## 22:11 +0800 — A11c implemented: dispatch-table victim part",
        tables=[
            dict(name="a11c_measurement", anchor="Measurement (`a11-baseline.sh /tmp/a11 3 200000 off 1024`", fn=a11c,
                 header=["", "req/s", "KJIT off", "ratio", "runtime entries", "cold", "conflict", "other",
                         "FP/SIMD boundary"],
                 columns=["test", "variant", "origin", "req_per_s_mean", "req_per_s_min", "req_per_s_max",
                          "kjit_off_req_per_s", "ratio_on_over_off", "runtime_entries_per_req", "miss_cold_per_req",
                          "miss_conflict_per_req", "miss_other_per_req", "fpsimd_boundary_per_req"]),
        ]),
    "ub-eval-e1": dict(
        journal="2026-10-09.md", out="csv",
        heading="## 19:59 +0800 — Design evaluation: Userspace Bypass (OSDI '23) against KJIT",
        tables=[
            dict(name="e1_syscall_gaps", anchor="E1 reduction (4 clients, 25000 requests)", fn=ub_eval_e1,
                 header=["pair", "share of syscalls", "median insns", "transfers/gap (of which indirect)"],
                 columns=["pair", "share_of_syscalls_pct", "median_insns_per_gap", "transfers_per_gap",
                          "indirect_transfers_per_gap"]),
        ]),
}


def build(args, entry):
    if entry not in ENTRIES:
        raise kd.ParseError(f"--entry {entry!r}: unknown, choose one of {sorted(ENTRIES)}")
    spec = ENTRIES[entry]
    if len(args) != 1 or not args[0].endswith(spec["journal"]):
        raise kd.ParseError(f"entry {entry} reads {spec['journal']}, given {args}")
    path = args[0]
    lines = section_lines(path, spec["heading"])
    tables = []
    for t in spec["tables"]:
        UB_REDIS_CARRY.clear()
        table = kd.Table(t["name"], t["columns"] + ["source"])
        for row in read_table(path, lines, t["anchor"], t["header"]):
            out = t["fn"](row)
            for d in (out if isinstance(out, list) else [out]):
                d = {("pass" if k == "pass_" else k): v for k, v in d.items()}
                d["source"] = "journal-table"
                try:
                    table.add(**d)
                except kd.ParseError as e:
                    kd.fail(path, row.lineno, str(e))
        tables.append(table)
    meta = {"extracted_by": "tests/guest/host/extract_journal_tables.py", "source": "journal-table",
            "journal": f"docs/journal/{spec['journal']}", "entry": spec["heading"][3:]}
    if "note" in spec:
        meta["note"] = spec["note"]
    return meta, tables, spec["out"]


if __name__ == "__main__":
    import argparse
    import sys

    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("journal", nargs=1, metavar="JOURNAL.md")
    ap.add_argument("--entry", required=True, choices=sorted(ENTRIES))
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    try:
        meta, tables, kind = build(a.journal, a.entry)
    except kd.ParseError as e:
        sys.exit(f"error: {e}")
    if not a.out.endswith("." + kind):
        ap.error(f"entry {a.entry} writes a .{kind} file")
    if kind == "csv":
        kd.write_csv(a.out, tables[0])
    else:
        kd.write_json(a.out, meta, tables)
    print(f"{a.out}: " + ", ".join(f"{t.name} {len(t)} rows" for t in tables))
