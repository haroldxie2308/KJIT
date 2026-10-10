"""Shared helpers of the extraction scripts that turn raw measurement logs (or a
journal table) into the machine-readable files under docs/data/.

Rules every script built on this follows:
  * a line the script is meant to read that is malformed, or a file that lacks the
    lines it must have, raises ParseError("<file>:<line>: <what>"); nothing is skipped
    or defaulted. Lines that are not measurement lines (kernel messages, shell echo)
    are not "expected" and are ignored by prefix;
  * numbers are stored as parsed (int when written without a point, else float), so
    the files do not depend on printf rounding of a second pass;
  * output is deterministic (fixed column order, "\\n" line ends), so a re-run gives
    byte-identical files.

Standard library only.
"""
import argparse
import csv
import importlib.util
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))

_NUMBER = re.compile(r"-?\d+(\.\d+)?$")


class ParseError(Exception):
    """Raised with "<file>:<line>: <message>" text."""


def fail(path, lineno, message):
    where = path if lineno is None else f"{path}:{lineno}"
    raise ParseError(f"{where}: {message}")


def number(path, lineno, field, text):
    """text -> int or float; raises ParseError naming the file and line otherwise."""
    if text is None or not _NUMBER.match(text):
        fail(path, lineno, f"{field}: not a number: {text!r}")
    return float(text) if "." in text else int(text)


def read_lines(path):
    """Yield (lineno, text) with the line end removed. A missing file is a ParseError."""
    try:
        f = open(path, errors="replace", newline="")
    except OSError as e:
        raise ParseError(f"{path}: cannot read: {e.strerror}") from e
    with f:
        for lineno, raw in enumerate(f, 1):
            yield lineno, raw.rstrip("\r\n")


def kv_pairs(path, lineno, text):
    """"a=1 b=2" -> [("a", "1"), ("b", "2")]; every token must be key=value, no duplicates."""
    out = []
    seen = set()
    for tok in text.split():
        k, sep, v = tok.partition("=")
        if not sep or not k or not v:
            fail(path, lineno, f"expected key=value, got {tok!r}")
        if k in seen:
            fail(path, lineno, f"duplicate key {k!r}")
        seen.add(k)
        out.append((k, v))
    return out


class Table:
    """Fixed columns, rows as lists. add() takes every column as a keyword; None is an
    empty cell (a column that does not apply to this row's kind, never a default)."""

    def __init__(self, name, columns):
        self.name = name
        self.columns = list(columns)
        self.rows = []

    def add(self, **row):
        if set(row) != set(self.columns):
            raise ParseError(f"table {self.name}: row keys {sorted(row)} != columns {sorted(self.columns)}")
        self.rows.append([row[c] for c in self.columns])

    def __len__(self):
        return len(self.rows)


class UniformKV:
    """Column list of a family of key=value lines: the first line fixes it and every
    later line must carry exactly the same keys in the same order."""

    def __init__(self, what):
        self.what = what
        self.keys = None
        self.first = None

    def check(self, path, lineno, pairs):
        keys = [k for k, _ in pairs]
        if self.keys is None:
            self.keys, self.first = keys, (path, lineno)
        elif keys != self.keys:
            missing = [k for k in self.keys if k not in keys]
            extra = [k for k in keys if k not in self.keys]
            fail(path, lineno, f"{self.what} line keys differ from those at {self.first[0]}:{self.first[1]} "
                               f"(missing {missing}, extra {extra}, or reordered)")


def write_csv(path, table):
    with open(path, "w", newline="") as f:
        w = csv.writer(f, lineterminator="\n")
        w.writerow(table.columns)
        for row in table.rows:
            w.writerow(["" if v is None else v for v in row])


def write_json(path, meta, tables):
    """meta: dict of provenance fields; tables: list of Table. Layout, one table row
    per line so that diffs and greps stay readable:
    {"meta": {...}, "tables": {name: {"columns": [...], "rows": [[...], ...]}}}."""
    dump = lambda v: json.dumps(v, ensure_ascii=False, separators=(", ", ": "))
    out = ['{\n "meta": ' + dump(meta) + ',\n "tables": {']
    for ti, t in enumerate(tables):
        out.append(f'  {dump(t.name)}: {{')
        out.append(f'   "columns": {dump(t.columns)},')
        out.append('   "rows": [')
        for ri, row in enumerate(t.rows):
            out.append("    " + dump(row) + ("," if ri + 1 < len(t.rows) else ""))
        out.append("   ]")
        out.append("  }" + ("," if ti + 1 < len(tables) else ""))
    out.append(" }\n}")
    with open(path, "w") as f:
        f.write("\n".join(out) + "\n")


def ub_summarize():
    """The ub-summarize.py module (its file name has a hyphen, so it is not importable by name)."""
    spec = importlib.util.spec_from_file_location("ub_summarize", os.path.join(HERE, "ub-summarize.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def run_cli(description, build, out_kind):
    """Common CLI: <script> LOG... --out FILE. build(logs) -> (meta, [Table]); out_kind
    "csv" needs exactly one table, "json" writes all of them."""
    ap = argparse.ArgumentParser(description=description, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("logs", nargs="+", metavar="LOG", help="raw log files (or run directories where the script says so)")
    ap.add_argument("--out", required=True, help=f"output .{out_kind} file")
    args = ap.parse_args()
    if not args.out.endswith("." + out_kind):
        ap.error(f"--out must end in .{out_kind}")
    try:
        meta, tables = build(args.logs)
    except ParseError as e:
        sys.exit(f"error: {e}")
    if out_kind == "csv":
        if len(tables) != 1:
            raise AssertionError("csv output needs exactly one table")
        write_csv(args.out, tables[0])
    else:
        write_json(args.out, meta, tables)
    print(f"{args.out}: " + ", ".join(f"{t.name} {len(t)} rows" for t in tables))
