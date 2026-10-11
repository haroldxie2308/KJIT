"""Shared plotting helpers for docs/viz: data loading, style, deterministic SVG output.

Numbers come only from docs/data. Constants typed here are published figures quoted by a
journal entry (named where used), never measurements.
"""
import json
import textwrap
from pathlib import Path

import matplotlib
matplotlib.use("svg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

HERE = Path(__file__).resolve().parent
DATA = HERE.parent / "data"
OUT = HERE / "svg"

# Categorical slots in fixed order (dataviz reference palette, light surface).
BLUE, ORANGE, AQUA, YELLOW, MAGENTA, GREEN, VIOLET, RED = (
    "#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4", "#008300", "#4a3aa7", "#e34948")
INK, INK2, MUTED, GRID, SURFACE = "#0b0b0b", "#52514e", "#8a8984", "#e3e2de", "#ffffff"

PLATFORM = "Platform: M1/HVF guest (4 vCPUs) on a shared, noisy host; ratios and spreads, not absolute hardware numbers."

plt.rcParams.update({
    "svg.fonttype": "none",            # keep text as text: small, diffable
    "svg.hashsalt": "kjit-viz",        # deterministic element ids
    "font.family": ["DejaVu Sans", "Helvetica", "Arial", "sans-serif"],
    "font.size": 9,
    "text.color": INK, "axes.labelcolor": INK2, "xtick.color": INK2, "ytick.color": INK2,
    "axes.edgecolor": MUTED, "axes.linewidth": 0.8,
    "axes.spines.top": False, "axes.spines.right": False,
    "axes.grid": True, "grid.color": GRID, "grid.linewidth": 0.6, "axes.axisbelow": True,
    "axes.titlesize": 10, "axes.titleweight": "bold", "axes.titlelocation": "left",
    "legend.frameon": False, "legend.fontsize": 8.5,
    "lines.linewidth": 2.0, "lines.markersize": 5,
    "figure.facecolor": SURFACE, "axes.facecolor": SURFACE, "savefig.facecolor": SURFACE,
})


def csv(rel):
    return pd.read_csv(DATA / rel)


def json_tables(rel):
    """docs/data JSON file -> (meta, {table name: DataFrame})."""
    j = json.loads((DATA / rel).read_text())
    return j["meta"], {k: pd.DataFrame(t["rows"], columns=t["columns"]) for k, t in j["tables"].items()}


def quartiles(x):
    x = np.asarray(x, dtype=float)
    return np.percentile(x, 25), np.median(x), np.percentile(x, 75)


def figure(width, height, title, takeaway, caption, nrows=1, ncols=1, **kw):
    """Figure with a headline, a one-line takeaway and a bottom caption (data files + entry)."""
    fig, axes = plt.subplots(nrows, ncols, figsize=(width, height), squeeze=False, **kw)
    cap = textwrap.fill(caption + " " + PLATFORM, width=int(width * 17))
    ncap = cap.count("\n") + 1
    cap_h = (ncap * 0.165 + 0.15) / height
    top_h = 0.62 / height
    fig.text(0.012, 1 - 0.1 / height, title, fontsize=12.5, fontweight="bold", va="top")
    fig.text(0.012, 1 - 0.36 / height, takeaway, fontsize=9, color=INK2, va="top")
    fig.text(0.012, 0.1 / height, cap, fontsize=7, color=MUTED, va="bottom", linespacing=1.35)
    fig._rect = [0, cap_h, 1, 1 - top_h]
    return fig, axes


def save(fig, name):
    fig.tight_layout(rect=fig._rect)
    OUT.mkdir(exist_ok=True)
    path = OUT / f"{name}.svg"
    fig.savefig(path, format="svg", metadata={"Date": None})
    plt.close(fig)
    return path


def log_size_axis(ax, sizes):
    ax.set_xscale("log", base=2)
    ax.set_xticks(sizes)
    ax.set_xticklabels([f"{s // 1024}K" if s >= 1024 else str(s) for s in sizes], fontsize=7.5)
    ax.minorticks_off()
