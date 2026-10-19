"""EXPERIMENT (exp/attrib-a22). Writes the tidy CSVs of the entry: one row per measured run (runs), per boot (boots), per micro item.

  python3 export.py RUNS_DIR OUT_PREFIX      -> OUT_PREFIX.csv, OUT_PREFIX-boots.csv, OUT_PREFIX-micro.csv
Column names: units in the names (`_us_per_req`, `_per_req`, `_per_1000req`); `x_*_t` are CNTVCT ticks (24 MHz) over the whole run, `x_*_n` counts.
"""
import subprocess
import sys

import pandas as pd

from parse import load_runs

runs_dir, prefix = sys.argv[1], sys.argv[2]
runs, boots = load_runs(runs_dir)
ren = {"cfg": "cell", "cpu_us": "cpu_us_per_req", "user_us": "user_us_per_req", "sys_us": "sys_us_per_req", "nvol_k": "nvol_per_1000req",
       "ninv_k": "ninv_per_1000req", "ipi_cl_k": "ipi_rx_cpu1to3_per_1000req", "ipi_c0_k": "ipi_rx_cpu0_per_1000req"}
runs = runs.rename(columns=ren)
runs = runs.rename(columns={c: c[:-3] + "_per_req" for c in runs.columns if c.endswith("_pr") and not c.startswith(("c_", "t_"))})
runs = runs.rename(columns={c: c[:-3] + "_per_req" for c in runs.columns if c.endswith("_pr") and c.startswith(("c_", "t_"))})
runs = runs.rename(columns={c: c[:-3] + "_us_per_req" for c in runs.columns if c.endswith("_us") and c.startswith(("c_", "t_"))})
runs = runs.rename(columns={"label": "boot_label", "boot": "boot_no", "type": "boot_type"})
runs.to_csv(prefix + ".csv", index=False)
b = boots.copy()
for c in b.columns:
    if b[c].dtype == object and c not in ("label", "type"):
        b[c] = b[c].map(lambda v: ";".join(str(x) for x in v) if isinstance(v, list) else v)
b.to_csv(prefix + "-boots.csv", index=False)
print(len(runs), "runs", len(b), "boots", runs.shape[1], "columns")
