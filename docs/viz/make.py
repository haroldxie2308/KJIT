#!/usr/bin/env python3
"""Regenerate every figure of docs/viz/svg from docs/data. Usage: python3 docs/viz/make.py (or `make viz`)."""
import sys
from pathlib import Path

sys.dont_write_bytecode = True   # keep __pycache__ out of the tree
sys.path.insert(0, str(Path(__file__).resolve().parent))

import fig01_redis_ub, fig02_pan_sweep, fig03_cpu_gap, fig04_code_speed, fig05_dispatch_stall  # noqa: E402
import fig06_attribution, fig07_simd_lowering, fig08_variants, fig09_progress  # noqa: E402

MODULES = [fig01_redis_ub, fig02_pan_sweep, fig03_cpu_gap, fig04_code_speed, fig05_dispatch_stall,
           fig06_attribution, fig07_simd_lowering, fig08_variants, fig09_progress]

if __name__ == "__main__":
    for m in MODULES:
        out = m.build()
        for p in (out if isinstance(out, list) else [out]):
            print(p.relative_to(Path(__file__).resolve().parents[2]))
