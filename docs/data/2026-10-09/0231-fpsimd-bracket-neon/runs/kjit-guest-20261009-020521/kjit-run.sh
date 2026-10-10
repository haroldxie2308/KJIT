#!/bin/sh
set -e
FPV_PROBE=1 FPV_BENCH_ARGS='-P 16' sh /opt/kjit-tests/fpv-bench.sh /tmp/fpv 3 200000 off v0 A B B2
