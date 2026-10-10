#!/bin/sh
set -e
FPV_PROBE=1 FPV_BENCH_ARGS='' sh /opt/kjit-tests/fpv-bench.sh /tmp/fpv 3 200000 A B2 off B v0
