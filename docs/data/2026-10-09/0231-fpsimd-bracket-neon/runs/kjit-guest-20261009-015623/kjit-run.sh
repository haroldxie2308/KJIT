#!/bin/sh
set -e
FPV_PROBE=0 FPV_BENCH_ARGS='' sh /opt/kjit-tests/fpv-bench.sh /tmp/fpv 5 200000 A B2 off B v0
