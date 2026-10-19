#!/bin/sh
# Absolute sticky-bracket counters of the a23 module after redis GET and SET runs (the sweep records per-run deltas only,
# and the flags are set during its warm-up): one guest boot, auto mode, TCP, 300000 requests each.
#   a23-sticky-abs.sh        (inside the kjit-guest; /kjit/kjit.ko = the a23 module)
set -eu
. /opt/kjit-tests/k4-lib.sh
k4_debugfs
echo "abs: module $(ls -l /kjit/kjit.ko | awk '{ print $5 }') bytes, fpsimd_timing=$(cat $K/fpsimd_timing)"
set_mode 1
start_server /tmp/abs-srv
bench -t set,get -n 300000 -c 50 -P 1 -d 1 -q > /dev/null
for n in fp_sticky_set ibtc_fpsimd_boundary fragment_entries fpsimd_entries hook_calls chains translate_ok fpsimd_exit_mem run_declined fpsimd_run_max_ns; do
    echo "abs: $n $(stat_of $K/stats $n)"
done
set_mode 0
stop_server
echo "abs: done"
