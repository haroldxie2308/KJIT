#!/bin/sh
# K4 (2)+(3): benchmark and adversarial campaign (inside the kjit-guest,
# kjit.ko loaded), run by scripts/redis-campaign.sh.
#
#   k4-campaign.sh OUTDIR [iterations] [requests]
#
# Each iteration: the K2 micro tests in auto mode (run-k2.sh --auto: among
# them munmap_race, hot text unmapped under a running fragment, and kill -9
# of hot processes), k4-bench.sh (requests per benchmark test, default
# 100000) and k4-adversarial.sh. Logs go to OUTDIR/iter-N/; the kernel log to
# OUTDIR/dmesg.txt. Exits non-zero on the first failure; prints
# "k4: ALL PASS" at the end.
set -eu

out=${1:?usage: k4-campaign.sh OUTDIR [iterations] [requests]}
iterations=${2:-1}
requests=${3:-100000}
T=/opt/kjit-tests
mkdir -p "$out"

. "$T/k4-lib.sh"
k4_debugfs

# step NAME LOG CMD...: run CMD, keep its output in LOG and print its summary
# lines ("k2:"/"k4...:" prefixes).
step() {
    local name=$1 log=$2 status
    shift 2
    set +e
    "$@" > "$log" 2>&1
    status=$?
    set -e
    grep -E '^(k2: .*(PASS|FAIL)|k2:   [a-z_]+: in_kernel|k4)' "$log" || true
    if [ "$status" != 0 ]; then
        tail -40 "$log"
        echo "k4: FAIL $name (status $status, log $log)"
        dmesg > "$out/dmesg.txt"
        exit 1
    fi
}

i=1
while [ "$i" -le "$iterations" ]; do
    dir="$out/iter-$i"
    rm -rf "$dir"
    mkdir -p "$dir"
    echo "k4: iteration $i"
    step k2-auto "$dir/k2.log" env K2_LEAVE_HOT=0 sh "$T/run-k2.sh" --auto 1
    step bench "$dir/bench.log" sh "$T/k4-bench.sh" "$dir/bench" "$requests"
    step adversarial "$dir/adv.log" sh "$T/k4-adversarial.sh" "$dir/adv"
    echo "k4: iteration $i PASS"
    i=$((i + 1))
done

set_mode 0
echo "k4: final stats"
sed 's/^/k4:   /' "$K/stats"
dmesg > "$out/dmesg.txt"
echo "k4: ALL PASS ($iterations iterations, $requests requests per benchmark test)"
