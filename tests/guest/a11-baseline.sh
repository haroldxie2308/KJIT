#!/bin/sh
# A11 Step 0 baseline: redis-benchmark SET and GET throughput against one
# redis-server, KJIT off and at several chain_budget values, with the KJIT
# counter deltas of each run (inside the kjit-guest, kjit.ko loaded).
#
#   a11-baseline.sh WORKDIR RUNS REQUESTS POINT...
#
# POINT is "off" (KJIT disabled) or a chain_budget (1..65536; KJIT on, auto
# mode). One redis-server serves the whole invocation. A warm-up (SET then GET
# at the first point, so every translation exists and the dataset is
# populated) is followed by RUNS passes over the points in the order given;
# each pass is, per point, one `redis-benchmark -t set -n REQUESTS -q` and one
# `-t get` (nojit, so the global KJIT counters are the server's; separate
# invocations so SET and GET get their own counter deltas; set first, so the
# GET finds its key). chain_budget is restored at exit.
#
# Optional environment: A11_BENCH_ARGS, extra redis-benchmark arguments for the
# warm-up and every run (word-split, default none), e.g. A11_BENCH_ARGS='-d 4096'
# for 4 KiB values or '-d 3 -c 50'. Without it the invocations are unchanged.
#
# One line per benchmark run on stdout:
#   a11 point=<p> pass=<i> test=<set|get> requests=<n> rps=<req/s> <counter>=<delta> ...
# Exits non-zero when a run reports no throughput, when a KJIT-on run shows no
# fragment entry, when a KJIT-off run shows one, or when the runtime reports
# an invalid exit or a verifier rejection. The A11 dispatch counters (ibtc_*)
# are deltas like the others; fpsimd_run_max_ns is the cumulative maximum.
#
# Dispatch misses (runtime/ibtc.rs): ibtc_miss_cold / _conflict / _other
# classify every BL/BLR/BR/RET exit by the run's table slot, except the
# ibtc_fpsimd_boundary ones, so cold + conflict + other + fpsimd_boundary ==
# exit_bl + exit_blr + exit_br + exit_ret; the line prints the difference as
# miss_residual (counters are read while the server idles, not atomically, so a
# few exits in flight can show). ibtc_slots is reset before and dumped after
# every run: the top conflicting slots per table go to
# $WORKDIR/slots.<point>.<pass>.<test> and, prefixed "a11slots point=.. pass=..
# test=..", to stdout. The server's /proc/<pid>/maps (after the warm-up and at
# the end) is printed prefixed "a11maps" and saved as $WORKDIR/redis.maps.*,
# to map the pcs of the slots to symbols on the host.
set -eu

. /opt/kjit-tests/k4-lib.sh

usage() {
    echo "usage: a11-baseline.sh WORKDIR RUNS REQUESTS POINT...   (POINT: off | chain_budget)" >&2
    exit 2
}
[ $# -ge 4 ] || usage
work=$1
runs=$2
n=$3
shift 3
points="$*"

mkdir -p "$work"
cd "$work"
k4_debugfs
for f in enable auto chain_budget stats unsupported_top ibtc_slots; do
    [ -f "$K/$f" ] || k4_fail "$K/$f missing (kjit.ko too old for chain_budget?)"
done

counters="hook_calls syscalls_in_kernel fragment_entries fpsimd_entries fpsimd_preempted chains chain_cap
exit_svc exit_bl exit_blr exit_br exit_ret exit_mem exit_unsupported exit_budget run_declined
ibtc_insert ibtc_replace ibtc_clear ibtc_fpsimd_boundary ibtc_miss_cold ibtc_miss_conflict ibtc_miss_other"

orig_budget=$(cat "$K/chain_budget")
restore() { echo "$orig_budget" > "$K/chain_budget"; set_mode 0; }
trap restore EXIT

# set_point POINT: off, or on with chain_budget POINT (read back).
set_point() {
    if [ "$1" = off ]; then
        set_mode 0
        return
    fi
    echo "$1" > "$K/chain_budget"
    [ "$(cat "$K/chain_budget")" = "$1" ] || k4_fail "chain_budget did not become $1"
    set_mode 1
}

# run_test POINT PASS TEST: one benchmark run; prints the a11 line.
run_test() {
    local point=$1 pass=$2 test=$3 rps line d resid
    echo reset > "$K/ibtc_slots"
    snap "$work/before"
    # shellcheck disable=SC2086  # A11_BENCH_ARGS is a word list by contract
    bench -t "$test" -n "$n" -q ${A11_BENCH_ARGS:-} > "$work/bench.out" 2>&1 || { tail "$work/bench.out"; k4_fail "benchmark $test at $point"; }
    snap "$work/after"
    cat "$K/ibtc_slots" > "$work/slots.$point.$pass.$test"
    rps=$(tr '\r' '\n' < "$work/bench.out" | awk -v t="$(echo "$test" | tr a-z A-Z):" \
        '$1 == t && $3 == "requests" { v = $2 } END { print v }')
    [ -n "$rps" ] || { cat "$work/bench.out"; k4_fail "no requests/s for $test at $point"; }
    line="a11 point=$point pass=$pass test=$test requests=$n rps=$rps"
    for c in $counters; do
        d=$(( $(stat_of "$work/after.stats" "$c") - $(stat_of "$work/before.stats" "$c") ))
        line="$line $c=$d"
    done
    # A maximum since module load, not a delta.
    line="$line fpsimd_run_max_ns=$(stat_of "$work/after.stats" fpsimd_run_max_ns)"
    resid=$(awk 'FILENAME == ARGV[1] { a[$1] = $2; next }
        { d[$1] = $2 - a[$1] }
        END { print d["exit_bl"] + d["exit_blr"] + d["exit_br"] + d["exit_ret"] \
            - d["ibtc_miss_cold"] - d["ibtc_miss_conflict"] - d["ibtc_miss_other"] - d["ibtc_fpsimd_boundary"] }' \
        "$work/before.stats" "$work/after.stats")
    echo "$line miss_residual=$resid"
    sed "s/^/a11slots point=$point pass=$pass test=$test /" "$work/slots.$point.$pass.$test"
    for c in exit_invalid translate_verify_rejected unsupported_bad_word; do
        d=$(( $(stat_of "$work/after.stats" "$c") - $(stat_of "$work/before.stats" "$c") ))
        [ "$d" = 0 ] || k4_fail "$point $test: runtime counter $c grew by $d"
    done
    d=$(( $(stat_of "$work/after.stats" fragment_entries) - $(stat_of "$work/before.stats" fragment_entries) ))
    if [ "$point" = off ]; then
        [ "$d" = 0 ] || k4_fail "$point $test: $d fragment entries with KJIT off"
    else
        [ "$d" -gt 0 ] || k4_fail "$point $test: no fragment entry with KJIT on"
    fi
}

set -- $points
first=$1
set_point "$first"
start_server "$work/srv"
# Warm-up: auto mode translates the server's hot code, the keys exist.
echo "a11: warm-up at $first"
# shellcheck disable=SC2086  # A11_BENCH_ARGS is a word list by contract
bench -t set -n "$n" -q ${A11_BENCH_ARGS:-} > /dev/null 2>&1
bench -t get -n "$n" -q ${A11_BENCH_ARGS:-} > /dev/null 2>&1
cp "/proc/$server/maps" "$work/redis.maps.start"
sed 's/^/a11maps /' "$work/redis.maps.start"

pass=1
while [ "$pass" -le "$runs" ]; do
    for p in $points; do
        set_point "$p"
        run_test "$p" "$pass" set
        run_test "$p" "$pass" get
    done
    pass=$((pass + 1))
done
set_mode 0
cp "/proc/$server/maps" "$work/redis.maps.end"
sed 's/^/a11maps-end /' "$work/redis.maps.end"
stop_server
echo "a11: done"
