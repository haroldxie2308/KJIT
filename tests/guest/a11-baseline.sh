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
# One line per benchmark run on stdout:
#   a11 point=<p> pass=<i> test=<set|get> requests=<n> rps=<req/s> <counter>=<delta> ...
# Exits non-zero when a run reports no throughput, when a KJIT-on run shows no
# fragment entry, when a KJIT-off run shows one, or when the runtime reports
# an invalid exit or a verifier rejection.
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
for f in enable auto chain_budget stats unsupported_top; do
    [ -f "$K/$f" ] || k4_fail "$K/$f missing (kjit.ko too old for chain_budget?)"
done

counters="hook_calls syscalls_in_kernel fragment_entries fpsimd_entries fpsimd_restores chains chain_cap
exit_svc exit_bl exit_blr exit_br exit_ret exit_mem exit_unsupported exit_budget run_declined"

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
    local point=$1 pass=$2 test=$3 rps line d
    snap "$work/before"
    bench -t "$test" -n "$n" -q > "$work/bench.out" 2>&1 || { tail "$work/bench.out"; k4_fail "benchmark $test at $point"; }
    snap "$work/after"
    rps=$(tr '\r' '\n' < "$work/bench.out" | awk -v t="$(echo "$test" | tr a-z A-Z):" \
        '$1 == t && $3 == "requests" { v = $2 } END { print v }')
    [ -n "$rps" ] || { cat "$work/bench.out"; k4_fail "no requests/s for $test at $point"; }
    line="a11 point=$point pass=$pass test=$test requests=$n rps=$rps"
    for c in $counters; do
        d=$(( $(stat_of "$work/after.stats" "$c") - $(stat_of "$work/before.stats" "$c") ))
        line="$line $c=$d"
    done
    echo "$line"
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
bench -t set -n "$n" -q > /dev/null 2>&1
bench -t get -n "$n" -q > /dev/null 2>&1

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
stop_server
echo "a11: done"
