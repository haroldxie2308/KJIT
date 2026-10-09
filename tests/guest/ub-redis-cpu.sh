#!/bin/sh
# Where the redis server's CPU time goes per request, KJIT off and on (inside the
# kjit-guest): user and system ticks of the server process (/proc/PID/stat) over one
# redis-benchmark run, plus the KJIT counter deltas. With KJIT on the fragments run
# at EL1, so the time they replace shows up as system time.
#
#   ub-redis-cpu.sh WORKDIR REQUESTS POINT...     POINT: off | chain_budget (1..65536)
#
# One line per run: "cpu point=<p> test=<set|get> requests=<n> rps=<r> utime_ticks=<u>
# stime_ticks=<s> clk_tck=<hz> hook_calls=.. syscalls_in_kernel=..
# fragment_entries=..". Ticks come from the kernel's tick accounting (CONFIG_HZ=250,
# reported in USER_HZ units of 10 ms), a sampling estimate: use many requests.
# A11_BENCH_ARGS as in a11-baseline.sh.
set -eu

. /opt/kjit-tests/k4-lib.sh

[ $# -ge 3 ] || { echo "usage: ub-redis-cpu.sh WORKDIR REQUESTS POINT..." >&2; exit 2; }
work=$1
n=$2
shift 2
points="$*"

mkdir -p "$work"
cd "$work"
k4_debugfs
orig_budget=$(cat "$K/chain_budget")
trap 'echo "$orig_budget" > "$K/chain_budget"; set_mode 0' EXIT

set_point() {
    if [ "$1" = off ]; then
        set_mode 0
        return
    fi
    echo "$1" > "$K/chain_budget"
    [ "$(cat "$K/chain_budget")" = "$1" ] || k4_fail "chain_budget did not become $1"
    set_mode 1
}

set -- $points
set_point "$1"
start_server "$work/srv"
# shellcheck disable=SC2086  # A11_BENCH_ARGS is a word list by contract
bench -t set -n 200000 -q ${A11_BENCH_ARGS:-} > /dev/null 2>&1
# shellcheck disable=SC2086
bench -t get -n 200000 -q ${A11_BENCH_ARGS:-} > /dev/null 2>&1

ticks() { awk '{ print $14, $15 }' "/proc/$server/stat"; }   # utime stime
clk=$(getconf CLK_TCK)

for p in $points; do
    set_point "$p"
    for test in set get; do
        snap "$work/before"
        set -- $(ticks)
        u0=$1 s0=$2
        # shellcheck disable=SC2086
        bench -t "$test" -n "$n" -q ${A11_BENCH_ARGS:-} > "$work/bench.out" 2>&1 || k4_fail "benchmark $test at $p"
        set -- $(ticks)
        u1=$1 s1=$2
        snap "$work/after"
        rps=$(tr '\r' '\n' < "$work/bench.out" | awk -v t="$(echo "$test" | tr a-z A-Z):" \
            '$1 == t && $3 == "requests" { v = $2 } END { print v }')
        [ -n "$rps" ] || k4_fail "no requests/s for $test at $p"
        line="cpu point=$p test=$test requests=$n rps=$rps utime_ticks=$((u1 - u0)) stime_ticks=$((s1 - s0)) clk_tck=$clk"
        for c in hook_calls syscalls_in_kernel fragment_entries; do
            line="$line $c=$(( $(stat_of "$work/after.stats" "$c") - $(stat_of "$work/before.stats" "$c") ))"
        done
        echo "$line"
    done
done
set_mode 0
stop_server
echo "ub-redis-cpu: done"
