#!/bin/sh
# K4 (2): redis-benchmark against redis-server under the auto mode (inside the
# kjit-guest, kjit.ko loaded).
#
#   k4-bench.sh WORKDIR [requests]      requests per test, default 100000
#
# 1. Throughput and KJIT counters, KJIT on (auto): one server, three runs of
#    the full default test set (redis-benchmark -q -n N, 50 clients):
#      default     -q -n N
#      pipelined   -q -n N -P 16
#      clients256  -q -n N -c 256 (the default is already 50 clients)
#    Per run: requests/s per test, and the counter deltas (in-kernel syscall
#    fraction, fragment entries, exits, top stopping words). redis-benchmark
#    runs under nojit, so the deltas are the server's.
# 2. Consistency, KJIT off and on: a fresh server, the deterministic dataset,
#    the full default test set pipelined (-P 16; fixed keys, so the resulting
#    dataset depends only on the request counts), then DBSIZE, DEBUG DIGEST
#    and the sha256 of the dataset read back with redis-cli. Must be identical.
set -eu

. /opt/kjit-tests/k4-lib.sh

work=${1:?usage: k4-bench.sh WORKDIR [requests]}
n=${2:-100000}
mkdir -p "$work"
cd "$work"
k4_debugfs

# phase NAME ARGS...: one full benchmark run with counters.
phase() {
    local name=$1
    shift
    snap "$work/$name.before"
    bench -q -n "$n" "$@" > "$work/$name.out" 2>&1 || { tail "$work/$name.out"; k4_fail "benchmark $name"; }
    snap "$work/$name.after"
    echo "k4-bench: $name (redis-benchmark -q -n $n $*):"
    # -q prints "\r" progress lines; keep the final "requests per second" ones.
    tr '\r' '\n' < "$work/$name.out" | grep "requests per second" | sed 's/^/k4:     /'
    [ "$(tr '\r' '\n' < "$work/$name.out" | grep -c "requests per second")" -ge 20 ] \
        || k4_fail "benchmark $name: fewer results than the default test set"
    report "$name" "$work/$name.before" "$work/$name.after"
    hot_check "$name" "$work/$name.before"
}

set_mode 1
K4_MODE=1
start_server "$work/srv"
phase default
phase pipelined -P 16
phase clients256 -c 256
stop_server

# Read-back of the whole dataset: every key, its type-specific content.
readback() {
    awk 'BEGIN {
        for (i = 0; i < 10000; i++) printf "GET key:%05d\n", i
        for (i = 0; i < 10; i++) {
            printf "LRANGE list:%d 0 -1\n", i
            printf "HGETALL hash:%d\n", i
            printf "GET counter:%d\n", i
            printf "SORT set:%d ALPHA\n", i
        }
        print "GET key:__rand_int__"
        print "GET counter:__rand_int__"
        print "LLEN mylist"
        print "LRANGE mylist 0 9"
        print "HGETALL myhash"
        print "SMEMBERS myset"
        print "ZRANGE myzset 0 -1 WITHSCORES"
    }' | cli --raw | sha256sum | cut -d' ' -f1
}

for mode in 0 1; do
    set_mode "$mode"
    K4_MODE=$mode
    rm -rf "$work/c$mode"
    start_server "$work/c$mode"
    load_dataset
    bench -q -n "$n" -P 16 > "$work/c$mode.bench" 2>&1 || k4_fail "consistency benchmark (KJIT $mode)"
    { digest; echo "readback sha256 $(readback)"; } > "$work/c$mode.out"
    stop_server
done
set_mode 0
if ! cmp -s "$work/c0.out" "$work/c1.out"; then
    diff "$work/c0.out" "$work/c1.out"
    k4_fail "consistency: dataset differs with KJIT off/on"
fi
echo "k4-bench: consistency PASS: $(tr '\n' ' ' < "$work/c1.out")"
echo "k4-bench: ALL PASS"
