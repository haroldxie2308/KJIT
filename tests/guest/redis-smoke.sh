#!/bin/sh
# K3 (f): redis smoke and data-consistency check (run by run-k3.sh, KJIT off
# and on). stdout is deterministic and must be identical in both runs:
#
#   1. start redis-server (no persistence) on $PORT;
#   2. load a deterministic dataset with redis-cli --pipe (10k strings plus
#      lists, hashes, counters and sets), print DBSIZE, DEBUG DIGEST and the
#      sha256 of every value read back with redis-cli;
#   3. redis-benchmark -n 100000 -t set,get,incr,lpush,lpop,sadd,hset -P 1 -c 4
#      under nojit (its own syscalls never reach KJIT, so the counters measure
#      the server); its keys are fixed (no -r), so the dataset after it is
#      deterministic too: print DBSIZE and DEBUG DIGEST again;
#   4. shut the server down.
#
# With STATS_DIR set, the KJIT stats and unsupported_top are copied there
# around the benchmark (bench.before/after, unsup.before/after), so run-k3.sh
# can report the server's in-kernel fraction and exit histogram.
#
#   redis-smoke.sh [requests]      default 100000
set -eu

T=/opt/kjit-tests
K=/sys/kernel/debug/kjit
PORT=${PORT:-6399}
requests=${1:-100000}
cli() { redis-cli -p "$PORT" "$@"; }

redis-server --port "$PORT" --save "" --appendonly no --daemonize no \
    --logfile redis.log > /dev/null 2>&1 &
server=$!
i=0
until [ "$(cli ping 2>/dev/null)" = PONG ]; do
    i=$((i + 1))
    [ "$i" -lt 100 ] || { echo "redis: server did not start"; exit 1; }
    sleep 0.1
done

awk 'BEGIN {
    for (i = 0; i < 10000; i++) {
        v = sprintf("v%d-", (i * 7919) % 100003)
        for (k = 0; k < i % 23; k++) v = v "x"
        printf "SET key:%05d %s\r\n", i, v
    }
    for (i = 0; i < 1000; i++) {
        printf "RPUSH list:%d item:%d\r\n", i % 10, i
        printf "HSET hash:%d f:%d %d\r\n", i % 10, i, i * i
        printf "INCRBY counter:%d %d\r\n", i % 10, i
        printf "SADD set:%d m:%d\r\n", i % 10, (i * 37) % 1000
    }
}' > load.txt
cli --pipe < load.txt > pipe.out
grep -q "errors: 0, replies: 14000" pipe.out || { cat pipe.out; exit 1; }
echo "redis load: $(tail -1 pipe.out)"

awk 'BEGIN {
    for (i = 0; i < 10000; i++) printf "GET key:%05d\n", i
    for (i = 0; i < 10; i++) {
        printf "LRANGE list:%d 0 -1\n", i
        printf "HGETALL hash:%d\n", i
        printf "GET counter:%d\n", i
        printf "SORT set:%d ALPHA\n", i
    }
}' > read.txt
cli --raw < read.txt > read.out
echo "redis read: $(wc -l < read.out) lines sha256 $(sha256sum < read.out | cut -d' ' -f1)"
echo "redis dbsize $(cli dbsize) digest $(cli debug digest)"

[ -z "${STATS_DIR:-}" ] || { cp "$K/stats" "$STATS_DIR/bench.before"; cp "$K/unsupported_top" "$STATS_DIR/unsup.before"; }
set +e
"$T/nojit" redis-benchmark -p "$PORT" -n "$requests" -t set,get,incr,lpush,lpop,sadd,hset \
    -P 1 -c 4 -q > bench.out 2>&1
status=$?
set -e
[ -z "${STATS_DIR:-}" ] || { cp "$K/stats" "$STATS_DIR/bench.after"; cp "$K/unsupported_top" "$STATS_DIR/unsup.after"; }
echo "redis benchmark exit=$status"
tr '\r' '\n' < bench.out | grep "requests per second" | sed 's/^/redis-bench: /' >&2
echo "redis after benchmark: dbsize $(cli dbsize) digest $(cli debug digest)"
echo "redis counter $(cli get counter:__rand_int__) myset $(cli scard myset) myhash $(cli hlen myhash)"

cli shutdown nosave > /dev/null 2>&1 || true
wait "$server" || true
echo "redis stopped"
