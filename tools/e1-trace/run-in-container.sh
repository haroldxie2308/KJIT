#!/usr/bin/env bash
# Runs inside the kjit-e1-trace container (see Dockerfile). Builds the plugin,
# runs redis-server under qemu-aarch64 + plugin, drives it with a native
# redis-benchmark, shuts it down and leaves trace.txt + run-meta.txt in $OUT.
set -euo pipefail

: "${OUT:?OUT must name the output directory}"
: "${E1_N:?E1_N (requests per benchmark test) must be set}"
: "${E1_CLIENTS:?E1_CLIENTS must be set}"
: "${E1_TESTS:?E1_TESTS must be set}"
: "${E1_CPU:?E1_CPU (qemu -cpu model) must be set}"
: "${E1_ELIDE:?E1_ELIDE (colon-separated syscall nrs) must be set}"

SRC="$(cd "$(dirname "$0")" && pwd)"
PORT=6379
PLUGIN=/tmp/libkjittrace.so
mkdir -p "$OUT"
rm -f "$OUT/trace.txt"

gcc -O2 -Wall -Wextra -Werror -Wno-unused-parameter -shared -fPIC \
    -I/opt/qemu-plugin -o "$PLUGIN" "$SRC/kjit_trace.c" -lpthread

now() { date +%s.%N; }

t_start=$(now)
qemu-aarch64 -cpu "$E1_CPU" \
    -plugin "$PLUGIN,out=$OUT/trace.txt,elide=$E1_ELIDE" \
    /usr/local/bin/redis-server --port "$PORT" --save "" --appendonly no \
    --daemonize no --loglevel warning &
qemu_pid=$!

ready=0
for _ in $(seq 1 600); do
    if ! kill -0 "$qemu_pid" 2>/dev/null; then
        echo "redis-server under qemu exited before becoming ready" >&2
        wait "$qemu_pid" || true
        exit 1
    fi
    if [ "$(redis-cli -p "$PORT" ping 2>/dev/null)" = "PONG" ]; then
        ready=1
        break
    fi
    sleep 0.2
done
[ "$ready" = 1 ] || { echo "redis-server not ready after 120s" >&2; kill "$qemu_pid"; exit 1; }
t_ready=$(now)

redis-benchmark -p "$PORT" -t "$E1_TESTS" -n "$E1_N" -c "$E1_CLIENTS" -P 1 -q \
    | tr '\r' '\n' | grep 'requests per second' > "$OUT/benchmark.txt"
t_bench=$(now)

redis-cli -p "$PORT" shutdown nosave
if ! wait "$qemu_pid"; then
    echo "redis-server under qemu exited non-zero" >&2
    exit 1
fi
t_end=$(now)

tail -n 1 "$OUT/trace.txt" | grep -qx 'E' || { echo "trace.txt is truncated (no end marker)" >&2; exit 1; }

cat > "$OUT/run-meta.txt" <<EOF
qemu_user_version: $(dpkg-query -W -f='${Version}' qemu-user)
qemu_plugin_header_source_version: $(cat /opt/qemu-plugin/SOURCE_VERSION)
redis_server: $(redis-server --version)
glibc: $(dpkg-query -W -f='${Version}' libc6)
cpu_model: $E1_CPU
elided_syscalls: $E1_ELIDE
benchmark: redis-benchmark -t $E1_TESTS -n $E1_N -c $E1_CLIENTS -P 1
startup_to_ready_s: $(awk "BEGIN{printf \"%.1f\", $t_ready - $t_start}")
benchmark_s: $(awk "BEGIN{printf \"%.1f\", $t_bench - $t_ready}")
shutdown_and_dump_s: $(awk "BEGIN{printf \"%.1f\", $t_end - $t_bench}")
total_traced_s: $(awk "BEGIN{printf \"%.1f\", $t_end - $t_start}")
trace_bytes: $(stat -c %s "$OUT/trace.txt")
EOF
cat "$OUT/run-meta.txt"
cat "$OUT/benchmark.txt"
