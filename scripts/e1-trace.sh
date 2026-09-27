#!/usr/bin/env bash
# E1 dynamic trace driver: build the tracer image, trace redis-server under
# load inside a linux/arm64 container, then run the offline e1-report on the
# host. Outputs land in $E1_OUT (default tmp/e1/).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
E1_OUT="${E1_OUT:-$ROOT/tmp/e1}"
E1_IMAGE="${E1_IMAGE:-kjit-e1-trace}"
# Workload knobs; defaults match the M3 brief.
E1_N="${E1_N:-20000}"
E1_CLIENTS="${E1_CLIENTS:-4}"
E1_TESTS="${E1_TESTS:-get,set,incr,lpush,lpop}"
# No SVE: glibc ifuncs would otherwise pick SVE string routines that the
# target cores (and Apple hosts) do not run.
E1_CPU="${E1_CPU:-neoverse-n1}"
# clock_gettime, clock_getres, gettimeofday: vDSO calls on native arm64,
# real SVCs under QEMU 7.2 linux-user. They are counted but do not end a gap.
E1_ELIDE="${E1_ELIDE:-113:114:169}"

mkdir -p "$E1_OUT"
E1_OUT="$(cd "$E1_OUT" && pwd)"

docker build --platform linux/arm64 -t "$E1_IMAGE" "$ROOT/tools/e1-trace"

docker run --rm --platform linux/arm64 \
    -v "$ROOT/tools/e1-trace:/e1:ro" \
    -v "$E1_OUT:/out" \
    -e OUT=/out -e E1_N="$E1_N" -e E1_CLIENTS="$E1_CLIENTS" -e E1_TESTS="$E1_TESTS" \
    -e E1_CPU="$E1_CPU" -e E1_ELIDE="$E1_ELIDE" \
    "$E1_IMAGE" bash /e1/run-in-container.sh

cargo run --release --manifest-path "$ROOT/harness/Cargo.toml" --bin e1-report -- \
    "$E1_OUT/trace.txt" "$E1_OUT"
