#!/usr/bin/env bash
set -euo pipefail

# E0 baseline (M2): build tools/e0/syscall_bench.c as a static aarch64 binary
# in the dev image, then run it (1) in a plain Docker container on the host's
# Linux VM, with and without Docker's seccomp filter, and (2) in the kjit-guest
# under QEMU, without kjit.ko. Each run also
# records the kernel, CPU features and /sys/devices/system/cpu/vulnerabilities.
# Runs on the host.

# shellcheck disable=SC1091
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/kjit-env.sh"

require_cmd docker

profile=kjit-guest
dev_image="${DOCKER_IMAGE:-kjit-dev:latest}"
docker_image="${KJIT_GUEST_BASE_IMAGE:-debian:bookworm}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --profile) profile="$2"; shift 2 ;;
        *) echo "Usage: $(basename "$0") [--profile kjit-guest|kjit-guest-debug]" >&2; exit 1 ;;
    esac
done

out="$KJIT_BUILD_ROOT/e0/$profile-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$out"

docker run --rm --user "$(id -u):$(id -g)" \
    -v "$ROOT_DIR/tools/e0:/src:ro" -v "$out:/out" "$dev_image" \
    cc -O2 -static -Wall -Werror -o /out/syscall_bench /src/syscall_bench.c

# Shared by both environments; runs from the directory holding syscall_bench.
cat > "$out/e0-report.sh" <<'EOF'
echo "e0: kernel $(uname -r) $(uname -v)"
echo "e0: cpus $(nproc) $(grep -m1 -E '^Features' /proc/cpuinfo)"
grep -E '^CPU (implementer|part)' /proc/cpuinfo | sort -u | sed 's/^/e0: /'
for f in /sys/devices/system/cpu/vulnerabilities/*; do
    echo "e0: vuln $(basename "$f"): $(cat "$f")"
done
./syscall_bench
EOF

# Docker's default seccomp filter runs on every syscall; the unconfined run
# separates that cost from the kernel's own entry/exit cost.
echo "== E0 in Docker ($docker_image)"
docker run --rm --platform linux/arm64 -v "$out:/e0" -w /e0 "$docker_image" \
    sh ./e0-report.sh 2>&1 | tee "$out/docker.txt"
echo "== E0 in Docker, seccomp=unconfined"
docker run --rm --platform linux/arm64 --security-opt seccomp=unconfined \
    -v "$out:/e0" -w /e0 "$docker_image" \
    sh ./e0-report.sh 2>&1 | tee "$out/docker-unconfined.txt"

echo "== E0 in $profile (QEMU)"
bash "$ROOT_DIR/scripts/guest-run.sh" --profile "$profile" --module none \
    --run-dir "$out" -- "sh ./e0-report.sh"
grep -a '^e0:' "$out/serial.log" | tr -d '\r' > "$out/guest.txt"

echo "== E0 summary ($out)"
for env in docker docker-unconfined guest; do
    grep -E '^e0: (kernel|getppid|write_devnull|pipe_pingpong)' "$out/$env.txt" | sed "s/^/$env /"
done
