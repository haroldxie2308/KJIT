#!/usr/bin/env bash
set -euo pipefail

# Boot a kjit-guest kernel with the Debian initramfs under QEMU (HVF/KVM,
# -cpu host), load that profile's kjit.ko, run one shell command, power off.
# Runs on the host. Fails unless the guest reports "kjit-init: run exit=0",
# hardware PAN was detected (K1), and the kernel log has no BUG/WARNING/oops.

# shellcheck disable=SC1091
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/kjit-env.sh"

profile=kjit-guest
module=""
run_dir=""
timeout_s=600
cmd=""

usage() {
    cat <<EOF
Usage: $(basename "$0") [options] -- '<shell command>'

Options:
  --profile <name>   kjit-guest (default) or kjit-guest-debug
  --module <path>    kjit.ko to load (default: <build>/kjit-module/kjit.ko); "none" skips it
  --run-dir <dir>    9p-shared run directory (default: new dir under \$KJIT_BUILD_ROOT/runs)
  --timeout <sec>    kill QEMU after this many seconds (default: $timeout_s)

The command runs in the guest as /kjit/kjit-run.sh with /kjit (the run
directory) as working directory. The serial log is <run-dir>/serial.log.
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --profile) profile="$2"; shift 2 ;;
        --module) module="$2"; shift 2 ;;
        --run-dir) run_dir="$2"; shift 2 ;;
        --timeout) timeout_s="$2"; shift 2 ;;
        --help) usage; exit 0 ;;
        --) shift; cmd="$*"; break ;;
        *) echo "Unknown option: $1" >&2; usage >&2; exit 1 ;;
    esac
done

if [[ -z "$cmd" ]]; then
    usage >&2
    exit 2
fi

build_dir="$KJIT_BUILD_ROOT/$profile"
kernel="$build_dir/arch/arm64/boot/Image"
rootfs="$KJIT_BUILD_ROOT/guest-rootfs/rootfs.cpio"
[[ -n "$module" ]] || module="$build_dir/kjit-module/kjit.ko"

if [[ ! -f "$kernel" ]]; then
    echo "Missing $kernel; run make guest-kernel (profile $profile) in the dev container." >&2
    exit 1
fi
if [[ ! -f "$rootfs" ]]; then
    echo "Missing $rootfs; run make guest-rootfs." >&2
    exit 1
fi
if [[ "$module" != "none" && ! -f "$module" ]]; then
    echo "Missing $module; build kjit.ko against $build_dir or pass --module none." >&2
    exit 1
fi

if [[ -z "$run_dir" ]]; then
    run_dir="$KJIT_BUILD_ROOT/runs/$profile-$(date +%Y%m%d-%H%M%S)"
fi
mkdir -p "$run_dir/qemu"
run_dir="$(cd "$run_dir" && pwd)"
rm -f "$run_dir/kjit.ko"
if [[ "$module" != "none" ]]; then
    cp "$module" "$run_dir/kjit.ko"
fi
printf '#!/bin/sh\nset -e\n%s\n' "$cmd" > "$run_dir/kjit-run.sh"

log="$run_dir/serial.log"
export QEMU_KERNEL_IMAGE="$kernel"
export QEMU_INITRAMFS="$rootfs"
export QEMU_SHARE_DIR="$run_dir"
export QEMU_STATE_DIR="$run_dir/qemu"
export QEMU_QMP_SOCKET="$QEMU_STATE_DIR/qmp.sock"
export QEMU_PID_FILE="$QEMU_STATE_DIR/qemu.pid"
export QEMU_USER_NET=0

echo "guest-run: profile=$profile run-dir=$run_dir"
timed_out="$run_dir/qemu/timed-out"
rm -f "$timed_out" "$QEMU_PID_FILE"
(
    sleep "$timeout_s"
    touch "$timed_out"
    kill "$(cat "$QEMU_PID_FILE")"
) 2>/dev/null &
watchdog=$!

# -no-reboot turns a guest panic (panic=-1) into a QEMU exit instead of a loop.
set +e
bash "$ROOT_DIR/scripts/qemu-run.sh" -- -no-reboot -device virtio-rng-pci \
    </dev/null 2>&1 | tee "$log"
qemu_status=${PIPESTATUS[0]}
set -e
pkill -P "$watchdog" 2>/dev/null || true
kill "$watchdog" 2>/dev/null || true
wait "$watchdog" 2>/dev/null || true

failures=()
[[ ! -f "$timed_out" ]] || failures+=("QEMU killed after ${timeout_s}s")
[[ "$qemu_status" == 0 ]] || failures+=("QEMU exited with status $qemu_status")
grep -q 'kjit-init: run exit=0' "$log" || failures+=("guest did not report 'kjit-init: run exit=0'")
grep -q 'CPU features: detected: Privileged Access Never' "$log" \
    || failures+=("hardware PAN not detected (K1 invariant)")
# Kernel lines carry a printk timestamp (PRINTK_TIME); user output (e.g. redis
# "WARNING:" lines) does not, so only kernel reports match.
# RCU stalls print "rcu: INFO: rcu_preempt detected stalls ..." (or
# "self-detected stall").
splat_re='^\[ *[0-9]+\.[0-9]+\] .*(BUG:|WARNING:|Oops|Kernel panic|Call trace:|INFO: (possible|inconsistent|trying|task)|detected stall)'
if grep -Eq "$splat_re" "$log"; then
    failures+=("kernel reported a BUG/WARNING/oops:")
    while IFS= read -r line; do failures+=("  $line"); done < <(grep -E "$splat_re" "$log" | head -20)
fi

if [[ ${#failures[@]} -gt 0 ]]; then
    echo "guest-run: FAIL ($log)" >&2
    printf '  %s\n' "${failures[@]}" >&2
    exit 1
fi
echo "guest-run: PASS ($log)"
