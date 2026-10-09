#!/usr/bin/env bash
# Host side of the userspace-bypass comparison: wait for a quiet host, boot one
# kjit-guest and run one command in it, optionally with KPTI forced on.
#
#   ub-run.sh LABEL KPTI GUEST_CMD...      KPTI: 0 (kernel default) or 1 (kpti=1)
#
# Waits until no qemu-system-aarch64 runs (other agents' guests) and the 1-minute
# load is <= UB_MAX_LOAD (default 6), polling every 3 s, then starts
# scripts/guest-run.sh with --run-dir $KJIT_BUILD_ROOT/runs/ub-LABEL. Writes the
# wait (seconds), the load before and after the boot and the command line to
# $KJIT_BUILD_ROOT/runs/ub-LABEL/host.txt. KPTI=1 appends kpti=1 to the guest
# kernel command line (QEMU_APPEND). Environment as scripts/guest-run.sh
# (KJIT_BUILD_ROOT, GUEST_PROFILE); QEMU_SSH_PORT / QEMU_GDB_PORT should be set.
# UB_MODULE=none boots without kjit.ko (the patched kernel's hook alone).
set -euo pipefail

[[ $# -ge 3 ]] || { echo "usage: ub-run.sh LABEL KPTI GUEST_CMD..." >&2; exit 2; }
label=$1
kpti=$2
shift 2
cmd="$*"

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
build_root="${KJIT_BUILD_ROOT:-$root/.kjit/build}"
profile="${GUEST_PROFILE:-kjit-guest}"
max_load="${UB_MAX_LOAD:-6}"
run_dir="$build_root/runs/ub-$label"
base_append="console=ttyAMA0 panic=-1 nokaslr"
# UB_APPEND_EXTRA: more kernel arguments, e.g. rodata=off. This kjit-guest kernel
# (7.1-rc1, HVF on an M1) hangs silently at boot with kpti=1 right after the
# "alternatives: applying system-wide alternatives" line, where setup_system_features()
# installs the nG mappings (PC in the exception vector; 1 and 4 vCPUs; rodata=on hangs
# too, rodata=off boots). Every KPTI boot therefore needs UB_APPEND_EXTRA=rodata=off,
# and a comparison against KPTI off must use it for both.
case "$kpti" in
    0) append="$base_append" ;;
    1) append="$base_append kpti=1" ;;
    *) echo "KPTI must be 0 or 1" >&2; exit 2 ;;
esac
[[ -z "${UB_APPEND_EXTRA:-}" ]] || append="$append $UB_APPEND_EXTRA"

load1() { sysctl -n vm.loadavg | awk '{ print $2 }'; }
# pgrep exits 1 when nothing matches: that is the quiet case, not an error.
others() { { pgrep -x qemu-system-aarch64 || true; } | wc -l | tr -d ' '; }

waited=0
while true; do
    n=$(others)
    l=$(load1)
    if [[ "$n" == 0 ]] && awk -v l="$l" -v m="$max_load" 'BEGIN { exit !(l <= m) }'; then
        break
    fi
    sleep 3
    waited=$((waited + 3))
done
load_before=$(load1)

mkdir -p "$run_dir"
{
    echo "label=$label kpti=$kpti profile=$profile"
    echo "append=$append"
    echo "waited_s=$waited load1_before=$load_before"
    echo "cmd=$cmd"
} > "$run_dir/host.txt"

export QEMU_APPEND="$append"
set +e
bash "$root/scripts/guest-run.sh" --profile "$profile" --run-dir "$run_dir" --timeout "${UB_TIMEOUT:-1800}" \
    ${UB_MODULE:+--module "$UB_MODULE"} -- "$cmd" \
    > "$run_dir/guest-run.out" 2>&1
status=$?
set -e
echo "load1_after=$(load1) guest_run_status=$status" >> "$run_dir/host.txt"
tail -2 "$run_dir/guest-run.out"
exit "$status"
