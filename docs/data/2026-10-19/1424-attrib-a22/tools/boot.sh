#!/usr/bin/env bash
# EXPERIMENT (exp/attrib-a22). One boot of the attribution study.
#   boot.sh LABEL KPTI MODULE_KO GUEST_CMD...      KPTI 0|1; the guest scripts of this directory are copied to the run dir (/kjit)
# Waits (0.5 s poll) for no running qemu-system-aarch64 and host load1 <= UB_MAX_LOAD (default 4), then boots through
# tests/guest/host/ub-run.sh of the worktree (rodata=off on both KPTI settings, as the UB protocol).
set -euo pipefail
label=$1 kpti=$2 ko=$3
shift 3
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export WT=${WT:-/Volumes/CaseSentitiveLocal/KJIT/.claude/worktrees/attrib-a22}
export KJIT_BUILD_ROOT=${KJIT_BUILD_ROOT:-/Volumes/CaseSentitiveLocal/KJIT/.kjit/build}
export QEMU_SSH_PORT=${QEMU_SSH_PORT:-13122} QEMU_GDB_PORT=${QEMU_GDB_PORT:-2355}
run_dir="$KJIT_BUILD_ROOT/runs/ub-$label"
mkdir -p "$run_dir"
cp "$here"/*.sh "$here"/*.pl "$run_dir/"
max_load=${UB_MAX_LOAD:-4}
t0=$(date +%s)
while true; do
    n=$({ pgrep -x qemu-system-aarch64 || true; } | wc -l | tr -d ' ')
    l=$(sysctl -n vm.loadavg | awk '{ print $2 }')
    if [[ "$n" = 0 ]] && awk -v l="$l" -v m="$max_load" 'BEGIN { exit !(l <= m) }'; then break; fi
    sleep 0.5
done
echo "boot.sh: $label start $(date '+%H:%M:%S') waited $(( $(date +%s) - t0 )) s load1 $l"
UB_APPEND_EXTRA=rodata=off UB_MODULE="$ko" UB_TIMEOUT="${UB_TIMEOUT:-5400}" "$WT/tests/guest/host/ub-run.sh" "$label" "$kpti" "$*"
