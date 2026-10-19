#!/usr/bin/env bash
# A23 measurement driver: KPTI-off boots first (priority), then KPTI-on boots of a23-boot.sh (states off | main = e16628d module | a23).
#   drive.sh        k0 b1-8 (4 cells, 4 reps), then k1 b1-6 (the same 4 cells, 4 reps)
# A failed boot is logged and skipped. Each boot waits for host load1 <= UB_MAX_LOAD (default 4) and no other qemu-system-aarch64.
set -uo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export WT=/Volumes/CaseSentitiveLocal/KJIT/.claude/worktrees/a23
export KJIT_BUILD_ROOT=$WT/.kjit/build
SHARED=/Volumes/CaseSentitiveLocal/KJIT/.kjit/build
export MOD_MAIN=$SHARED/mod-main-e16628d/kjit-guest/kjit.ko MOD_A23=$SHARED/mod-a23/kjit-guest/kjit.ko
export LABEL_PREFIX=a23 QEMU_SSH_PORT=13222 QEMU_GDB_PORT=2356 UB_MAX_LOAD=${UB_MAX_LOAD:-4}
CELLS="unix_get_c50_p1_d1:unix:get:1000000:50:1:1:2:0:1-3:unix unix_set_c50_p1_d1:unix:set:1000000:50:1:1:2:0:1-3:unix
unix_pingm_c50_p1:unix:ping_mbulk:1000000:50:1:1:2:0:1-3:unix get_c50_p1_d1:base:get:1000000:50:1:1:2:0:1-3:tcp"
run() { # KPTI BOOT REPS CELLS
  local kpti=$1 b=$2 reps=$3 cells=$4 label=${LABEL_PREFIX}-k$1-b$2 log st n
  "$here/a23-boot.sh" "$kpti" "$b" "$reps" $cells
  st=$?
  log=$KJIT_BUILD_ROOT/runs/ub-$label/serial.log
  n=$(grep -c 'kernel page table isolation forced ON' "$log" 2>/dev/null)
  if [[ $kpti = 1 ]]; then [[ ${n:-0} -gt 0 ]] || { echo "DRIVE: $label KPTI not forced on"; st=99; }
  else [[ ${n:-0} -eq 0 ]] || { echo "DRIVE: $label KPTI unexpectedly on"; st=98; }; fi
  grep -q '^cond: done' "$log" 2>/dev/null || { echo "DRIVE: $label did not finish"; st=97; }
  echo "DRIVE: $label status=$st $(date '+%H:%M:%S') $(grep -h 'load1_before' $KJIT_BUILD_ROOT/runs/ub-$label/host.txt)"
}
for b in 1 2 3 4 5 6 7 8; do run 0 $b 4 "$CELLS"; done
for b in 1 2 3 4 5 6; do run 1 $b 4 "$CELLS"; done
echo "DRIVE: done $(date '+%H:%M:%S')"
