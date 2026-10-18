#!/usr/bin/env bash
# A21 extra boots (KPTI on only): the two unix cells that decide the win, more reps, boots numbered after the main sweep.
#   drive.sh K1_FIRST K1_LAST K0_FIRST K0_LAST REPS
# Boot order: k1 b<first>, k0 b<first>, k1 b<first+1>, ... A failed boot is logged and skipped.
set -uo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export WT=/Volumes/CaseSentitiveLocal/KJIT/.claude/worktrees/a21
export KJIT_BUILD_ROOT=$WT/.kjit/build
SHARED=/Volumes/CaseSentitiveLocal/KJIT/.kjit/build
export MOD_MAIN=$SHARED/mod-main-88c635a/kjit-guest/kjit.ko MOD_A21=$SHARED/mod-a21/kjit-guest/kjit.ko
export LABEL_PREFIX=a21 QEMU_SSH_PORT=13222 QEMU_GDB_PORT=2381 UB_MAX_LOAD=${UB_MAX_LOAD:-6}
reps=$5
K1="unix_get_c50_p1_d1:unix:get:1000000:50:1:1:2:0:1-3:unix unix_pingm_c50_p1:unix:ping_mbulk:1000000:50:1:1:2:0:1-3:unix"
K0="unix_get_c50_p1_d1:unix:get:1000000:50:1:1:2:0:1-3:unix unix_set_c50_p1_d1:unix:set:1000000:50:1:1:2:0:1-3:unix"
run() { # KPTI BOOT CELLS
  local kpti=$1 b=$2 cells=$3 label=${LABEL_PREFIX}-k$1-b$2 log st n
  "$here/a21-boot.sh" "$kpti" "$b" "$reps" $cells
  st=$?
  log=$KJIT_BUILD_ROOT/runs/ub-$label/serial.log
  n=$(grep -c 'kernel page table isolation forced ON' "$log" 2>/dev/null)
  if [[ $kpti = 1 ]]; then [[ ${n:-0} -gt 0 ]] || { echo "DRIVE: $label KPTI not forced on"; st=99; }
  else [[ ${n:-0} -eq 0 ]] || { echo "DRIVE: $label KPTI unexpectedly on"; st=98; }; fi
  grep -q '^cond: done' "$log" 2>/dev/null || { echo "DRIVE: $label did not finish"; st=97; }
  echo "DRIVE: $label status=$st $(date '+%H:%M:%S') $(grep -h 'load1_before' $KJIT_BUILD_ROOT/runs/ub-$label/host.txt)"
}
b1=$1; e1=$2; b0=$3; e0=$4
n=$(( e1-b1 > e0-b0 ? e1-b1 : e0-b0 ))
for ((i=0;i<=n;i++)); do
  (( b1+i <= e1 )) && run 1 $((b1+i)) "$K1"
  (( b0+i <= e0 )) && run 0 $((b0+i)) "$K0"
done
echo "DRIVE: all done $(date '+%H:%M:%S')"
