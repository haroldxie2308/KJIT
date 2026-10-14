#!/usr/bin/env bash
# A20 measurement driver: interleaved KPTI-on and KPTI-off boots of a20-boot.sh.
#   drive.sh K1_FIRST K1_LAST K0_FIRST K0_LAST REPS
# Boot order: k1 b<first>, k0 b<first>, k1 b<first+1>, ... A failed boot is logged and skipped.
set -uo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export WT=/Volumes/CaseSentitiveLocal/KJIT/.claude/worktrees/a20
export KJIT_BUILD_ROOT=$WT/.kjit/build
SHARED=/Volumes/CaseSentitiveLocal/KJIT/.kjit/build
export MOD_MAIN=$SHARED/mod-main-dc1b962/kjit-guest/kjit.ko MOD_A20=$SHARED/mod-a20f/kjit-guest/kjit.ko
export LABEL_PREFIX=a20f QEMU_SSH_PORT=12822 QEMU_GDB_PORT=2351 UB_MAX_LOAD=${UB_MAX_LOAD:-6}
reps=$5
K1="unix_get_c50_p1_d1:unix:get:1000000:50:1:1:2:0:1-3:unix unix_set_c50_p1_d1:unix:set:1000000:50:1:1:2:0:1-3:unix
unix_pingm_c50_p1:unix:ping_mbulk:1000000:50:1:1:2:0:1-3:unix
get_c50_p1_d1:base:get:1000000:50:1:1:2:0:1-3:tcp set_c50_p1_d1:base:set:1000000:50:1:1:2:0:1-3:tcp"
K0="unix_get_c50_p1_d1:unix:get:1000000:50:1:1:2:0:1-3:unix unix_set_c50_p1_d1:unix:set:1000000:50:1:1:2:0:1-3:unix"
run() { # KPTI BOOT CELLS
  local kpti=$1 b=$2 cells=$3 label=${LABEL_PREFIX}-k$1-b$2 log st n
  "$here/a20-boot.sh" "$kpti" "$b" "$reps" $cells
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
