#!/usr/bin/env bash
# A22 measurement driver: interleaved KPTI-on and KPTI-off boots of a22-boot.sh (states off | a21 = 56bc781 module | a22 = ffb5fdc).
#   drive.sh MODE     MODE = main  : k1 b1-6 (5 cells, 3 reps), k0 b1-4 (2 cells, 3 reps), interleaved k1 b1, k0 b1, k1 b2, ...
#                      MODE = extra : k1 b7-12 (unix GET -d 1, unix PING_MBULK, 5 reps)
# A failed boot is logged and skipped. Each boot waits for host load1 <= UB_MAX_LOAD (default 4) and no other qemu-system-aarch64.
set -uo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export WT=/Volumes/CaseSentitiveLocal/KJIT/.claude/worktrees/a22-measure
export KJIT_BUILD_ROOT=$WT/.kjit/build
SHARED=/Volumes/CaseSentitiveLocal/KJIT/.kjit/build
export MOD_A21=$SHARED/mod-a21-56bc781/kjit-guest/kjit.ko MOD_A22=$SHARED/mod-a22/kjit-guest/kjit.ko
export LABEL_PREFIX=a22 QEMU_SSH_PORT=13022 QEMU_GDB_PORT=2354 UB_MAX_LOAD=${UB_MAX_LOAD:-4}
run() { # KPTI BOOT REPS CELLS
  local kpti=$1 b=$2 reps=$3 cells=$4 label=${LABEL_PREFIX}-k$1-b$2 log st n
  "$here/a22-boot.sh" "$kpti" "$b" "$reps" $cells
  st=$?
  log=$KJIT_BUILD_ROOT/runs/ub-$label/serial.log
  n=$(grep -c 'kernel page table isolation forced ON' "$log" 2>/dev/null)
  if [[ $kpti = 1 ]]; then [[ ${n:-0} -gt 0 ]] || { echo "DRIVE: $label KPTI not forced on"; st=99; }
  else [[ ${n:-0} -eq 0 ]] || { echo "DRIVE: $label KPTI unexpectedly on"; st=98; }; fi
  grep -q '^cond: done' "$log" 2>/dev/null || { echo "DRIVE: $label did not finish"; st=97; }
  echo "DRIVE: $label status=$st $(date '+%H:%M:%S') $(grep -h 'load1_before' $KJIT_BUILD_ROOT/runs/ub-$label/host.txt)"
}
case "$1" in
main)
  K1="unix_get_c50_p1_d1:unix:get:1000000:50:1:1:2:0:1-3:unix unix_set_c50_p1_d1:unix:set:1000000:50:1:1:2:0:1-3:unix
unix_pingm_c50_p1:unix:ping_mbulk:1000000:50:1:1:2:0:1-3:unix
get_c50_p1_d1:base:get:1000000:50:1:1:2:0:1-3:tcp set_c50_p1_d1:base:set:1000000:50:1:1:2:0:1-3:tcp"
  K0="unix_get_c50_p1_d1:unix:get:1000000:50:1:1:2:0:1-3:unix unix_set_c50_p1_d1:unix:set:1000000:50:1:1:2:0:1-3:unix"
  for i in 0 1 2 3 4 5; do
    (( 1+i <= 6 )) && run 1 $((1+i)) 3 "$K1"
    (( 1+i <= 4 )) && run 0 $((1+i)) 3 "$K0"
  done ;;
extra)
  K1="unix_get_c50_p1_d1:unix:get:1000000:50:1:1:2:0:1-3:unix unix_pingm_c50_p1:unix:ping_mbulk:1000000:50:1:1:2:0:1-3:unix"
  for b in 7 8 9 10 11 12; do run 1 $b 5 "$K1"; done ;;
*) echo "usage: drive.sh main|extra" >&2; exit 2 ;;
esac
echo "DRIVE: $1 done $(date '+%H:%M:%S')"
