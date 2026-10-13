#!/usr/bin/env bash
# Win-map driver: interleaved k1/k0 boots of tests/guest/host/cond-sweep.sh (set custom).
#   drive.sh K1_BOOT_FIRST K1_BOOT_LAST K0_BOOT_FIRST K0_BOOT_LAST REPS
# Boot order: k1 b1, k0 b1, k1 b2, ... A boot that fails is logged and skipped (re-run it by number later).
set -uo pipefail
WT=/Volumes/CaseSentitiveLocal/KJIT/.claude/worktrees/winmap
export KJIT_BUILD_ROOT=/Volumes/CaseSentitiveLocal/KJIT/.kjit/build
export QEMU_SSH_PORT=12722 QEMU_GDB_PORT=2350
export UB_MODULE=$KJIT_BUILD_ROOT/mod-winmap/kjit.ko
export UB_TIMEOUT=${UB_TIMEOUT:-2400}
export UB_MAX_LOAD=${UB_MAX_LOAD:-6}
reps=$3
# Extra boots: the cells nearest to zero, more boots (k1 only).
K1_CELLS=$(echo pingm_c50_p1:base:ping_mbulk:1000000:50:1:1:2:0:1-3:tcp get_c50_p1_d1:base:get:1000000:50:1:1:2:0:1-3:tcp \
  incr_c50_p1:base:incr:1000000:50:1:1:2:0:1-3:tcp \
  unix_pingm_c50_p1:unix:ping_mbulk:1000000:50:1:1:2:0:1-3:unix unix_set_c50_p1_d1:unix:set:1000000:50:1:1:2:0:1-3:unix \
  unix_get_c50_p1_d1:unix:get:1000000:50:1:1:2:0:1-3:unix unix_pingi_c50_p1:unix:ping_inline:1000000:50:1:1:2:0:1-3:unix)
run() { # NAME BOOT ARGS CELLS
  local name=$1 b=$2 args=$3 cells=$4 label=cond-wm-$1-b$2 log n
  CONDSW_FIRST=$b CONDSW_CELLS="$cells" "$WT/tests/guest/host/cond-sweep.sh" wm "$name:kjit-guest:$args" 1 custom "$reps"
  local st=$?
  log=$KJIT_BUILD_ROOT/runs/ub-$label/serial.log
  if [[ $name == k1 ]]; then
    n=$(grep -c 'kernel page table isolation forced ON' "$log" 2>/dev/null); [[ ${n:-0} -gt 0 ]] || { echo "DRIVE: $label KPTI not forced on"; st=99; }
  else
    n=$(grep -c 'kernel page table isolation forced ON' "$log" 2>/dev/null); [[ ${n:-0} -eq 0 ]] || { echo "DRIVE: $label KPTI unexpectedly on"; st=98; }
  fi
  grep -q '^cond: done' "$log" 2>/dev/null || { echo "DRIVE: $label did not finish"; st=97; }
  echo "DRIVE: $label status=$st $(date '+%H:%M:%S') $(grep -h 'load1_before' $KJIT_BUILD_ROOT/runs/ub-$label/host.txt)"
}
b1=$1; e1=$2
for ((i=b1;i<=e1;i++)); do run k1 $i kpti=1 "$K1_CELLS"; done
echo "DRIVE: all done $(date '+%H:%M:%S')"
