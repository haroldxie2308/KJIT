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
reps=$5
BASE="set_c50_p1_d1:base:set:1000000:50:1:1:2:0:1-3:tcp get_c50_p1_d1:base:get:1000000:50:1:1:2:0:1-3:tcp
set_c50_p1_d1024:base:set:1000000:50:1:1024:2:0:1-3:tcp get_c50_p1_d1024:base:get:1000000:50:1:1024:2:0:1-3:tcp
set_c10_p1_d1:base:set:300000:10:1:1:2:0:1-3:tcp get_c10_p1_d1:base:get:300000:10:1:1:2:0:1-3:tcp
set_c1_p1_d1:base:set:100000:1:1:1:0:0:1-3:tcp get_c1_p1_d1:base:get:100000:1:1:1:0:0:1-3:tcp"
EXTRA_K1="incr_c50_p1:base:incr:1000000:50:1:1:2:0:1-3:tcp pingi_c50_p1:base:ping_inline:1000000:50:1:1:2:0:1-3:tcp
pingm_c50_p1:base:ping_mbulk:1000000:50:1:1:2:0:1-3:tcp get_c50_p4_d1:base:get:1000000:50:4:1:2:0:1-3:tcp
get_c50_p16_d1:base:get:2000000:50:16:1:2:0:1-3:tcp set_c50_p16_d1:base:set:2000000:50:16:1:2:0:1-3:tcp"
UNIX_K1="unix_get_c50_p1_d1:unix:get:1000000:50:1:1:2:0:1-3:unix unix_set_c50_p1_d1:unix:set:1000000:50:1:1:2:0:1-3:unix
unix_incr_c50_p1:unix:incr:1000000:50:1:1:2:0:1-3:unix unix_pingi_c50_p1:unix:ping_inline:1000000:50:1:1:2:0:1-3:unix
unix_pingm_c50_p1:unix:ping_mbulk:1000000:50:1:1:2:0:1-3:unix unix_get_c50_p1_d1024:unix:get:1000000:50:1:1024:2:0:1-3:unix
unix_set_c50_p1_d1024:unix:set:1000000:50:1:1024:2:0:1-3:unix
unix_get_c10_p1_d1:unix:get:300000:10:1:1:2:0:1-3:unix unix_set_c10_p1_d1:unix:set:300000:10:1:1:2:0:1-3:unix
unix_get_c1_p1_d1:unix:get:100000:1:1:1:0:0:1-3:unix unix_set_c1_p1_d1:unix:set:100000:1:1:1:0:0:1-3:unix
unix_get_c50_p4_d1:unix:get:1000000:50:4:1:2:0:1-3:unix"
UNIX_K0="unix_get_c50_p1_d1:unix:get:1000000:50:1:1:2:0:1-3:unix unix_set_c50_p1_d1:unix:set:1000000:50:1:1:2:0:1-3:unix"
AOF="aofalw_set_c50_p1:aof_always:set:300000:50:1:1:2:0:1-3:tcp
aofalw_unix_set_c50_p1:aof_always_unix:set:300000:50:1:1:2:0:1-3:unix"
K1_CELLS=$(echo $BASE $EXTRA_K1 $UNIX_K1 $AOF)
K0_CELLS=$(echo $BASE $UNIX_K0 $AOF)
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
b1=$1; e1=$2; b0=$3; e0=$4
n=$(( e1-b1 > e0-b0 ? e1-b1 : e0-b0 ))
for ((i=0;i<=n;i++)); do
  (( b1+i <= e1 )) && run k1 $((b1+i)) kpti=1 "$K1_CELLS"
  (( b0+i <= e0 )) && run k0 $((b0+i)) "" "$K0_CELLS"
done
echo "DRIVE: all done $(date '+%H:%M:%S')"
