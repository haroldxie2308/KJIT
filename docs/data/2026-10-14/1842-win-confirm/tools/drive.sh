#!/usr/bin/env bash
# Win-confirmation driver: interleaved k1/k0 boots of tests/guest/host/cond-sweep.sh (set custom).
#   drive.sh K1_FIRST K1_LAST K0_FIRST K0_LAST REPS
# Boot order: k1 b<f>, k0 b<f>, k1 b<f+1>, ... A boot that fails is logged and skipped.
# Environment: MODULE (main's kjit.ko, bd4ec3e), WT (worktree); the build root is the shared one.
set -uo pipefail
WT=${WT:-/Volumes/CaseSentitiveLocal/KJIT/.claude/worktrees/confirm}
export KJIT_BUILD_ROOT=/Volumes/CaseSentitiveLocal/KJIT/.kjit/build
export QEMU_SSH_PORT=13022 QEMU_GDB_PORT=2353
export UB_MODULE=${MODULE:?}
export UB_TIMEOUT=${UB_TIMEOUT:-2700}
export UB_MAX_LOAD=${UB_MAX_LOAD:-4}
reps=$5
U="1000000:50:1:1:2:0:1-3:unix"
UNIX_K1="unix_pingm_c50_p1:unix:ping_mbulk:$U unix_get_c50_p1_d1:unix:get:$U unix_set_c50_p1_d1:unix:set:$U
unix_incr_c50_p1:unix:incr:$U unix_pingi_c50_p1:unix:ping_inline:$U unix_lpush_c50_p1:unix:lpush:$U
unix_rpop_c50_p1:unix:rpop:500000:50:1:1:2:0:1-3:unix unix_sadd_c50_p1:unix:sadd:$U unix_hset_c50_p1:unix:hset:$U
unix_mset_c50_p1:unix:mset:500000:50:1:1:2:0:1-3:unix
unix_get_c50_p1_d64:unix:get:1000000:50:1:64:2:0:1-3:unix unix_get_c50_p1_d1024:unix:get:1000000:50:1:1024:2:0:1-3:unix"
TCP_K1="pingm_c50_p1:base:ping_mbulk:1000000:50:1:1:2:0:1-3:tcp get_c50_p1_d1:base:get:1000000:50:1:1:2:0:1-3:tcp"
UNIX_K0="unix_pingm_c50_p1:unix:ping_mbulk:$U unix_get_c50_p1_d1:unix:get:$U"
K1_CELLS=$(echo $UNIX_K1 $TCP_K1)
K0_CELLS=$(echo $UNIX_K0)
run() { # NAME BOOT ARGS CELLS
  local name=$1 b=$2 args=$3 cells=$4 label=cond-wc-$1-b$2 log n st
  CONDSW_FIRST=$b CONDSW_CELLS="$cells" "$WT/tests/guest/host/cond-sweep.sh" wc "$name:kjit-guest:$args" 1 custom "$reps"
  st=$?
  log=$KJIT_BUILD_ROOT/runs/ub-$label/serial.log
  n=$(grep -c 'kernel page table isolation forced ON' "$log" 2>/dev/null)
  if [[ $name == k1 ]]; then [[ ${n:-0} -gt 0 ]] || { echo "DRIVE: $label KPTI not forced on"; st=99; }
  else [[ ${n:-0} -eq 0 ]] || { echo "DRIVE: $label KPTI unexpectedly on"; st=98; }; fi
  grep -q '^cond: done' "$log" 2>/dev/null || { echo "DRIVE: $label did not finish"; st=97; }
  echo "DRIVE: $label status=$st $(date '+%H:%M:%S') $(grep -h 'load1_before' $KJIT_BUILD_ROOT/runs/ub-$label/host.txt) $(grep -h load1_after $KJIT_BUILD_ROOT/runs/ub-$label/host.txt)"
}
b1=$1; e1=$2; b0=$3; e0=$4
n=$(( e1-b1 > e0-b0 ? e1-b1 : e0-b0 ))
for ((i=0;i<=n;i++)); do
  (( b1+i <= e1 )) && run k1 $((b1+i)) kpti=1 "$K1_CELLS"
  (( b0+i <= e0 )) && run k0 $((b0+i)) "" "$K0_CELLS"
done
echo "DRIVE: all done $(date '+%H:%M:%S')"
