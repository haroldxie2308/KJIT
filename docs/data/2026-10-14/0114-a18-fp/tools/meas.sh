#!/bin/bash
# A18 measurement driver: the main (8483b2c) and A18 modules interleaved, KPTI forced on.
#   1. ub-standard.sh (UB protocol): -d 1 and 1024, SET and GET, 1 M requests, 2 reps, pinned.
#   2. cond-sweep.sh (guest side of exp/conditions, one server profile added: aof_unix):
#      redis with appendonly yes, appendfsync always, unix socket, SET, -c 50 -P 1, and for
#      reference the same over TCP and the unix socket without AOF.
# Per boot b: main std, a18 std, main aof, a18 aof. Both modules run on the same kernel and rootfs.
cd /Volumes/CaseSentitiveLocal/KJIT/.claude/worktrees/a18
export KJIT_BUILD_ROOT=/Volumes/CaseSentitiveLocal/KJIT/.kjit/build-a18 QEMU_SSH_PORT=12322 QEMU_GDB_PORT=2346 UB_MAX_LOAD=9
MOD=/Volumes/CaseSentitiveLocal/KJIT/.kjit/build/mod-a18
L=$KJIT_BUILD_ROOT/meas-logs
mkdir -p $L
BOOTS=${1:-3}
CELLS="aofunix_set_c50_p1:aof_unix:set:300000:50:1:1:2:0:1-3:unix aofalw_set_c50_p1:aof_always:set:300000:50:1:1:2:0:1-3:tcp unix_set_c50_p1:unix:set:300000:50:1:1:2:0:1-3:unix"
ko() { # module -> path
  if [ "$1" = main ]; then echo $MOD/main/kjit-guest/kjit.ko; else echo $MOD/kjit-guest/kjit.ko; fi
}
for b in $(seq 1 $BOOTS); do
  for m in main a18; do
    echo "std $m k1 b$b $(date +%H:%M:%S)" >> $L/meas.progress
    UB_APPEND_EXTRA=rodata=off UB_MODULE=$(ko $m) tests/guest/host/ub-run.sh $m-std-k1-b$b 1 \
      'sh /opt/kjit-tests/ub-standard.sh /tmp/ubstd pinned 1000000 2 1 1024' >> $L/meas-std-$m-b$b.out 2>&1
    rc=$?
    forced=$(grep -c 'kernel page table isolation forced ON' $KJIT_BUILD_ROOT/runs/ub-$m-std-k1-b$b/serial.log)
    echo "  rc=$rc kpti_forced_lines=$forced $(date +%H:%M:%S)" >> $L/meas.progress
  done
  for m in main a18; do
    echo "aof $m k1 b$b $(date +%H:%M:%S)" >> $L/meas.progress
    CONDSW_FIRST=$b CONDSW_CELLS="$CELLS" UB_MODULE=$(ko $m) tests/guest/host/cond-sweep.sh $m k1:kjit-guest:kpti=1 1 custom 2 \
      >> $L/meas-aof-$m-b$b.out 2>&1
    rc=$?
    forced=$(grep -c 'kernel page table isolation forced ON' $KJIT_BUILD_ROOT/runs/ub-cond-$m-k1-b$b/serial.log)
    echo "  rc=$rc kpti_forced_lines=$forced $(date +%H:%M:%S)" >> $L/meas.progress
  done
done
echo ALLDONE >> $L/meas.progress
