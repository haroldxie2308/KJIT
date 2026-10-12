#!/bin/bash
# A17 measurement driver: main and A17 modules interleaved, KPTI off and forced on.
cd /Volumes/CaseSentitiveLocal/KJIT/.claude/worktrees/a17
export KJIT_BUILD_ROOT=/Volumes/CaseSentitiveLocal/KJIT/.kjit/build QEMU_SSH_PORT=12022 QEMU_GDB_PORT=2343
B=$KJIT_BUILD_ROOT
L=$B/mod-a17/logs
mkdir -p $L
BOOTS=${1:-5}
for b in $(seq 1 $BOOTS); do
  for k in 0 1; do
    for m in main a17; do
      echo "boot $m k$k b$b $(date +%H:%M:%S)" >> $L/meas.progress
      UB_APPEND_EXTRA=rodata=off UB_MODULE=$B/mod-a17/$m/kjit-guest/kjit.ko tests/guest/host/ub-run.sh $m-std-k$k-b$b $k \
        'sh /opt/kjit-tests/ub-standard.sh /tmp/ubstd pinned 1000000 2 1 64 1024' >> $L/meas-$m-k$k-b$b.out 2>&1
      rc=$?
      forced=$(grep -c 'kernel page table isolation forced ON' $B/runs/ub-$m-std-k$k-b$b/serial.log)
      echo "  rc=$rc kpti_forced_lines=$forced $(date +%H:%M:%S)" >> $L/meas.progress
    done
  done
done
echo ALLDONE >> $L/meas.progress
