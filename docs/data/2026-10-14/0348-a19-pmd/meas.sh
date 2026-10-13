#!/bin/bash
# A19 measurement driver: A17 (main) and A19 modules interleaved on the A19 kernel, KPTI off and forced on.
# Driver root = the A17 source tree, whose ub-run.sh carries the claim/poll option of the c1 worktree (the stock one starves against 0.2 s pollers).
cd /Volumes/CaseSentitiveLocal/KJIT/.kjit/build-a19/src-a17
export KJIT_BUILD_ROOT=/Volumes/CaseSentitiveLocal/KJIT/.kjit/build-a19 QEMU_SSH_PORT=12622 QEMU_GDB_PORT=2349 UB_POLL=0.5 UB_CLAIM_BIN=/Volumes/CaseSentitiveLocal/KJIT/.kjit/build-a19/claim/qemu-system-aarch64 UB_CLAIM_CONFIRM=2.5
B=$KJIT_BUILD_ROOT
L=$B/logs
BOOTS=${1:-4}
for b in $(seq 1 $BOOTS); do
  for k in 0 1; do
    for m in a17 a19; do
      if [ $m = a17 ]; then ko=$B/mod-a17/kjit-guest/kjit.ko; else ko=$B/kjit-guest/kjit-module/kjit.ko; fi
      echo "boot $m k$k b$b $(date +%H:%M:%S)" >> $L/meas.progress
      UB_APPEND_EXTRA=rodata=off UB_MODULE=$ko tests/guest/host/ub-run.sh $m-std-k$k-b$b $k \
        'sh /opt/kjit-tests/ub-standard.sh /tmp/ubstd pinned 500000 6 1 1024' >> $L/meas-$m-k$k-b$b.out 2>&1
      rc=$?
      forced=$(grep -c 'kernel page table isolation forced ON' $B/runs/ub-$m-std-k$k-b$b/serial.log)
      echo "  rc=$rc kpti_forced_lines=$forced $(date +%H:%M:%S)" >> $L/meas.progress
    done
  done
done
echo ALLDONE >> $L/meas.progress
