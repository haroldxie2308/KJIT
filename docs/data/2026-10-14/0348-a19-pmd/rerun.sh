#!/bin/bash
cd /Volumes/CaseSentitiveLocal/KJIT/.kjit/build-a19/src-a17
export KJIT_BUILD_ROOT=/Volumes/CaseSentitiveLocal/KJIT/.kjit/build-a19 QEMU_SSH_PORT=12622 QEMU_GDB_PORT=2349 UB_POLL=0.5 UB_CLAIM_BIN=/Volumes/CaseSentitiveLocal/KJIT/.kjit/build-a19/claim/qemu-system-aarch64 UB_CLAIM_CONFIRM=2.5
B=$KJIT_BUILD_ROOT; L=$B/logs
until grep -q ALLDONE $L/c1.progress 2>/dev/null; do sleep 20; done
echo "rerun a17 k1 b1 $(date +%H:%M:%S)" >> $L/meas.progress
UB_APPEND_EXTRA=rodata=off UB_MODULE=$B/mod-a17/kjit-guest/kjit.ko tests/guest/host/ub-run.sh a17-std-k1-b1 1 'sh /opt/kjit-tests/ub-standard.sh /tmp/ubstd pinned 500000 6 1 1024' >> $L/meas-a17-k1-b1-rerun.out 2>&1
echo "  rerun rc=$? kpti_forced_lines=$(grep -c 'kernel page table isolation forced ON' $B/runs/ub-a17-std-k1-b1/serial.log) $(date +%H:%M:%S)" >> $L/meas.progress
echo RERUNDONE >> $L/meas.progress
