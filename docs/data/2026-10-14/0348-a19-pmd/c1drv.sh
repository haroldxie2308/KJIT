#!/bin/bash
# A19 low-client-count measurement (coordinator addendum): c1-sweep.sh of exp/c1, A17 and A19 modules interleaved, KPTI off.
cd /Volumes/CaseSentitiveLocal/KJIT/.kjit/build-a19/src-a17
export KJIT_BUILD_ROOT=/Volumes/CaseSentitiveLocal/KJIT/.kjit/build-a19 QEMU_SSH_PORT=12622 QEMU_GDB_PORT=2349 UB_POLL=0.5 UB_CLAIM_BIN=/Volumes/CaseSentitiveLocal/KJIT/.kjit/build-a19/claim/qemu-system-aarch64 UB_CLAIM_CONFIRM=2.5
B=$KJIT_BUILD_ROOT
L=$B/logs
BOOTS=${1:-4}
REPS=${2:-6}
until grep -q ALLDONE $L/meas.progress 2>/dev/null; do sleep 20; done
CELLS='get_c1:base:get:100000:1:1:1:0:0:1-3:tcp set_c1:base:set:100000:1:1:1:0:0:1-3:tcp get_c10:base:get:300000:10:1:1:2:0:1-3:tcp set_c10:base:set:300000:10:1:1:2:0:1-3:tcp'
for b in $(seq 1 $BOOTS); do
  for m in a17 a19; do
    if [ $m = a17 ]; then ko=$B/mod-a17/kjit-guest/kjit.ko; else ko=$B/kjit-guest/kjit-module/kjit.ko; fi
    label=c1-$m-b$b
    mkdir -p $B/runs/ub-$label; cp $B/c1/c1-sweep.sh $B/runs/ub-$label/
    echo "boot $label $(date +%H:%M:%S)" >> $L/c1.progress
    UB_APPEND_EXTRA=rodata=off UB_MODULE=$ko UB_TIMEOUT=2700 tests/guest/host/ub-run.sh $label 0 "STATES='off on' sh /kjit/c1-sweep.sh /tmp/c1 $REPS $CELLS" >> $L/c1-$label.out 2>&1
    echo "  rc=$? $(date +%H:%M:%S)" >> $L/c1.progress
  done
done
echo ALLDONE >> $L/c1.progress
