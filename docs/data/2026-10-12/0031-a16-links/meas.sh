#!/bin/bash
cd /Volumes/CaseSentitiveLocal/KJIT/.claude/worktrees/a16
export KJIT_BUILD_ROOT=/Volumes/CaseSentitiveLocal/KJIT/.kjit/build QEMU_SSH_PORT=12022 QEMU_GDB_PORT=2343
B=$KJIT_BUILD_ROOT
for b in 1 2 3 4; do
  for m in main a16; do
    echo "boot $m b$b $(date +%H:%M:%S)" >> $B/mod-a16/logs/meas.progress
    UB_MODULE=$B/mod-a16/$m/kjit-guest/kjit.ko tests/guest/host/ub-run.sh $m-std-k0-b$b 0 \
      'sh /opt/kjit-tests/ub-standard.sh /tmp/ubstd pinned 1000000 2 1 64 1024' >> $B/mod-a16/logs/meas-$m-b$b.out 2>&1
    echo "  rc=$? $(date +%H:%M:%S)" >> $B/mod-a16/logs/meas.progress
  done
done
echo ALLDONE >> $B/mod-a16/logs/meas.progress
