#!/bin/bash
# A18 kernel gates: both profiles, module = the A18 module of mod-a18/<profile>.
cd /Volumes/CaseSentitiveLocal/KJIT/.claude/worktrees/a18
export KJIT_BUILD_ROOT=/Volumes/CaseSentitiveLocal/KJIT/.kjit/build-a18 QEMU_SSH_PORT=12322 QEMU_GDB_PORT=2346
G=$KJIT_BUILD_ROOT/gates
bash ./scripts/mk-guest-rootfs.sh > $G/rootfs.log 2>&1 || { echo "ROOTFS FAIL" >> $G/progress; exit 1; }
for p in kjit-guest kjit-guest-debug; do
  echo "k2 $p $(date +%H:%M:%S)" >> $G/progress
  bash ./scripts/guest-run.sh --profile $p --run-dir $G/k2-$p --timeout 3600 -- "sh /opt/kjit-tests/run-k2.sh 1" > $G/k2-$p.log 2>&1
  echo "  rc=$? $(date +%H:%M:%S)" >> $G/progress
done
for p in kjit-guest kjit-guest-debug; do
  echo "k3 $p $(date +%H:%M:%S)" >> $G/progress
  bash ./scripts/guest-run.sh --profile $p --run-dir $G/k3-$p --timeout 14400 -- "sh /opt/kjit-tests/run-k3.sh 1 64 4" > $G/k3-$p.log 2>&1
  echo "  rc=$? $(date +%H:%M:%S)" >> $G/progress
done
for p in kjit-guest kjit-guest-debug; do
  echo "campaign $p $(date +%H:%M:%S)" >> $G/progress
  bash ./scripts/redis-campaign.sh --profile $p --iterations 1 --requests 100000 --no-suite > $G/campaign-$p.log 2>&1
  echo "  rc=$? $(date +%H:%M:%S)" >> $G/progress
done
echo ALLDONE >> $G/progress
