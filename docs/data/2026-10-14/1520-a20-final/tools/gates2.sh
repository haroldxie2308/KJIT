#!/usr/bin/env bash
cd /Volumes/CaseSentitiveLocal/KJIT/.claude/worktrees/a20
export KJIT_BUILD_ROOT=$PWD/.kjit/build QEMU_SSH_PORT=12822 QEMU_GDB_PORT=2351
L=/private/tmp/claude-501/scratch/r2
w() { while pgrep -x qemu-system-aarch64 >/dev/null; do sleep 0.5; done; }
for p in kjit-guest kjit-guest-debug; do
  w; bash scripts/guest-run.sh --profile $p --run-dir $KJIT_BUILD_ROOT/runs/gate-k2-$p --timeout 3600 -- "sh /opt/kjit-tests/run-k2.sh 1" > $L/gate-k2-$p.log 2>&1
done
for p in kjit-guest kjit-guest-debug; do
  w; bash scripts/guest-run.sh --profile $p --run-dir $KJIT_BUILD_ROOT/runs/gate-k3-$p --timeout 14400 -- "sh /opt/kjit-tests/run-k3.sh 1 64 4" > $L/gate-k3-$p.log 2>&1
done
for p in kjit-guest kjit-guest-debug; do
  w; bash scripts/redis-campaign.sh --profile $p --iterations 1 --requests 100000 --no-suite > $L/gate-campaign-$p.log 2>&1
done
echo done > $L/guestgates.done
