#!/usr/bin/env bash
# Guest gates of A22a, own build root ($SHARED/root-a22sp: symlinks to the shared kernels, kjit-module of each profile ->
# $SHARED/mod-a22sp/<profile>, the a22-sp module). Same commands as the make recipes of guest-tests / guest-tests-k3 /
# redis-campaign, without their guest-rootfs dependency (the rootfs is the shared one; tests/guest is unchanged).
# One guest at a time: waits for any other qemu-system-aarch64 to exit (never kills one).
#   gates.sh LOGDIR
cd /Volumes/CaseSentitiveLocal/KJIT/.claude/worktrees/a22-sp
export KJIT_BUILD_ROOT=/Volumes/CaseSentitiveLocal/KJIT/.kjit/build/root-a22sp QEMU_SSH_PORT=12822 QEMU_GDB_PORT=2352
L=$1
mkdir -p "$L"
w() { while pgrep -x qemu-system-aarch64 > /dev/null; do sleep 3; done; }
for p in kjit-guest kjit-guest-debug; do
  w; bash scripts/guest-run.sh --profile $p --run-dir $KJIT_BUILD_ROOT/runs/gate-k2-$p --timeout 3600 -- "sh /opt/kjit-tests/run-k2.sh 1" > $L/gate-k2-$p.log 2>&1
done
for p in kjit-guest kjit-guest-debug; do
  w; bash scripts/guest-run.sh --profile $p --run-dir $KJIT_BUILD_ROOT/runs/gate-k3-$p --timeout 14400 -- "sh /opt/kjit-tests/run-k3.sh 1 64 4" > $L/gate-k3-$p.log 2>&1
done
for p in kjit-guest kjit-guest-debug; do
  w; bash scripts/redis-campaign.sh --profile $p --iterations 1 --requests 100000 --no-suite > $L/gate-campaign-$p.log 2>&1
done
echo GATES-DONE > $L/gates.done
