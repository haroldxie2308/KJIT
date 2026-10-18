#!/usr/bin/env bash
# Guest gates of A22b, own build root (.kjit/build of the a22-budget worktree: symlinks to the shared kernel Images and
# rootfs, kjit-module of each profile = the a22b module). Same commands as the make recipes of guest-tests / guest-tests-k3 /
# redis-campaign, without their guest-rootfs dependency (the rootfs is the shared one; tests/guest is unchanged).
# One guest at a time: waits for any other qemu-system-aarch64 to exit before each command.
#   gates.sh LOGDIR
cd /Volumes/CaseSentitiveLocal/KJIT/.claude/worktrees/a22-budget
export KJIT_BUILD_ROOT=$PWD/.kjit/build QEMU_SSH_PORT=12922 QEMU_GDB_PORT=2353
L=$1
mkdir -p "$L"
w() { while pgrep -x qemu-system-aarch64 > /dev/null; do sleep 3; done; }
for p in kjit-guest kjit-guest-debug; do
  w; bash scripts/guest-run.sh --profile $p --run-dir $KJIT_BUILD_ROOT/runs/gate-k2-$p --timeout 3600 -- "sh /opt/kjit-tests/run-k2.sh 1" > $L/gate-k2-$p.log 2>&1
  echo "k2 $p rc=$?" >> $L/gates.progress
done
for p in kjit-guest kjit-guest-debug; do
  w; bash scripts/guest-run.sh --profile $p --run-dir $KJIT_BUILD_ROOT/runs/gate-k3-$p --timeout 14400 -- "sh /opt/kjit-tests/run-k3.sh 1 64 4" > $L/gate-k3-$p.log 2>&1
  echo "k3 $p rc=$?" >> $L/gates.progress
done
for p in kjit-guest kjit-guest-debug; do
  w; bash scripts/redis-campaign.sh --profile $p --iterations 1 --requests 100000 --no-suite > $L/gate-campaign-$p.log 2>&1
  echo "campaign $p rc=$?" >> $L/gates.progress
done
echo GATES-DONE > $L/gates.done
