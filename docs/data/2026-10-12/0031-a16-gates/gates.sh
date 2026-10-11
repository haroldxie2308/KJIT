#!/bin/bash
cd /Volumes/CaseSentitiveLocal/KJIT/.claude/worktrees/a16
export KJIT_BUILD_ROOT=/Volumes/CaseSentitiveLocal/KJIT/.kjit/build QEMU_SSH_PORT=12022 QEMU_GDB_PORT=2343
L=$KJIT_BUILD_ROOT/mod-a16/logs
for p in kjit-guest kjit-guest-debug; do
  for g in guest-tests guest-tests-k3 redis-campaign; do
    extra=""
    [ $g = redis-campaign ] && extra="K4_ARGS=--no-suite"
    echo "== $g $p $(date +%H:%M:%S)" >> $L/gates.progress
    make $g GUEST_PROFILE=$p $extra > $L/$g-$p.log 2>&1
    echo "   rc=$? $(date +%H:%M:%S)" >> $L/gates.progress
  done
done
echo ALLDONE >> $L/gates.progress
