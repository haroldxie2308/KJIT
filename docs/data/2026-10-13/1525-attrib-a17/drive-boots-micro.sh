#!/bin/bash
cd /Volumes/CaseSentitiveLocal/KJIT/.claude/worktrees/attrib
export KJIT_BUILD_ROOT=/Volumes/CaseSentitiveLocal/KJIT/.kjit/build QEMU_SSH_PORT=12122 QEMU_GDB_PORT=2344
B=$KJIT_BUILD_ROOT; export UB_TIMEOUT=3600
KO=$B/mod-attrib/kjit-guest/kjit.ko
P=$B/runs/attrib-progress.txt
until grep -q ALLDONE $P; do sleep 20; done
waitquiet() {
  while true; do
    n=$(pgrep -x qemu-system-aarch64 | wc -l | tr -d ' ')
    l=$(sysctl -n vm.loadavg | awk '{ print $2 }')
    if [ "$n" = 0 ] && awk -v l="$l" 'BEGIN { exit !(l <= 6) }'; then return; fi
    sleep 0.5
  done
}
for b in 1 2; do
  waitquiet
  echo "$(date +%H:%M:%S) start at-micro2-b$b" >> $P
  mkdir -p $B/runs/ub-at-micro2-b$b
  cp tests/guest/micro-a17.sh $B/runs/ub-at-micro2-b$b/
  cp $B/attrib/micro/code_speed $B/runs/ub-at-micro2-b$b/
  cp tests/guest/wake-cost.pl $B/runs/ub-at-micro2-b$b/
  UB_APPEND_EXTRA=rodata=off UB_MODULE=$KO tests/guest/host/ub-run.sh at-micro2-b$b 0 'sh /kjit/micro-a17.sh 7' >> $B/runs/attrib-at-micro2-b$b.out 2>&1
  echo "$(date +%H:%M:%S) end at-micro2-b$b rc=$?" >> $P
done
echo "$(date +%H:%M:%S) ALLDONE3" >> $P
