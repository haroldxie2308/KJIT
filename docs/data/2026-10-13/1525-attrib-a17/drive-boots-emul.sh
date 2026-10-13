#!/bin/bash
cd /Volumes/CaseSentitiveLocal/KJIT/.claude/worktrees/attrib
export KJIT_BUILD_ROOT=/Volumes/CaseSentitiveLocal/KJIT/.kjit/build QEMU_SSH_PORT=12122 QEMU_GDB_PORT=2344
B=$KJIT_BUILD_ROOT; export UB_TIMEOUT=3600
KO4=$B/mod-attrib4/kjit-guest/kjit.ko
P=$B/runs/attrib-progress.txt
until grep -q ALLDONE3 $P; do sleep 20; done
waitquiet() {
  while true; do
    n=$(pgrep -x qemu-system-aarch64 | wc -l | tr -d ' ')
    l=$(sysctl -n vm.loadavg | awk '{ print $2 }')
    if [ "$n" = 0 ] && awk -v l="$l" 'BEGIN { exit !(l <= 6) }'; then return; fi
    sleep 0.5
  done
}
run() { # label kpti ko reps configs states
  waitquiet
  echo "$(date +%H:%M:%S) start $1" >> $P
  tests/guest/host/attrib-a17.sh "$1" "$2" "$3" "$4" 1000000 100000 "$5" "$6" >> $B/runs/attrib-$1.out 2>&1
  echo "$(date +%H:%M:%S) end $1 rc=$? others_now=$(pgrep -x qemu-system-aarch64 | wc -l) load=$(sysctl -n vm.loadavg)" >> $P
}
SD="off on emul"
run at-D-k0-b1 0 $KO4 4 "d1t2:2:1 d1024t2:2:1024 d1t0:0:1" "$SD"
run at-D-k0-b2 0 $KO4 4 "d1024t2:2:1024 d1t0:0:1 d1t2:2:1" "$SD"
run at-D-k1-b1 1 $KO4 4 "d1t2:2:1 d1024t2:2:1024" "$SD"
echo "$(date +%H:%M:%S) ALLDONE4" >> $P
