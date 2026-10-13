#!/bin/bash
cd /Volumes/CaseSentitiveLocal/KJIT/.claude/worktrees/attrib
export KJIT_BUILD_ROOT=/Volumes/CaseSentitiveLocal/KJIT/.kjit/build QEMU_SSH_PORT=12122 QEMU_GDB_PORT=2344
B=$KJIT_BUILD_ROOT; export UB_TIMEOUT=3600
KO=$B/mod-attrib/kjit-guest/kjit.ko
P=$B/runs/attrib-progress.txt
until grep -q ALLDONE4 $P; do sleep 20; done
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
SK="off on svcn decl2 onT offT"
run at-A-k1-b3 1 $KO 4 "d1t2:2:1 d1024t2:2:1024" "$SK"
run at-A-k1-b4 1 $KO 4 "d1024t2:2:1024 d1t2:2:1" "$SK"
echo "$(date +%H:%M:%S) ALLDONE5" >> $P
