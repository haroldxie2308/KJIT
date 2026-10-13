#!/bin/bash
# EXPERIMENT driver: the boots of the attribution on A17, one after the other.
cd /Volumes/CaseSentitiveLocal/KJIT/.claude/worktrees/attrib
export KJIT_BUILD_ROOT=/Volumes/CaseSentitiveLocal/KJIT/.kjit/build QEMU_SSH_PORT=12122 QEMU_GDB_PORT=2344
B=$KJIT_BUILD_ROOT; export UB_TIMEOUT=3600
KO=$B/mod-attrib/kjit-guest/kjit.ko
A17=$B/mod-a17/a17/kjit-guest/kjit.ko
P=$B/runs/attrib-progress.txt
CFA="d1t2:2:1 d1024t2:2:1024 d1t0:0:1"
CFK="d1t2:2:1 d1024t2:2:1024"
SA="off on onT offT svcn svcnT decl1 decl2 nomod"
SB="off on ampcr amplk ampsr amppan ampbr ampat"
SC="off on nopB nopR nopA nopBRA onZ"
# Quiet-host wait with a 0.5 s poll (ub-run.sh polls every 3 s and then starts at once; the other agent's
# back-to-back boots would otherwise always find the host free before this one does).
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
ref() { # label ko
  waitquiet
  echo "$(date +%H:%M:%S) start $1" >> $P
  UB_APPEND_EXTRA=rodata=off UB_MODULE=$2 tests/guest/host/ub-run.sh "$1" 0 'sh /opt/kjit-tests/ub-standard.sh /tmp/ubstd pinned 1000000 3 1 1024' >> $B/runs/attrib-$1.out 2>&1
  echo "$(date +%H:%M:%S) end $1 rc=$?" >> $P
}
run at-A-k0-b1 0 $KO 3 "$CFA" "$SA"
run at-B-k0-b1 0 $KO 3 "$CFK" "$SB"
run at-C-k0-b1 0 $KO 3 "$CFK" "$SC"
run at-A-k1-b1 1 $KO 3 "$CFK" "$SA"
ref at-ref-a17-b1 $A17
ref at-ref-attrib-b1 $KO
run at-A-k0-b2 0 $KO 3 "d1024t2:2:1024 d1t0:0:1 d1t2:2:1" "$SA"
run at-C-k0-b2 0 $KO 3 "d1024t2:2:1024 d1t2:2:1" "$SC"
run at-B-k0-b2 0 $KO 3 "d1024t2:2:1024 d1t2:2:1" "$SB"
run at-A-k1-b2 1 $KO 3 "d1024t2:2:1024 d1t2:2:1" "$SA"
run at-A-k0-b3 0 $KO 3 "d1t0:0:1 d1t2:2:1 d1024t2:2:1024" "$SA"
run at-C-k0-b3 0 $KO 3 "$CFK" "$SC"
run at-B-k0-b3 0 $KO 3 "$CFK" "$SB"
ref at-ref-a17-b2 $A17
ref at-ref-attrib-b2 $KO
run at-A-k0-b4 0 $KO 3 "$CFA" "$SA"
echo "$(date +%H:%M:%S) ALLDONE" >> $P
