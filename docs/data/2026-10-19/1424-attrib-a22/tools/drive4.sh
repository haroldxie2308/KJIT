#!/usr/bin/env bash
# EXPERIMENT (exp/attrib-a22). Last boots: the A-k1-b2 retry (its first attempt hung before the first serial byte and was killed after 21 min)
# UB_TIMEOUT bounds a hung boot. (M-k1 micro and P-k1 were dropped to stay near the boot budget.)
set -uo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export WT=/Volumes/CaseSentitiveLocal/KJIT/.claude/worktrees/attrib-a22
export KJIT_BUILD_ROOT=/Volumes/CaseSentitiveLocal/KJIT/.kjit/build
export QEMU_SSH_PORT=13122 QEMU_GDB_PORT=2355 UB_MAX_LOAD=4 UB_TIMEOUT=1800
PLAIN=$KJIT_BUILD_ROOT/mod-attrib-a22/plain/kjit-guest/kjit.ko
INSTR2=$KJIT_BUILD_ROOT/mod-attrib-a22/instr2/kjit-guest/kjit.ko
P=$KJIT_BUILD_ROOT/runs/at22-progress.txt
UG=ug:get:50:1:1:2:unix:1-3 US=us:set:50:1:1:2:unix:1-3 UP=up:ping_mbulk:50:1:1:2:unix:1-3
SA="off on onT offT svcn svcnT decl1 decl2 offS onS ampcr amplk ampsr amppan ampbr ampat amptr amplink ampcl"
GP16=ugp16:get:50:16:1:2:unix:1-3 SP16=usp16:set:50:16:1:2:unix:1-3 GP4=ugp4:get:50:4:1:2:unix:1-3
boot() { # LABEL KPTI MODULE REPS ROT CELLS STATES
    echo "$(date +%H:%M:%S) start at22-$1" >> "$P"
    rm -rf "$KJIT_BUILD_ROOT/runs/ub-at22-$1"
    "$here/boot.sh" "at22-$1" "$2" "$3" "sh /kjit/attrib-a22.sh /tmp/atr $4 1000000 100000 $5 '$6' '$7'"
    echo "$(date +%H:%M:%S) end at22-$1 status=$? load=$(sysctl -n vm.loadavg)" | tee -a "$P"
}
boot A-k1-b2 1 "$INSTR2" 2 11 "$UP $UG $US" "$SA"
echo "$(date +%H:%M:%S) ALLDONE4" >> "$P"
