#!/usr/bin/env bash
# EXPERIMENT (exp/attrib-a22). The boots after the first part of drive.sh (which was stopped after A-k1-b2): D, P, N and micro boots.
set -uo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export WT=/Volumes/CaseSentitiveLocal/KJIT/.claude/worktrees/attrib-a22
export KJIT_BUILD_ROOT=/Volumes/CaseSentitiveLocal/KJIT/.kjit/build
export QEMU_SSH_PORT=13122 QEMU_GDB_PORT=2355 UB_MAX_LOAD=4
PLAIN=$KJIT_BUILD_ROOT/mod-attrib-a22/plain/kjit-guest/kjit.ko
INSTR2=$KJIT_BUILD_ROOT/mod-attrib-a22/instr2/kjit-guest/kjit.ko
INSTR3=$KJIT_BUILD_ROOT/mod-attrib-a22/instr3/kjit-guest/kjit.ko
P=$KJIT_BUILD_ROOT/runs/at22-progress.txt
UG=ug:get:50:1:1:2:unix:1-3 US=us:set:50:1:1:2:unix:1-3 UP=up:ping_mbulk:50:1:1:2:unix:1-3
SD="off on offD100 onD100 offD300 onD300 offS onS"
SN="off on nostats1 nostats2 nostats4 nostats7"
GP16=ugp16:get:50:16:1:2:unix:1-3 SP16=usp16:set:50:16:1:2:unix:1-3 GP4=ugp4:get:50:4:1:2:unix:1-3
boot() { # LABEL KPTI MODULE REPS ROT CELLS STATES
    echo "$(date +%H:%M:%S) start at22-$1" >> "$P"
    "$here/boot.sh" "at22-$1" "$2" "$3" "sh /kjit/attrib-a22.sh /tmp/atr $4 1000000 100000 $5 '$6' '$7'"
    echo "$(date +%H:%M:%S) end at22-$1 status=$? load=$(sysctl -n vm.loadavg)" | tee -a "$P"
}
micro() { # LABEL KPTI
    echo "$(date +%H:%M:%S) start at22-$1" >> "$P"
    "$here/boot.sh" "at22-$1" "$2" "$INSTR3" "sh /kjit/micro-a22.sh 3"
    echo "$(date +%H:%M:%S) end at22-$1 status=$? load=$(sysctl -n vm.loadavg)" | tee -a "$P"
}
boot P-k0-b9 0 "$PLAIN" 8 0 "$GP16 $SP16 $GP4" "off on"
boot D-k0-b4 0 "$INSTR2" 4 0 "$UG $US $UP" "$SD"
boot N-k0-b7 0 "$INSTR3" 4 0 "$UG $US $UP" "$SN"
boot N-k1-b8 1 "$INSTR3" 4 2 "$UG $US $UP" "$SN"
boot D-k1-b6 1 "$INSTR2" 4 0 "$UG $US $UP" "$SD"
micro M-k0-b1 0
micro M-k1-b1 1
echo "$(date +%H:%M:%S) ALLDONE3" >> "$P"
