#!/usr/bin/env bash
# EXPERIMENT (exp/attrib-a22). The boots of the study, one after the other; a failed boot is logged and skipped.
#   drive.sh                      all boots in order        drive.sh NAME...   only these boots
# Boot names: A-k0-b1.. (instrumented module, attribution states), H-k0-b1.. (plain module, off/on gap),
# D-k0-b4.. (instrumented module, x_delay / spin states), M-k0 (micro).
set -uo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export WT=/Volumes/CaseSentitiveLocal/KJIT/.claude/worktrees/attrib-a22
export KJIT_BUILD_ROOT=/Volumes/CaseSentitiveLocal/KJIT/.kjit/build
export QEMU_SSH_PORT=13122 QEMU_GDB_PORT=2355 UB_MAX_LOAD=4
PLAIN=$KJIT_BUILD_ROOT/mod-attrib-a22/plain/kjit-guest/kjit.ko
INSTR=$KJIT_BUILD_ROOT/mod-attrib-a22/instr2/kjit-guest/kjit.ko  # instr (077411cf...) without the chain timers and x_rep_link/clookup was used by A-k0-b1 and A-k1-b1
P=$KJIT_BUILD_ROOT/runs/at22-progress.txt
UG=ug:get:50:1:1:2:unix:1-3 US=us:set:50:1:1:2:unix:1-3 UP=up:ping_mbulk:50:1:1:2:unix:1-3 UG3=ug3:get:60:1:1:3:unix:1-3
SA="off on onT offT svcn svcnT decl1 decl2 offS onS ampcr amplk ampsr amppan ampbr ampat amptr amplink ampcl"
SD="off on offD100 onD100 offD300 onD300 offS onS"
rotate() { # N item... : the items rotated left by N
    local n=$1; shift; local a=("$@") i out=()
    for ((i = 0; i < ${#a[@]}; i++)); do out+=("${a[$(( (i + n) % ${#a[@]} ))]}"); done
    echo "${out[*]}"
}
run() { # NAME KPTI MODULE REPS ROT CELLS STATES
    local name=$1 kpti=$2 ko=$3 reps=$4 rot=$5 cells=$6 states=$7 label=at22-$1 st
    echo "$(date +%H:%M:%S) start $label" >> "$P"
    "$here/boot.sh" "$label" "$kpti" "$ko" "sh /kjit/attrib-a22.sh /tmp/atr $reps 1000000 100000 $rot '$cells' '$states'"
    st=$?
    local log=$KJIT_BUILD_ROOT/runs/ub-$label/serial.log n
    n=$(grep -c 'kernel page table isolation forced ON' "$log" 2>/dev/null)
    if [[ $kpti = 1 ]]; then [[ ${n:-0} -gt 0 ]] || { echo "DRIVE: $label KPTI not forced on"; st=99; }
    else [[ ${n:-0} -eq 0 ]] || { echo "DRIVE: $label KPTI unexpectedly on"; st=98; }; fi
    grep -aq '^atr: done' "$log" 2>/dev/null || { echo "DRIVE: $label did not finish"; st=97; }
    echo "$(date +%H:%M:%S) end $label status=$st load=$(sysctl -n vm.loadavg)" | tee -a "$P"
}
want() { [[ $# -eq 0 ]]; }
sel=("$@")
go() { local name=$1; shift; if [[ ${#sel[@]} -eq 0 ]] || [[ " ${sel[*]} " == *" $name "* ]]; then run "$name" "$@"; fi; }
#go A-k0-b1 0 "$INSTR" 2 0  "$(rotate 0 $UG $US $UP)" "$SA"
#go H-k0-b1 0 "$PLAIN" 8 0  "$(rotate 0 $UG $US $UP $UG3)" "off on"
#go A-k1-b1 1 (instr, running when the driver was restarted) "$INSTR" 2 7  "$(rotate 1 $UG $US $UP)" "$SA"
go A-k0-b2 0 "$INSTR" 2 14 "$(rotate 1 $UG $US $UP)" "$SA"
go H-k1-b1 1 "$PLAIN" 8 1  "$(rotate 1 $UG $US $UP $UG3)" "off on"
go H-k0-b2 0 "$PLAIN" 8 1  "$(rotate 2 $UG $US $UP $UG3)" "off on"
go A-k0-b3 0 "$INSTR" 2 4  "$(rotate 2 $UG $US $UP)" "$SA"
go A-k1-b2 1 "$INSTR" 2 11 "$(rotate 2 $UG $US $UP)" "$SA"
go H-k0-b3 0 "$PLAIN" 8 0  "$(rotate 3 $UG $US $UP $UG3)" "off on"
go D-k0-b4 0 "$INSTR" 4 0  "$(rotate 0 $UG $US $UP $UG3)" "$SD"
go D-k0-b5 0 "$INSTR" 4 3  "$(rotate 1 $UG $US $UP $UG3)" "$SD"
echo "$(date +%H:%M:%S) ALLDONE" >> "$P"
