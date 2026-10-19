#!/bin/bash
P=/Volumes/CaseSentitiveLocal/KJIT/.kjit/build/runs/at22-progress.txt
until grep -q "start at22-M-k0-b1" $P; do sleep 1; done
sleep 3
pkill -f "drive3.sh"
echo "$(date +%H:%M:%S) drive3 stopped after M-k0-b1 started (M-k1-b1 dropped); drive4 starts" >> $P
cd /Volumes/CaseSentitiveLocal/KJIT/.claude/worktrees/attrib-a22/docs/data/2026-10-19/wip-attrib-a22/tools
nohup ./drive4.sh >> ../drive.log 2>&1
