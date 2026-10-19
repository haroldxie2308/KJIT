#!/bin/bash
P=/Volumes/CaseSentitiveLocal/KJIT/.kjit/build/runs/at22-progress.txt
until grep -q "start at22-A-k1-b2" $P; do sleep 2; done
kill 18796
sleep 1
cd /Volumes/CaseSentitiveLocal/KJIT/.claude/worktrees/attrib-a22/docs/data/2026-10-19/wip-attrib-a22/tools
echo "$(date +%H:%M:%S) driver stopped after A-k1-b2 started; drive3 starts" >> $P
nohup ./drive3.sh >> ../drive.log 2>&1
