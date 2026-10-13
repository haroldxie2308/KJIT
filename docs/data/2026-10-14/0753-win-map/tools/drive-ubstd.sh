#!/usr/bin/env bash
# Cross-check of the UB protocol with the stock tools: host/ub-standard.sh (tick-sampled server CPU).
set -uo pipefail
export KJIT_BUILD_ROOT=/Volumes/CaseSentitiveLocal/KJIT/.kjit/build
export QEMU_SSH_PORT=12722 QEMU_GDB_PORT=2350
export UB_MODULE=$KJIT_BUILD_ROOT/mod-winmap/kjit.ko
export UB_TIMEOUT=2400 UB_MAX_LOAD=6
export UB_STD_SIZES="1 1024" UB_STD_UNPINNED_SIZE=1 UB_STD_REQUESTS=500000
/Volumes/CaseSentitiveLocal/KJIT/.claude/worktrees/winmap/tests/guest/host/ub-standard.sh wm "$1" "$2"
echo "DRIVE: ubstd done $(date '+%H:%M:%S') status=$?"
