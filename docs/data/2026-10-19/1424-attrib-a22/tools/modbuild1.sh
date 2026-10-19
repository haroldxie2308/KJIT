#!/usr/bin/env bash
# usage: modbuild1.sh SUBDIR   (builds kjit-guest only into $KJIT_BUILD_ROOT/mod-attrib-a22/SUBDIR/kjit-guest)
set -euo pipefail
cd /Volumes/CaseSentitiveLocal/KJIT/.claude/worktrees/attrib-a22
export KJIT_BUILD_ROOT=/Volumes/CaseSentitiveLocal/KJIT/.kjit/build
d=$KJIT_BUILD_ROOT/mod-attrib-a22/$1/kjit-guest
rm -rf "$d"; mkdir -p "$d"
./scripts/docker-dev.sh --no-tty -- make module-build KJIT_KERNEL_PROFILE=kjit-guest KJIT_MODULE_DIR=$d
md5 "$d/kjit.ko"
echo MODBUILD-DONE
