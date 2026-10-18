#!/usr/bin/env bash
# Builds kjit.ko for both guest profiles from the a22-sp worktree into $SHARED/mod-a22sp/<profile>, against the shared kernels.
set -euo pipefail
cd /Volumes/CaseSentitiveLocal/KJIT/.claude/worktrees/a22-sp
export KJIT_BUILD_ROOT=/Volumes/CaseSentitiveLocal/KJIT/.kjit/build
for p in kjit-guest kjit-guest-debug; do
  d=$KJIT_BUILD_ROOT/mod-a22sp/$p
  rm -rf "$d"; mkdir -p "$d"
  ./scripts/docker-dev.sh --no-tty -- make module-build KJIT_KERNEL_PROFILE=$p KJIT_MODULE_DIR=$d
  md5 "$d/kjit.ko"
done
echo MODBUILD-DONE
