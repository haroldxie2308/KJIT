#!/usr/bin/env bash
# Builds kjit.ko for both guest profiles against the shared kernels (no kernel rebuilt):
#   modbuild.sh TREE OUTNAME      TREE = a source tree (the a22-measure worktree, or a `git archive` extraction)
# -> $KJIT_BUILD_ROOT/OUTNAME/<profile>/kjit.ko ; stale OUTNAME is removed first.
set -euo pipefail
tree=$1 name=$2
cd "$tree"
export KJIT_BUILD_ROOT=/Volumes/CaseSentitiveLocal/KJIT/.kjit/build
for p in kjit-guest kjit-guest-debug; do
  d=$KJIT_BUILD_ROOT/$name/$p
  rm -rf "$d"; mkdir -p "$d"
  ./scripts/docker-dev.sh --no-tty -- make module-build KJIT_KERNEL_PROFILE=$p KJIT_MODULE_DIR=$d
  md5 "$d/kjit.ko"
done
echo MODBUILD-DONE
