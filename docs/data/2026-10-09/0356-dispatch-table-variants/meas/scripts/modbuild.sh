#!/bin/bash
# usage: modbuild.sh NAME [KCFLAGS...]  -> .kjit/mods/NAME/kjit.ko
set -euo pipefail
WT=/Volumes/CaseSentitiveLocal/KJIT/.claude/worktrees/agent-a4b243dcf4b342be4
cd "$WT"
name=$1; shift
export KJIT_BUILD_ROOT=/Volumes/CaseSentitiveLocal/KJIT/.claude/worktrees/agent-ac3b24e86f29900e2/.kjit/build
mkdir -p .kjit/mods/$name
./scripts/docker-dev.sh --no-tty -- make module-build KJIT_KERNEL_PROFILE=kjit-guest KJIT_MODULE_DIR=/workspace/.kjit/mods/$name KCFLAGS="$*"
ls -la .kjit/mods/$name/kjit.ko
