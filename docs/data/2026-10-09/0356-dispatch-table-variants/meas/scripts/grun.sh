#!/bin/bash
# usage: grun.sh VARIANT TIMEOUT 'shell command' [LOGNAME]
# Boots kjit-guest with .kjit/mods/vVARIANT/kjit.ko under my private build root.
WT=/Volumes/CaseSentitiveLocal/KJIT/.claude/worktrees/agent-a4b243dcf4b342be4
cd "$WT" || exit 1
export QEMU_SSH_PORT=10722 QEMU_GDB_PORT=1934
export KJIT_BUILD_ROOT=/Volumes/Local/kjit-a4b2/build
v=$1; t=$2; cmd=$3; name=${4:-run}
if [[ "$cmd" == @* ]]; then cmd=$(cat "${cmd#@}"); fi
ts=$(date +%Y%m%d-%H%M%S)
run_dir=/Volumes/Local/kjit-a4b2/build/runs/$name-v$v-$ts
bash scripts/guest-run.sh --profile kjit-guest --module "$WT/.kjit/mods/v$v/kjit.ko" \
    --run-dir "$run_dir" --timeout "$t" -- "$cmd"
rc=$?
echo "grun: rc=$rc run_dir=$run_dir"
exit $rc
