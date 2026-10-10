#!/bin/bash
# usage: htest_all.sh TAG VARIANT...   -> logs in /Volumes/Local/kjit-a4b2/logs/htest-v<N>-TAG.log
WT=/Volumes/CaseSentitiveLocal/KJIT/.claude/worktrees/agent-a4b243dcf4b342be4
cd "$WT" || exit 1
export CARGO_TARGET_DIR=/Volumes/Local/kjit-a4b2/cargo-target
make harness-prepare >/dev/null 2>&1
tag=$1; shift
for v in "$@"; do
    log=/Volumes/Local/kjit-a4b2/logs/htest-v$v-$tag.log
    KJIT_IBTC_VARIANT=$v cargo test --manifest-path harness/Cargo.toml -- --nocapture > "$log" 2>&1
    echo "exit $?" >> "$log"
    grep -E "^test result|^exit" "$log" | tr '\n' ' '
    echo " [variant $v]"
done
