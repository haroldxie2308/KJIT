#!/bin/bash
# usage: native_all.sh TAG VARIANT...
# Same as scripts/native-test.sh's docker invocation (that script does not pass
# environment variables into the container, and its cargo target/home would live in
# the worktree on the nearly full case-sensitive volume), plus KJIT_IBTC_VARIANT and
# target/home directories on /Volumes/Local.
WT=/Volumes/CaseSentitiveLocal/KJIT/.claude/worktrees/agent-a4b243dcf4b342be4
cd "$WT" || exit 1
make harness-prepare >/dev/null 2>&1
tag=$1; shift
mkdir -p /Volumes/Local/kjit-a4b2/native-target /Volumes/Local/kjit-a4b2/native-cargo-home .kjit/docker-home
for v in "$@"; do
    log=/Volumes/Local/kjit-a4b2/logs/native-v$v-$tag.log
    docker run --rm --platform linux/arm64 --user "$(id -u):$(id -g)" \
        -e HOME=/workspace/.kjit/docker-home \
        -e CARGO_HOME=/native-cargo-home \
        -e CARGO_TARGET_DIR=/native-target \
        -e KJIT_IGNORE_LOCAL_ENV=1 \
        -e KJIT_IBTC_VARIANT=$v \
        -v "$WT:/workspace" \
        -v /Volumes/Local/kjit-a4b2/native-target:/native-target \
        -v /Volumes/Local/kjit-a4b2/native-cargo-home:/native-cargo-home \
        -w /workspace kjit-dev:latest \
        bash /workspace/scripts/native-test.sh --in-container > "$log" 2>&1
    echo "exit $?" >> "$log"
    grep -E "^test result|^exit|native fixture suite" "$log" | tr '\n' ' '
    echo " [variant $v]"
done
