#!/bin/bash
# usage: gates.sh TAG VARIANT...   (native, fuzz, guest-tests, guest-tests-k3 per variant)
# harness-test is run separately (htest_all.sh).
S=/private/tmp/claude-501/-Volumes-CaseSentitiveLocal-KJIT/b06f19aa-bc63-41a1-912e-50230c2c0e32/scratchpad
WT=/Volumes/CaseSentitiveLocal/KJIT/.claude/worktrees/agent-a4b243dcf4b342be4
L=/Volumes/Local/kjit-a4b2/logs
cd "$WT" || exit 1
export CARGO_TARGET_DIR=/Volumes/Local/kjit-a4b2/cargo-target
tag=$1; shift
for v in "$@"; do
    echo "=== variant $v: native"
    $S/native_all.sh $tag $v
    echo "=== variant $v: fuzz"
    KJIT_IBTC_VARIANT=$v make fuzz ITERS=10000 > $L/fuzz-v$v-$tag.log 2>&1
    echo "fuzz exit $? : $(grep -E 'passed|failed' $L/fuzz-v$v-$tag.log | tail -2 | tr '\n' ' ')"
    echo "=== variant $v: guest-tests (K2)"
    $S/grun.sh $v 3600 "sh /opt/kjit-tests/run-k2.sh 1" k2-$tag > $L/k2-v$v-$tag.log 2>&1
    echo "k2 rc=$? : $(grep -E 'k2.*ALL PASS|guest-run: (PASS|FAIL)' $L/k2-v$v-$tag.log | tail -3 | tr '\n' ' ')"
    echo "=== variant $v: guest-tests-k3"
    $S/grun.sh $v 14400 "sh /opt/kjit-tests/run-k3.sh 1 64 4" k3-$tag > $L/k3-v$v-$tag.log 2>&1
    echo "k3 rc=$? : $(grep -E 'k3.*ALL PASS|guest-run: (PASS|FAIL)' $L/k3-v$v-$tag.log | tail -3 | tr '\n' ' ')"
done
