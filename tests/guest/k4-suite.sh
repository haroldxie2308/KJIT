#!/bin/sh
# K4 (1): redis's own test suite (/opt/redis/runtest, redis built from the
# official tarball by mk-guest-rootfs.sh) in the kjit-guest.
#
#   k4-suite.sh OUTDIR [runtest options...]
#
# If kjit.ko is loaded, KJIT runs with enable=1 and auto=1 for the whole run,
# so every redis-server (and redis-cli, tclsh, ...) the suite spawns runs
# under the auto mode; without the module this is the baseline. OUTDIR gets:
#   suite.log      the runtest output, ANSI colours stripped
#   results        one line per test outcome, "<status> <test name>", sorted
#                  (status ok/err/skip/ignore; a name can repeat)
#   results.norm   the set the campaign compares between the two runs: the
#                  distinct outcomes with every digit run replaced by "N".
#                  Some tests are not deterministic by name or count: psync2
#                  loops for a fixed time (more or fewer "CYCLE <n>" and
#                  "Set #<a> to replicate from #<b>" rounds, random topology,
#                  "consistent after load (x = <random>)"), so the raw lists
#                  differ between two runs of the same kernel.
#   exit           runtest's exit status (1 when any test failed)
#   stats.*, unsupported_top.*   KJIT counters before/after (module loaded)
# Exits 0 when the suite ran to its end ("The End"), whatever the test results;
# non-zero when runtest aborted (an [exception], a test-server timeout).
set -eu

out=${1:?usage: k4-suite.sh OUTDIR [runtest options...]}
shift
K=/sys/kernel/debug/kjit
mkdir -p "$out"

kjit=0
if grep -q '^kjit ' /proc/modules; then
    kjit=1
    grep -q " /sys/kernel/debug debugfs" /proc/mounts || mount -t debugfs debugfs /sys/kernel/debug
    echo 1 > "$K/enable"
    echo 1 > "$K/auto"
    cp "$K/stats" "$out/stats.before"
    cp "$K/unsupported_top" "$out/unsupported_top.before"
fi
echo "k4-suite: kjit=$kjit runtest $*"

cd /opt/redis
set +e
./runtest "$@" > "$out/suite.raw" 2>&1
status=$?
set -e
echo "$status" > "$out/exit"
sed 's/\x1b\[[0-9;]*m//g' "$out/suite.raw" > "$out/suite.log"
rm -f "$out/suite.raw"

if [ "$kjit" = 1 ]; then
    cp "$K/stats" "$out/stats.after"
    cp "$K/unsupported_top" "$out/unsupported_top.after"
    echo 0 > "$K/auto"
fi

# "[ok]: name (12 ms)", "[err]: name in tests/unit/x.tcl", "[skip]: name",
# "[ignore]: name". Only the name is kept, so timings do not enter the set.
sed -n -e 's/^\[ok\]: \(.*\) ([0-9]* ms)$/ok \1/p' \
       -e 's/^\[err\]: \(.*\) in tests\/.*$/err \1/p' \
       -e 's/^\[\(skip\|ignore\)\]: \(.*\)$/\1 \2/p' "$out/suite.log" | LC_ALL=C sort > "$out/results"
sed 's/[0-9][0-9]*/N/g' "$out/results" | LC_ALL=C sort -u > "$out/results.norm"

awk '{ n[$1]++ } END { printf "k4-suite: ok=%d err=%d skip=%d ignore=%d\n", n["ok"], n["err"], n["skip"], n["ignore"] }' \
    "$out/results"
# No match (every test passed) is not an error.
grep -E '^\[(err|exception)\]' "$out/suite.log" | head -50 || true
if ! grep -q 'The End' "$out/suite.log"; then
    echo "k4-suite: runtest did not reach its end (exit $status):"
    tail -30 "$out/suite.log"
    exit 1
fi
echo "k4-suite: done (runtest exit $status)"
