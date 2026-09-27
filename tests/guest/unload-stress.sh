#!/bin/sh
# Unload race stress (tmp/pipeline.md, "Unload race"; kernel-patches/0006):
# rmmod/insmod kjit.ko `cycles` times while unload_fault keeps auto-mode
# fragments faulting on fresh pages, in long chains of in-place demand paging
# (gpr threads) and through the Mem stub of FP/SIMD fragments (fp threads). A
# fragment fault without its fixup during rmmod is an oops, which
# scripts/guest-run.sh fails on; this script checks that the workload stays
# alive and that fragments were running and faulting before every rmmod.
#
#   unload-stress.sh [cycles] [threads]    default 50, 4
set -eu

cycles=${1:-50}
threads=${2:-4}
T=/opt/kjit-tests
K=/sys/kernel/debug/kjit
KO=${KJIT_MODULE:-/kjit/kjit.ko}

grep -q " /sys/kernel/debug debugfs" /proc/mounts || mount -t debugfs debugfs /sys/kernel/debug
[ -d "$K" ] || { echo "unload: $K missing (kjit.ko not loaded?)"; exit 1; }
work=$(mktemp -d)
cd "$work"

fail() {
    echo "unload: FAIL $*"
    [ -s unload_fault.err ] && { echo "--- unload_fault.err"; tail -20 unload_fault.err; }
    exit 1
}

stat() { awk -v k="$1" '$1 == k { print $2 }' "$K/stats"; }

echo 1 > "$K/enable"
echo 1 > "$K/auto"
"$T/unload_fault" "$threads" > /dev/null 2> unload_fault.err &
pid=$!

# Counters restart with every insmod: each cycle's values are that load's.
busy=0
n=1
while [ "$n" -le "$cycles" ]; do
    sleep 0.3
    kill -0 "$pid" 2>/dev/null || fail "unload_fault exited before rmmod $n"
    entries=$(stat fragment_entries)
    mem=$(stat exit_mem)
    fpmem=$(stat fpsimd_exit_mem)
    [ "$entries" -gt 0 ] && [ "$fpmem" -gt 0 ] && busy=$((busy + 1))
    rmmod kjit || fail "rmmod $n under unload_fault"
    insmod "$KO" auto=1 || fail "insmod $n"
    [ -d "$K" ] || fail "debugfs missing after insmod $n"
    n=$((n + 1))
done
sleep 0.3
kill -0 "$pid" 2>/dev/null || fail "unload_fault exited"
kill -9 "$pid"
wait "$pid" 2>/dev/null || true
echo 0 > "$K/auto"
# Most cycles must have unloaded under running, faulting fragments; the first
# loads after a cold start may still be warming up.
[ "$busy" -ge $((cycles * 3 / 4)) ] || fail "only $busy of $cycles loads ran faulting FP/SIMD fragments"
echo "unload: last load: entries=$entries exit_mem=$mem fpsimd_exit_mem=$fpmem"
echo "unload: PASS ($cycles unloads under faulting fragments, $busy with fragment entries and FP/SIMD Mem exits)"
