#!/bin/sh
# Unload race stress (docs/pipeline.md, "Hook lifetime and unload (patch 0006)";
# kernel-patches/0006, "Dispatch tables (A11, kernel side)"): rmmod/insmod kjit.ko
# `cycles` times while unload_fault keeps
# auto-mode fragments faulting on fresh pages, in long chains of in-place
# demand paging (gpr threads) and through the Mem stub of FP/SIMD fragments (fp
# threads), and keeps runs linked across fragments (link and linkfp threads:
# bl/ret across three fragments, dispatched inside fragment code, FP/SIMD
# boundary included) in flight. A fragment fault without its fixup during
# rmmod is an oops, a fragment or dispatch table freed under a linked run is a
# fault, and a callback left behind is a use after unload; scripts/guest-run.sh
# fails on all of them. This script checks that the workload stays alive, that
# fragments were running and faulting before every rmmod, and that the runs
# were linked (published in the dispatch tables, few runtime entries per
# syscall).
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
linked=0
n=1
while [ "$n" -le "$cycles" ]; do
    sleep 0.3
    kill -0 "$pid" 2>/dev/null || fail "unload_fault exited before rmmod $n"
    entries=$(stat fragment_entries)
    mem=$(stat exit_mem)
    fpmem=$(stat fpsimd_exit_mem)
    [ "$entries" -gt 0 ] && [ "$fpmem" -gt 0 ] && busy=$((busy + 1))
    # Published in the dispatch tables, and dispatched: a hook call that runs a
    # linked path makes a handful of runtime entries (the svc resume, misses),
    # not one per call and return (A10: hundreds).
    insert=$(stat ibtc_insert)
    in_kernel=$(stat syscalls_in_kernel)
    [ "$insert" -gt 0 ] && [ "$entries" -le $((8 * in_kernel)) ] && linked=$((linked + 1))
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
[ "$linked" -ge $((cycles * 3 / 4)) ] || fail "only $linked of $cycles loads ran linked paths (last: entries=$entries in_kernel=$in_kernel ibtc_insert=$insert)"
echo "unload: last load: entries=$entries exit_mem=$mem fpsimd_exit_mem=$fpmem in_kernel=$in_kernel ibtc_insert=$insert"
echo "unload: PASS ($cycles unloads under faulting fragments, $busy with fragment entries and FP/SIMD Mem exits, $linked with linked runs)"
