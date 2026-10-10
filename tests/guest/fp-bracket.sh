#!/bin/sh
# A13 FP/SIMD bracket: stress, latency and entry-cost runs, inside the
# kjit-guest (kjit.ko loaded, binaries in /opt/kjit-tests).
#
#   fp-bracket.sh stress [noise_us=25] [rounds=3]
#       fp_preempt (V state across preemption, migration and syscalls) with
#       KJIT off and on, without and with softirq kernel-mode NEON noise
#       (debugfs neon_noise_us), outputs compared. One line per noise setting:
#         fpb stress noise_us=<n> rounds=<r> result=ok preempted=<d> brackets=<d> in_kernel=<d>
#             noise_kernel=<d> noise_live=<d> noise_other=<d> run_max_ns=<since load>
#       preempted = brackets the task was switched out in (fpsimd_preempted);
#       noise_kernel = NEON rounds that interrupted a task inside a bracket.
#   fp-bracket.sh lat REPS [seconds=20]
#       lat_probe (SCHED_FIFO sleepers, one per CPU, under nojit) beside the
#       fp_preempt load, KJIT off then on, REPS times. One line per run:
#         fpb lat state=<off|on> rep=<i> <lat_probe line> preempted=<d> brackets=<d>
#       Recorded, not a gate: the host decides the maxima.
#   fp-bracket.sh entry ROUNDS
#       entry_cost gpr and fp at calls=16 and 128, KJIT off and on, ROUNDS
#       interleaved rounds. One line per run:
#         fpb entry state=<off|on> kind=<k> calls=<c> round=<i> ns_per_outer=<median of 7>
#             [preempted=<d> brackets=<d>]
set -eu

T=/opt/kjit-tests
K=/sys/kernel/debug/kjit

grep -q " /sys/kernel/debug debugfs" /proc/mounts || mount -t debugfs debugfs /sys/kernel/debug
[ -d "$K" ] || { echo "fpb: $K missing (kjit.ko not loaded?)"; exit 1; }
work=$(mktemp -d)
cd "$work"

fail() { echo "fpb: FAIL $*"; exit 1; }
stat() { awk -v k="$1" '$1 == k { print $2 }' "$K/stats"; }
hit() { awk -v k="$1" '{ for (i = 1; i < NF; i++) if ($i == k) print $(i + 1) }' "$K/neon_noise_hits"; }
restore() { echo 0 > "$K/neon_noise_us" 2> /dev/null || true; echo 0 > "$K/enable"; echo 0 > "$K/auto"; }
trap restore EXIT
echo 0 > "$K/auto"

cmd=${1:-}
[ -n "$cmd" ] || { sed -n '2,24p' "$0"; exit 2; }
shift

case "$cmd" in
stress)
    noise=${1:-25}
    rounds=${2:-3}
    for n in 0 "$noise"; do
        echo "$n" > "$K/neon_noise_us"
        echo 0 > "$K/enable"
        "$T/fp_preempt" 0 2000 3000 "$rounds" > off.out 2> off.err || { cat off.err; fail "stress noise=$n: KJIT off"; }
        echo 1 > "$K/enable"
        p0=$(stat fpsimd_preempted); b0=$(stat fpsimd_entries); k0=$(stat syscalls_in_kernel)
        nk0=$(hit kernel_section); nl0=$(hit live_user); no0=$(hit other)
        KJIT_EXPECT=fpsimd "$T/fp_preempt" 0 2000 3000 "$rounds" > on.out 2> on.err || { cat on.err; fail "stress noise=$n: KJIT on"; }
        cmp -s off.out on.out || { diff off.out on.out | head; fail "stress noise=$n: output differs with KJIT on/off"; }
        echo "fpb stress noise_us=$n rounds=$rounds result=ok preempted=$(( $(stat fpsimd_preempted) - p0 )) brackets=$(( $(stat fpsimd_entries) - b0 )) in_kernel=$(( $(stat syscalls_in_kernel) - k0 )) noise_kernel=$(( $(hit kernel_section) - nk0 )) noise_live=$(( $(hit live_user) - nl0 )) noise_other=$(( $(hit other) - no0 )) run_max_ns=$(stat fpsimd_run_max_ns)"
    done
    echo 0 > "$K/neon_noise_us"
    echo "fpb: stress PASS"
    ;;
lat)
    reps=${1:?reps}
    secs=${2:-20}
    i=1
    while [ "$i" -le "$reps" ]; do
        for state in off on; do
            if [ "$state" = on ]; then echo 1 > "$K/enable"; else echo 0 > "$K/enable"; fi
            p0=$(stat fpsimd_preempted); b0=$(stat fpsimd_entries)
            "$T/nojit" "$T/lat_probe" "$secs" 1000 50 > lat.out 2> lat.err &
            probe=$!
            # The load: fp_preempt rounds back to back until the probe window
            # (its own bound) is over, then the probe is stopped.
            end=$(( $(date +%s) + secs ))
            while [ "$(date +%s)" -lt "$end" ]; do
                "$T/fp_preempt" 0 2000 3000 1 > /dev/null 2> load.err || { cat load.err; kill "$probe" 2> /dev/null || true; fail "lat $state: load failed"; }
            done
            wait "$probe" || { cat lat.err; fail "lat $state: lat_probe failed (SCHED_FIFO?)"; }
            echo "fpb lat state=$state rep=$i $(cat lat.out) preempted=$(( $(stat fpsimd_preempted) - p0 )) brackets=$(( $(stat fpsimd_entries) - b0 )) run_max_ns=$(stat fpsimd_run_max_ns)"
        done
        i=$((i + 1))
    done
    ;;
entry)
    rounds=${1:?rounds}
    r=1
    while [ "$r" -le "$rounds" ]; do
        for kind in gpr fp; do
            for calls in 16 128; do
                for state in off on; do
                    if [ "$state" = on ]; then echo 1 > "$K/enable"; else echo 0 > "$K/enable"; fi
                    out=$("$T/entry_cost" "$kind" 4000 "$calls" 7) || { echo "$out"; fail "entry $state $kind $calls"; }
                    res=$(echo "$out" | sed -n 's/^result .* median_ns_per_outer=\([0-9.]*\) .*/\1/p')
                    ctr=$(echo "$out" | sed -n 's/^counters //p' | tr ' ' '\n' | grep -E '^fpsimd_(entries|preempted)=' | tr '\n' ' ' || true)
                    echo "fpb entry state=$state kind=$kind calls=$calls round=$r ns_per_outer=$res $ctr"
                done
            done
        done
        r=$((r + 1))
    done
    ;;
*)
    echo "fpb: unknown command $cmd" >&2
    exit 2
    ;;
esac
