#!/bin/sh
# Userspace-bypass comparison runs inside the kjit-guest (one boot):
#
#   ub-bench.sh sys [REPS]    null syscall and small read/write loops (svc_bench), KJIT off then on
#   ub-bench.sh code [REPS]   translated-code speed (code_speed), KJIT off then on
#   ub-bench.sh foot [REPS]   the same for a growing code footprint (code_speed foot)
#
# Per configuration the program runs with KJIT disabled (debugfs enable=0 auto=0)
# and enabled (enable=1 auto=1, chain_budget 1024, KJIT_AUTO=1), alternating, so
# slow host drift hits both. Every line of the programs goes to stdout, prefixed
# "ub <state> " (state off|on); the header lines name the kernel command line
# and the KPTI state ("ub: meltdown: ..."), so a log says what it measured.
# Fails (set -e) when a program fails, e.g. when KJIT-on work did not run in
# fragments.
set -eu

T=/opt/kjit-tests
K=/sys/kernel/debug/kjit
what=${1:-}
reps=${2:-7}

grep -q " /sys/kernel/debug debugfs" /proc/mounts || mount -t debugfs debugfs /sys/kernel/debug

echo "ub: cmdline: $(cat /proc/cmdline)"
echo "ub: meltdown: $(cat /sys/devices/system/cpu/vulnerabilities/meltdown)"
echo "ub: spectre_v2: $(cat /sys/devices/system/cpu/vulnerabilities/spectre_v2)"
echo "ub: kpti dmesg: $(dmesg | grep -i 'page table isolation' || echo none)"
echo "ub: kernel: $(uname -r) cpus: $(grep -c ^processor /proc/cpuinfo)"
if [ -d "$K" ]; then
    echo "ub: chain_budget: $(cat $K/chain_budget) hot_threshold: $(cat $K/hot_threshold)"
else
    echo "ub: kjit module not loaded"
fi

# run STATE PROGRAM ARGS...: STATE off|on.
run() {
    state=$1
    shift
    if [ -d "$K" ]; then
        if [ "$state" = on ]; then
            echo 1024 > "$K/chain_budget"
            echo 1 > "$K/enable"
            echo 1 > "$K/auto"
        else
            echo 0 > "$K/enable"
            echo 0 > "$K/auto"
        fi
    fi
    # nojit is not used: the program's own syscalls are the workload.
    # A pipe would hide the program's exit status (no pipefail in this sh).
    rc=0
    KJIT_AUTO=$([ "$state" = on ] && echo 1 || echo 0) "$@" > /tmp/ub.out 2>&1 || rc=$?
    sed "s/^/ub $state /" /tmp/ub.out
    [ "$rc" = 0 ] || { echo "ub: FAIL ($state) $* exit=$rc"; exit 1; }
}

both() {
    run off "$@"
    run on "$@"
}

case "$what" in
sys)
    both $T/svc_bench getppid 1 200000 "$reps"
    both $T/svc_bench raw_zn 1 200000 "$reps"
    both $T/svc_bench raw_pipe 1 200000 "$reps"
    for size in 1 16 64; do
        both $T/svc_bench zn "$size" 200000 "$reps"
        both $T/svc_bench pipe "$size" 200000 "$reps"
    done
    ;;
code)
    for n in 128 256 512 1024 2048; do both $T/code_speed hash "$n" 40 "$reps"; done
    for n in 256 512 1024 2048 3072; do both $T/code_speed strlen "$n" 40 "$reps"; done
    for n in 128 256 512 1024 2048; do both $T/code_speed copy "$n" 40 "$reps"; done
    for n in 512 1024 2048 4096; do both $T/code_speed copy16 "$n" 40 "$reps"; done
    for n in 512 1024 2048 4096; do both $T/code_speed simd32 "$n" 40 "$reps"; done
    for n in 64 128 256 512 1000; do both $T/code_speed calls "$n" 40 "$reps"; done
    for n in 64 128 256 512 1000; do both $T/code_speed callsi "$n" 40 "$reps"; done
    for n in 40 80 160 320 600; do both $T/code_speed calls2 "$n" 40 "$reps"; done
    ;;
foot)
    for n in 16 32 64 96 128; do both $T/code_speed foot "$n" 40 "$reps"; done
    for n in 16 32 64 96 128; do both $T/code_speed footl "$n" 40 "$reps"; done
    ;;
*)
    echo "usage: ub-bench.sh sys|code|foot [REPS]" >&2
    exit 2
    ;;
esac
echo "ub: done"
