#!/bin/sh
# K2 guest test suite (runs inside the kjit-guest; binaries in /opt/kjit-tests).
#
#   run-k2.sh [--auto] [iterations]
#
# --auto: the K3 auto mode translates hot code (debugfs auto=1 for the enabled
# runs, KJIT_AUTO=1 for the tests): no test registers itself.
# K2_LEAVE_HOT=0 skips leaving a hot process behind for the rmmod check.
#
# Every test runs with KJIT disabled and enabled (/sys/kernel/debug/kjit/enable);
# stdout and the exit status must be identical, and the enabled run must show
# the expected KJIT activity (in-kernel syscalls, Mem/Budget exits, or none at
# all for declined processes). Exits non-zero on the first failure. Prints
# "k2: ALL PASS" and the final stats at the end.
set -eu

auto=0
if [ "${1:-}" = --auto ]; then
    auto=1
    shift
fi
iterations=${1:-1}
T=/opt/kjit-tests
K=/sys/kernel/debug/kjit

grep -q " /sys/kernel/debug debugfs" /proc/mounts || mount -t debugfs debugfs /sys/kernel/debug
[ -d "$K" ] || { echo "k2: $K missing (kjit.ko not loaded?)"; exit 1; }
work=$(mktemp -d)
cd "$work"

fail() {
    echo "k2: FAIL $*"
    for f in *.out *.err; do
        [ -f "$f" ] && { echo "--- $f"; cat "$f"; }
    done
    exit 1
}

stat() { awk -v k="$1" '$1 == k { print $2 }' "$K/stats"; }

# run NAME ENABLE EXPECT CMD...: stdout -> NAME.ENABLE.out, stderr -> .err,
# status -> NAME.ENABLE.status.
run() {
    local name=$1 enable=$2 expect=$3
    shift 3
    echo "$enable" > "$K/enable"
    if [ "$enable" = 1 ]; then echo "$auto" > "$K/auto"; else echo 0 > "$K/auto"; fi
    set +e
    # No timeout(1) wrapper: the tests' getppid results must see the same
    # parent (this shell) in both runs. guest-run's QEMU timeout bounds hangs.
    if [ "$enable" = 1 ]; then
        KJIT_AUTO=$auto KJIT_EXPECT="$expect" "$@" > "$name.$enable.out" 2> "$name.$enable.err"
    else
        KJIT_AUTO=$auto "$@" > "$name.$enable.out" 2> "$name.$enable.err"
    fi
    echo $? > "$name.$enable.status"
    set -e
}

# onoff NAME EXPECT WANT_STATUS CMD...: identical output/status off and on.
onoff() {
    local name=$1 expect=$2 want=$3 e got
    shift 3
    run "$name" 0 "" "$@"
    run "$name" 1 "$expect" "$@"
    for e in 0 1; do
        got=$(cat "$name.$e.status")
        [ "$got" = "$want" ] || fail "$name (enable=$e): exit status $got, want $want"
    done
    cmp -s "$name.0.out" "$name.1.out" || fail "$name: output differs with KJIT on/off"
    [ -s "$name.1.out" ] || fail "$name: no output"
    sed "s/^/k2:   /" "$name.1.err"
}

kill_hot() {
    local name=$1 before pid hot status
    shift
    echo 1 > "$K/enable"
    echo "$auto" > "$K/auto"
    before=$(stat fragment_entries)
    KJIT_AUTO=$auto "$@" > "$name.kill.out" 2> "$name.kill.err" &
    pid=$!
    sleep 1
    hot=$(( $(stat fragment_entries) - before ))
    kill -9 "$pid"
    set +e
    wait "$pid"
    status=$?
    set -e
    [ "$status" = 137 ] || fail "$name: kill -9 while hot: status $status, want 137"
    [ "$hot" -gt 1000 ] || fail "$name: not hot before kill ($hot fragment entries)"
}

i=1
while [ "$i" -le "$iterations" ]; do
    rm -f ./*.out ./*.err ./*.status

    onoff toy_loop inkernel 0 "$T/toy_loop" 100000
    grep -q "syscalls in kernel" toy_loop.1.err || fail "toy_loop: the in-kernel check did not run"

    onoff mem_loop inkernel 0 "$T/mem_loop" 20000

    for mode in null unmapped readonly; do
        before=$(stat exit_mem)
        onoff "fault_segv_$mode" "" 0 "$T/fault_segv" "$mode"
        mem=$(( $(stat exit_mem) - before ))
        grep -q "addr_ok 1 pc_ok 1 iters_left 0" "fault_segv_$mode.1.out" \
            || fail "fault_segv $mode: wrong siginfo"
        [ "$mem" -ge 1 ] || fail "fault_segv $mode: no Mem exit ($mem)"
    done

    before=$(stat exit_mem)
    onoff fork_cow "" 0 "$T/fork_cow"
    mem=$(( $(stat exit_mem) - before ))
    [ "$mem" = 0 ] || fail "fork_cow: $mem Mem exits (CoW must not fault out)"
    grep -q "child" fork_cow.1.out || fail "fork_cow: no child output"

    onoff tight_loop budget 0 "$T/tight_loop" 2000

    onoff signal_loop inkernel 0 "$T/signal_loop" 200000
    grep -q "handled=1" signal_loop.1.out || fail "signal_loop: no signal handled"

    # A9b: fragments that use the user's FP/SIMD registers.
    onoff fp_loop fpsimd 0 "$T/fp_loop" 20000
    onoff fp_regs fpsimd 0 "$T/fp_regs" 100000
    before=$(stat fpsimd_restores)
    onoff fp_switch fpsimd 0 "$T/fp_switch" 20000
    restores=$(( $(stat fpsimd_restores) - before ))
    [ "$restores" -ge 1 ] || fail "fp_switch: no FP/SIMD state reload"
    onoff fp_signal fpsimd 0 "$T/fp_signal" 200000
    grep -q "handled=1" fp_signal.1.out || fail "fp_signal: no signal handled"
    for mode in ro_store unmapped_load null_ld1; do
        before=$(stat fpsimd_exit_mem)
        onoff "fp_fault_$mode" "" 0 "$T/fp_fault" "$mode"
        mem=$(( $(stat fpsimd_exit_mem) - before ))
        grep -q "addr_ok 1 pc_ok 1 iters_left 0" "fp_fault_$mode.1.out" \
            || fail "fp_fault $mode: wrong siginfo"
        [ "$mem" -ge 1 ] || fail "fp_fault $mode: no FP/SIMD Mem exit ($mem)"
    done
    before=$(stat fpsimd_exit_mem)
    onoff fp_fault_demand "" 0 "$T/fp_fault" demand
    mem=$(( $(stat fpsimd_exit_mem) - before ))
    [ "$mem" -ge 100 ] || fail "fp_fault demand: $mem FP/SIMD Mem exits, want one per first touch"
    echo "k2:   fpsimd_run_max_ns=$(stat fpsimd_run_max_ns) before fp_budget"
    onoff fp_budget budget 0 "$T/fp_budget" 400
    echo "k2:   fpsimd_run_max_ns=$(stat fpsimd_run_max_ns) after fp_budget"

    before=$(stat invalidated_fragments)
    onoff munmap_race inkernel 139 "$T/munmap_race"
    inval=$(( $(stat invalidated_fragments) - before ))
    [ "$inval" -ge 1 ] || fail "munmap_race: no fragment invalidated"

    onoff seccomp_loop declined 0 "$T/seccomp_loop" 20000
    onoff ptrace_loop declined 0 "$T/ptrace_loop" 20000

    kill_hot toy_loop_kill "$T/toy_loop" 0
    kill_hot tight_loop_kill "$T/tight_loop" 0

    echo "k2: iteration $i PASS"
    i=$((i + 1))
done

echo 1 > "$K/enable"
echo "k2: stats"
sed 's/^/k2:   /' "$K/stats"
echo "k2: ALL PASS ($iterations iterations, auto=$auto)"

# Module unload safety: leave a hot process running. The guest's /init
# unloads kjit.ko after this script (it must succeed while the process is in
# its in-kernel syscall loop) and powers off.
if [ "${K2_LEAVE_HOT:-1}" = 1 ]; then
    echo "$auto" > "$K/auto"
    KJIT_AUTO=$auto "$T/toy_loop" 0 > /dev/null 2>&1 &
    sleep 1
    echo "k2: left toy_loop $! hot for rmmod ($(stat syscalls_in_kernel) syscalls in kernel so far)"
fi
