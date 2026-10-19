#!/bin/sh
# EXPERIMENT (exp/attrib-a22). Fixed per-run path of the hook, one boot, hot loops. svc_bench getppid / raw_zn
# (a pure fragment: a few register words between two SVCs, so repeating it on a copy of pt_regs is exact)
# with the amplifiers of the instrumented module:
#   amptr    x_rep_tramp  N trampoline round trips into a stub per fragment run
#   ampcall  x_rep_call   N real fragment runs per hook call (trampoline + prologue + body + epilogue)
#   amprun   x_rep_run    N whole kjit_rs_after_syscall bodies per hook call (can_run, lookup, run, stats)
#   ampcr amplk ampsr amppan ampat   as attrib-a22.sh
# Rounds interleave all configurations; the slope in N is the cost of one repetition (ns).
#   micro-a22.sh [ROUNDS]
set -eu
. /opt/kjit-tests/k4-lib.sh
rounds=${1:-3}
k4_debugfs
xw() { echo "$2" > "$K/$1"; }
reset() { for k in canrun lookup srcu pan brk atomic tramp call run; do xw x_rep_$k 0; done; xw x_svcnative 0; xw x_decline 0; xw chain_budget 1024; }
echo "mic: cmdline: $(cat /proc/cmdline)"
echo "mic: meltdown: $(cat /sys/devices/system/cpu/vulnerabilities/meltdown)"
echo "mic: x_micro $(cat "$K/x_micro")"
echo "mic: x_micro $(cat "$K/x_micro")"
# bench MODE CONFIG: one svc_bench under the current knobs
bench() {
    KJIT_AUTO=0 "$T/svc_bench" "$1" 1 200000 7 > /tmp/mic.out 2>&1 || { tail -3 /tmp/mic.out; k4_fail "svc_bench $1 ($2)"; }
    echo "mic $2 $(grep '^result' /tmp/mic.out)"
}
cfg() { # NAME MODE
    reset
    # auto=0: svc_bench registers its SVC sites itself; the repeats on a copy of pt_regs must not feed the auto profiler
    echo 1 > "$K/enable"; echo 0 > "$K/auto"
    case "$1" in
        off) set_mode 0 ;;
        on) ;;
        svcn) xw x_svcnative 1 ;;
        decl1) xw x_decline 1 ;;
        decl2) xw x_decline 2 ;;
        amptr*) xw x_rep_tramp "${1#amptr}" ;;
        ampcall*) xw x_rep_call "${1#ampcall}" ;;
        amprun*) xw x_rep_run "${1#amprun}" ;;
        ampcr*) xw x_rep_canrun "${1#ampcr}" ;;
        amplk*) xw x_rep_lookup "${1#amplk}" ;;
        ampsr*) xw x_rep_srcu "${1#ampsr}" ;;
        amppan*) xw x_rep_pan "${1#amppan}" ;;
        ampat*) xw x_rep_atomic "${1#ampat}" ;;
        *) k4_fail "cfg $1" ;;
    esac
    bench "$2" "$1/$2"
}
r=1
while [ "$r" -le "$rounds" ]; do
    for mode in getppid raw_zn; do
        for c in off on svcn amptr32 amptr128 ampcall32 ampcall128 amprun16 amprun64 ampcr256 amplk64 ampsr64 amppan64 ampat64; do
            cfg "$c" "$mode"
        done
    done
    r=$((r + 1))
done
reset
# entry_cost (rootfs): a loop of one syscall and N calls; gpr and fp variants, off vs on
for c in 1 16 128; do
    for v in gpr fp; do
        for state in off on; do
            set_mode 0; [ "$state" = off ] || set_mode 1
            echo "mic entry_cost $state $v calls=$c $("$T/entry_cost" $v 20000 $c 5 2>&1 | grep -i 'result\|median' | tr '\n' ' ')"
        done
    done
done
set_mode 0
perl /kjit/wake-cost.pl 20000 200 5 2>&1 | sed 's/^/mic wake /'
echo "mic: done"
