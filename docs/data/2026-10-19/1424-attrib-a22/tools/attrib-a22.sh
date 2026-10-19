#!/bin/sh
# EXPERIMENT (exp/attrib-a22), not for main. Inside the kjit-guest with the instrumented kjit.ko
# (kjit_glue.c, "EXPERIMENT" block): server CPU per request of redis under the UB protocol, for a
# list of module STATES paired inside one boot. Derived from tests/guest/attrib-a17.sh of exp/attrib-a17
# and the cell syntax of a22-sweep.sh (unix sockets).
#
#   attrib-a22.sh OUTDIR REPS REQUESTS WARM ROT "CELL ..." "STATE ..."
#
# CELL = NAME:TEST:C:P:D:THR:XPORT:CCPUS   (redis-benchmark -t TEST -c C -P P -d D [--threads THR] -q,
#        THR 0 = flag absent; XPORT tcp|unix; CCPUS taskset list of the load generator, run under nojit).
# One redis-server (CPU 0, tcp port and a unix socket). Per CELL and rep every STATE runs once, the state order
# rotated by (rep - 1 + ROT). WARM requests follow every state change (not recorded).
#
# STATE (every state sets the module's knobs from scratch):
#   off      enable=0 auto=0                    on   enable=1 auto=1 chain_budget=1024
#   offT onT svcnT   the same / svcn with the module's timers on the server thread (x_pid)
#   svcn     on + x_svcnative=1: every SVC executes at EL0 (fragments still run in the kernel)
#   decl1    on + x_decline=1: the hook runs kjit_can_run, then returns to EL0 (all code native)
#   decl2    on + x_decline=2: ... and kjit_lookup
#   ampcr amplk ampsr amppan ampbr ampat amptr amplink ampcl   on + one amplifier (x_rep_*), 256/32/64/64/16/16/64/64/64 repeats
#                    (amplink, ampcl: the chain exit's label search + publish, and the publish of a linked lookup; instr2 module only)
#   offS onS  off / on with a SCHED_IDLE busy loop on CPU 0 (the vCPU never idles)
#   nostats<M>       on + x_nostats=M (instr3 module): bit 1 the runtime's counter updates, bit 2 the per-CPU hook_calls add,
#                    bit 4 the FP/SIMD bracket's two CNTVCT reads (fpsimd_run_max_ns); the counters are then not valid
#   offD<N> onD<N>   off / on + x_delay=N: a busy loop of N iterations at the start of every hook call
# With the plain module (no x_* files) only off and on are valid states; the micro items and the knob checks are skipped.
#
# Output lines (grep "^atr"), key=value:
#   atr seq cfg rep state test n rps wall_cs ticks_u ticks_s sched_ms nsw nvol ninv main_ms <KJIT counter deltas>
#   atrd seq stat_c<k>=... int_<id>_c<k>=... si_<NAME>_c<k>=...      per-CPU /proc deltas (nonzero)
#   atrx seq <timer key> <value>...                                   the module's timers (T states)
set -eu

. /opt/kjit-tests/k4-lib.sh

[ $# -eq 7 ] || { echo "usage: attrib-a22.sh OUTDIR REPS REQUESTS WARM ROT CELLS STATES" >&2; exit 2; }
work=$1
reps=$2
n=$3
warm=$4
rot=$5
cells=$6
states=$7
chain=1024
out=$work/atr.out
sock=/tmp/atr.sock

mkdir -p "$work"
cd "$work"
: > "$out"
k4_debugfs

counters="hook_calls syscalls_in_kernel fragment_entries fpsimd_entries chains chain_cap exit_svc exit_bl
exit_blr exit_br exit_ret exit_mem exit_unsupported exit_budget run_declined svc_declined translate_ok
invalidated_fragments ibtc_miss_cold ibtc_miss_conflict ibtc_miss_other ibtc_fpsimd_boundary"

emit() { echo "$*" | tee -a "$out"; }

xw() { echo "$2" > "$K/$1"; }

spin_pid=
spin_stop() {
    [ -z "$spin_pid" ] || { kill -9 "$spin_pid" 2> /dev/null || true; wait "$spin_pid" 2> /dev/null || true; }
    spin_pid=
}
reset_knobs() {
    if [ -z "$HAVEX" ]; then xw chain_budget "$chain"; return; fi
    xw x_delay 0
    [ ! -e "$K/x_rep_link" ] || { xw x_rep_link 0; xw x_rep_clookup 0; }
    [ ! -e "$K/x_nostats" ] || xw x_nostats 0
    xw x_pid 0
    xw x_svcnative 0
    xw x_decline 0
    for k in canrun lookup srcu pan brk atomic tramp call run; do xw x_rep_$k 0; done
    xw chain_budget "$chain"
}
HAVEX=
[ ! -e "$K/x_pid" ] || HAVEX=1
trap 'set +e; spin_stop; [ -d "$K" ] && { reset_knobs; set_mode 0; }' EXIT

cur_state=
timed=0
# set_state NAME: apply the state's knobs. Timers are armed in measure().
set_state() {
    cur_state=$1
    spin_stop
    reset_knobs
    timed=0
    case "$1" in
        off) set_mode 0 ;;
        offT) set_mode 0; timed=1 ;;
        offS) set_mode 0; spin_start ;;
        on) set_mode 1 ;;
        onT) set_mode 1; timed=1 ;;
        onS) set_mode 1; spin_start ;;
        svcn) set_mode 1; xw x_svcnative 1 ;;
        svcnT) set_mode 1; xw x_svcnative 1; timed=1 ;;
        decl1) set_mode 1; xw x_decline 1 ;;
        decl2) set_mode 1; xw x_decline 2 ;;
        ampcr) set_mode 1; xw x_rep_canrun 256 ;;
        amplk) set_mode 1; xw x_rep_lookup 32 ;;
        ampsr) set_mode 1; xw x_rep_srcu 64 ;;
        amppan) set_mode 1; xw x_rep_pan 64 ;;
        ampbr) set_mode 1; xw x_rep_brk 16 ;;
        ampat) set_mode 1; xw x_rep_atomic 16 ;;
        amptr) set_mode 1; xw x_rep_tramp 64 ;;
        nostats*) set_mode 1; xw x_nostats "${1#nostats}" ;;
        amplink) set_mode 1; xw x_rep_link 64 ;;
        ampcl) set_mode 1; xw x_rep_clookup 64 ;;
        offD*) set_mode 0; xw x_delay "${1#offD}" ;;
        onD*) set_mode 1; xw x_delay "${1#onD}" ;;
        *) k4_fail "unknown state $1" ;;
    esac
}
spin_start() {
    taskset -c 0 chrt -i 0 "$T/nojit" sh -c 'while :; do :; done' &
    spin_pid=$!
}

cfg_name= cfg_test= cfg_c= cfg_p= cfg_d= cfg_thr= cfg_xport= cfg_ccpus=
use_cell() {
    local IFS=:
    set -- $1
    [ $# -eq 8 ] || k4_fail "bad CELL '$*'"
    cfg_name=$1 cfg_test=$2 cfg_c=$3 cfg_p=$4 cfg_d=$5 cfg_thr=$6 cfg_xport=$7 cfg_ccpus=$8
    case "$cfg_xport" in tcp | unix) ;; *) k4_fail "bad XPORT '$cfg_xport'" ;; esac
}

bench_run() { # TEST REQUESTS
    local thr="" conn
    [ "$cfg_thr" = 0 ] || thr="--threads $cfg_thr"
    if [ "$cfg_xport" = unix ]; then conn="-s $sock"; else conn="-p $PORT"; fi
    # shellcheck disable=SC2086
    taskset -c "$cfg_ccpus" "$T/nojit" "$R/redis-benchmark" $conn -t "$1" -n "$2" -c "$cfg_c" -P "$cfg_p" \
        -d "$cfg_d" $thr -q > "$work/bench.out" 2>&1 || { tail "$work/bench.out"; k4_fail "benchmark $1 ($cfg_name)"; }
    rps=$(tr '\r' '\n' < "$work/bench.out" | awk '$0 ~ /requests per second/ {
        for (i = 2; i <= NF; i++) if ($i == "requests" && $(i + 1) == "per") v = $(i - 1) } END { print v }')
    [ -n "$rps" ] || { cat "$work/bench.out"; k4_fail "no requests/s for $1 ($cfg_name)"; }
}

snapall() {
    snap "$1"
    cp /proc/stat "$1.stat"
    cp /proc/interrupts "$1.int"
    cp /proc/softirqs "$1.si"
    cat /proc/"$server"/task/*/sched > "$1.sched"
    cp /proc/"$server"/sched "$1.main"
    cp /proc/"$server"/stat "$1.pstat"
}

schedsum() {
    awk '$1 == "se.sum_exec_runtime" { s += $3 } $1 == "nr_switches" { a += $3 }
         $1 == "nr_voluntary_switches" { v += $3 } $1 == "nr_involuntary_switches" { i += $3 }
         END { printf "%.6f %d %d %d\n", s, a, v, i }' "$1"
}
delta() {
    awk -v k="$1" -v f="$2" 'FILENAME == ARGV[1] && $1 == k { b = $f } FILENAME == ARGV[2] && $1 == k { a = $f }
        END { printf "%.6f", a - b }' "$3" "$4"
}
pdelta() { awk -v f="$1" 'FILENAME == ARGV[1] { b = $f } FILENAME == ARGV[2] { a = $f } END { printf "%d", a - b }' "$2" "$3"; }
diffcols() {
    awk -v p="$3" 'FILENAME == ARGV[1] { if ($1 ~ /:$/) for (k = 2; k <= 5; k++) b[$1, k] = $k; next }
        $1 ~ /:$/ { l = $1; sub(/:$/, "", l)
            for (k = 2; k <= 5; k++) if ($k ~ /^[0-9]+$/) { d = $k - b[$1, k]; if (d != 0) printf " %s_%s_c%d=%d", p, l, k - 2, d } }' "$1" "$2"
}
diffstat() {
    awk 'FILENAME == ARGV[1] { if ($1 ~ /^cpu[0-9]/) for (k = 2; k <= 9; k++) b[$1, k] = $k; next }
        $1 ~ /^cpu[0-9]/ { printf " stat_c%d=", substr($1, 4)
            for (k = 2; k <= 9; k++) printf "%s%d", (k > 2 ? ":" : ""), $k - b[$1, k] }' "$1" "$2"
}

seq=0
rep=0
measure() { # TEST
    local test=$1 t0 t1 line d c a b
    seq=$((seq + 1))
    sleep 0.3
    if [ "$timed" = 1 ]; then
        xw x_pid "$server"
        echo reset > "$K/x_timers"
    fi
    cli info stats | tr -d '\r' > "$work/b.info"
    snapall "$work/b"
    t0=$(awk '{ printf "%d", $1 * 100 }' /proc/uptime)
    bench_run "$test" "$n"
    t1=$(awk '{ printf "%d", $1 * 100 }' /proc/uptime)
    snapall "$work/a"
    cli info stats | tr -d '\r' > "$work/a.info"
    if [ "$timed" = 1 ]; then
        cp "$K/x_timers" "$work/x.out"
        xw x_pid 0
        emit "atrx seq=$seq $(tr '\n' ' ' < "$work/x.out")"
    fi
    a=$(schedsum "$work/a.sched")
    b=$(schedsum "$work/b.sched")
    line="atr seq=$seq cfg=$cfg_name rep=$rep state=$cur_state test=$test n=$n rps=$rps wall_cs=$((t1 - t0))"
    line="$line ticks_u=$(pdelta 14 "$work/b.pstat" "$work/a.pstat") ticks_s=$(pdelta 15 "$work/b.pstat" "$work/a.pstat")"
    line="$line $(echo "$b $a" | awk '{ printf "sched_ms=%.6f nsw=%d nvol=%d ninv=%d", $5 - $1, $6 - $2, $7 - $3, $8 - $4 }')"
    line="$line main_ms=$(delta se.sum_exec_runtime 3 "$work/b.main" "$work/a.main")"
    for c in $counters; do
        d=$(( $(stat_of "$work/a.stats" "$c") - $(stat_of "$work/b.stats" "$c") ))
        line="$line $c=$d"
    done
    # redis' own event loop counters (INFO stats): one eventloop cycle = one epoll_pwait of the server
    line="$line$(awk -F: 'FILENAME == ARGV[1] { b[$1] = $2; next }
        $1 == "eventloop_cycles" || $1 == "total_commands_processed" || $1 == "total_reads_processed" || $1 == "total_writes_processed" \
        { printf " ev_%s=%d", $1, $2 - b[$1] }' "$work/b.info" "$work/a.info")"
    emit "$line"
    emit "atrd seq=$seq$(diffstat "$work/b.stat" "$work/a.stat")$(diffcols "$work/b.int" "$work/a.int" int)$(diffcols "$work/b.si" "$work/a.si" si)"
    for c in exit_invalid translate_verify_rejected unsupported_bad_word; do
        d=$(( $(stat_of "$work/a.stats" "$c") - $(stat_of "$work/b.stats" "$c") ))
        [ "$d" = 0 ] || k4_fail "$cur_state $test ($cfg_name): runtime counter $c grew by $d"
    done
    d=$(( $(stat_of "$work/a.stats" fragment_entries) - $(stat_of "$work/b.stats" fragment_entries) ))
    case "$cur_state" in
        off* | decl1 | decl2)
            [ "$d" = 0 ] || k4_fail "$cur_state $test ($cfg_name): $d fragment entries" ;;
        nostats*) ;;	# counters are not updated: no check
        *)
            [ "$d" -gt 0 ] || k4_fail "$cur_state $test ($cfg_name): no fragment entry" ;;
    esac
}

emit "atr: cmdline: $(cat /proc/cmdline)"
emit "atr: kernel: $(uname -r) cpus: $(grep -c ^processor /proc/cpuinfo) redis: $("$R/redis-server" --version)"
emit "atr: reps=$reps n=$n warm=$warm rot=$rot chain_budget=$chain cells: $cells states: $states"
emit "atr: meltdown: $(cat /sys/devices/system/cpu/vulnerabilities/meltdown)"
emit "atr: kpti dmesg: $(dmesg | grep -i 'page table isolation' || echo none)"
emit "atr: module: $(cat "$K/hot_threshold") hot_threshold, $(cat "$K/hot_window_ms") hot_window_ms"
case "$states" in
    *T* | *svcn* | *decl* | *amp* | *S* | *D[0-9]* | *nostats*) [ -n "$HAVEX" ] || k4_fail "states $states need the instrumented module" ;;
esac
if [ -n "$HAVEX" ]; then
    for f in x_pid x_timers x_svcnative x_decline x_rep_canrun x_rep_lookup x_rep_srcu x_rep_pan x_rep_brk x_rep_atomic x_rep_tramp x_delay x_micro; do
        [ -e "$K/$f" ] || k4_fail "$K/$f missing (kjit.ko without the attribution instrumentation?)"
    done
fi

# One-time micro measurements (KJIT off): the module's hot-loop ns, the null syscall, the x_delay loop.
set_state off
if [ -n "$HAVEX" ]; then
    emit "atr: x_micro $(cat "$K/x_micro")"
    emit "atr: x_micro $(cat "$K/x_micro")"
fi
for m in "getppid 1" "raw_zn 1" "getppid 1" "raw_zn 1"; do
    emit "atr: svc_bench $("$T/svc_bench" $m 200000 5 2>&1 | grep '^result' | tr '\n' ' ')"
done
if [ -n "$HAVEX" ]; then
    for d in 0 1000 4000 0 1000 4000; do
        xw x_delay $d
        emit "atr: x_delay $d svc_bench $("$T/svc_bench" getppid 1 200000 5 2>&1 | grep '^result' | tr '\n' ' ')"
    done
    xw x_delay 0
fi

set -- $cells
use_cell "$1"
set_state on
start_server "$work/srv" --unixsocket "$sock" --unixsocketperm 777
taskset -a -pc 0 "$server" > /dev/null
emit "atr: server $server tasks allowed CPUs: $(cat /proc/"$server"/task/*/status | awk '/^Cpus_allowed_list/ { print $2 }' | sort | uniq -c | tr '\n' ' ')"

nstates=$(echo $states | wc -w)
for cell in $cells; do
    use_cell "$cell"
    set_state on
    if [ "$cfg_test" = get ]; then bench_run set 5000; fi
    bench_run "$cfg_test" "$n"
    emit "atr: cell $cfg_name translate_ok after warm-up: $(stat_of "$K/stats" translate_ok)"
    bench_run "$cfg_test" "$warm"
    rep=1
    while [ "$rep" -le "$reps" ]; do
        r=$(( (rep - 1 + rot) % nstates ))
        first=$(echo $states | cut -d' ' -f$((r + 1))-)
        last=
        [ "$r" = 0 ] || last=$(echo $states | cut -d' ' -f1-"$r")
        for s in $first $last; do
            set_state "$s"
            bench_run "$cfg_test" "$warm"
            measure "$cfg_test"
        done
        rep=$((rep + 1))
    done
done
set_state off
cp "$K/stats" "$work/stats.end"
cat "$K/x_frags" > /kjit/frags.txt 2> /dev/null || true
cp "$K/stats" /kjit/stats.end 2> /dev/null || true
stop_server
emit "atr: done"
