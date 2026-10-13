#!/bin/sh
# EXPERIMENT (exp/c1): redis -c 1 overhead. c1-sweep.sh (exp/conditions) with ablation states,
# a spinner option, and full counter / softirq / context-switch deltas per run.
#
#   c1-sweep.sh WORKDIR REPS CELL...        STATES="off on ..." in the environment
#
# A state is BASE[+MOD...]: BASE off|on; MOD spin (a SCHED_IDLE busy loop on CPU 0 for the run, so
# CPU 0 never idles) or KNOB[=VAL] (writes VAL, default 1, to debugfs kjit/x_KNOB for the run; all
# x_ knobs are cleared to 0 between runs). Unknown knob = fail.
#
# CELL = NAME:SRV:TEST:N:C:P:D:THR:SCPUS:CCPUS:XPORT
#   SRV     server profile: base | aof_always | aof_everysec | aof_no | aof9p_always | unix | iot2
#   TEST    redis-benchmark -t value (set get incr lpush ping_inline ping_mbulk mset ...), or
#           pub<N><l|r>: PUBLISH to channel ch with N redis-cli subscribers on the server (l) or client (r) CPUs
#   N       -n requests per measured run
#   C       -c clients;  P  -P pipeline;  D  -d value size
#   THR     --threads (0 = flag absent)
#   SCPUS   taskset list of every server task;  CCPUS  taskset list of the load generator
#   XPORT   tcp | unix (unix: redis-benchmark -s; needs SRV=unix)
# Cells with the same SRV must be adjacent: one redis-server per run of equal SRV values.
# Per cell: (GET only) a SET to create the key, then one unrecorded run of min(N,200000)
# requests per state, then REPS reps; a rep is one run per state, off,on in odd reps and
# on,off in even reps. Off = enable=0 auto=0; on = enable=1 auto=1 chain_budget=1024.
# Before the first cell of a server, one unrecorded run at on with that cell's parameters.
#
# Per run, one stdout line (also appended to $WORKDIR/cond.out), "cond run":
#   cell= srv= test= n= c= p= d= thr= subs= rep= order= state= rps= wall_cs=
#   ticks_u= ticks_s=            /proc/PID/stat utime stime (USER_HZ ticks, thread group)
#   sched_ms= nvol= ninv=        sum of se.sum_exec_runtime (ms) and context switches over /proc/PID/task/*/sched
#   c0_busy= c0_idle=            ticks of CPU 0 in /proc/stat (busy = all but idle, iowait)
#   ipi_c0= ipi_other=           IPI interrupts received, CPU 0 and CPUs 1-3 (/proc/interrupts)
#   <KJIT counter>=<delta> ...
# After each cell one "cond unsup cell=<name> <word>(exits/entry_stops) ..." line: the most frequent
# Unsupported words (unsupported_top delta over the cell, warm-ups included).
# Exits non-zero when a run reports no throughput, a KJIT-on run shows no fragment entry, a
# KJIT-off run shows one, or the runtime reports an invalid exit or a verifier rejection.
set -eu

. /opt/kjit-tests/k4-lib.sh

[ $# -ge 3 ] || { echo "usage: c1-sweep.sh WORKDIR REPS CELL..." >&2; exit 2; }
work=$1
reps=$2
shift 2
cells="$*"
chain=1024
STATES=${STATES:-off on}
out=$work/cond.out
sock=/tmp/cond.sock

mkdir -p "$work"
cd "$work"
: > "$out"
k4_debugfs
for f in enable auto chain_budget stats; do
    [ -f "$K/$f" ] || k4_fail "$K/$f missing"
done

counters="hook_calls syscalls_in_kernel fragment_entries exit_svc exit_bl exit_blr exit_br exit_ret
exit_mem exit_unsupported exit_budget run_declined svc_declined fpsimd_entries translate_ok
invalidated_fragments"

orig_budget=$(cat "$K/chain_budget")
trap 'spin_stop; x_clear; echo "$orig_budget" > "$K/chain_budget"; set_mode 0' EXIT

emit() { echo "$*" | tee -a "$out"; }

spin_pid=
spin_stop() {
    [ -z "$spin_pid" ] || { kill -9 "$spin_pid" 2> /dev/null || true; wait "$spin_pid" 2> /dev/null || true; }
    spin_pid=
}
x_clear() {
    local f
    for f in "$K"/x_*; do
        [ -f "$f" ] || continue
        case "$f" in */x_stats) continue ;; esac
        echo 0 > "$f"
    done
}
# set_state STATE: configure KJIT (and the spinner) for one run; see the header.
set_state() {
    local base mods m k v
    spin_stop
    x_clear
    base=${1%%+*}
    mods=
    [ "$base" = "$1" ] || mods=${1#*+}
    if [ "$base" = off ]; then
        set_mode 0
    else
        [ "$base" = on ] || k4_fail "bad state '$1'"
        echo "$chain" > "$K/chain_budget"
        [ "$(cat "$K/chain_budget")" = "$chain" ] || k4_fail "chain_budget did not become $chain"
        set_mode 1
    fi
    IFS=+
    for m in $mods; do
        unset IFS
        case "$m" in
            spin)
                taskset -c 0 chrt -i 0 "$T/nojit" sh -c 'while :; do :; done' &
                spin_pid=$!
                ;;
            time) echo "$server" > "$K/x_pid" ;;
            *)
                k=${m%%=*}
                v=1
                [ "$k" = "$m" ] || v=${m#*=}
                [ -f "$K/x_$k" ] || k4_fail "no knob x_$k in state '$1'"
                echo "$v" > "$K/x_$k"
                ;;
        esac
        IFS=+
    done
    unset IFS
}

cfg_name= cfg_srv= cfg_test= cfg_n= cfg_c= cfg_p= cfg_d= cfg_thr= cfg_scpus= cfg_ccpus= cfg_xport=
use_cell() {
    local IFS=:
    set -- $1
    [ $# -eq 11 ] || k4_fail "bad CELL '$*'"
    cfg_name=$1 cfg_srv=$2 cfg_test=$3 cfg_n=$4 cfg_c=$5 cfg_p=$6 cfg_d=$7 cfg_thr=$8
    cfg_scpus=$9 cfg_ccpus=${10} cfg_xport=${11}
    case "$cfg_xport" in tcp | unix) ;; *) k4_fail "bad XPORT '$cfg_xport'" ;; esac
}

# srv_start SRV: starts $server for the profile (sets $srv_dir).
srv_start() {
    srv_dir=$work/srv
    case "$1" in
        base) start_server "$srv_dir" ;;
        aof_always) start_server "$srv_dir" --appendonly yes --appendfsync always --auto-aof-rewrite-percentage 0 ;;
        aof_everysec) start_server "$srv_dir" --appendonly yes --appendfsync everysec --auto-aof-rewrite-percentage 0 ;;
        aof_no) start_server "$srv_dir" --appendonly yes --appendfsync no --auto-aof-rewrite-percentage 0 ;;
        aof9p_always)
            # The data directory is on the 9p share: fsync and write go to the host.
            srv_dir=/kjit/cond-srv-9p
            rm -rf "$srv_dir"
            start_server "$srv_dir" --appendonly yes --appendfsync always --auto-aof-rewrite-percentage 0
            ;;
        unix) start_server "$srv_dir" --unixsocket "$sock" --unixsocketperm 777 ;;
        iot2) start_server "$srv_dir" --io-threads 2 --io-threads-do-reads yes ;;
        *) k4_fail "bad SRV '$1'" ;;
    esac
}

# srv_stop SRV
srv_stop() {
    stop_server
    case "$1" in aof9p_always) rm -rf /kjit/cond-srv-9p ;; esac
    rm -rf "$work/srv" "$sock"
}

# bench_run TEST REQUESTS: one redis-benchmark run with the current cell; sets $rps.
# TEST pub<N><l|r>: PUBLISH ch x with N subscribers (see subs_start).
bench_run() {
    local thr="" conn tflag="-t $1" tail=""
    [ "$cfg_thr" = 0 ] || thr="--threads $cfg_thr"
    if [ "$cfg_xport" = unix ]; then conn="-s $sock"; else conn="-p $PORT"; fi
    case "$1" in pub*) tflag="" tail="PUBLISH ch x" ;; esac
    # shellcheck disable=SC2086
    taskset -c "$cfg_ccpus" "$T/nojit" "$R/redis-benchmark" $conn $tflag -n "$2" -c "$cfg_c" \
        -P "$cfg_p" -d "$cfg_d" $thr -q $tail > "$work/bench.out" 2>&1 || { tail "$work/bench.out"; k4_fail "benchmark $1 ($cfg_name)"; }
    # The last "<n> requests per second" of the -q output (titles differ: "MSET (10 keys):").
    rps=$(tr '\r' '\n' < "$work/bench.out" | awk '$0 ~ /requests per second/ {
        for (i = 2; i <= NF; i++) if ($i == "requests" && $(i + 1) == "per") v = $(i - 1) } END { print v }')
    [ -n "$rps" ] || { cat "$work/bench.out"; k4_fail "no requests/s for $1 ($cfg_name)"; }
}

# subs_start / subs_stop: for TEST pub<N><l|r>, N redis-cli subscribers of channel ch (under nojit,
# output to /dev/null) on the server CPUs (l: local wake-ups) or the client CPUs (r: remote).
subs=0 subpids=
subs_start() {
    local spec cnt side cpus i
    case "$cfg_test" in pub*) ;; *) return 0 ;; esac
    spec=${cfg_test#pub}
    side=${spec##*[0-9]}
    cnt=${spec%"$side"}
    case "$side" in l) cpus=$cfg_scpus ;; r) cpus=$cfg_ccpus ;; *) k4_fail "bad TEST $cfg_test" ;; esac
    i=0
    while [ "$i" -lt "$cnt" ]; do
        taskset -c "$cpus" "$T/nojit" "$R/redis-cli" -p "$PORT" subscribe ch > /dev/null 2>&1 &
        subpids="$subpids $!"
        i=$((i + 1))
    done
    until [ "$(cli pubsub numsub ch | tail -1 | tr -d '\r')" = "$cnt" ]; do sleep 0.1; done
    subs=$cnt
}
subs_stop() {
    [ -z "$subpids" ] || kill $subpids 2> /dev/null || true
    for p in $subpids; do wait "$p" 2> /dev/null || true; done
    subpids= subs=0
}

snapall() {
    snap "$1"
    cp /proc/stat "$1.stat"
    grep '^ctxt' /proc/stat > "$1.stat.ctxt"
    cp /proc/interrupts "$1.int"
    cp /proc/softirqs "$1.sirq"
    cat /proc/"$server"/task/*/sched > "$1.sched"
    cp /proc/"$server"/stat "$1.pstat"
}

pdelta() { awk -v f="$1" 'FILENAME == ARGV[1] { b = $f } FILENAME == ARGV[2] { a = $f } END { printf "%d", a - b }' "$2" "$3"; }

# schedsum FILE: sum_exec_runtime (ms) nr_voluntary nr_involuntary summed over the tasks.
schedsum() {
    awk '$1 == "se.sum_exec_runtime" { s += $3 } $1 == "nr_voluntary_switches" { v += $3 }
         $1 == "nr_involuntary_switches" { i += $3 } END { printf "%.6f %d %d\n", s, v, i }' "$1"
}

# cpu0 BEFORE AFTER: "busy idle" ticks of CPU 0.
cpu0() {
    awk 'FILENAME == ARGV[1] && $1 == "cpu0" { for (k = 2; k <= 9; k++) b[k] = $k }
         FILENAME == ARGV[2] && $1 == "cpu0" { for (k = 2; k <= 9; k++) d[k] = $k - b[k]
             printf "%d %d\n", d[2] + d[3] + d[4] + d[7] + d[8] + d[9], d[5] + d[6] }' "$1" "$2"
}

# ipis BEFORE AFTER: "ipi_c0 ipi_other": IPI rows of /proc/interrupts, CPU 0 and CPUs 1-3.
ipis() {
    awk 'FILENAME == ARGV[1] { if ($1 ~ /^IPI/) for (k = 2; k <= 5; k++) b[$1, k] = $k; next }
         $1 ~ /^IPI/ { for (k = 2; k <= 5; k++) { d = $k - b[$1, k]; if (k == 2) c0 += d; else o += d } }
         END { printf "%d %d\n", c0, o }' "$1" "$2"
}

measure() {
    local order=$1 rep=$2 state=$3 t0 t1 line d c a b x
    sleep 0.5
    if [ -f "$K/x_stats" ]; then echo reset > "$K/x_stats"; fi
    snapall "$work/b"
    t0=$(awk '{ printf "%d", $1 * 100 }' /proc/uptime)
    bench_run "$cfg_test" "$cfg_n"
    t1=$(awk '{ printf "%d", $1 * 100 }' /proc/uptime)
    snapall "$work/a"
    a=$(schedsum "$work/a.sched")
    b=$(schedsum "$work/b.sched")
    line="cond run cell=$cfg_name srv=$cfg_srv test=$cfg_test n=$cfg_n c=$cfg_c p=$cfg_p d=$cfg_d thr=$cfg_thr subs=$subs"
    line="$line rep=$rep order=$order state=$state rps=$rps wall_cs=$((t1 - t0))"
    line="$line ticks_u=$(pdelta 14 "$work/b.pstat" "$work/a.pstat") ticks_s=$(pdelta 15 "$work/b.pstat" "$work/a.pstat")"
    line="$line $(echo "$b $a" | awk '{ printf "sched_ms=%.6f nvol=%d ninv=%d", $4 - $1, $5 - $2, $6 - $3 }')"
    x=$(cpu0 "$work/b.stat" "$work/a.stat")
    line="$line c0_busy=${x% *} c0_idle=${x#* }"
    x=$(ipis "$work/b.int" "$work/a.int")
    line="$line ipi_c0=${x% *} ipi_other=${x#* }"
    for c in $counters; do
        d=$(( $(stat_of "$work/a.stats" "$c") - $(stat_of "$work/b.stats" "$c") ))
        line="$line $c=$d"
    done
    # Every other counter that moved, and context switches / softirqs of the whole system.
    line="$line $(awk 'FILENAME == ARGV[1] { b[$1] = $2; next } $1 ~ /^(chain_max|fpsimd_run_max_ns)$/ { next }
        $2 != b[$1] && $1 !~ /^chain_hist/ { printf "k_%s=%d ", $1, $2 - b[$1] }' "$work/b.stats" "$work/a.stats")"
    line="$line ctxt=$(pdelta 2 "$work/b.stat.ctxt" "$work/a.stat.ctxt")"
    line="$line $(awk 'FILENAME == ARGV[1] { for (k = 2; k <= 5; k++) b[$1, k] = $k; next }
        $1 ~ /:$/ { t = 0; for (k = 2; k <= 5; k++) t += $k - b[$1, k]; printf "sirq_%s=%d ", tolower(substr($1, 1, length($1) - 1)), t }' "$work/b.sirq" "$work/a.sirq")"
    line="$line $(awk 'FILENAME == ARGV[1] { if ($1 ~ /^([0-9]+|IPI[0-9]):$/) for (k = 2; k <= 5; k++) b[$1, k] = $k; next }
        ($1 ~ /^([0-9]+|IPI[0-9]):$/) { t = 0; for (k = 2; k <= 5; k++) t += $k - b[$1, k]; if (t > 0) printf "irq%s=%d ", substr($1, 1, length($1) - 1), t }' "$work/b.int" "$work/a.int")"
    emit "$line"
    if [ -f "$K/x_pid" ] && [ "$(cat "$K/x_pid")" != 0 ]; then
        emit "cond xstats cell=$cfg_name rep=$rep state=$state $(tr '\n' ';' < "$K/x_stats")"
    fi
    for c in exit_invalid translate_verify_rejected unsupported_bad_word; do
        d=$(( $(stat_of "$work/a.stats" "$c") - $(stat_of "$work/b.stats" "$c") ))
        [ "$d" = 0 ] || k4_fail "$state $cfg_test ($cfg_name): runtime counter $c grew by $d"
    done
    d=$(( $(stat_of "$work/a.stats" fragment_entries) - $(stat_of "$work/b.stats" fragment_entries) ))
    if [ "${state%%+*}" = off ]; then
        [ "$d" = 0 ] || k4_fail "$state $cfg_test ($cfg_name): $d fragment entries with KJIT off"
    else
        case "$state" in *decline* | *guard*) ;; *) [ "$d" -gt 0 ] || k4_fail "$state $cfg_test ($cfg_name): no fragment entry with KJIT on" ;; esac
    fi
}

emit "cond: cmdline: $(cat /proc/cmdline)"
emit "cond: kernel: $(uname -r) cpus: $(grep -c ^processor /proc/cpuinfo) redis: $("$R/redis-server" --version)"
emit "cond: states=$STATES"
emit "cond: reps=$reps chain_budget=$chain hz_ticks=$(getconf CLK_TCK) cells: $cells"
emit "cond: module: $(cat "$K/hot_threshold") hot_threshold, $(cat "$K/hot_window_ms") hot_window_ms"

prev_srv=
for cell in $cells; do
    use_cell "$cell"
    if [ "$cfg_srv" != "$prev_srv" ]; then
        [ -z "$prev_srv" ] || srv_stop "$prev_srv"
        set_state on
        srv_start "$cfg_srv"
        prev_srv=$cfg_srv
        server_first=1
    else
        server_first=0
    fi
    taskset -a -pc "$cfg_scpus" "$server" > /dev/null
    emit "cond: cell $cfg_name: server tasks allowed CPUs: $(cat /proc/"$server"/task/*/status | awk '/^Cpus_allowed_list/ { print $2 }' | sort | uniq -c | tr '\n' ' ')"
    set_state on
    snap "$work/cellb"
    subs_start
    if [ "$cfg_test" = get ]; then bench_run set 5000; fi
    if [ "$server_first" = 1 ]; then
        bench_run "$cfg_test" "$cfg_n"
        emit "cond: translate_ok after server warm-up: $(stat_of "$K/stats" translate_ok)"
    fi
    warm=$cfg_n
    [ "$warm" -le 200000 ] || warm=200000
    for state in $STATES; do
        set_state "$state"
        bench_run "$cfg_test" "$warm"
    done
    rep=1
    while [ "$rep" -le "$reps" ]; do
        # Rotate the state order left by (rep - 1).
        states=$(echo "$STATES" | awk -v r="$rep" '{ n = NF; for (i = 0; i < n; i++) printf "%s ", $(((i + r - 1) % n) + 1) }')
        order=$(echo $states | tr ' ' ',')
        for state in $states; do
            set_state "$state"
            measure "$order" "$rep" "$state"
        done
        rep=$((rep + 1))
    done
    subs_stop
    # The stopping words of the cell (warm-ups included): word(exits/entry_stops).
    snap "$work/cella"
    emit "cond unsup cell=$cfg_name $(awk 'FILENAME == ARGV[1] { e[$1] = $2; s[$1] = $3; next }
        { de = $2 - e[$1]; ds = $3 - s[$1]; if (de + ds > 0) printf "%d %s(%d/%d)\n", de + ds, $1, de, ds }' \
        "$work/cellb.unsup" "$work/cella.unsup" | sort -rn | head -6 | cut -d' ' -f2 | tr '\n' ' ')"
done
set_mode 0
srv_stop "$prev_srv"
emit "cond: done"
