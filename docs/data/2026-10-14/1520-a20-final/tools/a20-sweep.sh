#!/bin/sh
# A20 measurement (derived from tests/guest/cond-sweep.sh of branch exp/win-map): redis server CPU per
# request, three states paired in one boot: off, main (module of dc1b962) and a20 (module of
# feat/a20-paths). Both modules are in /kjit (kjit-main.ko, kjit-a20.ko); /kjit/kjit.ko, the one init
# loaded, is the a20 one. A switch between main and a20 is rmmod + insmod of the other file, followed by
# an unrecorded run of min(N,200000) requests (the new module starts with no fragments). Off is
# enable=0 auto=0 on whichever module is loaded.
#
#   a20-sweep.sh WORKDIR REPS BOOT CELL...
#
# CELL = NAME:SRV:TEST:N:C:P:D:THR:SCPUS:CCPUS:XPORT
#   SRV     server profile: base | aof_always | aof_always_unix | aof_everysec | aof_no | aof9p_always | unix | iot2
#   TEST    redis-benchmark -t value (set get incr lpush ping_inline ping_mbulk mset ...), or
#           pub<N><l|r>: PUBLISH to channel ch with N redis-cli subscribers on the server (l) or client (r) CPUs
#   N       -n requests per measured run
#   C       -c clients;  P  -P pipeline;  D  -d value size
#   THR     --threads (0 = flag absent)
#   SCPUS   taskset list of every server task;  CCPUS  taskset list of the load generator
#   XPORT   tcp | unix (unix: redis-benchmark -s; needs SRV=unix)
# Cells with the same SRV must be adjacent: one redis-server per run of equal SRV values.
# Per cell: (GET only) a SET to create the key, then one unrecorded run of min(N,200000)
# requests per state, then REPS reps; a rep is one run per state, in the order of permutation
# ((rep - 1) + 2 * (BOOT - 1)) mod 6 of the six orders of (off main a20): all six orders occur
# equally often over six consecutive boots. On = enable=1 auto=1 chain_budget=1024.
# Before the first cell of a server, one unrecorded run at a20 with that cell's parameters.
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

[ $# -ge 4 ] || { echo "usage: a20-sweep.sh WORKDIR REPS BOOT CELL..." >&2; exit 2; }
work=$1
reps=$2
boot=$3
shift 3
cells="$*"
chain=1024
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
invalidated_fragments chains chain_cap translate_exists released_fragments ibtc_insert ibtc_miss_cold
ibtc_miss_conflict ibtc_miss_other link_made link_out_of_range auto_req_exit_target auto_req_svc_resume"

orig_budget=$(cat "$K/chain_budget")
trap 'echo "$orig_budget" > "$K/chain_budget"; set_mode 0' EXIT

emit() { echo "$*" | tee -a "$out"; }

# The module init loaded (/kjit/kjit.ko) is the a20 one.
loaded=a20
switched=0

# load_module NAME: unload the loaded module and load /kjit/kjit-NAME.ko, if it is not the loaded one.
load_module() {
    [ "$loaded" != "$1" ] || return 0
    set_mode 0
    rmmod kjit || k4_fail "rmmod kjit ($loaded)"
    insmod "/kjit/kjit-$1.ko" || k4_fail "insmod kjit-$1.ko"
    loaded=$1
    switched=1
    k4_debugfs
}

set_state() {
    switched=0
    case "$1" in
        off) set_mode 0 ;;
        main | a20)
            load_module "$1"
            echo "$chain" > "$K/chain_budget"
            [ "$(cat "$K/chain_budget")" = "$chain" ] || k4_fail "chain_budget did not become $chain"
            set_mode 1
            ;;
        *) k4_fail "bad state $1" ;;
    esac
}

# Order of the three states for rep REP of this boot.
perm() { # REP -> "s1 s2 s3"
    case $(( ($1 - 1 + 2 * (boot - 1)) % 6 )) in
        0) echo "off main a20" ;;
        1) echo "a20 main off" ;;
        2) echo "main a20 off" ;;
        3) echo "off a20 main" ;;
        4) echo "a20 off main" ;;
        5) echo "main off a20" ;;
    esac
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
        aof_always_unix) start_server "$srv_dir" --unixsocket "$sock" --unixsocketperm 777 --appendonly yes --appendfsync always --auto-aof-rewrite-percentage 0 ;;
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
    cp /proc/interrupts "$1.int"
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
    # Absolute values at the end of the run (since the module was loaded): translations, fragments freed,
    # arena bytes and link slots patched/waiting (the gauges are over all mms).
    line="$line abs_translate_ok=$(stat_of "$work/a.stats" translate_ok) abs_released=$(stat_of "$work/a.stats" released_fragments)"
    line="$line abs_arena_bytes=$(stat_of "$work/a.stats" arena_bytes) abs_links_linked=$(stat_of "$work/a.stats" link_sites_linked)"
    line="$line abs_links_pending=$(stat_of "$work/a.stats" link_sites_pending)"
    emit "$line"
    for c in exit_invalid translate_verify_rejected unsupported_bad_word; do
        d=$(( $(stat_of "$work/a.stats" "$c") - $(stat_of "$work/b.stats" "$c") ))
        [ "$d" = 0 ] || k4_fail "$state $cfg_test ($cfg_name): runtime counter $c grew by $d"
    done
    d=$(( $(stat_of "$work/a.stats" fragment_entries) - $(stat_of "$work/b.stats" fragment_entries) ))
    if [ "$state" = off ]; then
        [ "$d" = 0 ] || k4_fail "$state $cfg_test ($cfg_name): $d fragment entries with KJIT off"
    else
        [ "$d" -gt 0 ] || k4_fail "$state $cfg_test ($cfg_name): no fragment entry with KJIT on"
        # The fragments of a measured run are the loaded module's: it must be the state's.
        [ "$loaded" = "$state" ] || k4_fail "state $state measured with $loaded loaded"
    fi
}

emit "cond: cmdline: $(cat /proc/cmdline)"
emit "cond: kernel: $(uname -r) cpus: $(grep -c ^processor /proc/cpuinfo) redis: $("$R/redis-server" --version)"
emit "cond: reps=$reps boot=$boot chain_budget=$chain hz_ticks=$(getconf CLK_TCK) cells: $cells"
emit "cond: modules: $(ls -l /kjit/kjit.ko /kjit/kjit-main.ko /kjit/kjit-a20.ko | awk '{ printf "%s(%s) ", $NF, $5 }')"
emit "cond: module: $(cat "$K/hot_threshold") hot_threshold, $(cat "$K/hot_window_ms") hot_window_ms"

prev_srv=
for cell in $cells; do
    use_cell "$cell"
    if [ "$cfg_srv" != "$prev_srv" ]; then
        [ -z "$prev_srv" ] || srv_stop "$prev_srv"
        set_state a20
        srv_start "$cfg_srv"
        prev_srv=$cfg_srv
        server_first=1
    else
        server_first=0
    fi
    taskset -a -pc "$cfg_scpus" "$server" > /dev/null
    emit "cond: cell $cfg_name: server tasks allowed CPUs: $(cat /proc/"$server"/task/*/status | awk '/^Cpus_allowed_list/ { print $2 }' | sort | uniq -c | tr '\n' ' ')"
    set_state a20
    snap "$work/cellb"
    subs_start
    if [ "$cfg_test" = get ]; then bench_run set 5000; fi
    if [ "$server_first" = 1 ]; then
        bench_run "$cfg_test" "$cfg_n"
        emit "cond: translate_ok after server warm-up: $(stat_of "$K/stats" translate_ok)"
    fi
    warm=$cfg_n
    [ "$warm" -le 200000 ] || warm=200000
    for state in off main a20; do
        set_state "$state"
        bench_run "$cfg_test" "$warm"
    done
    rep=1
    while [ "$rep" -le "$reps" ]; do
        states=$(perm "$rep")
        order=$(echo "$states" | tr ' ' ',')
        for state in $states; do
            set_state "$state"
            # A fresh module has no fragments: one unrecorded run (as a state's warm-up).
            if [ "$switched" = 1 ]; then bench_run "$cfg_test" "$warm"; fi
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
