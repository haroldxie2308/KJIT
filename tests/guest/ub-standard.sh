#!/bin/sh
# redis under the Userspace Bypass paper's benchmark protocol (OSDI '23, section
# 6.2: tmp/UserspaceBypass/Readme.md, "Redis test"), KJIT off and on, inside the
# kjit-guest (one boot, kjit.ko loaded).
#
#   ub-standard.sh WORKDIR PIN REQUESTS REPS SIZE...
#
# PIN is "pinned" (server on CPU 0, redis-benchmark on CPUs 1-3: two machines
# approximated in one guest) or "unpinned" (nothing pinned). SIZE is a redis-benchmark
# -d value. Per SIZE, SET then GET (`redis-benchmark -t set|get -n REQUESTS -d SIZE
# --threads 2 -q`, everything else default), KJIT off then on (off: enable=0 auto=0;
# on: enable=1 auto=1, chain_budget 1024), REPS times, off and on alternating so slow
# host drift hits both. The SET of a size always precedes its GET, in the warm-up and in
# every measured pass, so the GET finds the value.
#
# One redis-server serves the whole invocation. Before the measured passes of a size,
# every state runs SET and GET once at UB_STD_WARM requests (default 200000, not
# recorded) so the code of that value size is translated; before the first size, SET and
# GET run once at KJIT on with REQUESTS requests (UB found its boost needed 20-30 s of
# load). Whether translation had settled is in the output: translate_ok is a counter
# delta per measured run, expected 0.
#
# Output (stdout, grep "^ubstd "):
#   ubstd: ...                                 header lines (kernel, KPTI, affinity, module state)
#   ubstd run pin=<p> size=<d> rep=<i> state=<off|on> test=<set|get> requests=<n> rps=<r>
#       wall_cs=<centiseconds> utime_ticks=<u> stime_ticks=<s> clk_tck=<hz> <counter>=<delta> ...
# Server CPU is the user + system ticks of the server process (all its threads, from
# /proc/PID/stat) over one run, as ub-redis-cpu.sh: CONFIG_HZ tick sampling, use many
# requests. The counters are the KJIT debugfs counter deltas of the run (the load
# generator runs under nojit, so they are the server's); with direct BL links (A16) also
# link_made, link_restored, link_out_of_range, link_class_refused (deltas) and the gauges
# link_sites_linked and link_sites_pending after the run; with the image arena (A17) also
# the gauges arena_chunks and arena_bytes after the run. Exits non-zero when a run
# reports no throughput, when a KJIT-on run shows no fragment entry, when a KJIT-off run
# shows one, or when the runtime reports an invalid exit or a verifier rejection.
set -eu

. /opt/kjit-tests/k4-lib.sh

usage() {
    echo "usage: ub-standard.sh WORKDIR PIN REQUESTS REPS SIZE...   (PIN: pinned | unpinned)" >&2
    exit 2
}
[ $# -ge 5 ] || usage
work=$1
pin=$2
n=$3
reps=$4
shift 4
sizes="$*"
case "$pin" in
    pinned | unpinned) ;;
    *) usage ;;
esac
warm=${UB_STD_WARM:-200000}
chain=1024
server_cpus=0
client_cpus=1-3

mkdir -p "$work"
cd "$work"
k4_debugfs
for f in enable auto chain_budget stats unsupported_top; do
    [ -f "$K/$f" ] || k4_fail "$K/$f missing"
done

counters="hook_calls syscalls_in_kernel fragment_entries exit_svc exit_bl exit_blr exit_br exit_ret
exit_mem exit_unsupported exit_budget run_declined svc_declined fpsimd_entries translate_ok
invalidated_fragments"
link_counters="link_made link_restored link_out_of_range link_class_refused"

orig_budget=$(cat "$K/chain_budget")
trap 'echo "$orig_budget" > "$K/chain_budget"; set_mode 0' EXIT

# set_state off|on
set_state() {
    if [ "$1" = off ]; then
        set_mode 0
        return
    fi
    echo "$chain" > "$K/chain_budget"
    [ "$(cat "$K/chain_budget")" = "$chain" ] || k4_fail "chain_budget did not become $chain"
    set_mode 1
}

# cbench ARGS...: redis-benchmark under nojit, on the client CPUs when pinned.
cbench() {
    if [ "$pin" = pinned ]; then
        taskset -c "$client_cpus" "$T/nojit" "$R/redis-benchmark" -p "$PORT" "$@"
    else
        bench "$@"
    fi
}

ticks() { awk '{ print $14, $15 }' "/proc/$server/stat"; }   # utime stime
clk=$(getconf CLK_TCK)

# run_bench TEST SIZE REQUESTS: one `redis-benchmark -t TEST -n REQUESTS -d SIZE
# --threads 2 -q`; sets $rps.
run_bench() {
    cbench -t "$1" -n "$3" -d "$2" --threads 2 -q > "$work/bench.out" 2>&1 \
        || { tail "$work/bench.out"; k4_fail "benchmark $1 -d $2"; }
    rps=$(tr '\r' '\n' < "$work/bench.out" | awk -v t="$(echo "$1" | tr a-z A-Z):" \
        '$1 == t && $3 == "requests" { v = $2 } END { print v }')
    [ -n "$rps" ] || { cat "$work/bench.out"; k4_fail "no requests/s for $1 -d $2"; }
}

# measure SIZE REP STATE TEST: one measured run; prints the ubstd run line.
measure() {
    local size=$1 rep=$2 state=$3 test=$4 u0 s0 u1 s1 t0 t1 line d
    snap "$work/before"
    set -- $(ticks)
    u0=$1 s0=$2
    t0=$(awk '{ printf "%d", $1 * 100 }' /proc/uptime)
    run_bench "$test" "$size" "$n"
    t1=$(awk '{ printf "%d", $1 * 100 }' /proc/uptime)
    set -- $(ticks)
    u1=$1 s1=$2
    snap "$work/after"
    line="ubstd run pin=$pin size=$size rep=$rep state=$state test=$test requests=$n rps=$rps"
    line="$line wall_cs=$((t1 - t0)) utime_ticks=$((u1 - u0)) stime_ticks=$((s1 - s0)) clk_tck=$clk"
    for c in $counters; do
        line="$line $c=$(( $(stat_of "$work/after.stats" "$c") - $(stat_of "$work/before.stats" "$c") ))"
    done
    # A16 counters (a module without direct BL links has none) and the number of
    # link slots linked / pending after the run (gauges, not deltas), then the
    # A17 arena gauges (a module without the arena has none).
    for c in $link_counters; do
        [ -n "$(stat_of "$work/after.stats" "$c")" ] || continue
        line="$line $c=$(( $(stat_of "$work/after.stats" "$c") - $(stat_of "$work/before.stats" "$c") ))"
    done
    for c in link_sites_linked link_sites_pending arena_chunks arena_bytes; do
        [ -n "$(stat_of "$work/after.stats" "$c")" ] || continue
        line="$line $c=$(stat_of "$work/after.stats" "$c")"
    done
    echo "$line"
    for c in exit_invalid translate_verify_rejected unsupported_bad_word; do
        d=$(( $(stat_of "$work/after.stats" "$c") - $(stat_of "$work/before.stats" "$c") ))
        [ "$d" = 0 ] || k4_fail "$state $test -d $size: runtime counter $c grew by $d"
    done
    d=$(( $(stat_of "$work/after.stats" fragment_entries) - $(stat_of "$work/before.stats" fragment_entries) ))
    if [ "$state" = off ]; then
        [ "$d" = 0 ] || k4_fail "$state $test -d $size: $d fragment entries with KJIT off"
    else
        [ "$d" -gt 0 ] || k4_fail "$state $test -d $size: no fragment entry with KJIT on"
    fi
}

echo "ubstd: cmdline: $(cat /proc/cmdline)"
echo "ubstd: kpti dmesg: $(dmesg | grep -i 'page table isolation' || echo none)"
echo "ubstd: kernel: $(uname -r) cpus: $(grep -c ^processor /proc/cpuinfo) redis: $("$R/redis-server" --version)"
echo "ubstd: pin=$pin sizes='$sizes' requests=$n reps=$reps warm=$warm chain_budget=$chain hz_ticks=$clk"
echo "ubstd: module: $(cat "$K/hot_threshold") hot_threshold, $(cat "$K/hot_window_ms") hot_window_ms"

set_state on
start_server "$work/srv"
[ "$pin" != pinned ] || taskset -a -pc "$server_cpus" "$server" > /dev/null
echo "ubstd: server tasks allowed CPUs: $(cat /proc/"$server"/task/*/status | awk '/^Cpus_allowed_list/ { print $2 }' | sort | uniq -c | tr '\n' ' ')"

# Global warm-up at KJIT on, with the first size (not recorded).
set -- $sizes
echo "ubstd: warm-up at on, -d $1, $n requests"
run_bench set "$1" "$n"
run_bench get "$1" "$n"
echo "ubstd: translate_ok after warm-up: $(stat_of "$K/stats" translate_ok)"

for size in $sizes; do
    # Per-size warm-up, every state (not recorded).
    for state in off on; do
        set_state "$state"
        run_bench set "$size" "$warm"
        run_bench get "$size" "$warm"
    done
    rep=1
    while [ "$rep" -le "$reps" ]; do
        for state in off on; do
            set_state "$state"
            measure "$size" "$rep" "$state" set
            measure "$size" "$rep" "$state" get
        done
        rep=$((rep + 1))
    done
done
set_mode 0
stop_server
echo "ubstd: done"
