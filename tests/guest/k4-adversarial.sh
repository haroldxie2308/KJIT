#!/bin/sh
# K4 (3): adversarial tests on redis-server under the auto mode (inside the
# kjit-guest, kjit.ko loaded).
#
#   k4-adversarial.sh WORKDIR
#
# Every test runs twice, KJIT off (enable=0, auto=0) and on (enable=1,
# auto=1). Its stdout (exit statuses, signals, crash-report lines, digests) is
# deterministic and must be identical in both runs; the enabled run also
# prints the counter deltas (and, before the disruptive event, whether the
# server ran in fragments: hot_check, K4_REQUIRE_HOT). Tests:
#   kill9       kill -9 of a hot server, 3 times: status 137
#   sigterm     SIGTERM under load: clean shutdown, status 0
#   sigusr1     SIGUSR1 under load (not handled by the redis parent): 138
#   stopcont    SIGSTOP/SIGCONT 5 times under a fixed-key load: the load
#               completes, same digest
#   segfault    DEBUG SEGFAULT under load: redis's crash report, then death by
#               SIGSEGV (139) with a core file (if the kernel dumps cores)
#   bgsave      BGSAVE 5 times under load (fork while hot: the child's mm
#               starts empty, the parent's pages are CoW), then SAVE the final
#               dataset: redis-check-rdb accepts dump.rdb and a restart from it
#               has the same digest
#   aofrw       CONFIG SET appendonly yes under load (AOF rewrite fork), then a
#               restart from the AOF: same digest
#   config      CONFIG SET churn and MODULE LOAD/UNLOAD of a test module (its
#               text is mapped and unmapped while the server is hot) under load
#   reload      rmmod/insmod kjit.ko 5 times while the server is under load
#               (in the off run the reloaded module stays disabled)
#   maxmemory   allkeys-lru eviction at maxmemory 32mb under a random-key load,
#               then noeviction OOM errors
# Exits non-zero on the first failure; prints "k4-adv: ALL PASS".
set -eu

. /opt/kjit-tests/k4-lib.sh

work=${1:?usage: k4-adversarial.sh WORKDIR}
mkdir -p "$work"
cd "$work"
k4_debugfs

cores=/tmp/k4-cores
mkdir -p "$cores"
# Cores go to a known place with the executable name; only if the kernel
# has core dump support (/proc/sys/kernel/core_pattern exists).
if [ -f /proc/sys/kernel/core_pattern ]; then
    echo "$cores/core.%e.%p" > /proc/sys/kernel/core_pattern
    ulimit -c unlimited
    have_cores=1
else
    have_cores=0
fi

t_kill9() {
    local n
    for n in 1 2 3; do
        start_server "$d/srv"
        load_dataset
        snap "$d/k$n"
        bg_load
        sleep 1
        hot_check "kill9#$n" "$d/k$n"
        kill -9 "$server"
        wait_status "$server"
        stop_load
        echo "kill9 #$n: server status $wstatus"
    done
}

# signal_under_load SIG: the server's exit status after SIG under load.
signal_under_load() {
    start_server "$d/srv"
    load_dataset
    snap "$d/s"
    bg_load
    sleep 1
    hot_check "$1" "$d/s"
    kill -"$1" "$server"
    wait_status "$server"
    stop_load
    echo "$1: server status $wstatus"
}

t_sigterm() {
    signal_under_load TERM
    grep -q "Received SIGTERM scheduling shutdown" "$d/srv/redis.log" || k4_fail "sigterm: no shutdown logged"
    grep -q "Redis is now ready to exit, bye bye" "$d/srv/redis.log" || k4_fail "sigterm: no clean exit logged"
    echo "sigterm: shutdown and clean exit logged"
}

t_sigusr1() {
    signal_under_load USR1
}

t_stopcont() {
    local n load_pid
    start_server "$d/srv"
    load_dataset
    snap "$d/s"
    fixed_load 300000 &
    load_pid=$!
    sleep 1
    hot_check stopcont "$d/s"
    for n in 1 2 3 4 5; do
        kill -STOP "$server"
        sleep 0.3
        kill -CONT "$server"
        sleep 0.3
    done
    wait_status "$load_pid"
    echo "stopcont: load status $wstatus"
    digest
    stop_server
}

t_segfault() {
    rm -f "$cores"/*
    start_server "$d/srv"
    load_dataset
    snap "$d/s"
    bg_load
    sleep 1
    hot_check segfault "$d/s"
    # The connection dies with the server: no reply.
    cli debug segfault > /dev/null 2>&1 || true
    wait_status "$server"
    stop_load
    echo "segfault: server status $wstatus"
    # Deterministic lines of the crash report. DEBUG SEGFAULT writes to a
    # read-only page it mmaps, so the address varies with ASLR; only its page
    # alignment is compared.
    grep -o "crashed by signal: [0-9]*, si_code: [0-9]*" "$d/srv/redis.log" | head -1
    grep -o "Accessing address: 0x[0-9a-f]*" "$d/srv/redis.log" | head -1 | sed 's/0x[0-9a-f]*000$/<page-aligned>/'
    echo "segfault: stack trace names debugCommand: $(grep -q debugCommand "$d/srv/redis.log" && echo yes || echo no)"
    if [ "$have_cores" = 1 ]; then
        echo "segfault: core files $(find "$cores" -name 'core.redis-server.*' | wc -l)"
    fi
    rm -f "$cores"/*
}

t_bgsave() {
    local n load_pid d1 d2
    start_server "$d/srv" --dbfilename dump.rdb
    load_dataset
    snap "$d/s"
    fixed_load 300000 &
    load_pid=$!
    sleep 1
    hot_check bgsave "$d/s"
    for n in 1 2 3 4 5; do
        # "Background saving started"; an error reply fails the test.
        [ "$(cli bgsave)" = "Background saving started" ] || k4_fail "bgsave #$n did not start"
        wait_info persistence rdb_bgsave_in_progress 0
        [ "$(info_field persistence rdb_last_bgsave_status)" = ok ] || k4_fail "bgsave #$n failed"
    done
    wait_status "$load_pid"
    echo "bgsave: load status $wstatus"
    [ "$(cli bgsave)" = "Background saving started" ] || k4_fail "final bgsave did not start"
    wait_info persistence rdb_bgsave_in_progress 0
    [ "$(info_field persistence rdb_last_bgsave_status)" = ok ] || k4_fail "final bgsave failed"
    d1=$(digest)
    echo "bgsave: before restart $d1"
    stop_server
    "$R/redis-check-rdb" "$d/srv/dump.rdb" > "$d/check-rdb.out" 2>&1 || { cat "$d/check-rdb.out"; k4_fail "redis-check-rdb"; }
    echo "bgsave: redis-check-rdb ok"
    start_server "$d/srv" --dbfilename dump.rdb
    d2=$(digest)
    echo "bgsave: after restart $d2"
    [ "$d1" = "$d2" ] || k4_fail "bgsave: digest changed across the restart"
    stop_server
}

t_aofrw() {
    local load_pid d1 d2
    start_server "$d/srv"
    load_dataset
    snap "$d/s"
    fixed_load 300000 &
    load_pid=$!
    sleep 1
    hot_check aofrw "$d/s"
    [ "$(cli config set appendonly yes)" = OK ] || k4_fail "config set appendonly yes"
    wait_info persistence aof_rewrite_in_progress 0
    wait_info persistence aof_rewrite_scheduled 0
    [ "$(info_field persistence aof_last_bgrewrite_status)" = ok ] || k4_fail "AOF rewrite failed"
    wait_status "$load_pid"
    echo "aofrw: load status $wstatus"
    d1=$(digest)
    echo "aofrw: before restart $d1"
    # SHUTDOWN flushes and fsyncs the AOF.
    stop_server
    start_server "$d/srv" --appendonly yes
    d2=$(digest)
    echo "aofrw: after restart from the AOF $d2"
    [ "$d1" = "$d2" ] || k4_fail "aofrw: digest changed across the restart"
    stop_server
}

t_config() {
    local n load_pid mod_pid
    start_server "$d/srv" --enable-module-command yes
    load_dataset
    snap "$d/s"
    fixed_load 300000 &
    load_pid=$!
    # A second load that calls the module command forever on one connection;
    # redis-cli -r keeps going through the "unknown command" errors while the
    # module is unloaded (redis-benchmark would exit). Killed below.
    "$T/nojit" "$R/redis-cli" -p "$PORT" -r -1 test.dbsize > /dev/null 2>&1 &
    mod_pid=$!
    sleep 1
    hot_check config "$d/s"
    for n in 1 2 3 4 5; do
        cli module load /opt/redis/tests/modules/misc.so > /dev/null
        cli test.dbsize | grep -Eq '^[0-9]+$' || k4_fail "module command after load #$n"
        for kv in "hz 100" "maxmemory-policy allkeys-lru" "lazyfree-lazy-user-del yes" \
                  "activerehashing no" "appendfsync always" "list-max-listpack-size 4" \
                  "hz 10" "maxmemory-policy noeviction" "lazyfree-lazy-user-del no" \
                  "activerehashing yes" "appendfsync everysec" "list-max-listpack-size -2"; do
            # shellcheck disable=SC2086
            [ "$(cli config set $kv)" = OK ] || k4_fail "config set $kv"
        done
        sleep 0.2
        [ "$(cli module unload misc)" = OK ] || k4_fail "module unload #$n"
        sleep 0.1
    done
    echo "config: 5 module load/unload and config set rounds ok"
    wait_status "$load_pid"
    kill -9 "$mod_pid"
    wait "$mod_pid" 2> /dev/null || true
    echo "config: load status $wstatus; misc module still loaded: $(cli module list | awk '/^misc$/ { n++ } END { print n + 0 }')"
    digest
    stop_server
}

t_reload() {
    local n load_pid
    start_server "$d/srv"
    load_dataset
    snap "$d/s"
    fixed_load 400000 &
    load_pid=$!
    sleep 1
    hot_check reload "$d/s"
    for n in 1 2 3 4 5; do
        rmmod kjit || k4_fail "rmmod #$n under load"
        sleep 0.1
        insmod "$KO" auto="$K4_MODE" || k4_fail "insmod #$n"
        k4_debugfs
        echo "$K4_MODE" > "$K/enable"
        sleep 0.4
    done
    wait_status "$load_pid"
    echo "reload: 5 unloads under load; load status $wstatus; ping $(cli ping)"
    digest
    stop_server
}

t_maxmemory() {
    local used evicted
    start_server "$d/srv" --maxmemory 32mb --maxmemory-policy allkeys-lru
    snap "$d/s"
    bench -n 400000 -r 2000000 -d 200 -c 20 -t set -q > /dev/null 2>&1 &
    load=$!
    sleep 1
    hot_check maxmemory "$d/s"
    wait_status "$load"
    [ "$wstatus" = 0 ] || k4_fail "maxmemory: random-key load failed"
    used=$(info_field memory used_memory)
    evicted=$(info_field stats evicted_keys)
    echo "maxmemory: evicted $([ "$evicted" -gt 0 ] && echo yes || echo no)"
    # The limit is enforced before each command, so the overshoot is bounded by
    # one command's allocations plus client buffers.
    echo "maxmemory: used within 32mb+1mb $([ "$used" -le $((33 * 1048576)) ] && echo yes || echo "no ($used)")"
    cli config set maxmemory-policy noeviction > /dev/null
    cli config set maxmemory 1mb > /dev/null
    echo "maxmemory: noeviction write: $(cli set k4:oom v 2>&1 | cut -c1-40)"
    cli config set maxmemory 0 > /dev/null
    echo "maxmemory: after lifting the limit: $(cli set k4:oom v)"
    cli debug digest > /dev/null
    stop_server
}

# onoff NAME: run t_NAME with KJIT off, then on; identical stdout.
onoff() {
    local name=$1 mode status
    for mode in 0 1; do
        d="$work/$name.$mode"
        rm -rf "$d"
        mkdir -p "$d"
        K4_MODE=$mode
        set_mode "$mode"
        snap "$d/begin"
        # Not "( ... ) || fail": errexit is off inside a tested command.
        set +e
        ( set -e; "t_$name" ) > "$d/out" 2> "$d/err"
        status=$?
        set -e
        [ "$status" = 0 ] || { cat "$d/out" "$d/err"; k4_fail "$name (KJIT $mode)"; }
        snap "$d/end"
    done
    set_mode 0
    if ! cmp -s "$work/$name.0/out" "$work/$name.1/out"; then
        diff "$work/$name.0/out" "$work/$name.1/out" | head -20
        k4_fail "$name: output differs with KJIT off/on"
    fi
    echo "k4-adv: $name PASS: $(tr '\n' ';' < "$work/$name.1/out" | cut -c1-200)"
    # hot_check lines (none in a test without a hot phase).
    grep -h '^k4:' "$work/$name.1/err" || true
    if [ "$name" = reload ]; then
        # Every insmod starts the counters from zero: no deltas.
        echo "k4:   reload: counters of the last load: $(grep -E '^(fragment_entries|syscalls_in_kernel|exit_invalid|translate_verify_rejected) ' "$work/$name.1/end.stats" | tr '\n' ' ')"
    else
        report "$name" "$work/$name.1/begin" "$work/$name.1/end"
    fi
}

for t in kill9 sigterm sigusr1 stopcont segfault bgsave aofrw config reload maxmemory; do
    onoff "$t"
done
echo "k4-adv: ALL PASS"
