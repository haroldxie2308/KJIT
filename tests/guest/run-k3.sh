#!/bin/sh
# K3 guest test suite: unmodified programs under the auto mode (runs inside
# the kjit-guest; binaries and scripts in /opt/kjit-tests).
#
#   run-k3.sh [iterations] [file_mib] [dd1_mib]
#
# Every test runs twice, KJIT disabled (enable=0, auto=0) and then enabled
# with auto mode (enable=1, auto=1); stdout and the exit status must be
# identical. For the enabled run it prints the KJIT counter deltas (the
# counters are global: they include the runner shell and every process the
# test starts). Tests:
#   (a) the K2 micro tests with auto mode instead of self-registration
#       (run-k2.sh --auto);
#   (b) coreutils and busybox pipelines on a generated file_mib MiB text file
#       (default 64): dd bs=4k and bs=1 (the first dd1_mib MiB, default 4),
#       cat, sha256sum, gzip | gunzip, sort, wc;
#   (c) pipe_ring: 4 threads passing a token through pipes;
#   (d) epoll_echo: epoll echo server + client, 100k round trips;
#   (f) redis-smoke.sh: redis-server + redis-benchmark + a data-consistency
#       check; also reports the server's in-kernel syscall fraction, its exit
#       histogram and the top Unsupported words during the benchmark.
#   (u) module unload/reload while jit_churn keeps translations queued.
# Exits non-zero on the first failure; prints "k3: ALL PASS" at the end.
set -eu

iterations=${1:-1}
file_mib=${2:-64}
dd1_mib=${3:-4}
T=/opt/kjit-tests
K=/sys/kernel/debug/kjit
KO=${KJIT_MODULE:-/kjit/kjit.ko}

grep -q " /sys/kernel/debug debugfs" /proc/mounts || mount -t debugfs debugfs /sys/kernel/debug
[ -d "$K" ] || { echo "k3: $K missing (kjit.ko not loaded?)"; exit 1; }
work=$(mktemp -d)
data="$work/data.txt"
cd "$work"

fail() {
    echo "k3: FAIL $*"
    for f in "$work"/*.off.err "$work"/*.on.err; do
        [ -s "$f" ] && { echo "--- $f"; tail -20 "$f"; }
    done
    exit 1
}

now_ms() { echo $(( $(date +%s%N) / 1000000 )); }
stat_of() { awk -v k="$2" '$1 == k { print $2 }' "$1"; }
set_mode() { echo "$1" > "$K/enable"; echo "$1" > "$K/auto"; }

# report NAME BEFORE AFTER: counter deltas of one enabled run.
report() {
    awk -v name="$1" '
        NR == FNR { a[$1] = $2; next }
        { d[$1] = $2 - a[$1] }
        END {
            frac = d["hook_calls"] ? 100 * d["syscalls_in_kernel"] / d["hook_calls"] : 0
            printf "k3:   %s: translated=%d (req svc=%d exit=%d neg=%d) entries=%d chains=%d chain_cap=%d in_kernel=%d/%d syscalls (%.1f%%)\n",
                name, d["translate_ok"], d["auto_req_svc_resume"], d["auto_req_exit_target"],
                d["auto_neg_added"], d["fragment_entries"], d["chains"], d["chain_cap"],
                d["syscalls_in_kernel"], d["hook_calls"], frac
            printf "k3:   %s: exits svc=%d bl=%d blr=%d br=%d ret=%d mem=%d unsupported=%d budget=%d; translate fail entry_unsupported=%d compile=%d verify=%d text=%d capped=%d\n",
                name, d["exit_svc"], d["exit_bl"], d["exit_blr"], d["exit_br"], d["exit_ret"],
                d["exit_mem"], d["exit_unsupported"], d["exit_budget"], d["translate_entry_unsupported"], d["translate_compile_failed"],
                d["translate_verify_rejected"], d["translate_text_unreadable"], d["translate_capped"]
            if (d["exit_invalid"] || d["translate_verify_rejected"] || d["auto_req_dropped"])
                printf "k3:   %s: WARNING exit_invalid=%d verify_rejected=%d req_dropped=%d\n",
                    name, d["exit_invalid"], d["translate_verify_rejected"], d["auto_req_dropped"]
        }' "$2" "$3"
}

# unsup_delta BEFORE AFTER N: the N words that stopped fragments most often
# between two unsupported_top snapshots, as "total word(exits/entry_stops)".
unsup_delta() {
    awk 'NR == FNR { e[$1] = $2; s[$1] = $3; next }
         { de = $2 - e[$1]; ds = $3 - s[$1]; if (de + ds > 0) printf "%d %s(%d/%d)\n", de + ds, $1, de, ds }' \
        "$1" "$2" | sort -rn | head -"$3"
}

# onoff NAME CMD: run `sh -c CMD` in $work with KJIT off, then on (auto).
onoff() {
    local name=$1 cmd=$2 s0 s1 t0 t1 t2
    set_mode 0
    t0=$(now_ms)
    set +e
    sh -c "$cmd" > "$name.off.out" 2> "$name.off.err"
    s0=$?
    t1=$(now_ms)
    set_mode 1
    cp "$K/stats" "$name.before"
    cp "$K/unsupported_top" "$name.ubefore"
    STATS_DIR="$work/$name.d" sh -c "$cmd" > "$name.on.out" 2> "$name.on.err"
    s1=$?
    t2=$(now_ms)
    cp "$K/stats" "$name.after"
    cp "$K/unsupported_top" "$name.uafter"
    set -e
    set_mode 0
    [ "$s0" = 0 ] || fail "$name: exit status $s0 with KJIT off"
    [ "$s1" = "$s0" ] || fail "$name: exit status $s1 with KJIT on, $s0 off"
    [ -s "$name.off.out" ] || fail "$name: no output"
    if ! cmp -s "$name.off.out" "$name.on.out"; then
        diff "$name.off.out" "$name.on.out" | head -20
        fail "$name: output differs with KJIT on/off"
    fi
    echo "k3: $name PASS off=$((t1 - t0))ms on=$((t2 - t1))ms"
    report "$name" "$name.before" "$name.after"
    echo "k3:   $name: top Unsupported (total word(exits/entry_stops)): $(unsup_delta "$name.ubefore" "$name.uafter" 5 | tr '\n' ',' | sed 's/,$//')"
}

# Unload and reload the module while jit_churn keeps auto-mode translation
# requests queued and running (task_work) and fragments hot. A request still
# queued when the module goes is freed by the kernel (0004); the module's exit
# message counts them ("N of M translation requests still queued"). That needs
# the task to be preempted between queueing (in the syscall-return hook) and
# its return to user mode, so it is rare; requests in flight are the common
# case (unload waits for them).
orphans_logged() {
    dmesg | sed -n 's/.*kjit: \([0-9]*\) of [0-9]* translation requests still queued.*/\1/p' \
        | awk '{ n += $1 } END { print n + 0 }'
}

reload_churn() {
    local pid n before
    before=$(orphans_logged)
    set_mode 1
    "$T/jit_churn" 8 200 > /dev/null 2>&1 &
    pid=$!
    for n in 1 2 3 4 5; do
        sleep 0.3
        rmmod kjit || fail "rmmod $n with jit_churn running"
        sleep 0.1
        insmod "$KO" auto=1 || fail "insmod $n"
        [ -d "$K" ] || fail "debugfs missing after insmod $n"
    done
    sleep 0.3
    kill -9 "$pid"
    wait "$pid" 2>/dev/null || true
    set_mode 0
    grep -q . "$K/stats" || fail "stats unreadable after reload"
    echo "k3: reload_churn PASS (5 unloads while jit_churn ran; $(( $(orphans_logged) - before )) queued requests left to the kernel; $(stat_of "$K/stats" auto_req_svc_resume) requests since the last load)"
}

i=1
while [ "$i" -le "$iterations" ]; do
    rm -rf "$work"/*
    set_mode 0

    # (a)
    K2_LEAVE_HOT=0 sh "$T/run-k2.sh" --auto 1 > k2.log 2>&1 || { cat k2.log; fail "run-k2.sh --auto"; }
    grep -E "^k2:   [a-z_]+: in_kernel|ALL PASS" k2.log | sed 's/^k2:/k3: k2/'

    # (b)
    "$T/gen_data" "$file_mib" > "$data"
    onoff gen_data "$T/gen_data $file_mib | sha256sum"
    onoff dd_4k "dd if=$data of=copy bs=4k status=none && sha256sum < copy && cmp $data copy && echo same; rm -f copy"
    onoff dd_1 "dd if=$data of=copy bs=1 count=$((dd1_mib * 1048576)) status=none && sha256sum < copy; rm -f copy"
    onoff bb_dd "busybox dd if=$data bs=4096 2>/dev/null | busybox sha256sum"
    onoff cat_wc "cat $data | wc -l -w -c"
    onoff sha256sum "sha256sum $data"
    onoff gzip "gzip -c $data | gunzip -c | sha256sum"
    onoff sort "LC_ALL=C sort $data | sha256sum"
    onoff wc "wc $data"
    onoff bb_gzip "busybox gzip -c $data | busybox gunzip -c | busybox wc -c"
    onoff bb_sort "busybox sort $data | busybox md5sum"
    onoff bb_cat "busybox cat $data | busybox wc -l"

    # (c), (d)
    onoff pipe_ring "$T/pipe_ring 100000"
    onoff epoll_echo "$T/epoll_echo 100000"

    # (e) sqlite3: only if the rootfs has it.
    if command -v sqlite3 > /dev/null; then
        onoff sqlite "sqlite3 :memory: 'create table t(k integer primary key, v text); with recursive c(x) as (select 1 union all select x + 1 from c limit 200000) insert into t select x, hex(x * 7919) from c; select count(*), sum(k), sum(length(v)) from t; select v from t order by v limit 3;'"
    else
        echo "k3: sqlite SKIP (sqlite3 not in the rootfs)"
    fi

    # (f)
    mkdir -p redis.d
    onoff redis "sh $T/redis-smoke.sh 100000"
    sed 's/^/k3:   /' redis.on.err
    report redis-bench redis.d/bench.before redis.d/bench.after
    echo "k3:   redis-bench: top Unsupported words (total word(exits/entry_stops)):"
    unsup_delta redis.d/unsup.before redis.d/unsup.after 20 | sed 's/^/k3:     /'

    # (u)
    reload_churn

    echo "k3: iteration $i PASS"
    i=$((i + 1))
done

set_mode 0
echo "k3: stats"
sed 's/^/k3:   /' "$K/stats"
echo "k3: ALL PASS ($iterations iterations, file ${file_mib} MiB, dd bs=1 ${dd1_mib} MiB)"
