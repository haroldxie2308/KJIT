# K4 helpers, sourced by k4-bench.sh, k4-adversarial.sh and k4-campaign.sh
# (inside the kjit-guest). redis is the /opt/redis build (mk-guest-rootfs.sh);
# every load generator runs under nojit (allow-all seccomp: its syscalls never
# reach KJIT), so the global KJIT counters measure the server.

R=/opt/redis/src
T=/opt/kjit-tests
K=/sys/kernel/debug/kjit
KO=${KJIT_MODULE:-/kjit/kjit.ko}
PORT=${PORT:-6400}
# 1: a phase that is meant to run hot must show fragment entries (fails
# otherwise). 0: only report them (used while no redis path is translatable).
K4_REQUIRE_HOT=${K4_REQUIRE_HOT:-1}

k4_fail() {
    echo "k4: FAIL $*"
    exit 1
}

cli() { "$R/redis-cli" -p "$PORT" "$@"; }
bench() { "$T/nojit" "$R/redis-benchmark" -p "$PORT" "$@"; }

k4_debugfs() {
    grep -q " /sys/kernel/debug debugfs" /proc/mounts || mount -t debugfs debugfs /sys/kernel/debug
    [ -d "$K" ] || k4_fail "$K missing (kjit.ko not loaded?)"
}

# set_mode 0|1: KJIT off (enable=0, auto=0) or on with the auto mode.
set_mode() {
    echo "$1" > "$K/enable"
    echo "$1" > "$K/auto"
}

stat_of() { awk -v k="$2" '$1 == k { print $2 }' "$1"; }
snap() {
    cp "$K/stats" "$1.stats"
    cp "$K/unsupported_top" "$1.unsup"
}

# report NAME BEFORE AFTER: counter deltas between two snap()s, one line of
# activity, one line of exits, one of the most frequent stopping words.
report() {
    awk -v name="$1" '
        FILENAME == ARGV[1] { a[$1] = $2; next }
        { d[$1] = $2 - a[$1]; v[$1] = $2 }
        END {
            frac = d["hook_calls"] ? 100 * d["syscalls_in_kernel"] / d["hook_calls"] : 0
            printf "k4:   %s: in_kernel=%d/%d syscalls (%.1f%%) entries=%d chains=%d chain_cap=%d translated=%d (entry_unsupported=%d compile=%d verify=%d capped=%d neg=%d) invalidated=%d released=%d\n",
                name, d["syscalls_in_kernel"], d["hook_calls"], frac, d["fragment_entries"], d["chains"],
                d["chain_cap"], d["translate_ok"], d["translate_entry_unsupported"], d["translate_compile_failed"],
                d["translate_verify_rejected"], d["translate_capped"], d["auto_neg_added"],
                d["invalidated_fragments"], d["released_fragments"]
            printf "k4:   %s: exits svc=%d bl=%d blr=%d br=%d ret=%d mem=%d unsupported=%d budget=%d invalid=%d svc_declined=%d\n",
                name, d["exit_svc"], d["exit_bl"], d["exit_blr"], d["exit_br"], d["exit_ret"], d["exit_mem"],
                d["exit_unsupported"], d["exit_budget"], d["exit_invalid"], d["svc_declined"]
            printf "k4:   %s: fpsimd entries=%d preempted=%d exit_mem=%d refused_sve_sme=%d run_max_ns(since load)=%d\n",
                name, d["fpsimd_entries"], d["fpsimd_preempted"], d["fpsimd_exit_mem"],
                d["fpsimd_refused_sve_sme"], v["fpsimd_run_max_ns"]
            # A11 dispatch tables: slot stores (per table), replacements,
            # slots cleared by retirement, runtime resolutions of a transfer
            # from a non-FP/SIMD run into an FP/SIMD fragment. Per syscall in
            # the kernel: runtime entries (fragment_entries) and Budget exits.
            printf "k4:   %s: ibtc insert=%d replace=%d clear=%d fpsimd_boundary=%d miss cold=%d conflict=%d other=%d; per in-kernel syscall: entries=%.2f exit_budget=%.4f\n",
                name, d["ibtc_insert"], d["ibtc_replace"], d["ibtc_clear"], d["ibtc_fpsimd_boundary"],
                d["ibtc_miss_cold"], d["ibtc_miss_conflict"], d["ibtc_miss_other"],
                d["syscalls_in_kernel"] ? d["fragment_entries"] / d["syscalls_in_kernel"] : 0,
                d["syscalls_in_kernel"] ? d["exit_budget"] / d["syscalls_in_kernel"] : 0
            # Fragment entries per hook call that ran one (log2 buckets), and
            # the longest chain since the module was loaded.
            hist = ""
            for (lo = 1; lo <= 65536; lo *= 2) {
                k = "chain_hist_" lo "_" (2 * lo - 1)
                if (d[k] > 0) hist = hist " " lo "-" (2 * lo - 1) ":" d[k]
            }
            printf "k4:   %s: entries per hook call:%s (chain_max since load %d)\n", name, hist, v["chain_max"]
        }' "$2.stats" "$3.stats"
    printf 'k4:   %s: unsupported_top (word(exits/entry_stops)): %s\n' "$1" \
        "$(awk 'FILENAME == ARGV[1] { e[$1] = $2; s[$1] = $3; next }
                { de = $2 - e[$1]; ds = $3 - s[$1]; if (de + ds > 0) printf "%d %s(%d/%d)\n", de + ds, $1, de, ds }' \
               "$2.unsup" "$3.unsup" | sort -rn | head -8 | cut -d' ' -f2 | tr '\n' ' ')"
    # A runtime bug or a rejected fragment is never acceptable.
    awk 'FILENAME == ARGV[1] { a[$1] = $2; next }
         ($1 == "exit_invalid" || $1 == "translate_verify_rejected" || $1 == "unsupported_bad_word") && $2 != a[$1] { bad = bad " " $1 "+" ($2 - a[$1]) }
         END { if (bad != "") { print "k4:   " bad; exit 1 } }' "$2.stats" "$3.stats" \
        || k4_fail "$1: runtime counters report a KJIT bug"
}

# hot_check NAME BEFORE: the load since snap BEFORE ran in fragments. Only in
# a KJIT-on run (K4_MODE=1); reported always, fatal with K4_REQUIRE_HOT=1 when
# there was no fragment entry.
hot_check() {
    local entries
    [ "${K4_MODE:-1}" = 1 ] || return 0
    snap "$2.hot"
    entries=$(( $(stat_of "$2.hot.stats" fragment_entries) - $(stat_of "$2.stats" fragment_entries) ))
    echo "k4:   $1: hot: $entries fragment entries, $(( $(stat_of "$2.hot.stats" syscalls_in_kernel) - $(stat_of "$2.stats" syscalls_in_kernel) )) syscalls in kernel before the event" >&2
    if [ "$K4_REQUIRE_HOT" = 1 ] && [ "$entries" -le 0 ]; then
        k4_fail "$1: not hot (no fragment entry under load; K4_REQUIRE_HOT=0 only reports this)"
    fi
}

wait_ping() {
    local i=0
    until [ "$(cli ping 2>/dev/null)" = PONG ]; do
        i=$((i + 1))
        [ "$i" -lt 400 ] || k4_fail "redis-server on port $PORT did not answer PING"
        sleep 0.05
    done
}

# start_server DIR [redis-server options...]: $server is its pid.
start_server() {
    local dir=$1
    shift
    mkdir -p "$dir"
    "$R/redis-server" --port "$PORT" --dir "$dir" --save "" --appendonly no \
        --enable-debug-command yes --logfile "$dir/redis.log" "$@" > /dev/null 2>&1 &
    server=$!
    wait_ping
}

# stop_server: SHUTDOWN NOSAVE, the server must exit 0.
stop_server() {
    # redis-cli reports the closed connection of a SHUTDOWN as an error.
    cli shutdown nosave > /dev/null 2>&1 || true
    wait_status "$server"
    [ "$wstatus" = 0 ] || k4_fail "redis-server exited with status $wstatus after SHUTDOWN"
}

# wait_status PID: $wstatus = exit status of a background child of this
# shell (128 + signal if killed). Not usable in $(...): a subshell cannot wait
# for its parent's children.
wait_status() {
    set +e
    wait "$1"
    wstatus=$?
    set -e
}

# A load generator that never ends by itself: killed by the caller.
bg_load() {
    bench -n 100000000 -c 20 -t set,get,incr,lpush,hset -q > /dev/null 2>&1 &
    load=$!
}

stop_load() {
    kill -9 "$load" 2> /dev/null || true
    wait "$load" 2> /dev/null || true
}

# Deterministic dataset (as redis-smoke.sh): 10k strings of varying length
# plus lists, hashes, counters and sets, loaded with redis-cli --pipe.
load_dataset() {
    [ -f /tmp/k4-load.txt ] || awk 'BEGIN {
        for (i = 0; i < 10000; i++) {
            v = sprintf("v%d-", (i * 7919) % 100003)
            for (k = 0; k < i % 23; k++) v = v "x"
            printf "SET key:%05d %s\r\n", i, v
        }
        for (i = 0; i < 1000; i++) {
            printf "RPUSH list:%d item:%d\r\n", i % 10, i
            printf "HSET hash:%d f:%d %d\r\n", i % 10, i, i * i
            printf "INCRBY counter:%d %d\r\n", i % 10, i
            printf "SADD set:%d m:%d\r\n", i % 10, (i * 37) % 1000
        }
    }' > /tmp/k4-load.txt
    cli --pipe < /tmp/k4-load.txt > /tmp/k4-pipe.out
    grep -q "errors: 0, replies: 14000" /tmp/k4-pipe.out || { cat /tmp/k4-pipe.out; k4_fail "dataset load"; }
}

# Fixed-key load (no -r): the dataset after it depends only on the request
# counts, so it is deterministic when every request completed.
fixed_load() {
    bench -n "$1" -c 20 -t set,get,incr,lpush,rpush,hset,sadd -q > /dev/null 2>&1
}

digest() { echo "dbsize $(cli dbsize) digest $(cli debug digest)"; }

# info_field SECTION FIELD
info_field() { cli info "$1" | tr -d '\r' | awk -F: -v f="$2" '$1 == f { print $2 }'; }

# wait_info SECTION FIELD VALUE: poll until INFO shows the value (max 120 s).
wait_info() {
    local i=0
    until [ "$(info_field "$1" "$2")" = "$3" ]; do
        i=$((i + 1))
        [ "$i" -lt 2400 ] || k4_fail "INFO $1 $2 never became $3"
        sleep 0.05
    done
}
