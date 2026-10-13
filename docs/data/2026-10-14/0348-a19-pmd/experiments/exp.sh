# EXPERIMENT (A19): alias probe and helper-failure knob. Runs in the guest as /kjit/exp.sh.
mount -t debugfs debugfs /sys/kernel/debug 2>/dev/null
K=/sys/kernel/debug/kjit
echo "== cmdline: $(cat /proc/cmdline)"
echo 1 > $K/enable
info() { echo "-- $1"; grep -E "^(MemFree|VmallocUsed)" /proc/meminfo; echo "vmallocinfo chunk areas: $(grep -c kjit_arena_chunk_new /proc/vmallocinfo)"; grep -E "^arena" $K/stats; }
probe() {
    /opt/kjit-tests/arena_churn 6 4 > /tmp/churn.out 2>&1 &
    pid=$!
    sleep 3
    echo "-- $1: stats"; grep -E "^arena" $K/stats
    echo "-- $1: exp_alias"; cat $K/exp_alias
    echo "-- $1: vmallocinfo"; grep kjit_arena_chunk_new /proc/vmallocinfo
    wait $pid; echo "churn exit=$? $(tr '\n' ' ' < /tmp/churn.out | cut -c1-120)"
}
info "before"
echo 0 > $K/exp_rox_fail; probe "fail=0 (helper succeeds)"
sleep 2; info "after fail=0 churn"
echo 1 > $K/exp_rox_fail; probe "fail=1 (helper fails after the alias is unmapped; glue falls back)"
sleep 2; info "after fail=1 churn"
echo 0 > $K/exp_rox_fail; probe "fail=0 again"
sleep 2; info "end"
echo "== dmesg splat scan"; dmesg | grep -E "BUG:|WARNING:|Oops|Call trace" || echo "none"
