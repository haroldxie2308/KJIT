# EXPERIMENT (A19): repeated helper success and failure, then touch (nearly) all free memory through the linear map.
mount -t debugfs debugfs /sys/kernel/debug 2>/dev/null
K=/sys/kernel/debug/kjit
echo "== cmdline: $(cat /proc/cmdline)"
echo 1 > $K/enable
for mode in 1 0; do
    echo $mode > $K/exp_rox_fail
    i=0
    while [ $i -lt 12 ]; do
        /opt/kjit-tests/arena_churn 1 2 > /tmp/churn.out 2>&1 || { echo "churn failed"; cat /tmp/churn.out; }
        i=$((i + 1))
    done
    sleep 2
    echo "-- fail=$mode: 12 churn runs done: $(grep -E '^arena' $K/stats | tr '\n' ' ')"
    mkdir -p /mnt/fill; mount -t tmpfs -o size=3300m none /mnt/fill
    dd if=/dev/zero of=/mnt/fill/x bs=1M count=3200 2>&1 | tail -1
    free -m | sed -n 2p
    rm -f /mnt/fill/x; umount /mnt/fill
    echo "-- fail=$mode: memory filled and released"
done
echo 0 > $K/exp_rox_fail
echo "== dmesg splat scan"; dmesg | grep -E "BUG:|WARNING:|Oops|Call trace|Unable to handle" || echo "none"
