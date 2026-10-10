#!/bin/sh
set -e
mount -t debugfs debugfs /sys/kernel/debug 2>/dev/null; echo 0 > /sys/kernel/debug/kjit/enable; echo 0 > /sys/kernel/debug/kjit/auto; echo "FACT cmdline: $(cat /proc/cmdline)"; echo "FACT spec_store_bypass: $(cat /sys/devices/system/cpu/vulnerabilities/spec_store_bypass)"; dmesg | grep -i -E "spectre-v4|ssbs|ssbd" | sed "s/^/FACT dmesg /"; echo "ids 1 1 0 0" > /sys/kernel/debug/kjit/exp_bench; cat /sys/kernel/debug/kjit/exp_bench; /opt/kjit-tests/exp_el1 7 20; /opt/kjit-tests/exp_el0 7 20
