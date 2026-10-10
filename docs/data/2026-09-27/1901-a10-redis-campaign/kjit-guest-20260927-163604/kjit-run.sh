#!/bin/sh
set -e
mount -t debugfs debugfs /sys/kernel/debug 2>/dev/null; cat /sys/module/kjit/parameters/chain_budget; echo 65536 > /sys/module/kjit/parameters/chain_budget; cat /sys/kernel/debug/kjit/chain_budget; echo 0 > /sys/kernel/debug/kjit/chain_budget || echo rejected0; echo 65537 > /sys/module/kjit/parameters/chain_budget || echo rejected65537; cat /sys/module/kjit/parameters/chain_budget; sh /opt/kjit-tests/k4-bench.sh /tmp/w 100000; cat /sys/kernel/debug/kjit/stats | grep chain
