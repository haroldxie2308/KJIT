#!/bin/sh
set -e
mount -t debugfs debugfs /sys/kernel/debug; echo "ids 1 1 0 0" > /sys/kernel/debug/kjit/exp_bench; cat /sys/kernel/debug/kjit/exp_bench; grep -c ssbs /proc/cpuinfo
