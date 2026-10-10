#!/bin/sh
set -e
mount -t debugfs debugfs /sys/kernel/debug 2>/dev/null; echo 0 > /sys/kernel/debug/kjit/enable; echo 0 > /sys/kernel/debug/kjit/auto; /opt/kjit-tests/exp_el1 7 20; /opt/kjit-tests/exp_el0 7 20
