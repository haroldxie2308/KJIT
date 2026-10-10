#!/bin/sh
set -e
K=/sys/kernel/debug/kjit; grep -q " /sys/kernel/debug debugfs" /proc/mounts || mount -t debugfs debugfs /sys/kernel/debug; for s in 0 1; do echo $s > $K/enable; echo $s > $K/auto; KJIT_AUTO=$s /opt/kjit-tests/code_speed sites64 1 40 7 | grep "^result"; done
