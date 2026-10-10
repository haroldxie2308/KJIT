#!/bin/sh
set -e
mount -t debugfs debugfs /sys/kernel/debug; K=/sys/kernel/debug/kjit; T=/opt/kjit-tests; for e in 0 1; do echo $e > $K/enable; echo "== enable=$e"; KJIT_EXPECT=$( [ $e = 1 ] && echo fpsimd ) $T/fp_stale 300; done; grep -E "fpsimd|translate_entry" $K/stats
