#!/bin/sh
set -e
mount -t debugfs debugfs /sys/kernel/debug; K=/sys/kernel/debug/kjit; T=/opt/kjit-tests; echo 1 > $K/enable; for i in 1 2 3; do echo "== try $i"; KJIT_EXPECT=fpsimd $T/fp_stale 300 ; echo "status=$?"; done; echo 0 > $K/enable; echo "== kjit off"; $T/fp_stale 300; echo "status=$?"
