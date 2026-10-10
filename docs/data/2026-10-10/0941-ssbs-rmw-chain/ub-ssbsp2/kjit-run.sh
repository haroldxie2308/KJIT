#!/bin/sh
set -e
mount -t debugfs debugfs /sys/kernel/debug; echo 0 > /sys/kernel/debug/kjit/enable; echo 0 > /sys/kernel/debug/kjit/auto; /opt/kjit-tests/exp_el1 7 20 exp_ssbs_pair exp_loop exp_pan_pair
