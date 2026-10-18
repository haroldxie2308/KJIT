#!/bin/sh
# What the booted kernel enables (entry-cost knobs of the operating-condition sweep),
# then the null-syscall round trip, KJIT off and on (ub-bench.sh sys, which prints
# "ub <state> ..." lines). Inside the kjit-guest. No arguments: REPS via $1 (default 7).
set -u
grep -q " /sys/kernel/debug debugfs" /proc/mounts || mount -t debugfs debugfs /sys/kernel/debug
echo "cond: cmdline: $(cat /proc/cmdline)"
for f in /sys/devices/system/cpu/vulnerabilities/*; do
    echo "cond: vuln $(basename "$f"): $(cat "$f")"
done
dmesg | grep -iE "spectre|ssb|mitigat|isolation|bhb|errata|workaround" | sed 's/^/cond: dmesg: /'
echo "cond: kernel: $(uname -r) cpus: $(grep -c ^processor /proc/cpuinfo)"
sh /opt/kjit-tests/ub-bench.sh sys "${1:-7}"
