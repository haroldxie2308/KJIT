#!/bin/sh
set -e
for f in /sys/devices/system/cpu/vulnerabilities/*; do echo "VULN $(basename $f): $(cat $f)"; done; echo "CMDLINE $(cat /proc/cmdline)"; grep -m1 -i "^Features" /proc/cpuinfo | sed "s/^/CPUINFO /"; grep -m3 -i "implementer\|part\|variant" /proc/cpuinfo | sed "s/^/CPUINFO /"; dmesg | grep -i -E "ssbs|spectre|workaround|store bypass|SSBD|CPU features|mitigat" | sed "s/^/DMESG /"; zcat /proc/config.gz 2>/dev/null | grep -i -E "SSBD|ERRATUM_3194386|MITIGATE|SPECTRE" | sed "s/^/CONFIG /"
