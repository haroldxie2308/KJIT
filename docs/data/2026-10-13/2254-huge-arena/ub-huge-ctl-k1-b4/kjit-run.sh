#!/bin/sh
set -e
UB_HUGE_STATES='k4a pmd' UB_HUGE_FIRST=pmd UB_HUGE_WARM=300000 UB_HUGE_KB=1 sh /opt/kjit-tests/huge-sweep.sh /tmp/hs 500000 6 1 1024
