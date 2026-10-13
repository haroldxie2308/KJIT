#!/bin/sh
set -e
UB_HUGE_STATES='k4 pmd' UB_HUGE_FIRST=k4 UB_HUGE_WARM=300000 UB_HUGE_KB=0 sh /opt/kjit-tests/huge-sweep.sh /tmp/hs 300000 6 1
