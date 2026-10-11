#!/bin/sh
set -e
UB_ROX_WARM=300000 UB_ROX_KB=1 sh /kjit/rox-sweep.sh /tmp/rox 1000000 6 'rox rwx' 1 1024
