#!/bin/sh
set -e
UB_PAN_WARM=300000 sh /kjit/pan-sweep.sh /tmp/pan 1000000 2 1 64 1024 4096 16384
