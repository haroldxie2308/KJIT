#!/bin/sh
set -e
UB_PAN_WARM=300000 sh /kjit/pan-sweep.sh /tmp/pan 1000000 2 2 4 8 16 32 128 256 512 2048 8192
