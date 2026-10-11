#!/bin/sh
set -e
UB_ROX_INSN_COPY=0xffff800080515844 UB_ROX_WARM=300000 UB_ROX_KB=1 sh /kjit/rox-sweep.sh /tmp/rox 1000000 4 'rox roxnc rwxnc' 1 1024
