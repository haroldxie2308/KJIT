#!/bin/sh
set -e
sh /kjit/cond-info.sh 5; sh /kjit/cond-sweep.sh /tmp/cond 4 get_c50_p1_d1_n2m:base:get:2000000:50:1:1:2:0:1-3:tcp set_c50_p1_d1_n500k:base:set:500000:50:1:1:2:0:1-3:tcp set_c50_p1_d1_n2m:base:set:2000000:50:1:1:2:0:1-3:tcp get_c50_p1_d1_n500k:base:get:500000:50:1:1:2:0:1-3:tcp
