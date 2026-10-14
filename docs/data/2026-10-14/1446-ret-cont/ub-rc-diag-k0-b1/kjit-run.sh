#!/bin/sh
set -e
sh /kjit/cond-info.sh 5; sh /kjit/retcont-sweep.sh /tmp/cond 1 set_c50_p1_d1:base:set:300000:50:1:1:2:0:1-3:tcp get_c50_p1_d1:base:get:300000:50:1:1:2:0:1-3:tcp
