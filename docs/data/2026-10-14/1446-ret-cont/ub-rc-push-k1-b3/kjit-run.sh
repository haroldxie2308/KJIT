#!/bin/sh
set -e
sh /kjit/cond-info.sh 5; RC_STATES='m0 m1 m2 m3' sh /kjit/retcont-sweep.sh /tmp/cond 4 set_c50_p1_d1:base:set:1000000:50:1:1:2:0:1-3:tcp get_c50_p1_d1:base:get:1000000:50:1:1:2:0:1-3:tcp unix_set_c50_p1_d1:unix:set:1000000:50:1:1:2:0:1-3:unix unix_pingm_c50_p1:unix:ping_mbulk:1000000:50:1:1:2:0:1-3:unix unix_get_c50_p1_d1:unix:get:1000000:50:1:1:2:0:1-3:unix
