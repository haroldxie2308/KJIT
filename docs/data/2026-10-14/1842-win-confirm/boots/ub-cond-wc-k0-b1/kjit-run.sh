#!/bin/sh
set -e
sh /kjit/cond-info.sh 5; sh /kjit/cond-sweep.sh /tmp/cond 4 unix_pingm_c50_p1:unix:ping_mbulk:1000000:50:1:1:2:0:1-3:unix unix_get_c50_p1_d1:unix:get:1000000:50:1:1:2:0:1-3:unix
