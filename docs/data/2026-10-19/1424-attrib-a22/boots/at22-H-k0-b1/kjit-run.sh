#!/bin/sh
set -e
sh /kjit/attrib-a22.sh /tmp/atr 8 1000000 100000 0 'ug:get:50:1:1:2:unix:1-3 us:set:50:1:1:2:unix:1-3 up:ping_mbulk:50:1:1:2:unix:1-3 ug3:get:60:1:1:3:unix:1-3' 'off on'
