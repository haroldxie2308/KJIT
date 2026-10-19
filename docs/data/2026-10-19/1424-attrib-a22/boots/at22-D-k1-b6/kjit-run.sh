#!/bin/sh
set -e
sh /kjit/attrib-a22.sh /tmp/atr 4 1000000 100000 0 'ug:get:50:1:1:2:unix:1-3 us:set:50:1:1:2:unix:1-3 up:ping_mbulk:50:1:1:2:unix:1-3' 'off on offD100 onD100 offD300 onD300 offS onS'
