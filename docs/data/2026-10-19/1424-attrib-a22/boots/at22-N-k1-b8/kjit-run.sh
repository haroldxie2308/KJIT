#!/bin/sh
set -e
sh /kjit/attrib-a22.sh /tmp/atr 4 1000000 100000 2 'ug:get:50:1:1:2:unix:1-3 us:set:50:1:1:2:unix:1-3 up:ping_mbulk:50:1:1:2:unix:1-3' 'off on nostats1 nostats2 nostats4 nostats7'
