#!/bin/sh
set -e
sh /kjit/attrib-a22.sh /tmp/atr 2 1000000 100000 4 'up:ping_mbulk:50:1:1:2:unix:1-3 ug:get:50:1:1:2:unix:1-3 us:set:50:1:1:2:unix:1-3' 'off on onT offT svcn svcnT decl1 decl2 offS onS ampcr amplk ampsr amppan ampbr ampat amptr amplink ampcl'
