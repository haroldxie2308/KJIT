#!/bin/sh
set -e
STATES='off on' sh /kjit/c1-sweep.sh /tmp/c1 6 get_c1:base:get:100000:1:1:1:0:0:1-3:tcp set_c1:base:set:100000:1:1:1:0:0:1-3:tcp get_c10:base:get:300000:10:1:1:2:0:1-3:tcp set_c10:base:set:300000:10:1:1:2:0:1-3:tcp
