#!/bin/sh
set -e
STATES='off on on+guard=64' sh /kjit/c1-sweep.sh /tmp/c1 3 get_c1:base:get:100000:1:1:1:0:0:1-3:tcp get_c1s:base:get:100000:1:1:1:0:0:0:tcp get_c10:base:get:300000:10:1:1:2:0:1-3:tcp get_c10s:base:get:300000:10:1:1:0:0:0:tcp set_c1s:base:set:100000:1:1:1:0:0:0:tcp
