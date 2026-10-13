#!/bin/sh
set -e
STATES='off on on+spin on+guard=64' sh /kjit/c1-sweep.sh /tmp/c1 2 get_c1:base:get:100000:1:1:1:0:0:1-3:tcp get_c2:base:get:150000:2:1:1:0:0:1-3:tcp get_c4:base:get:200000:4:1:1:0:0:1-3:tcp get_c10:base:get:300000:10:1:1:2:0:1-3:tcp get_c50:base:get:500000:50:1:1:2:0:1-3:tcp set_c1:base:set:100000:1:1:1:0:0:1-3:tcp set_c2:base:set:150000:2:1:1:0:0:1-3:tcp set_c4:base:set:200000:4:1:1:0:0:1-3:tcp set_c10:base:set:300000:10:1:1:2:0:1-3:tcp set_c50:base:set:500000:50:1:1:2:0:1-3:tcp
