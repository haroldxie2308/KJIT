#!/bin/sh
set -e
STATES='off on on+guard=4 on+guard=16 on+guard=64' sh /kjit/c1-sweep.sh /tmp/c1 2 get_c1:base:get:100000:1:1:1:0:0:1-3:tcp get_c10:base:get:300000:10:1:1:2:0:1-3:tcp get_c50:base:get:500000:50:1:1:2:0:1-3:tcp
