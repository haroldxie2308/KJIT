#!/bin/sh
set -e
STATES='off on on+time on+decline+time on+spin+time on+decline+spin+time off+spin' sh /kjit/c1-sweep.sh /tmp/c1 3 get_c1:base:get:100000:1:1:1:0:0:1-3:tcp get_c10:base:get:300000:10:1:1:2:0:1-3:tcp
