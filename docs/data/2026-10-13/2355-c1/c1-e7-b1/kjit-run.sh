#!/bin/sh
set -e
STATES='off on on+time on+pf=7+time on+pf=8+time on+svc22 on+decline on+epoll_native on+nofpinv on+spin+time' sh /kjit/c1-sweep.sh /tmp/c1 3 get_c1:base:get:100000:1:1:1:0:0:1-3:tcp get_c10:base:get:300000:10:1:1:2:0:1-3:tcp
