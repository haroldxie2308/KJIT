#!/bin/sh
set -e
sh /opt/kjit-tests/k4-suite.sh /kjit/suite --clients 16 --dump-logs
