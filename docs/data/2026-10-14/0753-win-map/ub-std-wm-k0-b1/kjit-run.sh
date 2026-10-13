#!/bin/sh
set -e
sh /opt/kjit-tests/ub-bench.sh sys 7; sh /opt/kjit-tests/ub-standard.sh /tmp/ubs pinned 500000 3 1 1024; sh /opt/kjit-tests/ub-standard.sh /tmp/ubu unpinned 500000 3 1
