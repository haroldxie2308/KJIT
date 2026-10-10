#!/bin/bash
# usage: guest_gates.sh TAG VARIANT...   (guest-tests and guest-tests-k3 only)
S=/Volumes/Local/kjit-a4b2/meas/scripts
L=/Volumes/Local/kjit-a4b2/logs
tag=$1; shift
for v in "$@"; do
    $S/grun.sh $v 3600 "sh /opt/kjit-tests/run-k2.sh 1" k2-$tag > $L/k2-v$v-$tag.log 2>&1
    echo "v$v k2 rc=$? : $(grep -E 'k2: ALL PASS' $L/k2-v$v-$tag.log | head -1)"
    $S/grun.sh $v 14400 "sh /opt/kjit-tests/run-k3.sh 1 64 4" k3-$tag > $L/k3-v$v-$tag.log 2>&1
    echo "v$v k3 rc=$? : $(grep -E 'k3: ALL PASS' $L/k3-v$v-$tag.log | head -1)"
done
