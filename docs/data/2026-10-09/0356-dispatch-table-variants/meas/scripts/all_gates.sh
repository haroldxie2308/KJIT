#!/bin/bash
S=/private/tmp/claude-501/-Volumes-CaseSentitiveLocal-KJIT/b06f19aa-bc63-41a1-912e-50230c2c0e32/scratchpad
$S/htest_all.sh 3 0 1 2 3 4 5
$S/gates.sh 3 0 1 2 3 4 5
echo ALL_GATES_DONE
