#!/bin/sh
set -e
for n in 256 64 16; do COLD_BIN=/kjit/cold_calls$n VARIANTS="calls ret alu" sh /kjit/c1-cold.sh 3 50 "off on"; done; COLD_BIN=/kjit/cold_calls64 VARIANTS="calls ret" sh /kjit/c1-cold.sh 3 0 "off on"
