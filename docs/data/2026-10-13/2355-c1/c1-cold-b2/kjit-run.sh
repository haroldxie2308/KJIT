#!/bin/sh
set -e
VARIANTS="calls brret retx ret alu" sh /kjit/c1-cold.sh 3 50 "off off+spin on"; VARIANTS="calls brret retx" sh /kjit/c1-cold.sh 2 0 "off on"; VARIANTS="calls brret retx" sh /kjit/c1-cold.sh 2 1000 "off on"
