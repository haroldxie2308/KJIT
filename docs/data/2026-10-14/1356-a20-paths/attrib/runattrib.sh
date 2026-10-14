#!/bin/bash
# usage: runattrib.sh before|after set|get
S=/private/tmp/claude-501/-Volumes-CaseSentitiveLocal-KJIT/b06f19aa-bc63-41a1-912e-50230c2c0e32/scratchpad
$S/target/debug/attrib-$1 --trace $S/lowering-$2.tsv \
 --map /usr/local/bin/redis-server=$S/elf/redis-server \
 --map /usr/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1=$S/elf/ld-linux-aarch64.so.1 \
 --map /usr/lib/aarch64-linux-gnu/libc.so.6=$S/elf/libc.so.6 \
 --map /usr/lib/aarch64-linux-gnu/libm.so.6=$S/elf/libm.so.6 \
 --out $S/out/$1-$2.tsv
