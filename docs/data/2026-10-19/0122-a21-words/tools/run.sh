#!/bin/bash
# Regenerates the census of docs/journal/2026-10-14.md "Hot-path word census on A20".
#   tools/run.sh ELFDIR WORKTREE OUTDIR
# ELFDIR: redis-server, ld-linux-aarch64.so.1, libc.so.6, libm.so.6 as in the guest rootfs of the
#   A20 entry (md5 in logs/elf-md5.txt); the census dies if an executed word of the trace differs from the ELF.
# Needs llvm-mc on PATH (disassembly) and a harness built from a tree whose shared/ is the one to count.
set -euo pipefail
E=$1; W=$2; O=$3
mkdir -p "$O"
make -C "$W" harness-sync >/dev/null
cp "$(dirname "$0")/census.rs" "$W/harness/src/bin/census.rs"      # untracked helper, remove afterwards
(cd "$W/harness" && cargo build --bin census)
for t in set get; do
  "$W/harness/target/debug/census" \
    --trace "$W/docs/data/2026-10-13/1525-attrib-a17/attrib-lowering-$t.tsv" \
    --map /usr/local/bin/redis-server="$E/redis-server" \
    --map /usr/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1="$E/ld-linux-aarch64.so.1" \
    --map /usr/lib/aarch64-linux-gnu/libc.so.6="$E/libc.so.6" \
    --map /usr/lib/aarch64-linux-gnu/libm.so.6="$E/libm.so.6" \
    --out "$O/$t.tsv"
done
# then: python3 "$(dirname "$0")/census.py" "$O" <data dir>/<HHMM>-word-census
