#!/usr/bin/env python3
"""For the hot pairs of the V0 boots (ibtc_slots), how many victim-index collisions would a
victim table of 2^bits entries (fold hash) have among the pcs that can be evicted?
Either pc of a pair may be the one in the victim table, so count both choices per pair:
the number of colliding pairs among all pcs (upper bound) and the expectation over
random choices of one pc per pair."""
import glob, itertools, random, re, sys

out = sys.argv[1]
def fold(pc, bits):
    return (((pc ^ (pc >> 12)) >> 2) & ((1 << bits) - 1))

for path in sorted(glob.glob(out + "/boot-*-v0.serial.log")):
    text = open(path, errors="replace").read().replace("\r", "")
    pairs = {}
    for line in text.splitlines():
        m = re.match(r"a11slots point=1024 pass=2 test=set (all|nofp) (\d+) (\d+) (0x[0-9a-f]+) (0x[0-9a-f]+)", line)
        if m and int(m.group(3)) >= 1000:
            pairs[(m.group(1), int(m.group(2)))] = (int(m.group(4), 16), int(m.group(5), 16))
    for table in ("all", "nofp"):
        ps = [v for (t, s), v in pairs.items() if t == table]
        allpcs = [pc for p in ps for pc in p]
        for bits in (8, 9):
            col_all = sum(1 for a, b in itertools.combinations(allpcs, 2) if fold(a, bits) == fold(b, bits))
            rng = random.Random(1)
            tot = 0
            n = 2000
            for _ in range(n):
                pick = [rng.choice(p) for p in ps]
                tot += sum(1 for a, b in itertools.combinations(pick, 2) if fold(a, bits) == fold(b, bits))
            print(f"{path.split('/')[-1][:10]} {table:4s} pairs={len(ps):2d} bits={bits}: colliding pc pairs among all {len(allpcs)} pcs: {col_all}; expected over one-pc-per-pair choices: {tot / n:.3f}")
