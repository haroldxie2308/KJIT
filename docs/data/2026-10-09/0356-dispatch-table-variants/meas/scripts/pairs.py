#!/usr/bin/env python3
"""pairs.py LOG: resolve the ibtc_slots pairs of a baseline boot to symbols and compare hash families."""
import bisect, re, subprocess, sys, itertools, collections

NM = "/opt/homebrew/opt/llvm/bin/llvm-nm"
BASE = "/Volumes/Local/kjit-a4b2/bins/"

def syms(path, dyn=False):
    args = [NM, "-n", "--defined-only"] + (["-D"] if dyn else []) + [path]
    out = subprocess.run(args, capture_output=True, text=True).stdout
    res = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[1] in "TtWw":
            res.append((int(parts[0], 16), parts[2]))
    return res

redis = syms(BASE + "opt/redis/src/redis-server")
libc = syms(BASE + "usr/lib/aarch64-linux-gnu/libc.so.6", dyn=True)
addrs = [a for a, _ in redis]

log = open(sys.argv[1], errors="replace").read().replace("\r", "")
maps = []
for line in log.splitlines():
    if line.startswith("a11maps ") and "r-xp" in line:
        parts = line.split()
        lo, hi = [int(x, 16) for x in parts[1].split("-")]
        maps.append((lo, hi, parts[-1]))
print("exec maps:", [(hex(lo), hex(hi), name) for lo, hi, name in maps][:6])

def resolve(pc):
    for lo, hi, name in maps:
        if lo <= pc < hi:
            off = pc - lo
            table = redis if "redis-server" in name else libc if "libc" in name else None
            if table is None:
                return f"{name}+{off:#x}"
            keys = [a for a, _ in table]
            i = bisect.bisect_right(keys, off) - 1
            if i >= 0:
                return f"{table[i][1]}+{off - table[i][0]:#x}"
    return "?"

# top listings of the first SET pass
pairs = []
for line in log.splitlines():
    m = re.match(r"a11slots point=1024 pass=1 test=set (all|nofp) (\d+) (\d+) (0x[0-9a-f]+) (0x[0-9a-f]+)", line)
    if m:
        pairs.append((m.group(1), int(m.group(2)), int(m.group(3)), int(m.group(4), 16), int(m.group(5), 16)))

def direct(pc): return (pc >> 2) & 0xfff
def fold(shift): return lambda pc: (((pc ^ (pc >> shift)) >> 2) & 0xfff)
def fold2(pc): return (((pc ^ (pc >> 12) ^ (pc >> 24)) >> 2) & 0xfff)

hashes = {"direct pc[13:2]": direct, "fold12 (V1)": fold(12), "fold10": fold(10), "fold14": fold(14), "fold16": fold(16), "fold12+24": fold2}
print("\nhot pairs (per 200000 SET requests, table, slot, conflicts):")
sep = collections.Counter()
for table, slot, n, evictor, evicted in pairs:
    row = f"  {table:4s} slot {slot:4d} {n:7d} {evictor:#x} {evicted:#x} d={evictor - evicted:#x}  {resolve(evictor)} <-> {resolve(evicted)}"
    print(row)
    if n > 1000:
        for name, h in hashes.items():
            if h(evictor) != h(evicted):
                sep[name] += 1
hot = [p for p in pairs if p[2] > 1000]
print(f"\nhot pairs separated by each hash (of {len(hot)}):", dict(sep))

# collisions over all function entries of redis and libc (unweighted structure check)
for label, table, base in (("redis-server functions", redis, 0xaaaad6b20000),):
    pcs = sorted({base + a for a, _ in table})
    print(f"\n{label}: {len(pcs)} entries")
    for name, h in hashes.items():
        buckets = collections.Counter(h(pc) for pc in pcs)
        pairs_ = sum(c * (c - 1) // 2 for c in buckets.values())
        print(f"  {name:16s} colliding pairs {pairs_:6d}  max bucket {max(buckets.values())}")
# union with libc functions at the observed base
libc_map = [m for m in maps if "libc" in m[2]]
if libc_map:
    lbase = libc_map[0][0]
    pcs = sorted({0xaaaad6b20000 + a for a, _ in redis} | {lbase + a for a, _ in libc})
    print(f"\nredis + libc functions: {len(pcs)} entries (libc at {lbase:#x})")
    for name, h in hashes.items():
        buckets = collections.Counter(h(pc) for pc in pcs)
        pairs_ = sum(c * (c - 1) // 2 for c in buckets.values())
        print(f"  {name:16s} colliding pairs {pairs_:6d}  max bucket {max(buckets.values())}")
    # Expected for N random keys in 4096 slots
    n = len(pcs)
    print(f"  random expectation N^2/2/4096 = {n * n / 2 / 4096:.0f}")
