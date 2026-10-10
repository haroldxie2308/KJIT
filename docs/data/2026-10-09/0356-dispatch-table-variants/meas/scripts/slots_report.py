#!/usr/bin/env python3
"""slots_report.py MEASDIR [test] [pass]: remaining ibtc_slots listings per boot, with symbols."""
import bisect, glob, os, re, subprocess, sys

NM = "/opt/homebrew/opt/llvm/bin/llvm-nm"
BASE = "/Volumes/Local/kjit-a4b2/bins/"
NAMES = {0: "V0 direct", 1: "V1 hash", 2: "V2a 2-way 2048x2", 3: "V2b 2-way 4096x2",
         4: "V3a victim 256", 5: "V3b victim 512"}

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

out = sys.argv[1]
test = sys.argv[2] if len(sys.argv) > 2 else "set"
npass = sys.argv[3] if len(sys.argv) > 3 else "2"
for path in sorted(glob.glob(os.path.join(out, "boot-*.serial.log")), key=lambda p: (int(re.search(r"-v(\d)", p).group(1)), p)):
    m = re.search(r"boot-(\d+)-v(\d)", path)
    boot, variant = int(m.group(1)), int(m.group(2))
    text = open(path, errors="replace").read().replace("\r", "")
    maps = []
    for line in text.splitlines():
        if line.startswith("a11maps ") and "r-xp" in line:
            parts = line.split()
            lo, hi = [int(x, 16) for x in parts[1].split("-")]
            maps.append((lo, hi, parts[-1]))

    def resolve(pc):
        for lo, hi, name in maps:
            if lo <= pc < hi:
                off = pc - lo
                table = redis if "redis-server" in name else libc if "libc" in name else None
                if table is None:
                    return f"{os.path.basename(name)}+{off:#x}"
                keys = [a for a, _ in table]
                i = bisect.bisect_right(keys, off) - 1
                return f"{table[i][1]}+{off - table[i][0]:#x}" if i >= 0 else "?"
        return "?"

    print(f"-- boot {boot:02d} {NAMES[variant]} ({test.upper()} pass {npass} at chain_budget 1024)")
    for line in text.splitlines():
        m = re.match(rf"a11slots point=1024 pass={npass} test={test} (.*)", line)
        if not m:
            continue
        body = m.group(1)
        if body.startswith("#"):
            print("  ", body)
            continue
        f = body.split()
        if len(f) == 5 and int(f[2]) >= 1000:
            ev, ed = int(f[3], 16), int(f[4], 16)
            print(f"   {f[0]:4s} slot {int(f[1]):4d} {int(f[2]):7d} {resolve(ev)} <-> {resolve(ed)}")
