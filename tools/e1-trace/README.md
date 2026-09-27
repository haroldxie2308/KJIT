# E1 dynamic trace

Measures what a real server executes between consecutive syscalls of a thread:
per gap, its length in dynamic instructions and the exact instructions run. The
offline `e1-report` (harness) turns that into syscall/gap-length/form tables and
checks every traced word against KJIT's current `admit_word`.

```sh
make e1-trace                 # build image, trace, report -> tmp/e1/
E1_N=5000 make e1-trace       # smaller workload
```

Knobs (env, see `scripts/e1-trace.sh`): `E1_N` (requests per test, default
20000), `E1_CLIENTS` (4), `E1_TESTS` (`get,set,incr,lpush,lpop`), `E1_CPU`
(QEMU CPU model, `neoverse-n1`), `E1_ELIDE` (`113:114:169`), `E1_OUT`
(`tmp/e1`).

## Pieces

| file | role |
|---|---|
| `Dockerfile` | `redis:7.4-bookworm` + Debian `qemu-user` 7.2 + the `qemu-plugin.h` from the exact Debian source version of that qemu-user |
| `kjit_trace.c` | QEMU TCG plugin (plugin API v1) |
| `run-in-container.sh` | builds the plugin, runs `redis-server` under `qemu-aarch64 -plugin`, drives it with a native `redis-benchmark`, shuts it down |
| `../../scripts/e1-trace.sh` | host driver: image build, container run, `e1-report` |
| `../../harness/src/bin/e1-report.rs` | offline report |

## Why a QEMU plugin

Debian bookworm's `qemu-user` is built with TCG plugin support, so no QEMU build
is needed; only the header is taken from the matching source package. A plugin
sees every executed instruction (per-insn exec callback) and every syscall
(syscall callback, with the number), per vCPU, which in linux-user is one guest
thread. A ptrace single-step tracer would be exact too but costs two context
switches per instruction; the plugin traces the default workload (100k
requests) in about 20 s.

## Semantics and known distortions

- A gap starts after a syscall and ends at the next syscall of the same thread.
  Its length counts every executed instruction, including the ending `svc`.
- `clock_gettime`, `clock_getres` and `gettimeofday` are vDSO calls on native
  arm64 but real SVCs under QEMU 7.2 linux-user (its vDSO is absent). They are
  counted but do not end a gap (`elide=`). The glibc fallback path (a few
  instructions and an `svc`) replaces the native vDSO body (a few dozen
  instructions, including `mrs cntvct_el0`), so those gaps are slightly short.
- `-cpu neoverse-n1`: no SVE, so glibc's ifuncs select the same non-SVE string
  routines as on Apple/Neoverse-N1 hosts. MIDR-dependent ifunc choices can
  still differ from a given native host.
- Traced redis runs ~10x slower than native (5.0-6.7k vs 51-67k requests/s
  for the default benchmark in the same container), while time-driven work
  (`serverCron`, `hz 10`) keeps its wall-clock rate. Long cron gaps (e.g. the
  jemalloc `mallctl` stats refresh, ~1.7M insns) are therefore over-represented
  relative to request gaps, and how many ready clients one `epoll_pwait`
  returns (the `read -> read` vs `epoll_pwait -> read` mix) is timing
  dependent. Per-gap instruction sequences are unaffected.
- Forked children (clone without `CLONE_VM`, e.g. redis' startup MADV_FREE
  check) are not traced; the parent counts them (`T forks_not_traced`).
- `rseq` returns `ENOSYS` under QEMU 7.2, so glibc runs without rseq.
- Not handled (would double count): QEMU re-executing an instruction after
  `EXCP_ATOMIC`, or a guest instruction faulting mid-block. Redis does neither
  in normal operation; the trace does not detect it.

## Output format (`trace.txt`, text, one record per line)

Written once at process exit (the parent only), in this order:

| record | fields |
|---|---|
| `V 1` | format version |
| `B l0 l1 l2` | length bucket upper bounds (256 1000 10000); bucket 3 is > l2 |
| `X nr...` | elided syscall numbers |
| `M id path` | image (host `/proc/self/maps` path of the guest mapping) |
| `I id pc word image fileoff` | distinct (pc, word); pc/word/fileoff hex |
| `S nr count` | syscall histogram, all syscalls including elided |
| `G vcpu start end len elided shape` | one gap; `start` -1 = thread start, `end` -1 = open at exit; `shape` = id of its distinct-insn set for closed gaps within l2, else -1 |
| `H id n insn...` | shape: sorted distinct insn ids |
| `C start end bucket insn count` | dynamic count of insn in closed gaps of (start, end, bucket) |
| `T key value` | tracer counters (`word_changes`, `maps_reloads`, `forks_not_traced`) |
| `E` | end marker |

`e1-report` cross-checks that, per (start, end, bucket), the `C` counts sum to
the `G` lengths, and rejects a trace without `E`.
