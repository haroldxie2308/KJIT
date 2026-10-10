# KJIT

KJIT runs hot AArch64 userspace code in the kernel. Code between syscalls is
translated into verified EL1 fragments, so a program can issue its next syscall
without returning to EL0. Contracts are in [`docs/pipeline.md`](docs/pipeline.md);
experiments and decisions are in [`docs/journal/`](docs/journal/).

![Architecture](figs/architecture.svg)

## Repository layout

| Path | What |
|---|---|
| `spec/arm64/subset.toml`, `specgen/` | Supported A64 subset and the generator of `A64Insn` from Arm XML |
| `shared/` | `no_std` translator, ABI and verifier, used by both the kernel module and the harness |
| `harness/` | Userspace proving ground: interpreter, kernel-runtime model, native oracle, fuzzer |
| `runtime/`, `kjit_glue.c`, `rust_kjit.rs`, `Kbuild` | The kernel module `kjit.ko` |
| `kernel-patches/` | Patch series on the pinned `dep/linux` (7.1-rc1) |
| `kernel-config/` | Kernel config fragments per profile |
| `tests/arm64/`, `tests/guest/` | Harness fixtures; guest tests and the redis campaign |
| `scripts/`, `docker/`, `tools/` | Dev container, kernel and guest builds, QEMU, benchmarks |
| `docs/` | `pipeline.md` (contracts), `journal/` (dated entries), `data/` (measurement data) |
| `figs/` | draw.io sources and SVGs |

`shared/` is the source of truth; `harness/src/shared/` is a synced copy
(`make harness-sync`). Generated A64 code is never edited by hand: change
`spec/arm64/subset.toml` or `specgen/`, then `make spec-gen`.

## Build and run

### Userspace: harness (no kernel needed)

Prerequisites: a Rust toolchain; `llvm-mc`, `llvm-nm` and `llvm-objcopy` on
`PATH` (for example Homebrew `llvm`); Docker for the native-hardware oracle on
macOS.

```sh
make harness-test            # unit tests, fixture differential check, verifier mutation suite, fuzz slice
make harness-test-native     # adds the host CPU as a third oracle (linux/arm64 container on macOS)
make fuzz SEED=1 ITERS=200000          # differential fuzzer; FUZZ_ARGS=... for more options
make harness-test-asm ASM=tests/arm64/toy_cfg.s    # one fixture, full pipeline check
make harness-dump-cfg        # CFG dump of the toy fixture
make harness-tui ASM=tests/arm64/toy_cfg.s         # interactive trace explorer (OpenTUI)
make coverage-scan ELF=path/to/aarch64.elf         # how far the translator gets on a real binary
make e1-trace                # dynamic trace of redis between syscalls (needs Docker)
make spec-gen                # regenerate A64 code from subset.toml (needs the Arm ISA XML, see ARM64_ISA_XML_DIR)
make spec-test-encoding      # generated encodings against LLVM's assembler
```

Every `*_mark` symbol in `tests/arm64/*.s` is a differential case (hot SVC PC =
the symbol, entry = symbol + 4).

### Kernel: dev container, patched tree, guest images

Kernels build out of tree from a patched worktree of `dep/linux`
(`$KJIT_BUILD_ROOT/linux-kjit`). Builds run in the Linux dev container; QEMU runs
on the host (HVF on Apple Silicon). Local overrides go in `.kjit.env`.

```sh
git submodule update --init dep/linux
export KJIT_BUILD_ROOT=/Volumes/CaseSentitiveLocal/kjit-build     # optional; must be case-sensitive
make kernel-tree KJIT_LINUX_GIT=/path/to/KJIT/dep/linux           # host: create/update the patched tree
./scripts/docker-dev.sh --build-image -- true                     # build the dev image
./scripts/docker-dev.sh -- make guest-kernel                      # kernel + kjit.ko, profile kjit-guest
./scripts/docker-dev.sh -- make guest-kernel-debug                # + KASAN, lockdep, DEBUG_ATOMIC_SLEEP
make guest-rootfs                                                 # host: Debian + redis 7.0.15 + guest tests -> rootfs.cpio
```

Profiles (`KJIT_KERNEL_PROFILE`):

| Profile | Use |
|---|---|
| `tiny-qemu`, `tiny-qemu-debug` (default) | K0: boot, golden fragment check, load and unload |
| `kjit-guest` | Debian bookworm + redis in an initramfs: K2/K3 guest tests, the redis campaign |
| `kjit-guest-debug` | `kjit-guest` + generic KASAN, lockdep, `DEBUG_ATOMIC_SLEEP`, `DEBUG_LIST` |

K0 smoke test: `./scripts/docker-dev.sh -- make kernel-prepare kernel-build
module-build initramfs`, then `make qemu-run`. After a deliberate translator
change, regenerate the golden fragment with `make kernel-golden`.

Other targets: `make prepare` (tiny profile kernel + harness sync),
`make rust-analyzer`, `make qemu-run-bg`, `make qemu-reset`, `make pack`,
`make help`.

### Running programs in the guest

```sh
make guest-run GUEST_PROFILE=kjit-guest CMD='redis-server --daemonize yes --save "" --appendonly no; sleep 1; redis-benchmark -q -n 10000'
make guest-run GUEST_PROFILE=kjit-guest CMD=sh        # interactive shell on the serial console
make e0-bench GUEST_PROFILE=kjit-guest                # cost of a syscall, native vs guest
```

Each run boots one guest, loads `kjit.ko`, runs the command and keeps
`serial.log` in its run directory. It fails on a non-zero exit, a timeout or any
kernel `BUG:`/`WARNING:`/oops line.

### Guest tests

```sh
make guest-tests GUEST_PROFILE=kjit-guest              # K2: micro tests in tests/guest, KJIT off vs on
make guest-tests GUEST_PROFILE=kjit-guest-debug K2_ITERATIONS=100
make guest-tests-k3 GUEST_PROFILE=kjit-guest           # K3: real programs under the auto mode
make guest-tests-k3 GUEST_PROFILE=kjit-guest-debug K3_ITERATIONS=20
```

Every test runs with KJIT off and on and must print the same output with the
same exit status.

### Redis campaign (K4)

redis 7.0.15 under the auto mode: the full test suite, `redis-benchmark` and
adversarial tests, each KJIT off and on.

```sh
make redis-campaign GUEST_PROFILE=kjit-guest
make redis-campaign GUEST_PROFILE=kjit-guest-debug K4_ITERATIONS=10
make redis-campaign K4_ARGS=--no-suite                 # only benchmark + adversarial
```

Pass criteria and exclusions: [section
10](docs/pipeline.md#10-validation-of-the-kernel-runtime-k2-k4).

### Module interface

Module parameters: `auto`, `hot_threshold`, `hot_window_ms`, `chain_budget`,
`max_frags_per_mm`, `max_code_per_mm`, `max_frags_total`, `max_code_total`
(for example `insmod kjit.ko auto=1`).

debugfs, `/sys/kernel/debug/kjit/` (root only):

| File | Use |
|---|---|
| `translate` | write `"<pid> <pc>"`: translate that entry PC |
| `translate_svc_sites` | write `"<pid>"`: translate after every `svc` of the process |
| `enable` | `Y`/`N`: global switch |
| `auto`, `hot_threshold`, `hot_window_ms` | K3 auto mode |
| `chain_budget` | runtime fragment entries per hook call (1..65536, default 1024) |
| `stats` | all counters |
| `unsupported_top` | most frequent untranslatable words |
| `ibtc_slots` | per-table dispatch slots with the most conflict misses; write `reset` to zero them |

```sh
mount -t debugfs debugfs /sys/kernel/debug
echo $PID > /sys/kernel/debug/kjit/translate_svc_sites
cat /sys/kernel/debug/kjit/stats
```

Counter semantics: [section 8](docs/pipeline.md#8-kernel-runtime-k2).

### Editor setup

Use the dev container (`.devcontainer/` in VS Code, or `./scripts/docker-dev.sh`),
then `make prepare && make rust-analyzer` inside it.

## License

GPLv2, see [`LISCENSE/GPLv2`](LISCENSE/GPLv2).
