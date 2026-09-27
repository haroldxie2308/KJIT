# SPDX-License-Identifier: GPL-2.0

ARCH ?= arm64
LLVM ?= 1
ARM64_ISA_XML_DIR ?= $(CURDIR)/tmp/isa_a64_2026_03/ISA_A64_xml_A_profile-2026-03
HARNESS_SHARED_DIR := harness/src/shared
HARNESS_SHARED_BACKUP := harness/.shared.bak
KERNEL_GOLDEN_ASM := tests/arm64/toy_cfg.s
KERNEL_GOLDEN := tests/arm64/golden/toy_cfg_hot_svc_mark.rs

# Kernels build out of tree only: KDIR stays a clean source tree and the
# selected profile builds in $(KJIT_BUILD_ROOT)/$(KJIT_KERNEL_PROFILE). kjit.ko
# is built next to that kernel (Kbuild MO=). Same defaults as scripts/kjit-env.sh.
KJIT_BUILD_ROOT ?= $(CURDIR)/.kjit/build
KJIT_KERNEL_PROFILE ?= tiny-qemu-debug
# Every profile builds from the patched tree: kernel-patches/ applied to a
# worktree of the dep/linux submodule by scripts/kjit-kernel-tree.sh.
KJIT_PATCHED_KDIR ?= $(KJIT_BUILD_ROOT)/linux-kjit
KDIR ?= $(KJIT_PATCHED_KDIR)
KBUILD_OUTPUT ?= $(KJIT_BUILD_ROOT)/$(KJIT_KERNEL_PROFILE)
KJIT_MODULE_DIR ?= $(abspath $(KBUILD_OUTPUT))/kjit-module
GUEST_PROFILE ?= kjit-guest

# The scripts get the same selection, so every target keys off one build dir.
SCRIPT_ENV = KDIR=$(KDIR) KJIT_PATCHED_KDIR=$(KJIT_PATCHED_KDIR) KJIT_BUILD_ROOT=$(KJIT_BUILD_ROOT) \
	KJIT_KERNEL_PROFILE=$(KJIT_KERNEL_PROFILE) KBUILD_OUTPUT=$(KBUILD_OUTPUT) \
	KJIT_MODULE_DIR=$(KJIT_MODULE_DIR)

KMAKE = $(MAKE) -C $(KDIR) ARCH=$(ARCH) LLVM=$(LLVM) O=$(KBUILD_OUTPUT)
MODULE_MAKE = mkdir -p $(KJIT_MODULE_DIR) && $(KMAKE) M=$(CURDIR) MO=$(KJIT_MODULE_DIR)

.PHONY: initramfs kernel-tree guest-kernel guest-kernel-debug guest-rootfs guest-run e0-bench guest-tests guest-tests-k3
.PHONY: default modules_install install uninstall dm test rust-analyzer prepare harness-sync harness-prepare module-build \
    rustavailable-check kernel-prepare kernel-build kernel-clean clean qemu-run qemu-run-bg qemu-reset pack \
	harness-test harness-test-native fuzz harness-dump-cfg harness-tui tui harness-test-asm spec-test-encoding spec-gen coverage-scan e1-trace kernel-golden help

default:
	$(MODULE_MAKE)

modules_install: default
	$(MODULE_MAKE) modules_install

install:
	sudo insmod $(KJIT_MODULE_DIR)/kjit.ko

uninstall:
	sudo rmmod kjit

dm:
	@if [ -z "$(N)" ]; then \
		echo "Please provide N=<number> when calling make dm"; \
	else \
		echo "Saving dmesg to ./log/dm"$(N)".log"; \
		sudo dmesg -Wx > ./log/dm$(N).log; \
	fi

test:
	objdump -D kjit.ko -C rust > kjit_test.S

rust-analyzer:
	$(SCRIPT_ENV) bash ./scripts/gen-rust-project.sh

rustavailable-check:
	$(KMAKE) rustavailable

prepare: kernel-prepare kernel-build harness-prepare

harness-sync:
	@if [ -d "$(HARNESS_SHARED_DIR)" ]; then \
		rm -rf "$(HARNESS_SHARED_BACKUP)"; \
		cp -a "$(HARNESS_SHARED_DIR)" "$(HARNESS_SHARED_BACKUP)"; \
		echo "Backed up $(HARNESS_SHARED_DIR) to $(HARNESS_SHARED_BACKUP)"; \
	fi
	rsync -a --delete shared/ "$(HARNESS_SHARED_DIR)/"
	cp spec/arm64/generated/a64_subset.rs "$(HARNESS_SHARED_DIR)/arm64/generated.rs"

harness-prepare: harness-sync

kernel-prepare:
	$(SCRIPT_ENV) bash ./scripts/setup-kernel-build.sh

kernel-build:
	$(SCRIPT_ENV) bash ./scripts/setup-kernel-build.sh --build

kernel-clean:
	$(SCRIPT_ENV) bash ./scripts/setup-kernel-build.sh --clean

clean: kernel-clean

initramfs:
	$(SCRIPT_ENV) bash ./scripts/mk-initramfs.sh

qemu-run:
	$(SCRIPT_ENV) bash ./scripts/qemu-run.sh

qemu-run-bg:
	$(SCRIPT_ENV) bash ./scripts/qemu-run.sh --detach

qemu-reset:
	bash ./scripts/qemu-reset.sh

pack:
	bash ./scripts/pack.sh

module-build: default

# Host (needs dep/linux's git dir; override KJIT_LINUX_GIT from a git worktree of
# this repo): create/update the patched tree. setup-kernel-build.sh runs the
# same script and is a no-op when the tree is current.
kernel-tree:
	$(SCRIPT_ENV) bash ./scripts/kjit-kernel-tree.sh

guest-kernel:
	$(MAKE) kernel-build KJIT_KERNEL_PROFILE=kjit-guest
	$(MAKE) module-build KJIT_KERNEL_PROFILE=kjit-guest

guest-kernel-debug:
	$(MAKE) kernel-build KJIT_KERNEL_PROFILE=kjit-guest-debug
	$(MAKE) module-build KJIT_KERNEL_PROFILE=kjit-guest-debug

guest-rootfs:
	KJIT_BUILD_ROOT=$(KJIT_BUILD_ROOT) bash ./scripts/mk-guest-rootfs.sh

# CMD from the make command line is exported to the recipe environment;
# reading it as $$CMD avoids re-quoting it through make.
guest-run:
	@if [ -z "$(CMD)" ]; then echo "usage: make guest-run CMD='shell command' [GUEST_PROFILE=kjit-guest|kjit-guest-debug]" >&2; exit 2; fi
	KJIT_BUILD_ROOT=$(KJIT_BUILD_ROOT) bash ./scripts/guest-run.sh --profile $(GUEST_PROFILE) -- "$$CMD"

# K2 guest suite (tests/guest/run-k2.sh, in the rootfs since make guest-rootfs).
K2_ITERATIONS ?= 1
guest-tests: guest-rootfs
	KJIT_BUILD_ROOT=$(KJIT_BUILD_ROOT) bash ./scripts/guest-run.sh --profile $(GUEST_PROFILE) \
		--timeout 3600 -- "sh /opt/kjit-tests/run-k2.sh $(K2_ITERATIONS)"

# K3 guest suite (tests/guest/run-k3.sh): real programs under the auto mode.
K3_ITERATIONS ?= 1
K3_FILE_MIB ?= 64
K3_DD1_MIB ?= 4
guest-tests-k3: guest-rootfs
	KJIT_BUILD_ROOT=$(KJIT_BUILD_ROOT) bash ./scripts/guest-run.sh --profile $(GUEST_PROFILE) \
		--timeout 14400 -- "sh /opt/kjit-tests/run-k3.sh $(K3_ITERATIONS) $(K3_FILE_MIB) $(K3_DD1_MIB)"

e0-bench:
	KJIT_BUILD_ROOT=$(KJIT_BUILD_ROOT) bash ./scripts/e0-bench.sh --profile $(GUEST_PROFILE)

harness-test:
	cargo test --manifest-path harness/Cargo.toml -- --nocapture

harness-test-native:
	bash ./scripts/native-test.sh

SEED ?= 1
ITERS ?= 10000
MAX_LEN ?= 64
FUZZ_ARGS ?=

fuzz:
	cargo run --release --manifest-path harness/Cargo.toml --bin fuzz -- \
		--seed $(SEED) --iters $(ITERS) --max-len $(MAX_LEN) $(FUZZ_ARGS)

kernel-golden: harness-sync
	eval "$$(bash ./scripts/compile-asm-fixture.sh $(KERNEL_GOLDEN_ASM) tmp/kernel-golden)" && \
	cargo run --quiet --manifest-path harness/Cargo.toml --bin dump-golden -- \
		"$$COMPILED_ASM_PATH" "$$COMPILED_HOT_SVC_SYMBOL" "$$COMPILED_BIN_PATH" \
		"$$COMPILED_TEXT_BASE" "$$COMPILED_ENTRY_PC" > $(KERNEL_GOLDEN).tmp
	mv $(KERNEL_GOLDEN).tmp $(KERNEL_GOLDEN)

harness-dump-cfg:
	bash ./scripts/demo-toy-cfg.sh

harness-test-asm:
	ASM_PATH="$(ASM)" bash ./scripts/run-asm-fixture.sh

harness-tui:
	ASM_PATH="$(ASM)" bash ./scripts/run-trace-tui.sh

tui: harness-tui

COVERAGE_OUT ?= tmp/coverage-scan

coverage-scan:
	@if [ -z "$(ELF)" ]; then echo "usage: make coverage-scan ELF=path/to/aarch64.elf [COVERAGE_OUT=dir]" >&2; exit 2; fi
	cargo run --manifest-path harness/Cargo.toml --bin coverage-scan -- "$(ELF)" "$(COVERAGE_OUT)"

e1-trace:
	bash ./scripts/e1-trace.sh

spec-test-encoding:
	cargo test --manifest-path harness/Cargo.toml encoding_matches_llvm_for_handwritten_cases -- --ignored --nocapture

spec-gen:
	cargo run --manifest-path specgen/Cargo.toml -- --xml-dir "$(ARM64_ISA_XML_DIR)"
	cp spec/arm64/generated/a64_subset.rs harness/src/shared/arm64/generated.rs

help:
	@printf '%-20s %s\n' \
		'prepare' 'Prepare/build the kernel in the container dev environment' \
		'kernel-prepare' 'Configure $$KJIT_BUILD_ROOT/$$KJIT_KERNEL_PROFILE (default tiny-qemu-debug)' \
		'kernel-build' 'Build Image/modules in the profile build dir' \
		'kernel-clean' 'Clean the profile build dir' \
		'clean' 'Alias for kernel-clean' \
		'harness-sync' 'Copy shared/ into harness/src/shared with one backup' \
		'rust-analyzer' 'Generate rust-project.json for this module' \
		'rustavailable-check' 'Check Rust-for-Linux toolchain readiness' \
		'module-build' 'Build kjit.ko into <profile build dir>/kjit-module' \
		'initramfs' 'Container: K0 golden initramfs for the profile (after module-build)' \
		'kernel-tree' 'Host: git worktree of dep/linux + kernel-patches/ at $$KJIT_BUILD_ROOT/linux-kjit (K2 profiles)' \
		'guest-kernel' 'Container: configure+build kjit-guest and its kjit.ko in $$KJIT_BUILD_ROOT/kjit-guest' \
		'guest-kernel-debug' 'Container: same for kjit-guest-debug (KASAN, lockdep)' \
		'guest-rootfs' 'Host: build the Debian bookworm + redis initramfs (+ K2 guest tests in /opt/kjit-tests)' \
		'guest-tests' 'Host: run the K2 guest suite on GUEST_PROFILE, K2_ITERATIONS times' \
		'guest-tests-k3' 'Host: run the K3 auto-mode suite (real programs) on GUEST_PROFILE, K3_ITERATIONS times' \
		'guest-run' "Host: boot GUEST_PROFILE under QEMU, insmod kjit.ko, run CMD='...', power off" \
		'e0-bench' 'Host: E0 syscall microbenchmark in the guest and in a plain Docker container' \
		'spec-gen' 'Generate the checked-in ARM64 subset tables from the Arm XML bundle' \
		'harness-test' 'Run the standalone harness tests' \
		'harness-test-native' 'Run the harness tests plus the native hardware oracle on Linux arm64 (container on macOS)' \
		'fuzz' 'Differential fuzzer: SEED=, ITERS=, MAX_LEN=, FUZZ_ARGS= (e.g. --native)' \
		'harness-dump-cfg' 'Assemble the toy AArch64 fixture and print its basic blocks' \
		'harness-tui' 'Open the full-pipeline trace TUI; use ASM=path/to/file.s to select a fixture' \
		'tui' 'Alias for harness-tui' \
		'harness-test-asm' 'Run assembly fixture validation; use ASM=path/to/file.s or select interactively' \
		'spec-test-encoding' 'Compare generated A64Insn encoding against LLVM assembler output' \
		'coverage-scan' 'Translate from every SVC site in ELF=path and report exits/unsupported forms' \
		'e1-trace' 'Trace redis-server under load (QEMU plugin, Docker) and report syscall gaps to tmp/e1/' \
		'kernel-golden' 'Regenerate the kernel module golden fragment from the harness' \
		'qemu-run' "Boot the profile's kernel + golden initramfs in QEMU (foreground)" \
		'qemu-run-bg' 'Boot the local kernel image in QEMU (background)' \
		'qemu-reset' 'Reset the running QEMU guest through QMP' \
		'pack' 'Create a tar.gz of tracked files under tmp/pack/'
