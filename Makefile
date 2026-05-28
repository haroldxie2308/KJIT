# SPDX-License-Identifier: GPL-2.0

KDIR ?= $(CURDIR)/dep/linux
KBUILD_OUTPUT ?= $(KDIR)
ARCH ?= arm64
LLVM ?= 1
ARM64_ISA_XML_DIR ?= $(CURDIR)/tmp/isa_a64_2026_03/ISA_A64_xml_A_profile-2026-03
HARNESS_SHARED_DIR := userspace-harness/src/shared
HARNESS_SHARED_BACKUP := userspace-harness/.shared.bak

KMAKE = $(MAKE) -C $(KDIR) ARCH=$(ARCH) LLVM=$(LLVM)
ifneq ($(abspath $(KBUILD_OUTPUT)),$(abspath $(KDIR)))
KMAKE += O=$(KBUILD_OUTPUT)
endif

.PHONY: default modules_install install uninstall dm test rust-analyzer prepare sync harness-prepare module-build \
    rustavailable-check kernel-prepare kernel-build kernel-clean clean qemu-run qemu-run-bg qemu-reset \
	userspace-harness-test userspace-harness-dump-cfg userspace-harness-trace-tui tui test-asm-pipeline test-encoding arm64-spec-gen arm64-spec-gen-py workflow-help

default:
	$(KMAKE) M=$$PWD

modules_install: default
	$(KMAKE) M=$$PWD modules_install

install:
	sudo insmod kjit.ko

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
	bash ./scripts/gen-rust-project.sh

rustavailable-check:
	$(KMAKE) rustavailable

prepare: kernel-prepare kernel-build harness-prepare

sync:
	@if [ -d "$(HARNESS_SHARED_DIR)" ]; then \
		rm -rf "$(HARNESS_SHARED_BACKUP)"; \
		cp -a "$(HARNESS_SHARED_DIR)" "$(HARNESS_SHARED_BACKUP)"; \
		echo "Backed up $(HARNESS_SHARED_DIR) to $(HARNESS_SHARED_BACKUP)"; \
	fi
	rsync -a --delete shared/ "$(HARNESS_SHARED_DIR)/"
	cp spec/arm64/generated/a64_subset.rs "$(HARNESS_SHARED_DIR)/arm64/generated.rs"

harness-prepare: sync

kernel-prepare:
	bash ./scripts/setup-kernel-build.sh

kernel-build:
	bash ./scripts/setup-kernel-build.sh --build

kernel-clean:
	bash ./scripts/setup-kernel-build.sh --clean

clean: kernel-clean

qemu-run:
	bash ./scripts/qemu-run.sh

qemu-run-bg:
	bash ./scripts/qemu-run.sh --detach

qemu-reset:
	bash ./scripts/qemu-reset.sh

module-build: default

userspace-harness-test:
	cargo test --manifest-path userspace-harness/Cargo.toml -- --nocapture

userspace-harness-dump-cfg:
	bash ./scripts/demo-toy-cfg.sh

test-asm-pipeline:
	bash ./scripts/run-asm-fixture.sh

userspace-harness-trace-tui:
	ASM_PATH="$(ASM)" TRACE_TUI_SELECT=1 TRACE_TUI_FLAGS= bash ./scripts/run-asm-fixture.sh

tui: userspace-harness-trace-tui

test-encoding:
	cargo test --manifest-path userspace-harness/Cargo.toml encoding_matches_llvm_for_handwritten_cases -- --ignored --nocapture

arm64-spec-gen:
	cargo run --manifest-path specgen/Cargo.toml -- --xml-dir "$(ARM64_ISA_XML_DIR)"
	cp spec/arm64/generated/a64_subset.rs userspace-harness/src/shared/arm64/generated.rs

arm64-spec-gen-py:
	python3 ./scripts/gen-arm64-spec.py --xml-dir "$(ARM64_ISA_XML_DIR)"
	cp spec/arm64/generated/a64_subset.rs userspace-harness/src/shared/arm64/generated.rs

workflow-help:
	@printf '%s\n' \
		'prepare         Prepare/build the kernel in the container dev environment' \
		'kernel-prepare  Prepare the kernel build tree for ARM64 Rust development' \
		'kernel-build    Build Image/modules into the kernel build tree' \
		'kernel-clean    Clean the kernel build tree' \
		'clean           Alias for kernel-clean' \
		'sync            Copy shared/ into userspace-harness/src/shared with one backup' \
		'rust-analyzer   Generate rust-project.json for this module' \
		'rustavailable-check Check Rust-for-Linux toolchain readiness' \
		'module-build    Build the KJIT module' \
		'arm64-spec-gen  Generate the checked-in ARM64 subset tables from the Arm XML bundle' \
		'arm64-spec-gen-py Generate the ARM64 subset tables using the legacy Python generator' \
		'userspace-harness-test Run the standalone userspace validation harness tests' \
		'userspace-harness-dump-cfg Assemble the toy AArch64 fixture and print its basic blocks' \
		'userspace-harness-trace-tui Open the full-pipeline trace TUI; use ASM=path/to/file.s to select a fixture' \
		'tui             Alias for userspace-harness-trace-tui' \
		'test-asm-pipeline Run assembly fixture through trace/full-pipeline validation' \
		'test-encoding   Compare generated A64Insn encoding against LLVM assembler output' \
		'qemu-run        Boot the local kernel image in QEMU (foreground)' \
		'qemu-run-bg     Boot the local kernel image in QEMU (background)' \
		'qemu-reset      Reset the running QEMU guest through QMP'
