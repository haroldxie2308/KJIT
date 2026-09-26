# SPDX-License-Identifier: GPL-2.0

KDIR ?= $(CURDIR)/dep/linux
KBUILD_OUTPUT ?= $(KDIR)
ARCH ?= arm64
LLVM ?= 1
ARM64_ISA_XML_DIR ?= $(CURDIR)/tmp/isa_a64_2026_03/ISA_A64_xml_A_profile-2026-03
HARNESS_SHARED_DIR := harness/src/shared
HARNESS_SHARED_BACKUP := harness/.shared.bak
KERNEL_GOLDEN_ASM := tests/arm64/toy_cfg.s
KERNEL_GOLDEN := tests/arm64/golden/toy_cfg_hot_svc_mark.rs

KMAKE = $(MAKE) -C $(KDIR) ARCH=$(ARCH) LLVM=$(LLVM)
ifneq ($(abspath $(KBUILD_OUTPUT)),$(abspath $(KDIR)))
KMAKE += O=$(KBUILD_OUTPUT)
endif

.PHONY: default modules_install install uninstall dm test rust-analyzer prepare harness-sync harness-prepare module-build \
    rustavailable-check kernel-prepare kernel-build kernel-clean clean qemu-run qemu-run-bg qemu-reset pack \
	harness-test harness-dump-cfg harness-tui tui harness-test-asm spec-test-encoding spec-gen coverage-scan kernel-golden help

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

pack:
	bash ./scripts/pack.sh

module-build: default

harness-test:
	cargo test --manifest-path harness/Cargo.toml -- --nocapture

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

spec-test-encoding:
	cargo test --manifest-path harness/Cargo.toml encoding_matches_llvm_for_handwritten_cases -- --ignored --nocapture

spec-gen:
	cargo run --manifest-path specgen/Cargo.toml -- --xml-dir "$(ARM64_ISA_XML_DIR)"
	cp spec/arm64/generated/a64_subset.rs harness/src/shared/arm64/generated.rs

help:
	@printf '%-20s %s\n' \
		'prepare' 'Prepare/build the kernel in the container dev environment' \
		'kernel-prepare' 'Prepare the kernel build tree for ARM64 Rust development' \
		'kernel-build' 'Build Image/modules into the kernel build tree' \
		'kernel-clean' 'Clean the kernel build tree' \
		'clean' 'Alias for kernel-clean' \
		'harness-sync' 'Copy shared/ into harness/src/shared with one backup' \
		'rust-analyzer' 'Generate rust-project.json for this module' \
		'rustavailable-check' 'Check Rust-for-Linux toolchain readiness' \
		'module-build' 'Build the KJIT module' \
		'spec-gen' 'Generate the checked-in ARM64 subset tables from the Arm XML bundle' \
		'harness-test' 'Run the standalone harness tests' \
		'harness-dump-cfg' 'Assemble the toy AArch64 fixture and print its basic blocks' \
		'harness-tui' 'Open the full-pipeline trace TUI; use ASM=path/to/file.s to select a fixture' \
		'tui' 'Alias for harness-tui' \
		'harness-test-asm' 'Run assembly fixture validation; use ASM=path/to/file.s or select interactively' \
		'spec-test-encoding' 'Compare generated A64Insn encoding against LLVM assembler output' \
		'coverage-scan' 'Translate from every SVC site in ELF=path and report exits/unsupported forms' \
		'kernel-golden' 'Regenerate the kernel module golden fragment from the harness' \
		'qemu-run' 'Boot the local kernel image in QEMU (foreground)' \
		'qemu-run-bg' 'Boot the local kernel image in QEMU (background)' \
		'qemu-reset' 'Reset the running QEMU guest through QMP' \
		'pack' 'Create a tar.gz of tracked files under tmp/pack/'
