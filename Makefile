# SPDX-License-Identifier: GPL-2.0

KDIR ?= $(CURDIR)/linux-w-capstone
KBUILD_OUTPUT ?= $(KDIR)
ARCH ?= arm64
LLVM ?= 1
ARM64_ISA_XML_DIR ?= $(CURDIR)/tmp/isa_a64_2026_03/ISA_A64_xml_A_profile-2026-03

KMAKE = $(MAKE) -C $(KDIR) ARCH=$(ARCH) LLVM=$(LLVM)
ifneq ($(abspath $(KBUILD_OUTPUT)),$(abspath $(KDIR)))
KMAKE += O=$(KBUILD_OUTPUT)
endif

.PHONY: default modules_install install uninstall dm test rust-analyzer prepare module-build rustavailable-check \
	kernel-prepare kernel-build kernel-clean clean qemu-run qemu-run-bg qemu-reset \
	userspace-harness-test userspace-harness-run arm64-spec-gen workflow-help

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

prepare: kernel-prepare kernel-build

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

userspace-harness-run:
	cargo run --manifest-path userspace-harness/Cargo.toml -- $(CASE)

arm64-spec-gen:
	python3 ./scripts/gen-arm64-spec.py --xml-dir "$(ARM64_ISA_XML_DIR)"

workflow-help:
	@printf '%s\n' \
		'prepare         Prepare/build the kernel in the container dev environment' \
		'kernel-prepare  Prepare the kernel build tree for ARM64 Rust development' \
		'kernel-build    Build Image/modules into the kernel build tree' \
		'kernel-clean    Clean the kernel build tree' \
		'clean           Alias for kernel-clean' \
		'rust-analyzer   Generate rust-project.json for this module' \
		'rustavailable-check Check Rust-for-Linux toolchain readiness' \
		'module-build    Build the KJIT module' \
		'arm64-spec-gen  Generate the checked-in ARM64 subset tables from the Arm XML bundle' \
		'userspace-harness-test Run the standalone userspace validation harness tests' \
		'userspace-harness-run  Run the standalone userspace validation harness CLI' \
		'qemu-run        Boot the local kernel image in QEMU (foreground)' \
		'qemu-run-bg     Boot the local kernel image in QEMU (background)' \
		'qemu-reset      Reset the running QEMU guest through QMP'
