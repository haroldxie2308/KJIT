# SPDX-License-Identifier: GPL-2.0

KDIR ?= <path-to-linux-w-capstone>

default:
	$(MAKE) -C $(KDIR) LLVM=1 M=$$PWD

modules_install: default
	$(MAKE) -C $(KDIR) M=$$PWD modules_install

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
	$(MAKE) -C $(KDIR) M=$$PWD rust-analyzer
