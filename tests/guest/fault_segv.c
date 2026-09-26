// SPDX-License-Identifier: GPL-2.0
/*
 * A hot loop whose store faults after some iterations: to NULL + 8, to an
 * unmapped page, or to a read-only page. The fragment's STTR takes the fault
 * in the kernel, leaves through its Mem stub, and userspace re-executes the
 * store and gets the SIGSEGV itself: same si_code, si_addr and PC as without
 * KJIT. The runner checks exit_mem.
 *
 *   fault_segv null|unmapped|readonly
 */
#include "kjit_test.h"
#include <signal.h>
#include <sys/mman.h>
#include <ucontext.h>

extern char fault_store_insn[];
static uintptr_t bad_addr;

static void on_segv(int sig, siginfo_t *si, void *ucv)
{
	ucontext_t *uc = ucv;
	char buf[160];
	int n;

	n = snprintf(buf, sizeof(buf),
		     "fault_segv: signal %d code %d addr_ok %d pc_ok %d iters_left %llu\n", sig,
		     si->si_code, (uintptr_t)si->si_addr == bad_addr,
		     uc->uc_mcontext.pc == (uintptr_t)fault_store_insn,
		     (unsigned long long)uc->uc_mcontext.regs[20]);
	_exit(write(1, buf, n) == n ? 0 : 2);
}

int main(int argc, char **argv)
{
	const char *mode = argc > 1 ? argv[1] : "null";
	uint64_t *good = calloc(2, sizeof(uint64_t));
	struct sigaction sa = { .sa_sigaction = on_segv, .sa_flags = SA_SIGINFO };
	void *page;

	if (!good)
		die("calloc");
	if (!strcmp(mode, "null")) {
		bad_addr = 8;
	} else {
		page = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (page == MAP_FAILED)
			die("mmap");
		*(volatile char *)page = 1;
		if (!strcmp(mode, "unmapped")) {
			if (munmap(page, 4096))
				die("munmap");
		} else if (!strcmp(mode, "readonly")) {
			if (mprotect(page, 4096, PROT_READ))
				die("mprotect");
		} else {
			die("mode %s", mode);
		}
		bad_addr = (uintptr_t)page + 16;
	}
	if (sigaction(SIGSEGV, &sa, NULL))
		die("sigaction");
	kjit_register_self();
	printf("fault_segv: mode %s\n", mode);
	fflush(stdout);

	/* 3000 iterations store to `good`; the last one to `bad`. */
	asm volatile(
		"	mov	x20, #3000\n"
		"	mov	x21, #0\n"
		"1:\n"
		"	mov	x8, #173\n"			/* getppid */
		"	svc	#0\n"
		"	add	x21, x21, #1\n"
		"	subs	x20, x20, #1\n"
		"	csel	x9, %[bad], %[good], eq\n"
		"	.globl	fault_store_insn\n"
		"fault_store_insn:\n"
		"	str	x21, [x9]\n"
		"	b	1b\n"
		:
		: [bad] "r"(bad_addr), [good] "r"(good)
		: "x0", "x8", "x9", "x20", "x21", "cc", "memory");
	die("fault_segv: the loop ended without a fault");
}
