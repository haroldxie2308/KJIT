// SPDX-License-Identifier: GPL-2.0
/*
 * Faults of SIMD&FP accesses in FP/SIMD fragments (A9b), which run with page
 * faults disabled: every user-access fault leaves through the access's stub
 * (Mem exit), and userspace re-executes the access natively.
 *
 *   fp_fault ro_store|unmapped_load|null_ld1
 *     A hot loop whose SIMD access faults after 3000 iterations: str q to a
 *     read-only page, ldp q from an unmapped page, ld1 {2 regs} from address
 *     16. Same SIGSEGV code, address and PC as without KJIT (fault_segv's
 *     check).
 *   fp_fault demand
 *     st1 {2 regs} to 512 fresh anonymous pages, one per iteration: each first
 *     touch faults in the fragment (Mem exit), userspace re-executes it and
 *     demand-pages it; then a second pass over the now present pages. No
 *     signal; the data must be complete.
 *
 * The runner checks fpsimd_exit_mem.
 */
#include "kjit_test.h"
#include <signal.h>
#include <sys/mman.h>
#include <ucontext.h>

extern char fp_fault_insn_ro_store[], fp_fault_insn_unmapped_load[], fp_fault_insn_null_ld1[];
static uintptr_t bad_addr, fault_pc;

static void on_segv(int sig, siginfo_t *si, void *ucv)
{
	ucontext_t *uc = ucv;
	char buf[160];
	int n;

	n = snprintf(buf, sizeof(buf),
		     "fp_fault: signal %d code %d addr_ok %d pc_ok %d iters_left %llu\n", sig,
		     si->si_code, (uintptr_t)si->si_addr == bad_addr,
		     uc->uc_mcontext.pc == fault_pc, (unsigned long long)uc->uc_mcontext.regs[20]);
	_exit(write(1, buf, n) == n ? 0 : 2);
}

static __attribute__((noinline)) void segv_loop(const char *mode, uint8_t *good)
{
	uintptr_t bad = bad_addr;

	if (!strcmp(mode, "ro_store")) {
		fault_pc = (uintptr_t)fp_fault_insn_ro_store;
		asm volatile(
			"	mov	x20, #3000\n"
			"	mov	x21, #0\n"
			"1:\n"
			"	mov	x8, #173\n"		/* getppid */
			"	svc	#0\n"
			"	add	x21, x21, #1\n"
			"	dup	v0.2d, x21\n"
			"	subs	x20, x20, #1\n"
			"	csel	x9, %[bad], %[good], eq\n"
			"	.globl	fp_fault_insn_ro_store\n"
			"fp_fault_insn_ro_store:\n"
			"	str	q0, [x9]\n"
			"	b	1b\n"
			:
			: [bad] "r"(bad), [good] "r"(good)
			: "x0", "x8", "x9", "x20", "x21", "v0", "cc", "memory");
	} else if (!strcmp(mode, "unmapped_load")) {
		fault_pc = (uintptr_t)fp_fault_insn_unmapped_load;
		asm volatile(
			"	mov	x20, #3000\n"
			"	mov	x21, #0\n"
			"1:\n"
			"	mov	x8, #173\n"
			"	svc	#0\n"
			"	add	x21, x21, #1\n"
			"	subs	x20, x20, #1\n"
			"	csel	x9, %[bad], %[good], eq\n"
			"	.globl	fp_fault_insn_unmapped_load\n"
			"fp_fault_insn_unmapped_load:\n"
			"	ldp	q0, q1, [x9]\n"
			"	add	v0.16b, v0.16b, v1.16b\n"
			"	b	1b\n"
			:
			: [bad] "r"(bad), [good] "r"(good)
			: "x0", "x8", "x9", "x20", "x21", "v0", "v1", "cc", "memory");
	} else {
		fault_pc = (uintptr_t)fp_fault_insn_null_ld1;
		asm volatile(
			"	mov	x20, #3000\n"
			"	mov	x21, #0\n"
			"1:\n"
			"	mov	x8, #173\n"
			"	svc	#0\n"
			"	add	x21, x21, #1\n"
			"	subs	x20, x20, #1\n"
			"	csel	x9, %[bad], %[good], eq\n"
			"	.globl	fp_fault_insn_null_ld1\n"
			"fp_fault_insn_null_ld1:\n"
			"	ld1	{v0.16b, v1.16b}, [x9]\n"
			"	eor	v0.16b, v0.16b, v1.16b\n"
			"	b	1b\n"
			:
			: [bad] "r"(bad), [good] "r"(good)
			: "x0", "x8", "x9", "x20", "x21", "v0", "v1", "cc", "memory");
	}
	die("fp_fault: the loop ended without a fault");
}

#define DEMAND_PAGES 512

static void demand(void)
{
	uint8_t *area = mmap(NULL, DEMAND_PAGES * 4096, PROT_READ | PROT_WRITE,
			     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	uint64_t sum = 0;
	struct kjit_snap s0, s1;

	if (area == MAP_FAILED)
		die("mmap: %s", strerror(errno));
	kjit_register_self();
	s0 = kjit_snap();
	/* Two passes: first touches (faults), then the present pages again. */
	for (int pass = 0; pass < 2; pass++) {
		asm volatile(
			"	mov	x20, %[pages]\n"
			"	mov	x9, %[area]\n"
			"1:\n"
			"	mov	x8, #173\n"		/* getppid */
			"	svc	#0\n"
			"	add	x10, x20, %[pass]\n"
			"	dup	v0.16b, w10\n"
			"	movi	v1.16b, #0x3c\n"
			"	st1	{v0.16b, v1.16b}, [x9]\n"
			"	add	x9, x9, #4096\n"
			"	subs	x20, x20, #1\n"
			"	b.ne	1b\n"
			:
			: [pages] "r"((long)DEMAND_PAGES), [area] "r"(area), [pass] "r"((long)pass)
			: "x0", "x8", "x9", "x10", "x20", "v0", "v1", "cc", "memory");
	}
	s1 = kjit_snap();
	kjit_report("fp_fault demand", s0, s1);
	for (int p = 0; p < DEMAND_PAGES; p++) {
		uint8_t want = (uint8_t)(DEMAND_PAGES - p + 1);

		for (int i = 0; i < 16; i++)
			if (area[p * 4096 + i] != want || area[p * 4096 + 16 + i] != 0x3c)
				die("fp_fault demand: page %d byte %d wrong", p, i);
		sum += area[p * 4096] + area[p * 4096 + 31] + area[p * 4096 + 32];
	}
	printf("fp_fault: demand pages %d sum %llu\n", DEMAND_PAGES, (unsigned long long)sum);
}

int main(int argc, char **argv)
{
	const char *mode = argc > 1 ? argv[1] : "ro_store";
	uint8_t *good = aligned_alloc(64, 64);
	struct sigaction sa = { .sa_sigaction = on_segv, .sa_flags = SA_SIGINFO };
	void *page;

	if (!good)
		die("aligned_alloc");
	memset(good, 0, 64);
	printf("fp_fault: mode %s\n", mode);
	fflush(stdout);
	if (!strcmp(mode, "demand")) {
		demand();
		return 0;
	}
	if (!strcmp(mode, "null_ld1")) {
		bad_addr = 16;
	} else {
		page = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (page == MAP_FAILED)
			die("mmap");
		*(volatile char *)page = 1;
		if (!strcmp(mode, "unmapped_load")) {
			if (munmap(page, 4096))
				die("munmap");
		} else if (!strcmp(mode, "ro_store")) {
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
	segv_loop(mode, good);
	return 1;
}
