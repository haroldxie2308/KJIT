// SPDX-License-Identifier: GPL-2.0
/*
 * A countdown longer than the back-edge budget right after a hot SVC: every
 * fragment entry leaves through a Budget exit and userspace finishes the
 * countdown natively, so the process makes progress and stays killable.
 * KJIT_EXPECT=budget: one Budget exit per outer iteration.
 *
 *   tight_loop [outer]   0 = forever (kill test)
 */
#include "kjit_test.h"

int main(int argc, char **argv)
{
	long outer = argc > 1 ? atol(argv[1]) : 2000;
	uint64_t n = outer, a = 0;
	struct kjit_snap s0, s1;

	kjit_register_self();
	s0 = kjit_snap();
	asm volatile(
		"1:\n"
		"	mov	x8, #173\n"			/* getppid */
		"	svc	#0\n"
		"	mov	x3, #10000\n"
		"2:\n"
		"	subs	x3, x3, #1\n"
		"	b.ne	2b\n"
		"	add	%[a], %[a], #1\n"
		"	subs	%[n], %[n], #1\n"
		"	b.ne	1b\n"
		: [a] "+r"(a), [n] "+r"(n)
		:
		: "x0", "x3", "x8", "cc", "memory");
	s1 = kjit_snap();
	kjit_report("tight_loop", s0, s1);
	printf("tight_loop outer=%ld a=%llu\n", outer, (unsigned long long)a);
	if (kjit_expect("budget") && s1.exit_budget - s0.exit_budget < outer - kjit_auto_warmup())
		die("tight_loop: %lld Budget exits for %ld outer iterations",
		    s1.exit_budget - s0.exit_budget, outer);
	return 0;
}
