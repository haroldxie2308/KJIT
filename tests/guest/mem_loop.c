// SPDX-License-Identifier: GPL-2.0
/*
 * A hot loop with memory traffic between syscalls: LDP/STP on a heap block,
 * STR/LDR pre/post-index on the stack, a byte load, an `mrs tpidrro_el0`
 * (outside the decoded subset: Unsupported exit, runs natively), and a
 * write+read pair through a pipe plus a write to /dev/null. Output must be
 * identical with KJIT on/off. KJIT_EXPECT=inkernel: most syscalls still run in
 * the kernel, and the mrs's Unsupported exits happen.
 */
#include "kjit_test.h"

int main(int argc, char **argv)
{
	long iters = argc > 1 ? atol(argv[1]) : 20000;
	uint64_t *heap = calloc(4, sizeof(uint64_t));
	uint64_t rbuf[2] = { 0, 0 }, a = 1, c = 0, n = iters;
	struct kjit_snap s0, s1;
	int p[2], null = open("/dev/null", O_WRONLY);

	if (!heap || null < 0 || pipe(p))
		die("setup: %s", strerror(errno));
	heap[0] = 0x0123456789abcdefull;
	heap[1] = 0xfedcba9876543210ull;
	kjit_register_self();
	s0 = kjit_snap();

	asm volatile(
		"1:\n"
		"	ldp	x3, x4, [%[heap]]\n"
		"	add	x3, x3, %[n]\n"
		"	eor	x4, x4, x3, ror #7\n"
		"	stp	x3, x4, [%[heap]]\n"
		"	str	x4, [sp, #-16]!\n"
		"	ldr	x5, [sp], #16\n"
		"	add	%[a], %[a], x5\n"
		"	ldrb	w6, [%[heap], #3]\n"
		"	add	%[a], %[a], x6\n"
		"	mrs	x6, tpidrro_el0\n"		/* Unsupported: native */
		"	add	%[a], %[a], x6\n"
		"	mov	x0, %[wfd]\n"
		"	mov	x1, %[heap]\n"
		"	mov	x2, #16\n"
		"	mov	x8, #64\n"			/* write(pipe) */
		"	svc	#0\n"
		"	add	%[c], %[c], x0\n"
		"	mov	x0, %[rfd]\n"
		"	mov	x1, %[rbuf]\n"
		"	mov	x2, #16\n"
		"	mov	x8, #63\n"			/* read(pipe) */
		"	svc	#0\n"
		"	add	%[c], %[c], x0\n"
		"	ldr	x7, [%[rbuf], #8]\n"
		"	add	%[a], %[a], x7\n"
		"	mov	x0, %[null]\n"
		"	mov	x1, %[rbuf]\n"
		"	mov	x2, #8\n"
		"	mov	x8, #64\n"			/* write(/dev/null) */
		"	svc	#0\n"
		"	add	%[c], %[c], x0\n"
		"	subs	%[n], %[n], #1\n"
		"	b.ne	1b\n"
		: [a] "+r"(a), [c] "+r"(c), [n] "+r"(n)
		: [heap] "r"(heap), [rbuf] "r"(rbuf), [wfd] "r"((long)p[1]),
		  [rfd] "r"((long)p[0]), [null] "r"((long)null)
		: "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "cc", "memory");

	s1 = kjit_snap();
	kjit_report("mem_loop", s0, s1);
	printf("mem_loop iters=%ld a=%#llx c=%llu heap=%#llx,%#llx rbuf=%#llx,%#llx\n", iters,
	       (unsigned long long)a, (unsigned long long)c, (unsigned long long)heap[0],
	       (unsigned long long)heap[1], (unsigned long long)rbuf[0], (unsigned long long)rbuf[1]);
	if (kjit_expect("inkernel")) {
		long long got = s1.in_kernel - s0.in_kernel, total = 3 * iters;

		/* One syscall per iteration follows the Unsupported exit natively. */
		if (got * 100 < total * 60)
			die("mem_loop: only %lld of %lld syscalls in kernel", got, total);
		/*
		 * About one per iteration. Not exactly: the first iteration starts in
		 * userspace, and an iteration where the runtime declined after a
		 * syscall (need_resched, a signal) runs natively.
		 */
		if ((s1.exit_unsupported - s0.exit_unsupported) * 100 < iters * 95)
			die("mem_loop: %lld Unsupported exits for %ld iterations",
			    s1.exit_unsupported - s0.exit_unsupported, iters);
	}
	return 0;
}
