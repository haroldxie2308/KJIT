// SPDX-License-Identifier: GPL-2.0
/*
 * The longest FP/SIMD fragment run (A9b): after each getppid, a SIMD copy of
 * 1 MiB in 64-byte steps (two ldp q + two stp q per back-edge), far more
 * back-edges than the fragment budget. Each run leaves through a Budget exit
 * after KJIT_BACKEDGE_BUDGET iterations and userspace finishes the copy, so
 * the run is the longest non-preemptible stretch an FP/SIMD fragment can have
 * (the runner prints fpsimd_run_max_ns after it). Output must be identical
 * with KJIT on/off. KJIT_EXPECT=budget: the runs end in Budget exits.
 */
#include "kjit_test.h"

#define COPY (1 << 20)

int main(int argc, char **argv)
{
	long iters = argc > 1 ? atol(argv[1]) : 200;
	uint8_t *src = aligned_alloc(64, COPY), *dst = aligned_alloc(64, COPY);
	uint64_t acc = 0, h = 0xcbf29ce484222325ull;
	struct kjit_snap s0, s1;

	if (!src || !dst)
		die("aligned_alloc");
	for (int i = 0; i < COPY; i++)
		src[i] = (uint8_t)(i * 13 + (i >> 12));
	memset(dst, 0, COPY);
	kjit_register_self();
	s0 = kjit_snap();
	for (long it = 0; it < iters; it++) {
		src[it % COPY] ^= (uint8_t)it;
		asm volatile(
			"	mov	x8, #173\n"		/* getppid */
			"	svc	#0\n"
			"	add	%[acc], %[acc], x0\n"
			"	mov	x4, %[src]\n"
			"	mov	x5, %[dst]\n"
			"	mov	x6, %[len]\n"
			"1:\n"
			"	ldp	q0, q1, [x4]\n"
			"	ldp	q2, q3, [x4, #32]\n"
			"	stp	q0, q1, [x5]\n"
			"	stp	q2, q3, [x5, #32]\n"
			"	add	x4, x4, #64\n"
			"	add	x5, x5, #64\n"
			"	subs	x6, x6, #64\n"
			"	b.ne	1b\n"
			: [acc] "+r"(acc)
			: [src] "r"(src), [dst] "r"(dst), [len] "r"((long)COPY)
			: "x0", "x4", "x5", "x6", "x8", "v0", "v1", "v2", "v3", "cc", "memory");
		if (memcmp(src, dst, COPY))
			die("fp_budget: copy %ld differs", it);
		h = (h ^ dst[(it * 4099) % COPY]) * 0x100000001b3ull;
	}
	s1 = kjit_snap();
	kjit_report("fp_budget", s0, s1);
	printf("fp_budget iters=%ld acc=%llu h=%#llx\n", iters, (unsigned long long)acc,
	       (unsigned long long)h);
	if (kjit_expect("budget") &&
	    (s1.exit_budget - s0.exit_budget) * 100 < (iters - kjit_auto_warmup()) * 90)
		die("fp_budget: %lld Budget exits for %ld runs", s1.exit_budget - s0.exit_budget,
		    iters);
	return 0;
}
