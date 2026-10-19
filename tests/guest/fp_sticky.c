// SPDX-License-Identifier: GPL-2.0
/*
 * A23 sticky FP/SIMD bracket: after a raw svc getppid, one call (bl) of a
 * callee that uses SIMD registers, from code that does not. The caller's
 * fragment has no FP/SIMD, so its first run reaches the callee through the
 * runtime (an ibtc_fpsimd_boundary exit) and marks the fragment sticky; every
 * later run entered at it starts inside the bracket on table_all, where the
 * call and its return hit the dispatch table. Without the flag every
 * iteration would take a boundary exit.
 *
 * KJIT_EXPECT=sticky: the flag was set (fp_sticky_set grew), and after the
 * warm-up, in which boundary exits stop growing, not one more is taken while
 * the loop keeps calling the FP/SIMD callee. Output (an accumulator that
 * depends on the callee's SIMD result) must be identical with KJIT on/off.
 *
 *   fp_sticky [outer]
 */
#include "kjit_test.h"

void fp_sticky_run(uint64_t outer, uint64_t *acc);
extern char fp_sticky_callee[], fp_sticky_ret[];

asm(".text\n"
    ".global fp_sticky_run\n"
    ".type fp_sticky_run, %function\n"
    "fp_sticky_run:\n"
    "	mov	x9, x30\n"
    "	mov	x4, x0\n"
    "	ldr	x6, [x1]\n"
    "1:	mov	x8, #173\n"		/* getppid */
    "	svc	#0\n"
    "	bl	fp_sticky_callee\n"
    ".global fp_sticky_ret\n"
    "fp_sticky_ret:\n"
    "	subs	x4, x4, #1\n"
    "	b.ne	1b\n"
    "	str	x6, [x1]\n"
    "	mov	x30, x9\n"
    "	ret\n"
    ".global fp_sticky_callee\n"
    "fp_sticky_callee:\n"
    "	add	x6, x6, #1\n"
    "	dup	v0.2d, x6\n"
    "	add	v0.2d, v0.2d, v0.2d\n"
    "	umov	x7, v0.d[1]\n"
    "	eor	x6, x6, x7, lsr #1\n"
    "	add	x6, x6, #3\n"
    "	ret\n");

/* fp_sticky_run counts down from `outer`: 0 would be 2^64 iterations. */
static void run(uint64_t outer, uint64_t *acc)
{
	if (outer)
		fp_sticky_run(outer, acc);
}

/* Outer iterations per warm-up chunk, and the most chunks before giving up. */
#define CHUNK 200
#define MAX_CHUNKS 50

int main(int argc, char **argv)
{
	long outer = argc > 1 ? atol(argv[1]) : 3000;
	uint64_t acc = 0;
	long long boundary0, boundary1, boundary2, sticky0, sticky1, before;
	int err, chunk;

	kjit_register_self();
	if (!kjit_auto_mode()) {
		/* The callee and the return site are branch targets, not SVC resume PCs. */
		err = kjit_translate_self((uint64_t)fp_sticky_callee);
		if (err && err != EEXIST)
			die("translate callee: %s", strerror(err));
		err = kjit_translate_self((uint64_t)fp_sticky_ret);
		if (err && err != EEXIST)
			die("translate return site: %s", strerror(err));
	}
	boundary0 = kjit_stat("ibtc_fpsimd_boundary");
	sticky0 = kjit_stat("fp_sticky_set");
	/*
	 * Warm-up: auto mode learns the callee, then the return site, a chunk at
	 * a time; stop at the first chunk that takes no boundary exit once one
	 * has been taken. Without the flag no chunk is ever free of them.
	 */
	run(kjit_auto_warmup(), &acc);
	for (chunk = 0; chunk < MAX_CHUNKS; chunk++) {
		before = kjit_stat("ibtc_fpsimd_boundary");
		run(CHUNK, &acc);
		if (before != boundary0 && kjit_stat("ibtc_fpsimd_boundary") == before)
			break;
	}
	boundary1 = kjit_stat("ibtc_fpsimd_boundary");
	run(outer, &acc);
	boundary2 = kjit_stat("ibtc_fpsimd_boundary");
	sticky1 = kjit_stat("fp_sticky_set");
	fprintf(stderr, "fp_sticky: warm-up chunks=%d boundary=%lld measured boundary=%lld sticky_set=%lld outer=%ld\n",
		chunk, boundary1 - boundary0, boundary2 - boundary1, sticky1 - sticky0, outer);
	printf("fp_sticky outer=%ld acc=%llu\n", outer, (unsigned long long)acc);
	if (kjit_expect("sticky")) {
		if (chunk == MAX_CHUNKS)
			die("fp_sticky: boundary exits never stopped (%d chunks of %d)", MAX_CHUNKS, CHUNK);
		if (boundary1 == boundary0)
			die("fp_sticky: no boundary exit before the warm-up ended");
		if (sticky1 == sticky0)
			die("fp_sticky: no fragment turned sticky");
		if (boundary2 != boundary1)
			die("fp_sticky: %lld boundary exits in %ld runs after the warm-up",
			    boundary2 - boundary1, outer);
	}
	return 0;
}
