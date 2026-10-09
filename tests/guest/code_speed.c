// SPDX-License-Identifier: GPL-2.0
/*
 * Speed of translated code against native code (userspace-bypass comparison).
 *
 *   code_speed <variant> <n> [target_ms] [reps]
 *
 * Per outer iteration: one raw svc getppid, then n units of user work with no
 * syscall in it. The work between two syscalls is what a fragment runs in the
 * kernel, so (time per outer) with KJIT enabled against disabled, fitted as a
 * line over several n, gives the per-instruction slowdown of fragment code (the
 * slope) separately from the per-syscall constant (the intercept: the svc itself,
 * the hook, the run's entry and exit).
 *
 * Variants (insn = user instructions per unit of n, loop control included):
 *   hash     n bytes, djb2: ldrb, add (lsl 5), add, subs, b.ne                 5 per byte
 *   strlen   n bytes to a NUL: ldrb, cbnz                                      2 per byte
 *   copy     n bytes, byte copy: ldrb, strb, subs, b.ne                        4 per byte
 *   copy16   n bytes (n % 16 == 0), ldp/stp of x registers                     4 per 16 bytes
 *   simd32   n bytes (n % 32 == 0), ldp/stp of q registers (FP/SIMD bracket)   4 per 32 bytes
 *   calls    n calls of a framed leaf function (stp/ldp x29,x30 on the stack,
 *            a callee-saved spill), bl and ret                                 14 per call
 *   callsi   the same through blr                                              14 per call
 *   calls2   n calls of a framed function that calls a leaf                    23 per call
 *   foot     n DIFFERENT framed functions (96 bytes each, 24
 *            instructions: stack frame, loads and stores, ALU) called once each
 *            through blr: a code footprint of n * 96 bytes native, as a program
 *            whose hot path spans many functions; 29 per function. Their entry
 *            PCs are 96 bytes apart, so they alias in the direct-mapped dispatch
 *            table (pc[13:2], 16 KiB window) once n * 96 > 16 KiB: runtime entries
 *            per outer iteration are part of what this variant measures.
 *   footl    n different functions of 384 bytes (71 executed instructions each:
 *            frame, four load/store/ALU chunks, epilogue), called once each
 *            through blr: n * 384 bytes native, 49 KB at n = 128. Function entries
 *            are 96 words apart, which never collide in the dispatch table for
 *            n <= 128. 76 per function.
 *
 * The auto mode's profiler has 256 slots per mm (docs/pipeline.md, section 9): with
 * more than about 200 distinct hot targets (foot, n > 128) not every function
 * becomes hot and the run leaves the fragment at the first untranslated target, so
 * keep n <= 128 for foot and footl.
 *
 * Needs the kjit module and auto mode when KJIT is enabled (KJIT_AUTO=1, the
 * runner sets debugfs auto=1): nothing here registers PCs. A warm-up lets auto
 * mode translate the loop, then one probe run sizes `outer` to about target_ms
 * (default 40) per timed run, then `reps` (default 7) timed runs. Prints "rep"
 * lines, a "result" line (median ns per outer iteration) and, with the module,
 * a "counters" line. Enabled, it dies unless >= 95% of the syscalls of the timed
 * phase ran in the kernel with no Budget exits: n must keep the units of one
 * outer iteration (back-edges and dispatches, 1 each) under KJIT_BACKEDGE_BUDGET
 * = 4096.
 */
#include "bench_common.h"

#define DECL(v) void cs_##v(uint64_t outer, uint64_t n, void *src, void *dst)
DECL(hash);
DECL(strlen);
DECL(copy);
DECL(copy16);
DECL(simd32);
DECL(calls);
DECL(callsi);
DECL(calls2);
DECL(foot);
DECL(footl);

asm(".text\n"
    ".global cs_hash\n.type cs_hash, %function\n"
    "cs_hash:\n"
    "	mov	x9, x0\n"
    "	mov	x10, x1\n"
    "	mov	x11, x2\n"
    "	mov	x5, #5381\n"
    "1:	mov	x8, #173\n"
    "	svc	#0\n"
    "	mov	x3, x11\n"
    "	mov	x4, x10\n"
    "2:	ldrb	w6, [x3], #1\n"
    "	add	x5, x5, x5, lsl #5\n"
    "	add	x5, x5, x6\n"
    "	subs	x4, x4, #1\n"
    "	b.ne	2b\n"
    "	subs	x9, x9, #1\n"
    "	b.ne	1b\n"
    "	mov	x0, x5\n"
    "	ret\n"

    ".global cs_strlen\n.type cs_strlen, %function\n"
    "cs_strlen:\n"
    "	mov	x9, x0\n"
    "	mov	x11, x2\n"
    "	mov	x5, #0\n"
    "1:	mov	x8, #173\n"
    "	svc	#0\n"
    "	mov	x3, x11\n"
    "2:	ldrb	w6, [x3], #1\n"
    "	cbnz	w6, 2b\n"
    "	add	x5, x5, x3\n"
    "	subs	x9, x9, #1\n"
    "	b.ne	1b\n"
    "	mov	x0, x5\n"
    "	ret\n"

    ".global cs_copy\n.type cs_copy, %function\n"
    "cs_copy:\n"
    "	mov	x9, x0\n"
    "	mov	x10, x1\n"
    "	mov	x11, x2\n"
    "	mov	x12, x3\n"
    "1:	mov	x8, #173\n"
    "	svc	#0\n"
    "	mov	x3, x11\n"
    "	mov	x7, x12\n"
    "	mov	x4, x10\n"
    "2:	ldrb	w6, [x3], #1\n"
    "	strb	w6, [x7], #1\n"
    "	subs	x4, x4, #1\n"
    "	b.ne	2b\n"
    "	subs	x9, x9, #1\n"
    "	b.ne	1b\n"
    "	ret\n"

    ".global cs_copy16\n.type cs_copy16, %function\n"
    "cs_copy16:\n"
    "	mov	x9, x0\n"
    "	mov	x10, x1\n"
    "	mov	x11, x2\n"
    "	mov	x12, x3\n"
    "1:	mov	x8, #173\n"
    "	svc	#0\n"
    "	mov	x3, x11\n"
    "	mov	x7, x12\n"
    "	mov	x4, x10\n"
    "2:	ldp	x6, x13, [x3], #16\n"
    "	stp	x6, x13, [x7], #16\n"
    "	subs	x4, x4, #16\n"
    "	b.ne	2b\n"
    "	subs	x9, x9, #1\n"
    "	b.ne	1b\n"
    "	ret\n"

    ".global cs_simd32\n.type cs_simd32, %function\n"
    "cs_simd32:\n"
    "	mov	x9, x0\n"
    "	mov	x10, x1\n"
    "	mov	x11, x2\n"
    "	mov	x12, x3\n"
    "1:	mov	x8, #173\n"
    "	svc	#0\n"
    "	mov	x3, x11\n"
    "	mov	x7, x12\n"
    "	mov	x4, x10\n"
    "2:	ldp	q0, q1, [x3], #32\n"
    "	stp	q0, q1, [x7], #32\n"
    "	subs	x4, x4, #32\n"
    "	b.ne	2b\n"
    "	subs	x9, x9, #1\n"
    "	b.ne	1b\n"
    "	ret\n"

    /* A framed leaf: what a compiler emits for a small non-inlined function. */
    "cs_leaf:\n"
    "	stp	x29, x30, [sp, #-32]!\n"
    "	mov	x29, sp\n"
    "	str	x19, [sp, #16]\n"
    "	mov	x19, x0\n"
    "	add	x0, x19, x19, lsl #1\n"
    "	eor	x0, x0, x19, lsr #3\n"
    "	ldr	x19, [sp, #16]\n"
    "	ldp	x29, x30, [sp], #32\n"
    "	ret\n"
    /* A framed function that calls the leaf. */
    "cs_mid:\n"
    "	stp	x29, x30, [sp, #-32]!\n"
    "	mov	x29, sp\n"
    "	str	x19, [sp, #16]\n"
    "	mov	x19, x0\n"
    "	bl	cs_leaf\n"
    "	add	x0, x0, x19\n"
    "	ldr	x19, [sp, #16]\n"
    "	ldp	x29, x30, [sp], #32\n"
    "	ret\n"

    ".global cs_calls\n.type cs_calls, %function\n"
    "cs_calls:\n"
    "	mov	x15, x30\n"
    "	mov	x9, x0\n"
    "	mov	x10, x1\n"
    "	mov	x5, #1\n"
    "1:	mov	x8, #173\n"
    "	svc	#0\n"
    "	mov	x4, x10\n"
    "2:	mov	x0, x5\n"
    "	bl	cs_leaf\n"
    "	mov	x5, x0\n"
    "	subs	x4, x4, #1\n"
    "	b.ne	2b\n"
    "	subs	x9, x9, #1\n"
    "	b.ne	1b\n"
    "	mov	x0, x5\n"
    "	mov	x30, x15\n"
    "	ret\n"

    ".global cs_callsi\n.type cs_callsi, %function\n"
    "cs_callsi:\n"
    "	mov	x15, x30\n"
    "	mov	x9, x0\n"
    "	mov	x10, x1\n"
    "	mov	x5, #1\n"
    "	adr	x12, cs_leaf\n"
    "1:	mov	x8, #173\n"
    "	svc	#0\n"
    "	mov	x4, x10\n"
    "2:	mov	x0, x5\n"
    "	blr	x12\n"
    "	mov	x5, x0\n"
    "	subs	x4, x4, #1\n"
    "	b.ne	2b\n"
    "	subs	x9, x9, #1\n"
    "	b.ne	1b\n"
    "	mov	x0, x5\n"
    "	mov	x30, x15\n"
    "	ret\n"

    ".global cs_calls2\n.type cs_calls2, %function\n"
    "cs_calls2:\n"
    "	mov	x15, x30\n"
    "	mov	x9, x0\n"
    "	mov	x10, x1\n"
    "	mov	x5, #1\n"
    "1:	mov	x8, #173\n"
    "	svc	#0\n"
    "	mov	x4, x10\n"
    "2:	mov	x0, x5\n"
    "	bl	cs_mid\n"
    "	mov	x5, x0\n"
    "	subs	x4, x4, #1\n"
    "	b.ne	2b\n"
    "	subs	x9, x9, #1\n"
    "	b.ne	1b\n"
    "	mov	x0, x5\n"
    "	mov	x30, x15\n"
    "	ret\n"

    /*
     * 1280 functions of 24 instructions (96 bytes) each; foot calls the first n.
     * A body touches the stack and one cache line of a data table (x2 is set by
     * the caller), like a small non-leaf-free library function.
     */
    ".balign 128\n"
    "cs_foot_fns:\n"
    ".rept 1280\n"
    "	stp	x29, x30, [sp, #-32]!\n"
    "	mov	x29, sp\n"
    "	str	x19, [sp, #16]\n"
    "	ldr	x19, [x2]\n"
    "	add	x19, x19, x0\n"
    "	ldr	x1, [x2, #8]\n"
    "	eor	x1, x1, x19\n"
    "	add	x1, x1, #3\n"
    "	and	x3, x1, #0xff\n"
    "	orr	x19, x19, x3, lsl #2\n"
    "	add	x0, x19, x1, lsr #5\n"
    "	str	x1, [x2, #8]\n"
    "	eor	x0, x0, x19, lsr #3\n"
    "	add	x0, x0, #7\n"
    "	sub	x1, x1, x0\n"
    "	add	x3, x3, x1\n"
    "	eor	x0, x0, x3\n"
    "	str	x0, [x2, #16]\n"
    "	ldr	x19, [sp, #16]\n"
    "	add	x0, x0, x19\n"
    "	and	x0, x0, #0xffffffff\n"
    "	ldp	x29, x30, [sp], #32\n"
    "	ret\n"
    "	nop\n"
    ".endr\n"

    ".balign 128\n"
    "cs_footl_fns:\n"
    ".rept 128\n"
    "	stp	x29, x30, [sp, #-32]!\n"
    "	mov	x29, sp\n"
    "	str	x19, [sp, #16]\n"
    ".rept 4\n"
    "	ldr	x19, [x2]\n"
    "	add	x19, x19, x0\n"
    "	ldr	x1, [x2, #8]\n"
    "	eor	x1, x1, x19\n"
    "	add	x1, x1, #3\n"
    "	and	x3, x1, #0xff\n"
    "	orr	x19, x19, x3, lsl #2\n"
    "	add	x0, x19, x1, lsr #5\n"
    "	str	x1, [x2, #8]\n"
    "	eor	x0, x0, x19, lsr #3\n"
    "	add	x0, x0, #7\n"
    "	sub	x1, x1, x0\n"
    "	add	x3, x3, x1\n"
    "	eor	x0, x0, x3\n"
    "	str	x0, [x2, #16]\n"
    "	add	x0, x0, x19\n"
    ".endr\n"
    "	ldr	x19, [sp, #16]\n"
    "	and	x0, x0, #0xffffffff\n"
    "	ldp	x29, x30, [sp], #32\n"
    "	ret\n"
    ".fill 25, 4, 0xd503201f\n"		/* nop: pad to 96 words */
    ".endr\n"

    ".global cs_footl\n.type cs_footl, %function\n"
    "cs_footl:\n"
    "	mov	x15, x30\n"
    "	mov	x9, x0\n"
    "	mov	x10, x1\n"
    "	mov	x2, x3\n"
    "	mov	x5, #1\n"
    "1:	mov	x8, #173\n"
    "	svc	#0\n"
    "	mov	x4, x10\n"
    "	adr	x12, cs_footl_fns\n"
    "2:	mov	x0, x5\n"
    "	blr	x12\n"
    "	mov	x5, x0\n"
    "	add	x12, x12, #384\n"
    "	subs	x4, x4, #1\n"
    "	b.ne	2b\n"
    "	subs	x9, x9, #1\n"
    "	b.ne	1b\n"
    "	mov	x0, x5\n"
    "	mov	x30, x15\n"
    "	ret\n"

    ".global cs_foot\n.type cs_foot, %function\n"
    "cs_foot:\n"
    "	mov	x15, x30\n"
    "	mov	x9, x0\n"
    "	mov	x10, x1\n"
    "	mov	x2, x3\n"		/* data table: the dst argument */
    "	mov	x5, #1\n"
    "1:	mov	x8, #173\n"
    "	svc	#0\n"
    "	mov	x4, x10\n"
    "	adr	x12, cs_foot_fns\n"
    "2:	mov	x0, x5\n"
    "	blr	x12\n"
    "	mov	x5, x0\n"
    "	add	x12, x12, #96\n"
    "	subs	x4, x4, #1\n"
    "	b.ne	2b\n"
    "	subs	x9, x9, #1\n"
    "	b.ne	1b\n"
    "	mov	x0, x5\n"
    "	mov	x30, x15\n"
    "	ret\n");

struct variant {
	const char *name;
	void (*fn)(uint64_t, uint64_t, void *, void *);
	double insn_per_n;	/* user instructions per unit of n */
	double units_per_n;	/* budget units (back-edges + dispatches) per unit of n */
	long granule;		/* n must be a multiple of this */
};

/*
 * Instructions: the loop of calls/callsi is mov, bl|blr, mov, subs, b.ne (5)
 * plus the leaf (9) = 14; calls2 adds the mid function (9) = 23. Budget units:
 * calls = bl, ret, back-edge = 3; calls2 = 2 bl + 2 ret + back-edge = 5.
 */
static const struct variant variants[] = {
	{ "hash", cs_hash, 5, 1, 1 },
	{ "strlen", cs_strlen, 2, 1, 1 },
	{ "copy", cs_copy, 4, 1, 1 },
	{ "copy16", cs_copy16, 4.0 / 16, 1.0 / 16, 16 },
	{ "simd32", cs_simd32, 4.0 / 32, 1.0 / 32, 32 },
	{ "calls", cs_calls, 14, 3, 1 },
	{ "callsi", cs_callsi, 14, 3, 1 },
	{ "calls2", cs_calls2, 23, 5, 1 },
	{ "foot", cs_foot, 29, 3, 1 },
	{ "footl", cs_footl, 76, 3, 1 },
};

static char src[8192], dst[8192];
/* dst + DST_SKEW: not at the same offset in a 4 KiB page as src (store-to-load aliasing). */
#define DST_SKEW 320

int main(int argc, char **argv)
{
	const struct variant *v = NULL;
	long n, target_ms = argc > 3 ? atol(argv[3]) : 40, reps = argc > 4 ? atol(argv[4]) : 7;
	long long c0[BENCH_NCOUNTERS], c1[BENCH_NCOUNTERS];
	double ns[64], med, probe;
	long outer;
	int enabled = 0, have = bench_have_kjit();

	if (argc < 3)
		die("usage: code_speed <hash|strlen|copy|copy16|simd32|calls|callsi|calls2|foot|footl> <n> [target_ms] [reps]");
	for (size_t i = 0; i < sizeof(variants) / sizeof(variants[0]); i++)
		if (!strcmp(variants[i].name, argv[1]))
			v = &variants[i];
	if (!v)
		die("unknown variant %s", argv[1]);
	n = atol(argv[2]);
	if (n < 1 || n % v->granule || target_ms < 1 || reps < 1 || reps > 64)
		die("n >= 1 and a multiple of %ld, target_ms >= 1, 1 <= reps <= 64 required", v->granule);
	if (!strcmp(v->name, "foot") && n > 1280)
		die("foot: n <= 1280 functions");
	if (!strcmp(v->name, "footl") && n > 128)
		die("footl: n <= 128 functions");
	if (n * v->units_per_n + 2 > 4000)
		die("%.0f budget units per outer iteration: over KJIT_BACKEDGE_BUDGET (4096)",
		    n * v->units_per_n + 2);
	if (!strcmp(v->name, "strlen") || !strcmp(v->name, "hash") || !strncmp(v->name, "copy", 4) ||
	    !strcmp(v->name, "simd32")) {
		if (n >= (long)sizeof(src))
			die("n must be below %zu", sizeof(src));
	}
	memset(src, 'a', sizeof(src));
	src[n] = 0;	/* strlen's terminator; the other variants never read it as data that matters */

	if (have)
		enabled = bench_debugfs_bool("enable");
	if (enabled && !kjit_auto_mode())
		die("KJIT enabled: run with KJIT_AUTO=1 and debugfs auto=1");

	/* Warm-up: auto mode needs hot_threshold hits per PC to translate the loop. */
	for (int i = 0; i < 4; i++)
		v->fn(2000, n, src, dst + DST_SKEW);
	probe = bench_now_ns();
	v->fn(1000, n, src, dst + DST_SKEW);
	probe = (bench_now_ns() - probe) / 1000;
	outer = (long)(target_ms * 1e6 / probe);
	if (outer < 100)
		outer = 100;

	if (have)
		bench_read_counters(c0);
	for (long r = 0; r < reps; r++) {
		double t0 = bench_now_ns();

		v->fn(outer, n, src, dst + DST_SKEW);
		ns[r] = bench_now_ns() - t0;
		printf("rep %ld variant=%s n=%ld enabled=%d outer=%ld ns_per_outer=%.2f\n", r, v->name, n,
		       enabled, outer, ns[r] / outer);
	}
	if (have)
		bench_read_counters(c1);
	med = bench_median(ns, reps);
	printf("result variant=%s n=%ld enabled=%d outer=%ld reps=%ld insn_per_outer=%.0f median_ns_per_outer=%.2f min_ns_per_outer=%.2f\n",
	       v->name, n, enabled, outer, reps, n * v->insn_per_n + 6, med / outer, ns[0] / outer);
	if (!have)
		return 0;
	bench_print_counters(v->name, c0, c1);
	if (enabled) {
		bench_check_in_kernel(v->name, c0, c1, (long long)outer * reps);
		printf("kjit variant=%s n=%ld in_kernel_frac=%.4f runtime_entries_per_outer=%.4f\n", v->name, n,
		       (double)bench_delta(c0, c1, "syscalls_in_kernel") / ((double)outer * reps),
		       (double)bench_delta(c0, c1, "fragment_entries") / ((double)outer * reps));
	}
	return 0;
}
