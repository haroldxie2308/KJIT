// SPDX-License-Identifier: GPL-2.0
/*
 * FPCR trap enables (A18, docs/pipeline.md, "Scalar floating point (A18)").
 *
 * A fragment executes scalar floating point at EL1 with the user's FPCR. If that
 * FPCR enables a floating-point trap (IOE, DZE, OFE, UFE, IXE: bits 8-12, IDE: bit
 * 15) on a CPU that implements trapping, an instruction that raises the enabled
 * exception would take an FP exception in the kernel instead of the user's SIGFPE.
 * So kjit_call_fragment_fpsimd() declines the run when any trap-enable bit is set:
 * nothing runs, userspace executes the code natively from the entry pc (stats:
 * run_declined and fpsimd_trap_declined grow, fpsimd_entries do not).
 *
 *   fp_trap [iterations=20000]
 *
 * One loop of scalar floating point (ucvtf, fmadd, fadd, frintz, fcvtzs, fcmpe,
 * fcsel, fadd) and a getppid() per iteration, in two shapes:
 *   - inline: the floating point follows the syscall in the same fragment, so the
 *     decline is at the first entry of a hook call;
 *   - call: the syscall is followed by `bl callee`, the callee does the floating
 *     point. The fragment of the resume pc has none; its BL exit chains into the
 *     callee's fragment, so the decline is at a chained entry, and userspace must
 *     resume at the callee (not at the resume pc, which would run the increment
 *     of the loop counter, done by the fragment before the BL, a second time)
 *     with the link register the BL set.
 * Each shape runs in two phases:
 *   - FPCR = 0: the floating point runs in FP/SIMD fragments (KJIT_EXPECT=fptrap
 *     checks fpsimd_entries);
 *   - each trap-enable bit in turn that this CPU keeps (the loop raises no
 *     exception, so none of them ever fires natively): every run is declined
 *     (KJIT_EXPECT=fptrap checks fpsimd_trap_declined).
 * A CPU without trapping support reads the bits back as zero: the second phase's
 * counter check is then skipped (SKIP on stderr) but both loops still run and their
 * results are still checked. The results are exact (multiples of 0.25 below 2^53),
 * so the reference is the same arithmetic in C. stdout is identical with KJIT
 * on/off.
 */
#include "kjit_test.h"

static const unsigned trap_bits[] = { 8, 9, 10, 11, 12, 15 };

static inline uint64_t read_fpcr(void)
{
	uint64_t v;

	asm volatile("mrs %0, fpcr" : "=r"(v));
	return v;
}

/* Which of the trap-enable bits this CPU keeps. FPCR is restored to 0. */
static uint64_t supported_trap_bits(void)
{
	uint64_t kept = 0;

	for (unsigned i = 0; i < sizeof(trap_bits) / sizeof(trap_bits[0]); i++) {
		uint64_t bit = 1UL << trap_bits[i];

		asm volatile("msr fpcr, %0" : : "r"(bit));
		kept |= read_fpcr() & bit;
	}
	asm volatile("msr fpcr, xzr");
	return kept;
}

/*
 * The inline loop, with FPCR = @fpcr for its whole duration (set and cleared inside
 * the asm: no compiler-generated floating point runs under a trap enable).
 */
static void run_inline(long n, uint64_t fpcr, uint64_t out[3])
{
	uint64_t acc, sel;
	long i = 0;
	long long sum = 0;

	asm volatile(
		"	fmov	d1, #1.5\n"
		"	fmov	d2, #0.25\n"
		"	movi	d3, #0\n"
		"	movi	d7, #0\n"
		"	movz	x9, #0x4163, lsl #48\n"
		"	movk	x9, #0x12d0, lsl #32\n"
		"	fmov	d5, x9\n"			/* 1e7 */
		"	msr	fpcr, %[fpcr]\n"
		"1:\n"
		"	ucvtf	d0, %[i]\n"
		"	fmadd	d3, d0, d2, d3\n"		/* acc += i / 4 */
		"	fadd	d3, d3, d1\n"			/* acc += 1.5 */
		"	frintz	d4, d3\n"
		"	fcvtzs	x9, d4\n"
		"	add	%[sum], %[sum], x9\n"
		"	fcmpe	d3, d5\n"
		"	fcsel	d6, d1, d2, gt\n"
		"	fadd	d7, d7, d6\n"
		"	mov	x8, #173\n"			/* getppid() */
		"	svc	#0\n"
		"	add	%[i], %[i], #1\n"
		"	cmp	%[i], %[n]\n"
		"	b.lt	1b\n"
		"	msr	fpcr, xzr\n"
		"	fmov	%[acc], d3\n"
		"	fmov	%[sel], d7\n"
		: [i] "+r"(i), [sum] "+r"(sum), [acc] "=&r"(acc), [sel] "=&r"(sel)
		: [n] "r"(n), [fpcr] "r"(fpcr)
		: "x0", "x1", "x2", "x8", "x9", "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7",
		  "cc", "memory");
	out[0] = acc;
	out[1] = sel;
	out[2] = (uint64_t)sum;
}

/*
 * The call loop: the same arithmetic, but the floating point is in
 * fp_trap_callee, reached by `bl` right after the syscall. x19 = out, x20 = n,
 * x21 = i + 1 (incremented before the call), x22 = sum; d1 = 1.5, d2 = 0.25, d3 = acc, d5 = 1e7, d7 = sel.
 */
void fp_trap_call_loop(long n, uint64_t fpcr, uint64_t out[3]);
void fp_trap_callee(void);

asm(".text\n"
    ".global fp_trap_call_loop\n"
    ".type fp_trap_call_loop, %function\n"
    "fp_trap_call_loop:\n"
    "	stp	x29, x30, [sp, #-48]!\n"
    "	stp	x19, x20, [sp, #16]\n"
    "	stp	x21, x22, [sp, #32]\n"
    "	mov	x19, x2\n"
    "	mov	x20, x0\n"
    "	mov	x21, #0\n"
    "	mov	x22, #0\n"
    "	fmov	d1, #1.5\n"
    "	fmov	d2, #0.25\n"
    "	movi	d3, #0\n"
    "	movi	d7, #0\n"
    "	movz	x9, #0x4163, lsl #48\n"
    "	movk	x9, #0x12d0, lsl #32\n"
    "	fmov	d5, x9\n"
    "	msr	fpcr, x1\n"
    "1:\n"
    "	mov	x8, #173\n"			/* getppid() */
    "	svc	#0\n"
    "	add	x21, x21, #1\n"		/* counted before the call, see the header */
    "	bl	fp_trap_callee\n"
    "	cmp	x21, x20\n"
    "	b.lt	1b\n"
    "	msr	fpcr, xzr\n"
    "	fmov	x9, d3\n"
    "	str	x9, [x19]\n"
    "	fmov	x9, d7\n"
    "	str	x9, [x19, #8]\n"
    "	str	x22, [x19, #16]\n"
    "	ldp	x21, x22, [sp, #32]\n"
    "	ldp	x19, x20, [sp, #16]\n"
    "	ldp	x29, x30, [sp], #48\n"
    "	ret\n"
    ".size fp_trap_call_loop, .-fp_trap_call_loop\n"
    ".global fp_trap_callee\n"
    ".type fp_trap_callee, %function\n"
    "fp_trap_callee:\n"
    "	sub	x10, x21, #1\n"
    "	ucvtf	d0, x10\n"
    "	fmadd	d3, d0, d2, d3\n"
    "	fadd	d3, d3, d1\n"
    "	frintz	d4, d3\n"
    "	fcvtzs	x9, d4\n"
    "	add	x22, x22, x9\n"
    "	fcmpe	d3, d5\n"
    "	fcsel	d6, d1, d2, gt\n"
    "	fadd	d7, d7, d6\n"
    "	ret\n"
    ".size fp_trap_callee, .-fp_trap_callee\n");

static uint64_t bits_of(double d)
{
	uint64_t b;

	memcpy(&b, &d, sizeof(b));
	return b;
}

/* The loops' arithmetic in C: every operation is exact, so the order is the result. */
static void reference(long n, uint64_t out[3])
{
	double acc = 0, sel = 0;
	long long sum = 0;

	for (long i = 0; i < n; i++) {
		acc = __builtin_fma((double)i, 0.25, acc);
		acc += 1.5;
		sum += (long long)__builtin_trunc(acc);
		sel += acc > 1e7 ? 1.5 : 0.25;
	}
	out[0] = bits_of(acc);
	out[1] = bits_of(sel);
	out[2] = (uint64_t)sum;
}

static void run_checked(const char *what, void (*loop)(long, uint64_t, uint64_t[3]), long n,
			uint64_t fpcr)
{
	uint64_t got[3], want[3];

	loop(n, fpcr, got);
	reference(n, want);
	if (got[0] != want[0] || got[1] != want[1] || got[2] != want[2])
		die("fp_trap %s: acc %#llx sel %#llx sum %lld, want %#llx %#llx %lld", what,
		    (unsigned long long)got[0], (unsigned long long)got[1], (long long)got[2],
		    (unsigned long long)want[0], (unsigned long long)want[1], (long long)want[2]);
	printf("fp_trap %s iters=%ld acc=%#llx sel=%#llx sum=%lld\n", what, n,
	       (unsigned long long)got[0], (unsigned long long)got[1], (long long)got[2]);
}

int main(int argc, char **argv)
{
	long iters = argc > 1 ? atol(argv[1]) : 20000;
	long on_iters = iters / 4;
	long long warm = kjit_auto_warmup();
	static const struct {
		const char *name;
		void (*loop)(long, uint64_t, uint64_t[3]);
	} shapes[] = { { "inline", run_inline }, { "call", fp_trap_call_loop } };
	uint64_t kept;

	kjit_register_self();
	/* The call shape needs its callee translated: a branch exit chains into it. */
	if (!kjit_auto_mode() && kjit_translate_self((uint64_t)fp_trap_callee))
		die("fp_trap: translate fp_trap_callee failed");
	kept = supported_trap_bits();
	printf("fp_trap trap bits kept=%#llx\n", (unsigned long long)kept);

	for (unsigned s = 0; s < sizeof(shapes) / sizeof(shapes[0]); s++) {
		char what[48];
		struct kjit_snap s0, s1;

		/* Traps off: the floating point runs in FP/SIMD fragments. */
		snprintf(what, sizeof(what), "%s fpcr=0", shapes[s].name);
		s0 = kjit_snap();
		run_checked(what, shapes[s].loop, iters, 0);
		s1 = kjit_snap();
		kjit_report(what, s0, s1);
		if (kjit_expect("fptrap") &&
		    (s1.fp_entries - s0.fp_entries) * 100 < (iters - warm) * 90)
			die("fp_trap %s: only %lld FP/SIMD fragment entries for %ld iterations", what,
			    s1.fp_entries - s0.fp_entries, iters);

		/* Each trap enable the CPU keeps: every run is declined. */
		for (unsigned i = 0; i < sizeof(trap_bits) / sizeof(trap_bits[0]); i++) {
			uint64_t bit = 1UL << trap_bits[i];
			long long declined, run_declined;

			if (!(kept & bit))
				continue;
			snprintf(what, sizeof(what), "%s fpcr bit %u", shapes[s].name, trap_bits[i]);
			s0 = kjit_snap();
			declined = kjit_stat("fpsimd_trap_declined");
			run_declined = kjit_stat("run_declined");
			run_checked(what, shapes[s].loop, on_iters, bit);
			s1 = kjit_snap();
			declined = kjit_stat("fpsimd_trap_declined") - declined;
			run_declined = kjit_stat("run_declined") - run_declined;
			kjit_report(what, s0, s1);
			fprintf(stderr, "fp_trap %s: fpsimd_trap_declined=%lld run_declined=%lld\n", what,
				declined, run_declined);
			if (!kjit_expect("fptrap"))
				continue;
			if (declined * 100 < (on_iters - warm) * 90)
				die("fp_trap %s: only %lld trap-declined runs for %ld iterations", what,
				    declined, on_iters);
			if (run_declined < declined)
				die("fp_trap %s: run_declined grew less than fpsimd_trap_declined", what);
			if ((s1.fp_entries - s0.fp_entries) * 10 > on_iters)
				die("fp_trap %s: %lld FP/SIMD fragment entries ran under a trap enable",
				    what, s1.fp_entries - s0.fp_entries);
		}
	}
	if (!kept)
		fprintf(stderr,
			"fp_trap: SKIP counter check: this CPU does not implement FP trap enables (FPCR bits 8-12, 15 read back 0)\n");
	return 0;
}
