// SPDX-License-Identifier: GPL-2.0
/*
 * A11 Step 0 microbenchmark: the wall-clock cost of one fragment entry.
 *
 * Per outer iteration: one raw svc (getppid), then `calls` calls (bl) to a
 * trivial callee and back, no syscall in between. Each call is two control
 * transfers (the call, then the return), so one outer iteration makes
 * 2 * calls + 1 of them with KJIT on. Before A11 every one was a chained
 * fragment entry through the runtime and (T_on - T_off) / (2 * calls) was the
 * cost of one entry. Since A11 a transfer to a translated target is a dispatch
 * in the fragment's own code and only a miss is a runtime entry; (T_on -
 * T_off) / (2 * calls) is then the cost of one transfer, whichever path it
 * took (see "Counters" below). The svc cost is a per-outer constant; run it
 * with two `calls` values and take the slope to remove it.
 *
 * Callee variants (argv[1]):
 *   gpr   add x6, x6, #1; ret
 *   fp    fmov d0, x6; fmov x6, d0; add x6, x6, #1; ret
 *         the callee fragment uses FP/SIMD, so its entry runs inside the
 *         A13 bracket (fpsimd_entries); the return site stays integer-only.
 *
 *   entry_cost <gpr|fp> [outer] [calls] [reps]
 *
 * Runs `outer` iterations once as warm-up (auto mode learns the callee and the
 * return site there), then `reps` timed runs of `outer` iterations each
 * (clock_gettime(CLOCK_MONOTONIC) around the asm loop only). Prints one
 * "rep" line per run and a "result" line with the median, all on stdout.
 * KJIT enabled (debugfs enable=1): the PCs are translated up front unless
 * KJIT_AUTO=1, and the timed phase must have run in fragments or the test
 * fails (see "Counters"). KJIT disabled: nothing is registered and the
 * counters stay put.
 *
 * Counters (A11: `fragment_entries` counts runtime round trips only, not
 * dispatched transfers): one syscall per outer iteration must have run in the
 * kernel (syscalls_in_kernel), so the loop ran in fragments; no Budget exit
 * and no chain_cap (a call is a bl, a ret and the loop's back-edge, so
 * 3 * calls + 1 budget units must fit KJIT_BACKEDGE_BUDGET = 4096). Runtime
 * entries are at most 10% of the pre-A11 entry count: gpr takes about one per outer iteration (the
 * syscall resume), no FP/SIMD entry; fp takes two (the resume, then the one
 * entry into the FP/SIMD callee, which a non-FP/SIMD run never dispatches to,
 * `ibtc_fpsimd_boundary`): that bracketed run then continues through the
 * return site (an integer fragment, in table_all) and every later call to the
 * callee, so fpsimd_entries is about one per outer iteration, not `calls`.
 */
#include <time.h>

#include "kjit_test.h"

void ec_run_gpr(uint64_t outer, uint64_t calls, uint64_t *acc);
void ec_run_fp(uint64_t outer, uint64_t calls, uint64_t *acc);
extern char ec_callee_gpr[], ec_ret_gpr[], ec_callee_fp[], ec_ret_fp[];

/* Same loop as call_loop.c; one copy per callee so each has its own labels. */
#define EC_LOOP(V, CALLEE)							\
	".global ec_run_" #V "\n"						\
	".type ec_run_" #V ", %function\n"					\
	"ec_run_" #V ":\n"							\
	"	mov	x9, x30\n"						\
	"	mov	x4, x0\n"						\
	"	ldr	x6, [x2]\n"						\
	"1:	mov	x8, #173\n"		/* getppid */			\
	"	svc	#0\n"							\
	"	mov	x3, x1\n"						\
	"2:	bl	ec_callee_" #V "\n"					\
	".global ec_ret_" #V "\n"						\
	"ec_ret_" #V ":\n"							\
	"	subs	x3, x3, #1\n"						\
	"	b.ne	2b\n"							\
	"	subs	x4, x4, #1\n"						\
	"	b.ne	1b\n"							\
	"	str	x6, [x2]\n"						\
	"	mov	x30, x9\n"						\
	"	ret\n"								\
	".global ec_callee_" #V "\n"						\
	"ec_callee_" #V ":\n"							\
	CALLEE									\
	"	ret\n"

asm(".text\n"
    EC_LOOP(gpr, "	add	x6, x6, #1\n")
    EC_LOOP(fp, "	fmov	d0, x6\n"
		"	fmov	x6, d0\n"
		"	add	x6, x6, #1\n"));

/* debugfs bool: "Y"/"N" (or "1"/"0"). */
static int read_debugfs_bool(const char *file)
{
	char path[128], line[32];
	FILE *f;

	snprintf(path, sizeof(path), KJIT_DEBUGFS "/%s", file);
	f = fopen(path, "r");
	if (!f || !fgets(line, sizeof(line), f))
		die("read %s: %s", path, strerror(errno));
	fclose(f);
	if (line[0] == 'Y' || line[0] == '1')
		return 1;
	if (line[0] == 'N' || line[0] == '0')
		return 0;
	die("%s: unexpected content '%s'", path, line);
	return 0;
}

static const char *const counters[] = {
	"hook_calls", "syscalls_in_kernel", "fragment_entries", "fpsimd_entries", "fpsimd_preempted",
	"chains", "chain_cap", "exit_svc", "exit_bl", "exit_blr", "exit_br", "exit_ret", "exit_mem",
	"exit_unsupported", "exit_budget", "run_declined",
};
#define NCOUNTERS (sizeof(counters) / sizeof(counters[0]))

static void read_counters(long long *v)
{
	for (size_t i = 0; i < NCOUNTERS; i++)
		v[i] = kjit_stat(counters[i]);
}

static int cmp_double(const void *a, const void *b)
{
	double x = *(const double *)a, y = *(const double *)b;

	return (x > y) - (x < y);
}

int main(int argc, char **argv)
{
	const char *variant = argc > 1 ? argv[1] : NULL;
	long outer = argc > 2 ? atol(argv[2]) : 4000;
	long calls = argc > 3 ? atol(argv[3]) : 128;
	long reps = argc > 4 ? atol(argv[4]) : 7;
	void (*run)(uint64_t, uint64_t, uint64_t *);
	char *callee, *ret;
	uint64_t acc = 0;
	long long c0[NCOUNTERS], c1[NCOUNTERS], d[NCOUNTERS];
	long long expected_entries;
	double ns[64], per_outer, per_call;
	int enabled, err, is_fp;

	if (!variant || (strcmp(variant, "gpr") && strcmp(variant, "fp")))
		die("usage: entry_cost <gpr|fp> [outer] [calls] [reps]");
	if (outer < 1 || calls < 1 || reps < 1 || reps > 64)
		die("outer, calls >= 1 and 1 <= reps <= 64 required");
	is_fp = !strcmp(variant, "fp");
	run = is_fp ? ec_run_fp : ec_run_gpr;
	callee = is_fp ? ec_callee_fp : ec_callee_gpr;
	ret = is_fp ? ec_ret_fp : ec_ret_gpr;

	enabled = read_debugfs_bool("enable");
	if (enabled) {
		/*
		 * One budget unit per dispatch attempt and per back-edge: each call is
		 * a bl, a ret and the loop's b.ne. KJIT_BACKEDGE_BUDGET is 4096.
		 */
		if (3 * calls + 1 > 4096)
			die("3 * calls + 1 = %ld budget units per syscall exceed 4096", 3 * calls + 1);
		kjit_register_self();
		if (!kjit_auto_mode()) {
			/* The callee and the return site are branch targets, not SVC resume PCs. */
			err = kjit_translate_self((uint64_t)callee);
			if (err && err != EEXIST)
				die("translate callee: %s", strerror(err));
			err = kjit_translate_self((uint64_t)ret);
			if (err && err != EEXIST)
				die("translate return site: %s", strerror(err));
		}
	}

	run(outer, calls, &acc);	/* warm-up: caches, auto mode's learning */

	if (enabled)
		read_counters(c0);
	for (long r = 0; r < reps; r++) {
		struct timespec t0, t1;

		clock_gettime(CLOCK_MONOTONIC, &t0);
		run(outer, calls, &acc);
		clock_gettime(CLOCK_MONOTONIC, &t1);
		ns[r] = (double)(t1.tv_sec - t0.tv_sec) * 1e9 + (double)(t1.tv_nsec - t0.tv_nsec);
		printf("rep %ld variant=%s enabled=%d outer=%ld calls=%ld ns_per_outer=%.1f ns_per_call=%.2f\n",
		       r, variant, enabled, outer, calls, ns[r] / outer, ns[r] / outer / calls);
	}
	if (enabled) {
		read_counters(c1);
		for (size_t i = 0; i < NCOUNTERS; i++)
			d[i] = c1[i] - c0[i];
	}
	qsort(ns, reps, sizeof(ns[0]), cmp_double);
	per_outer = ns[reps / 2] / outer;
	per_call = per_outer / calls;
	printf("result variant=%s enabled=%d outer=%ld calls=%ld reps=%ld median_ns_per_outer=%.1f median_ns_per_call=%.2f min_ns_per_call=%.2f acc=%llu\n",
	       variant, enabled, outer, calls, reps, per_outer, per_call, ns[0] / outer / calls,
	       (unsigned long long)acc);
	if (!enabled)
		return 0;

	printf("counters variant=%s timed_outer=%ld", variant, outer * reps);
	for (size_t i = 0; i < NCOUNTERS; i++)
		printf(" %s=%lld", counters[i], d[i]);
	printf("\n");

	/*
	 * The timed phase must have run in fragments. The snapshots' own libc
	 * syscalls add a few runs, hence the slack.
	 */
	expected_entries = outer * reps * (2 * calls + 1);
	for (size_t i = 0; i < NCOUNTERS; i++) {
		if (!strcmp(counters[i], "syscalls_in_kernel") && d[i] * 100 < outer * reps * 95)
			die("only %lld of %ld syscalls ran in the kernel", d[i], outer * reps);
		if (!strcmp(counters[i], "fragment_entries")) {
			if (d[i] * 100 < outer * reps * 95)
				die("only %lld runtime entries for %ld syscalls", d[i], outer * reps);
			if (d[i] * 10 > expected_entries)
				die("%lld runtime entries: the transfers did not dispatch (want <= %lld)",
				    d[i], expected_entries / 10);
		}
		if (!strcmp(counters[i], "fpsimd_entries")) {
			if (is_fp && d[i] * 100 < outer * reps * 95)
				die("only %lld FP/SIMD entries for %ld syscalls", d[i], outer * reps);
			if (!is_fp && d[i] * 100 > expected_entries)
				die("%lld FP/SIMD entries in the integer-only variant", d[i]);
		}
		if (!strcmp(counters[i], "chain_cap") && d[i] != 0)
			die("chain_cap hit %lld times", d[i]);
		if (!strcmp(counters[i], "exit_budget") && d[i] != 0)
			die("%lld Budget exits with 3 * calls + 1 <= 4096", d[i]);
	}
	return 0;
}
