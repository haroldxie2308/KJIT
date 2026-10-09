/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Helpers of the userspace-bypass comparison microbenchmarks (svc_bench.c,
 * code_speed.c): timing, medians and KJIT counter deltas. Not a test: these
 * programs measure, they do not compare KJIT on against KJIT off.
 */
#ifndef BENCH_COMMON_H
#define BENCH_COMMON_H

#include <time.h>

#include "kjit_test.h"

static inline double bench_now_ns(void)
{
	struct timespec t;

	clock_gettime(CLOCK_MONOTONIC, &t);
	return (double)t.tv_sec * 1e9 + (double)t.tv_nsec;
}

static inline int bench_cmp_double(const void *a, const void *b)
{
	double x = *(const double *)a, y = *(const double *)b;

	return (x > y) - (x < y);
}

/* Median (upper median for even n); sorts the array. */
static inline double bench_median(double *v, long n)
{
	qsort(v, n, sizeof(v[0]), bench_cmp_double);
	return v[n / 2];
}

static const char *const bench_counters[] = {
	"hook_calls", "syscalls_in_kernel", "fragment_entries", "fpsimd_entries", "fpsimd_restores",
	"chains", "chain_cap", "exit_svc", "exit_bl", "exit_blr", "exit_br", "exit_ret", "exit_mem",
	"exit_unsupported", "exit_budget", "run_declined",
};
#define BENCH_NCOUNTERS (sizeof(bench_counters) / sizeof(bench_counters[0]))

/* 1 when the kjit debugfs is mounted and the module is loaded. */
static inline int bench_have_kjit(void)
{
	return access(KJIT_DEBUGFS "/stats", R_OK) == 0;
}

/* debugfs bool: "Y"/"N" (or "1"/"0"). */
static inline int bench_debugfs_bool(const char *file)
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

static inline void bench_read_counters(long long *v)
{
	for (size_t i = 0; i < BENCH_NCOUNTERS; i++)
		v[i] = kjit_stat(bench_counters[i]);
}

/* Delta of counter `name` between two bench_read_counters() snapshots. */
static inline long long bench_delta(const long long *c0, const long long *c1, const char *name)
{
	for (size_t i = 0; i < BENCH_NCOUNTERS; i++)
		if (!strcmp(bench_counters[i], name))
			return c1[i] - c0[i];
	die("counter %s not in bench_counters", name);
	return 0;
}

/* One "counters" line: every counter's delta over the timed phase. */
static inline void bench_print_counters(const char *tag, const long long *c0, const long long *c1)
{
	printf("counters %s", tag);
	for (size_t i = 0; i < BENCH_NCOUNTERS; i++)
		printf(" %s=%lld", bench_counters[i], c1[i] - c0[i]);
	printf("\n");
}

/*
 * KJIT enabled: the timed phase must have run in fragments, or the numbers say
 * nothing about KJIT. `syscalls` is the number of syscalls of the timed phase
 * (the counter snapshots' own libc calls are outside it; 5% slack). Also no
 * Budget exit and no chain cap: the work between two syscalls must fit one run.
 */
static inline void bench_check_in_kernel(const char *what, const long long *c0, const long long *c1,
					 long long syscalls)
{
	long long in = bench_delta(c0, c1, "syscalls_in_kernel");

	if (in * 100 < syscalls * 95)
		die("%s: only %lld of %lld syscalls ran in the kernel", what, in, syscalls);
	if (bench_delta(c0, c1, "exit_budget") * 100 > syscalls)
		die("%s: %lld Budget exits for %lld syscalls", what, bench_delta(c0, c1, "exit_budget"),
		    syscalls);
	if (bench_delta(c0, c1, "chain_cap") != 0)
		die("%s: chain_cap hit %lld times", what, bench_delta(c0, c1, "chain_cap"));
}

#endif
