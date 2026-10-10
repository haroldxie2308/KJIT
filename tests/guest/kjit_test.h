/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Helpers for the K2 guest tests (tests/guest/run-k2.sh).
 *
 * Contract with the runner: stdout is the test's semantic output and must be
 * byte-identical with KJIT enabled and disabled; diagnostics go to stderr.
 * When KJIT_EXPECT is set (the runner sets it only for the enabled run), the
 * test also checks the KJIT counters in /sys/kernel/debug/kjit/stats.
 * When KJIT_AUTO=1 (run-k2.sh --auto), the module's auto mode translates hot
 * code: the tests do not register themselves, and expectations allow for the
 * iterations that run before a PC is hot.
 */
#ifndef KJIT_TEST_H
#define KJIT_TEST_H

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define KJIT_DEBUGFS "/sys/kernel/debug/kjit"

static inline void die(const char *fmt, ...)
{
	va_list ap;

	fprintf(stderr, "FAIL: ");
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");
	exit(1);
}

static inline void kjit_write(const char *file, const char *text)
{
	char path[128];
	int fd;
	ssize_t n;

	snprintf(path, sizeof(path), KJIT_DEBUGFS "/%s", file);
	fd = open(path, O_WRONLY);
	if (fd < 0)
		die("open %s: %s", path, strerror(errno));
	n = write(fd, text, strlen(text));
	if (n != (ssize_t)strlen(text))
		die("write '%s' to %s: %s", text, path, n < 0 ? strerror(errno) : "short");
	close(fd);
}

/* KJIT_AUTO=1: auto mode translates hot code, nothing registers itself. */
static inline int kjit_auto_mode(void)
{
	const char *e = getenv("KJIT_AUTO");

	return e && !strcmp(e, "1");
}

/*
 * Iterations of a hot loop that may run natively in auto mode before its PCs
 * are translated: hot_threshold hits per PC, twice for slack (a hit window can
 * restart, a translation can race). 0 outside auto mode.
 */
static inline long kjit_auto_warmup(void)
{
	char line[32];
	long threshold;
	FILE *f;

	if (!kjit_auto_mode())
		return 0;
	f = fopen(KJIT_DEBUGFS "/hot_threshold", "r");
	if (!f || !fgets(line, sizeof(line), f))
		die("read hot_threshold: %s", strerror(errno));
	fclose(f);
	threshold = atol(line);
	return 2 * (threshold > 0 ? threshold : 1);
}

/*
 * Translates the resume PC of every SVC in this process's text. A no-op in
 * auto mode.
 */
static inline void kjit_register_self(void)
{
	char buf[32];

	if (kjit_auto_mode())
		return;
	snprintf(buf, sizeof(buf), "%d", getpid());
	kjit_write("translate_svc_sites", buf);
}

/* Translates one entry PC of this process; returns the write's errno or 0. */
static inline int kjit_translate_self(uint64_t pc)
{
	char path[128], buf[64];
	int fd, err = 0;

	snprintf(path, sizeof(path), KJIT_DEBUGFS "/translate");
	snprintf(buf, sizeof(buf), "%d %#llx", getpid(), (unsigned long long)pc);
	fd = open(path, O_WRONLY);
	if (fd < 0)
		die("open %s: %s", path, strerror(errno));
	if (write(fd, buf, strlen(buf)) < 0)
		err = errno;
	close(fd);
	return err;
}

static inline long long kjit_stat(const char *name)
{
	char line[128], key[64];
	long long value;
	FILE *f = fopen(KJIT_DEBUGFS "/stats", "r");

	if (!f)
		die("open stats: %s", strerror(errno));
	while (fgets(line, sizeof(line), f)) {
		if (sscanf(line, "%63s %lld", key, &value) == 2 && !strcmp(key, name)) {
			fclose(f);
			return value;
		}
	}
	die("stat %s missing", name);
	return -1;
}

/* "Is KJIT_EXPECT == what?" */
static inline int kjit_expect(const char *what)
{
	const char *e = getenv("KJIT_EXPECT");

	return e && !strcmp(e, what);
}

struct kjit_snap {
	long long in_kernel, entries, translate_ok, exit_mem, exit_budget, exit_unsupported;
	long long fp_entries, fp_preempted, fp_exit_mem;	/* A13 FP/SIMD bracket */
};

static inline struct kjit_snap kjit_snap(void)
{
	struct kjit_snap s = {
		.in_kernel = kjit_stat("syscalls_in_kernel"),
		.entries = kjit_stat("fragment_entries"),
		.translate_ok = kjit_stat("translate_ok"),
		.exit_mem = kjit_stat("exit_mem"),
		.exit_budget = kjit_stat("exit_budget"),
		.exit_unsupported = kjit_stat("exit_unsupported"),
		.fp_entries = kjit_stat("fpsimd_entries"),
		.fp_preempted = kjit_stat("fpsimd_preempted"),
		.fp_exit_mem = kjit_stat("fpsimd_exit_mem"),
	};
	return s;
}

static inline void kjit_report(const char *test, struct kjit_snap a, struct kjit_snap b)
{
	fprintf(stderr, "%s: in_kernel=%lld entries=%lld exit_mem=%lld exit_budget=%lld exit_unsupported=%lld fpsimd_entries=%lld fpsimd_preempted=%lld fpsimd_exit_mem=%lld\n",
		test, b.in_kernel - a.in_kernel, b.entries - a.entries, b.exit_mem - a.exit_mem,
		b.exit_budget - a.exit_budget, b.exit_unsupported - a.exit_unsupported,
		b.fp_entries - a.fp_entries, b.fp_preempted - a.fp_preempted,
		b.fp_exit_mem - a.fp_exit_mem);
}

/*
 * KJIT_EXPECT=fpsimd: at least @pct percent of @syscalls ran in the kernel and
 * at least @pct percent of @fp_runs expected FP/SIMD fragment entries happened
 * (both less the auto-mode warmup).
 */
static inline void kjit_check_fpsimd(const char *test, struct kjit_snap a, struct kjit_snap b,
				     long long syscalls, long long fp_runs, int pct)
{
	long long warm = kjit_auto_warmup(), in = b.in_kernel - a.in_kernel,
		  fp = b.fp_entries - a.fp_entries;

	if (!kjit_expect("fpsimd"))
		return;
	if (in * 100 < (syscalls - 2 * warm) * pct)
		die("%s: only %lld of %lld syscalls in kernel", test, in, syscalls);
	if (fp * 100 < (fp_runs - warm) * pct)
		die("%s: only %lld FP/SIMD fragment entries, want about %lld", test, fp, fp_runs);
}

/* 32 16-byte patterns for V registers: distinct, no zero bytes. */
static inline void kjit_vpattern(uint8_t v[32][16], uint8_t seed)
{
	for (int r = 0; r < 32; r++)
		for (int i = 0; i < 16; i++)
			v[r][i] = (uint8_t)(seed + 37 * r + 11 * i) | 1;
}

/*
 * The G2 hot loop (tests/arm64/toy_cfg.s shape): per iteration a raw svc
 * getppid and a raw svc write(fd, &byte, 1), with ALU work between them.
 * iters == 0 runs (practically) forever.
 */
static inline void toy_hot_loop(uint64_t iters, int fd, uint64_t *a_io, uint64_t *b_io)
{
	uint64_t a = *a_io, b = *b_io, n = iters;
	char byte = 'k';

	asm volatile(
		"1:\n"
		"	mov	x8, #173\n"		/* getppid */
		"	svc	#0\n"
		"	add	%[a], %[a], x0\n"
		"	eor	%[b], %[b], %[a], lsl #3\n"
		"	add	%[b], %[b], #7\n"
		"	mov	x0, %[fd]\n"
		"	mov	x1, %[buf]\n"
		"	mov	x2, #1\n"
		"	mov	x8, #64\n"		/* write */
		"	svc	#0\n"
		"	add	%[a], %[a], x0\n"
		"	subs	%[n], %[n], #1\n"
		"	b.ne	1b\n"
		: [a] "+r"(a), [b] "+r"(b), [n] "+r"(n)
		: [fd] "r"((long)fd), [buf] "r"(&byte)
		: "x0", "x1", "x2", "x8", "cc", "memory");
	*a_io = a;
	*b_io = b;
}

#endif
