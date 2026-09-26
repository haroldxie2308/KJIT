// SPDX-License-Identifier: GPL-2.0
/*
 * E0 baseline: cost of the userspace/kernel round trip that KJIT removes.
 *
 * Every syscall is a raw `svc #0` (no libc wrapper, no vDSO), so the numbers
 * are comparable across kernels and C libraries. Time comes from CNTVCT_EL0,
 * which ticks at CNTFRQ_EL0 in both a VM and a container.
 *
 *   getppid        null syscall
 *   write_devnull  write(/dev/null, 1 byte)
 *   pipe_pingpong  write(pipe, 1 byte) + read(pipe, 1 byte), one thread;
 *                  reported per pair (two syscalls)
 *
 * Each case runs RUNS times of ITERS operations after one warm-up run; the
 * report is ns/op for the median and fastest run.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <unistd.h>

#define RUNS 7

static inline long svc1(long nr, long a0)
{
	register long x8 asm("x8") = nr;
	register long x0 asm("x0") = a0;

	asm volatile("svc #0" : "+r"(x0) : "r"(x8) : "memory");
	return x0;
}

static inline long svc3(long nr, long a0, long a1, long a2)
{
	register long x8 asm("x8") = nr;
	register long x0 asm("x0") = a0;
	register long x1 asm("x1") = a1;
	register long x2 asm("x2") = a2;

	asm volatile("svc #0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2) : "memory");
	return x0;
}

static inline uint64_t ticks(void)
{
	uint64_t t;

	asm volatile("isb; mrs %0, cntvct_el0" : "=r"(t) : : "memory");
	return t;
}

static uint64_t freq(void)
{
	uint64_t f;

	asm volatile("mrs %0, cntfrq_el0" : "=r"(f));
	return f;
}

static int devnull_fd;
static int pipe_fd[2];
static char byte = 'x';

static void die(const char *what, long ret)
{
	fprintf(stderr, "syscall_bench: %s failed: %ld\n", what, ret);
	exit(1);
}

static void run_getppid(long iters)
{
	for (long i = 0; i < iters; i++)
		svc1(SYS_getppid, 0);
}

static void run_write_devnull(long iters)
{
	for (long i = 0; i < iters; i++) {
		long r = svc3(SYS_write, devnull_fd, (long)&byte, 1);

		if (r != 1)
			die("write(/dev/null)", r);
	}
}

static void run_pipe_pingpong(long iters)
{
	char in;

	for (long i = 0; i < iters; i++) {
		long w = svc3(SYS_write, pipe_fd[1], (long)&byte, 1);
		long r = svc3(SYS_read, pipe_fd[0], (long)&in, 1);

		if (w != 1)
			die("write(pipe)", w);
		if (r != 1)
			die("read(pipe)", r);
	}
}

static int cmp_u64(const void *a, const void *b)
{
	uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;

	return (x > y) - (x < y);
}

static void bench(const char *name, const char *unit, void (*fn)(long), long iters,
		  uint64_t hz)
{
	uint64_t t[RUNS];

	fn(iters / 10);
	for (int r = 0; r < RUNS; r++) {
		uint64_t start = ticks();

		fn(iters);
		t[r] = ticks() - start;
	}
	qsort(t, RUNS, sizeof(t[0]), cmp_u64);
	printf("e0: %-14s median %8.1f ns/%s   min %8.1f ns/%s   (%ld iters x %d runs)\n",
	       name, (double)t[RUNS / 2] * 1e9 / hz / iters, unit,
	       (double)t[0] * 1e9 / hz / iters, unit, iters, RUNS);
}

int main(int argc, char **argv)
{
	long scale = argc > 1 ? atol(argv[1]) : 1;
	uint64_t hz = freq();
	cpu_set_t cpus;
	int cpu;

	if (scale < 1) {
		fprintf(stderr, "usage: %s [iteration-scale >= 1]\n", argv[0]);
		return 2;
	}
	/*
	 * Stay on one CPU (the first one we may use) so a migration does not
	 * land inside a timed run.
	 */
	if (sched_getaffinity(0, sizeof(cpus), &cpus) != 0)
		die("sched_getaffinity", -errno);
	for (cpu = 0; cpu < CPU_SETSIZE && !CPU_ISSET(cpu, &cpus); cpu++)
		;
	CPU_ZERO(&cpus);
	CPU_SET(cpu, &cpus);
	if (sched_setaffinity(0, sizeof(cpus), &cpus) != 0)
		die("sched_setaffinity", -errno);

	devnull_fd = open("/dev/null", O_WRONLY | O_CLOEXEC);
	if (devnull_fd < 0)
		die("open(/dev/null)", -errno);
	if (pipe2(pipe_fd, O_CLOEXEC) != 0)
		die("pipe2", -errno);

	printf("e0: timer CNTVCT_EL0 at %lu Hz, pinned to CPU %d\n", (unsigned long)hz, cpu);
	bench("getppid", "op", run_getppid, 1000000 * scale, hz);
	bench("write_devnull", "op", run_write_devnull, 1000000 * scale, hz);
	bench("pipe_pingpong", "pair", run_pipe_pingpong, 500000 * scale, hz);
	return 0;
}
