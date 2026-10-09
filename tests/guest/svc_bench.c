// SPDX-License-Identifier: GPL-2.0
/*
 * Syscall round-trip and I/O microbenchmark (userspace-bypass comparison).
 *
 *   svc_bench <mode> <size> [iters] [reps]
 *
 * Modes (one loop iteration = `per_iter` syscalls, ns per syscall reported):
 *   getppid    1 raw svc getppid                                     (null syscall)
 *   raw_zn     2 raw svcs: read(/dev/zero, size), write(/dev/null, size)
 *   raw_pipe   2 raw svcs: write(pipe, size), read(pipe, size)       (size <= 64: never blocks)
 *   zn         the same as raw_zn through libc read()/write() with result checks
 *   pipe       the same as raw_pipe through libc read()/write() with result checks
 * The raw modes have no user code between the syscalls beyond the argument
 * moves; the libc modes run the static glibc wrappers (and a result check) in
 * between, the shape of a program doing small I/O.
 *
 * One warm-up run of max(iters / 10, 20000) iterations (auto mode learns the hot
 * PCs there), then `reps` timed runs of `iters` iterations (CLOCK_MONOTONIC around
 * the loop only); prints one "rep" line each, a "result" line with the median, and,
 * when the kjit debugfs exists, a "counters" line with the deltas of the timed
 * phase. With KJIT enabled (debugfs enable=1) the program dies unless >= 95% of
 * the timed syscalls ran in the kernel (bench_check_in_kernel). With KJIT_AUTO
 * unset and KJIT enabled it registers its SVC sites itself (translate_svc_sites);
 * in auto mode (KJIT_AUTO=1) nothing is registered.
 */
#include "bench_common.h"

void sb_getppid(uint64_t n);
void sb_rw2(uint64_t n, uint64_t fd1, uint64_t nr1, uint64_t fd2, uint64_t nr2, void *buf,
	    uint64_t size);

asm(".text\n"
    ".global sb_getppid\n"
    ".type sb_getppid, %function\n"
    "sb_getppid:\n"
    "	mov	x9, x0\n"
    "1:	mov	x8, #173\n"
    "	svc	#0\n"
    "	subs	x9, x9, #1\n"
    "	b.ne	1b\n"
    "	ret\n"
    ".global sb_rw2\n"
    ".type sb_rw2, %function\n"
    "sb_rw2:\n"
    "	mov	x9, x0\n"		/* count */
    "	mov	x10, x1\n"		/* fd1 */
    "	mov	x11, x2\n"		/* nr1 */
    "	mov	x12, x3\n"		/* fd2 */
    "	mov	x13, x4\n"		/* nr2 */
    "	mov	x14, x5\n"		/* buf */
    "	mov	x15, x6\n"		/* size */
    "1:	mov	x0, x10\n"
    "	mov	x1, x14\n"
    "	mov	x2, x15\n"
    "	mov	x8, x11\n"
    "	svc	#0\n"
    "	mov	x0, x12\n"
    "	mov	x1, x14\n"
    "	mov	x2, x15\n"
    "	mov	x8, x13\n"
    "	svc	#0\n"
    "	subs	x9, x9, #1\n"
    "	b.ne	1b\n"
    "	ret\n");

#define NR_READ 63
#define NR_WRITE 64

static int fd_zero, fd_null, pipe_r, pipe_w;
static char buf[4096];
static long size;

static void run(const char *mode, uint64_t n)
{
	if (!strcmp(mode, "getppid")) {
		sb_getppid(n);
	} else if (!strcmp(mode, "raw_zn")) {
		sb_rw2(n, fd_zero, NR_READ, fd_null, NR_WRITE, buf, size);
	} else if (!strcmp(mode, "raw_pipe")) {
		sb_rw2(n, pipe_w, NR_WRITE, pipe_r, NR_READ, buf, size);
	} else if (!strcmp(mode, "zn")) {
		for (uint64_t i = 0; i < n; i++) {
			if (read(fd_zero, buf, size) != size)
				die("read /dev/zero");
			if (write(fd_null, buf, size) != size)
				die("write /dev/null");
		}
	} else if (!strcmp(mode, "pipe")) {
		for (uint64_t i = 0; i < n; i++) {
			if (write(pipe_w, buf, size) != size)
				die("write pipe");
			if (read(pipe_r, buf, size) != size)
				die("read pipe");
		}
	} else {
		die("unknown mode %s", mode);
	}
}

int main(int argc, char **argv)
{
	const char *mode = argc > 1 ? argv[1] : NULL;
	long iters = argc > 3 ? atol(argv[3]) : 200000;
	long reps = argc > 4 ? atol(argv[4]) : 7;
	long long c0[BENCH_NCOUNTERS], c1[BENCH_NCOUNTERS];
	double ns[64], med;
	int per_iter, enabled = 0, have = bench_have_kjit(), pfd[2];
	long warm;

	if (!mode || argc < 3)
		die("usage: svc_bench <getppid|raw_zn|raw_pipe|zn|pipe> <size> [iters] [reps]");
	size = atol(argv[2]);
	if (size < 1 || size > 64 || iters < 1 || reps < 1 || reps > 64)
		die("1 <= size <= 64, iters >= 1, 1 <= reps <= 64 required");
	per_iter = !strcmp(mode, "getppid") ? 1 : 2;

	fd_zero = open("/dev/zero", O_RDONLY);
	fd_null = open("/dev/null", O_WRONLY);
	if (fd_zero < 0 || fd_null < 0 || pipe(pfd) < 0)
		die("open: %s", strerror(errno));
	pipe_r = pfd[0];
	pipe_w = pfd[1];
	memset(buf, 'x', sizeof(buf));

	if (have)
		enabled = bench_debugfs_bool("enable");
	if (enabled)
		kjit_register_self();

	warm = iters / 10 > 20000 ? iters / 10 : 20000;
	run(mode, warm);

	if (have)
		bench_read_counters(c0);
	for (long r = 0; r < reps; r++) {
		double t0 = bench_now_ns();

		run(mode, iters);
		ns[r] = bench_now_ns() - t0;
		printf("rep %ld mode=%s size=%ld enabled=%d ns_per_iter=%.2f ns_per_syscall=%.2f\n", r, mode,
		       size, enabled, ns[r] / iters, ns[r] / iters / per_iter);
	}
	if (have)
		bench_read_counters(c1);
	med = bench_median(ns, reps);
	printf("result mode=%s size=%ld enabled=%d iters=%ld reps=%ld syscalls_per_iter=%d median_ns_per_iter=%.2f median_ns_per_syscall=%.2f min_ns_per_syscall=%.2f\n",
	       mode, size, enabled, iters, reps, per_iter, med / iters, med / iters / per_iter,
	       ns[0] / iters / per_iter);
	if (!have)
		return 0;
	bench_print_counters(mode, c0, c1);
	if (enabled) {
		long long timed = (long long)iters * reps * per_iter;

		bench_check_in_kernel(mode, c0, c1, timed);
		printf("kjit mode=%s size=%ld in_kernel_frac=%.4f runtime_entries_per_syscall=%.4f\n", mode, size,
		       (double)bench_delta(c0, c1, "syscalls_in_kernel") / timed,
		       (double)bench_delta(c0, c1, "fragment_entries") / timed);
	}
	return 0;
}
