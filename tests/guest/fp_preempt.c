// SPDX-License-Identifier: GPL-2.0
/*
 * V-register state that must survive preemption, migration and kernel-mode
 * NEON in the middle of long fragment runs (the A13 bracket).
 *
 * `workers` processes (default 2 * online CPUs, so they preempt each other),
 * each running a pure FP/SIMD recurrence over V0-V7 (add, eor, shl, ushr, orr,
 * ext: every register feeds every other, so one corrupted lane changes the
 * final value) for `iters` syscalls with `inner` back-edges after each (one
 * fragment run per syscall; inner < the 4096-unit budget keeps it one run).
 * The state is carried in the registers across the whole function: through the
 * runs, through the in-kernel syscalls in between, through every context
 * switch. Each worker computes the reference first, natively without any
 * syscall (so no fragment can run), then the same recurrence with a getppid
 * after every `inner` back-edges (in fragments when KJIT is on), and fails
 * on any difference. Stdout (worker digests in index order) is identical with
 * KJIT on and off.
 *
 *   fp_preempt [workers] [iters] [inner] [rounds]
 *
 * With debugfs neon_noise_us set, soft-hrtimer softirqs do kernel-mode NEON
 * rounds that clobber V0-V31 on every CPU meanwhile (kjit_glue.c): the
 * context-switch and softirq save/restore of the bracket must make that
 * invisible (fp-bracket.sh stress).
 */
#include <sched.h>
#include <sys/wait.h>

#include "kjit_test.h"

/* x0 = iters, x1 = inner, x2 = 8 * 16 bytes of V0-V7 in and out, x3 = svc? */
void fp_preempt_run(uint64_t iters, uint64_t inner, uint8_t *state, uint64_t do_svc);

asm(".text\n"
    ".global fp_preempt_run\n"
    ".type fp_preempt_run, %function\n"
    "fp_preempt_run:\n"
    "	ld1	{v0.16b, v1.16b, v2.16b, v3.16b}, [x2]\n"
    "	add	x7, x2, #64\n"
    "	ld1	{v4.16b, v5.16b, v6.16b, v7.16b}, [x7]\n"
    "	mov	x4, x0\n"
    "1:	cbz	x3, 2f\n"
    "	mov	x8, #173\n"		/* getppid */
    "	svc	#0\n"
    "2:	mov	x6, x1\n"
    "3:	add	v0.2d, v0.2d, v1.2d\n"
    "	eor	v2.16b, v2.16b, v0.16b\n"
    "	shl	v3.2d, v2.2d, #7\n"
    "	ushr	v4.2d, v2.2d, #3\n"
    "	orr	v3.16b, v3.16b, v4.16b\n"
    "	add	v1.2d, v1.2d, v3.2d\n"
    "	ext	v5.16b, v0.16b, v1.16b, #3\n"
    "	eor	v6.16b, v6.16b, v5.16b\n"
    "	add	v7.2d, v7.2d, v6.2d\n"
    "	eor	v0.16b, v0.16b, v7.16b\n"
    "	subs	x6, x6, #1\n"
    "	b.ne	3b\n"
    "	subs	x4, x4, #1\n"
    "	b.ne	1b\n"
    "	st1	{v0.16b, v1.16b, v2.16b, v3.16b}, [x2]\n"
    "	st1	{v4.16b, v5.16b, v6.16b, v7.16b}, [x7]\n"
    "	ret\n");

static uint64_t fnv(const uint8_t *p, size_t n)
{
	uint64_t h = 0xcbf29ce484222325ull;

	for (size_t i = 0; i < n; i++)
		h = (h ^ p[i]) * 0x100000001b3ull;
	return h;
}

static void worker(int idx, long iters, long inner, long rounds, int wfd)
{
	uint8_t a[128] __attribute__((aligned(16))), b[128] __attribute__((aligned(16)));
	uint64_t digest = 0;

	kjit_register_self();
	for (long r = 0; r < rounds; r++) {
		for (int i = 0; i < 128; i++)
			a[i] = b[i] = (uint8_t)(idx * 31 + r * 17 + i * 7 + 1);
		fp_preempt_run(iters, inner, a, 0);	/* reference: native, no syscall */
		fp_preempt_run(iters, inner, b, 1);	/* with a syscall (a fragment run) per `inner` */
		if (memcmp(a, b, sizeof(a))) {
			fprintf(stderr, "FAIL: worker %d round %ld: V state differs (ref %#llx, got %#llx)\n",
				idx, r, (unsigned long long)fnv(a, sizeof(a)),
				(unsigned long long)fnv(b, sizeof(b)));
			_exit(1);
		}
		digest ^= fnv(a, sizeof(a)) + (uint64_t)r;
	}
	if (write(wfd, &digest, sizeof(digest)) != sizeof(digest))
		_exit(2);
	_exit(0);
}

int main(int argc, char **argv)
{
	int ncpu = (int)sysconf(_SC_NPROCESSORS_ONLN);
	long workers = argc > 1 && atol(argv[1]) > 0 ? atol(argv[1]) : (ncpu < 2 ? 4 : 2 * ncpu);
	long iters = argc > 2 ? atol(argv[2]) : 2000;
	long inner = argc > 3 ? atol(argv[3]) : 3000;
	long rounds = argc > 4 ? atol(argv[4]) : 3;
	struct kjit_snap s0, s1;
	int (*pipes)[2];
	pid_t *pids;
	int failed = 0;

	if (workers < 1 || workers > 64 || iters < 1 || inner < 1 || inner > 4000 || rounds < 1)
		die("usage: fp_preempt [workers<=64] [iters] [inner<=4000] [rounds]");
	pipes = calloc(workers, sizeof(*pipes));
	pids = calloc(workers, sizeof(*pids));
	if (!pipes || !pids)
		die("calloc");
	s0 = kjit_snap();
	for (long i = 0; i < workers; i++) {
		if (pipe(pipes[i]))
			die("pipe: %s", strerror(errno));
		pids[i] = fork();
		if (pids[i] < 0)
			die("fork: %s", strerror(errno));
		if (!pids[i]) {
			close(pipes[i][0]);
			worker((int)i, iters, inner, rounds, pipes[i][1]);
		}
		close(pipes[i][1]);
	}
	for (long i = 0; i < workers; i++) {
		uint64_t digest = 0;
		int status;

		if (read(pipes[i][0], &digest, sizeof(digest)) != sizeof(digest))
			failed = 1;
		if (waitpid(pids[i], &status, 0) < 0 || !WIFEXITED(status) || WEXITSTATUS(status))
			failed = 1;
		printf("worker %ld digest=%#llx\n", i, (unsigned long long)digest);
	}
	s1 = kjit_snap();
	kjit_report("fp_preempt", s0, s1);
	if (failed)
		die("fp_preempt: a worker failed");
	if (kjit_expect("fpsimd")) {
		long long want = workers * iters * rounds;

		if ((s1.in_kernel - s0.in_kernel) * 100 < want * 90)
			die("fp_preempt: only %lld of %lld syscalls in the kernel",
			    s1.in_kernel - s0.in_kernel, want);
	}
	return 0;
}
