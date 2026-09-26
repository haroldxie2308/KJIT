// SPDX-License-Identifier: GPL-2.0
/*
 * Keeps KJIT's auto mode busy with new work, for module unload/reload while
 * translations are queued or running: each thread repeatedly copies a small
 * syscall loop into a fresh RX mapping (at a varying offset, so the PCs are
 * new), runs it for `iters` iterations (past the hot threshold, so a
 * translation request is queued and then used), and unmaps it (which
 * invalidates the fragment). Runs until killed; prints nothing.
 *
 *   jit_churn [threads] [iters]    default 4, 200
 */
#include "kjit_test.h"
#include <pthread.h>
#include <sys/mman.h>

extern char churn_start[], churn_end[];
/* x0 = iterations: getpid() x0 times. */
asm(".text\n"
    ".p2align 2\n"
    ".globl churn_start\n"
    "churn_start:\n"
    "	mov	x9, x0\n"
    "1:	mov	x8, #172\n"		/* getpid */
    "	svc	#0\n"
    "	subs	x9, x9, #1\n"
    "	b.ne	1b\n"
    "	ret\n"
    ".globl churn_end\n"
    "churn_end:\n");

static long iters;

static void *churn(void *arg)
{
	size_t len = churn_end - churn_start;
	unsigned long round;

	for (round = (unsigned long)arg;; round++) {
		size_t off = (round * 64) % (4096 - 64);
		char *page = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
				  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

		if (page == MAP_FAILED)
			die("mmap: %s", strerror(errno));
		memcpy(page + off, churn_start, len);
		__builtin___clear_cache(page + off, page + off + len);
		if (mprotect(page, 4096, PROT_READ | PROT_EXEC))
			die("mprotect: %s", strerror(errno));
		((void (*)(long))(page + off))(iters);
		if (munmap(page, 4096))
			die("munmap: %s", strerror(errno));
	}
	return NULL;
}

int main(int argc, char **argv)
{
	long threads = argc > 1 ? atol(argv[1]) : 4, i;
	pthread_t t;

	iters = argc > 2 ? atol(argv[2]) : 200;
	for (i = 1; i < threads; i++)
		if (pthread_create(&t, NULL, churn, (void *)(i * 7)))
			die("pthread_create");
	churn(NULL);
	return 0;
}
