// SPDX-License-Identifier: GPL-2.0
/*
 * Fragments that take user-access faults while the module is unloaded
 * (tmp/pipeline.md, "Unload race"; kernel-patches/0006). Each thread loops
 * forever over a fresh anonymous region, so every store is a first touch:
 *
 *   gpr  after a raw svc getppid, `pages` calls (bl/ret) of a callee that
 *        stores to the next fresh page. The chain makes up to chain_budget
 *        entries in one hook call, and every callee entry demand-pages its
 *        page inside the fragment (page faults are enabled there): a hook
 *        call that is in flight for many faults.
 *   fp   after a raw svc getppid, one call of a callee that stores with st1
 *        to the next fresh page: an FP/SIMD fragment, run with page faults
 *        disabled, so the first touch leaves through its Mem stub (the
 *        fault that hit the race).
 *
 * Both fixups need the fragment exception table (patch 0002) until the hook
 * call has returned. Even threads run gpr, odd ones fp. Every page's first
 * word is checked after its region is done. Runs until killed; prints
 * nothing. Auto mode (the runner's insmod auto=1) translates the hot code.
 *
 *   unload_fault [threads]    default 4
 */
#include "kjit_test.h"
#include <pthread.h>
#include <sys/mman.h>

#define PAGES 256	/* per svc in gpr mode: 512 chain entries */
#define ROUNDS 4	/* svc rounds per region */
#define REGION (PAGES * ROUNDS)

/* x0 = first page, x1 = pages, x2 = value: stores x2 to each page's first word. */
void unload_fault_gpr(uint8_t *area, uint64_t pages, uint64_t val);
/* Same with st1 {v0.2d}, one page per svc. */
void unload_fault_fp(uint8_t *area, uint64_t pages, uint64_t val);

asm(".text\n"
    ".global unload_fault_gpr\n"
    ".type unload_fault_gpr, %function\n"
    "unload_fault_gpr:\n"
    "	mov	x10, x30\n"
    "	mov	x9, x0\n"
    "	mov	x6, x2\n"
    "	mov	x8, #173\n"		/* getppid */
    "	svc	#0\n"
    "	mov	x3, x1\n"
    "1:	bl	unload_fault_gpr_callee\n"
    "	subs	x3, x3, #1\n"
    "	b.ne	1b\n"
    "	mov	x30, x10\n"
    "	ret\n"
    "unload_fault_gpr_callee:\n"
    "	str	x6, [x9]\n"
    "	add	x9, x9, #4096\n"
    "	ret\n"
    ".global unload_fault_fp\n"
    ".type unload_fault_fp, %function\n"
    "unload_fault_fp:\n"
    "	mov	x10, x30\n"
    "	mov	x9, x0\n"
    "	mov	x3, x1\n"
    "	dup	v0.2d, x2\n"
    "1:	mov	x8, #173\n"		/* getppid */
    "	svc	#0\n"
    "	bl	unload_fault_fp_callee\n"
    "	subs	x3, x3, #1\n"
    "	b.ne	1b\n"
    "	mov	x30, x10\n"
    "	ret\n"
    "unload_fault_fp_callee:\n"
    "	st1	{v0.2d}, [x9]\n"
    "	add	x9, x9, #4096\n"
    "	ret\n");

static void *worker(void *arg)
{
	int fp = (uintptr_t)arg & 1;

	for (uint64_t round = 1;; round++) {
		uint8_t *area = mmap(NULL, REGION * 4096UL, PROT_READ | PROT_WRITE,
				     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

		if (area == MAP_FAILED)
			die("mmap: %s", strerror(errno));
		for (int r = 0; r < ROUNDS; r++) {
			uint8_t *p = area + (size_t)r * PAGES * 4096;

			if (fp)
				unload_fault_fp(p, PAGES, round);
			else
				unload_fault_gpr(p, PAGES, round);
		}
		for (int i = 0; i < REGION; i++)
			if (*(uint64_t *)(area + (size_t)i * 4096) != round)
				die("unload_fault: %s page %d: %#llx, want %#llx", fp ? "fp" : "gpr", i,
				    (unsigned long long)*(uint64_t *)(area + (size_t)i * 4096),
				    (unsigned long long)round);
		if (munmap(area, REGION * 4096UL))
			die("munmap: %s", strerror(errno));
	}
	return NULL;
}

int main(int argc, char **argv)
{
	long threads = argc > 1 ? atol(argv[1]) : 4;
	pthread_t t;

	for (long i = 1; i < threads; i++)
		if (pthread_create(&t, NULL, worker, (void *)(uintptr_t)i))
			die("pthread_create");
	worker((void *)0);
	return 0;
}
