// SPDX-License-Identifier: GPL-2.0
/*
 * Direct BL links (A16; docs/pipeline.md, "Direct BL links (A16, kernel side)")
 * under concurrent retirement.
 *
 * Callers run a hot loop in their own text page: a static `bl` to a callee in
 * another text page, then one `svc` (getpid) per call, so the loop's fragment F
 * has a linkable BL site whose target is the callee's fragment G. While they
 * run, one thread keeps changing the two pages without ever making them
 * writable or unexecutable (exec-only <-> read-exec, MADV_DONTNEED), each
 * change followed by a request for a new translation (not in auto mode, which
 * translates by itself):
 *  - a change to the callee page retires G only (F's source span is the other
 *    page): G's retirement must restore F's linked slot while callers may be on
 *    the `b` into G, and the next translation of G must link F's pending site;
 *  - a change to the caller page retires F only: F's own sites leave G's
 *    incoming list, and G stays live for the new F.
 *
 * Output must be identical with KJIT on and off:
 *  1. storm, for a fixed time: every batch of calls adds 1 per call;
 *  2. staleness: the callee is rewritten in place (RWX, store, RX) to add 1000;
 *     the very next batch must add 1000 per call. A `b` into the old G that
 *     survived G's retirement would add 1.
 *
 * KJIT_EXPECT=bl_link also checks the counters: the storm made links and
 * restored some, and in the steady state afterwards a site is linked.
 *
 *   bl_link_race [seconds] [callers]     storm length, default 3 and 3
 */
#include "kjit_test.h"
#include <pthread.h>
#include <stdatomic.h>
#include <sys/mman.h>
#include <time.h>

extern char bl_callee_page[], bl_callee_add[], bl_caller_page[], bl_resume[];
long bl_run(long n);

/*
 * bl_run(n): n times { bl callee; getpid }; returns the sum the callee built in
 * x2. The callee and the loop are in different pages, 4 KiB-aligned; the 64 KiB
 * alignment of the pair keeps a 16 KiB-page kernel's pages apart too.
 */
asm(".text\n"
    ".p2align 16\n"
    ".globl bl_callee_page\n"
    "bl_callee_page:\n"
    ".globl bl_callee_add\n"
    "bl_callee_add:\n"
    "	add	x2, x2, #1\n"
    "	ret\n"
    ".p2align 16\n"
    ".globl bl_caller_page\n"
    "bl_caller_page:\n"
    ".globl bl_run\n"
    "bl_run:\n"
    "	stp	x29, x30, [sp, #-16]!\n"
    "	mov	x9, x0\n"
    "	mov	x2, #0\n"
    "1:	bl	bl_callee_add\n"
    "	mov	x8, #172\n"		/* getpid */
    "	svc	#0\n"
    ".globl bl_resume\n"
    "bl_resume:\n"
    "	subs	x9, x9, #1\n"
    "	b.ne	1b\n"
    "	mov	x0, x2\n"
    "	ldp	x29, x30, [sp], #16\n"
    "	ret\n"
    ".p2align 16\n");

#define ADD_X2_1 0x91000442U	/* add x2, x2, #1    (llvm-mc) */
#define ADD_X2_1000 0x910fa042U	/* add x2, x2, #1000 (llvm-mc) */
#define BATCH 256
#define STORM_BATCH 20		/* batches per check */

static atomic_int stop;
static long page_size;

static void set_prot(char *page, int prot)
{
	if (mprotect(page, page_size, prot))
		die("mprotect %p: %s", page, strerror(errno));
}

/* A no-op in auto mode; errors: already translated, or raced and retried later. */
static void translate(void *pc)
{
	if (!kjit_auto_mode())
		kjit_translate_self((uintptr_t)pc);
}

static void *flipper(void *arg)
{
	struct timespec pause = { 0, 300 * 1000 };
	unsigned int i = 0;

	(void)arg;
	while (!atomic_load(&stop)) {
		switch (i++ % 6) {
		case 0:
			set_prot(bl_callee_page, PROT_EXEC);
			set_prot(bl_callee_page, PROT_READ | PROT_EXEC);
			break;
		case 1:
			translate(bl_callee_add);
			break;
		case 2:
			set_prot(bl_caller_page, PROT_EXEC);
			set_prot(bl_caller_page, PROT_READ | PROT_EXEC);
			break;
		case 3:
			translate(bl_resume);
			break;
		case 4:
			if (madvise(bl_callee_page, page_size, MADV_DONTNEED))
				die("madvise: %s", strerror(errno));
			break;
		default:
			translate(bl_callee_add);
			translate(bl_resume);
			break;
		}
		nanosleep(&pause, NULL);
	}
	return NULL;
}

static atomic_int done;

static void *caller_main(void *arg)
{
	uintptr_t id = (uintptr_t)arg;

	while (!atomic_load(&done)) {
		long sum = bl_run((long)STORM_BATCH * BATCH);

		if (sum != (long)STORM_BATCH * BATCH)
			die("bl_link_race: storm: caller %lu: sum %ld, want %ld", (unsigned long)id,
			    sum, (long)STORM_BATCH * BATCH);
	}
	return NULL;
}

static void run_checked(const char *what, long batches, long per)
{
	for (long i = 0; i < batches; i++) {
		long sum = bl_run(BATCH);

		if (sum != BATCH * per)
			die("bl_link_race: %s: batch %ld: sum %ld, want %ld", what, i, sum,
			    BATCH * per);
	}
}

int main(int argc, char **argv)
{
	long seconds = argc > 1 ? atol(argv[1]) : 3;
	long callers = argc > 2 ? atol(argv[2]) : 3;
	long long made0, restored0;
	pthread_t flip_thread, *threads;
	long sum;

	if (callers < 1 || seconds < 1)
		die("usage: bl_link_race [seconds] [callers]");
	page_size = sysconf(_SC_PAGESIZE);
	if ((uintptr_t)bl_callee_page % page_size || bl_caller_page - bl_callee_page < page_size)
		die("layout: callee page %p, caller page %p", bl_callee_page, bl_caller_page);
	if (*(volatile uint32_t *)bl_callee_add != ADD_X2_1)
		die("callee word %#x, want %#x", *(volatile uint32_t *)bl_callee_add, ADD_X2_1);

	kjit_register_self();
	translate(bl_callee_add);
	/* Warm-up: the loop and the callee are translated and linked. */
	run_checked("warm-up", 200, 1);

	made0 = kjit_stat("link_made");
	restored0 = kjit_stat("link_restored");
	threads = calloc(callers, sizeof(*threads));
	if (!threads)
		die("calloc");
	if (pthread_create(&flip_thread, NULL, flipper, NULL))
		die("pthread_create");
	for (long i = 0; i < callers; i++)
		if (pthread_create(&threads[i], NULL, caller_main, (void *)(uintptr_t)i))
			die("pthread_create");
	sleep(seconds);
	atomic_store(&done, 1);
	for (long i = 0; i < callers; i++)
		pthread_join(threads[i], NULL);
	atomic_store(&stop, 1);
	pthread_join(flip_thread, NULL);
	/* A caller that found a wrong sum died. */
	printf("storm: %ld callers ok\n", callers);
	if (kjit_expect("bl_link")) {
		long long made = kjit_stat("link_made") - made0;
		long long restored = kjit_stat("link_restored") - restored0;

		fprintf(stderr, "bl_link_race: storm: link_made=%lld link_restored=%lld\n", made,
			restored);
		if (made < 1 || restored < 1)
			die("bl_link_race: storm: %lld links made, %lld restored", made, restored);
	}

	/* Staleness: rewrite the callee in place, the next batch must see it. */
	translate(bl_callee_add);
	translate(bl_resume);
	run_checked("before rewrite", 50, 1);
	set_prot(bl_callee_page, PROT_READ | PROT_WRITE | PROT_EXEC);
	*(volatile uint32_t *)bl_callee_add = ADD_X2_1000;
	__builtin___clear_cache(bl_callee_add, bl_callee_add + 4);
	set_prot(bl_callee_page, PROT_READ | PROT_EXEC);
	sum = bl_run(BATCH);
	printf("rewritten: sum %ld (want %d)\n", sum, 1000 * BATCH);
	if (sum != 1000 * BATCH)
		die("bl_link_race: rewritten: sum %ld, want %d", sum, 1000 * BATCH);
	run_checked("rewritten", 200, 1000);

	/* Steady state: translated again, a site is linked. */
	set_prot(bl_callee_page, PROT_READ | PROT_WRITE | PROT_EXEC);
	*(volatile uint32_t *)bl_callee_add = ADD_X2_1;
	__builtin___clear_cache(bl_callee_add, bl_callee_add + 4);
	set_prot(bl_callee_page, PROT_READ | PROT_EXEC);
	translate(bl_callee_add);
	translate(bl_resume);
	run_checked("steady", 400, 1);
	if (kjit_expect("bl_link")) {
		long long linked = kjit_stat("link_sites_linked");

		fprintf(stderr, "bl_link_race: steady: link_sites_linked=%lld\n", linked);
		if (linked < 1)
			die("bl_link_race: steady: no site is linked");
	}
	printf("done\n");
	return 0;
}
