// SPDX-License-Identifier: GPL-2.0
/*
 * Fragments linked across mappings while the callee's mapping changes
 * (docs/journal/2026-10-02.md, "A11 contract pinned: in-fragment branch dispatch",
 * Kernel tests (A11b)). Callers run a hot loop of
 * `blr`/`ret` into a two-instruction callee that lives in its own mapping, one
 * `svc` per round, so their fragments (the loop, the callee) are entered and
 * left through the dispatch tables. Meanwhile one thread keeps changing that
 * mapping without ever making it unexecutable or writable: it replaces it
 * with an identical-effect variant from a memfd (MAP_FIXED: an atomic unmap
 * and map), flips it between exec-only and read-exec, zaps its pages
 * (MADV_DONTNEED), each followed by a request for a new translation (without
 * KJIT_AUTO; the auto mode learns it by itself). Every change retires the
 * callee's fragment (mmu_notifier), and with it the table slots that point
 * into it, while callers may be anywhere in the chain.
 *
 * Output must be identical with KJIT on and off:
 *  1. storm, for a fixed time (a count would end it before the remapper does
 *     anything, natively): every batch of calls sums to its call count whatever
 *     variant ran (both variants add 1);
 *  2. staleness: after the mapping is replaced by a variant that adds 1000, and
 *     after it is rewritten in place (mprotect RWX, store, mprotect RX) to one
 *     that adds 3000, the very next calls must run the new code: a fragment of
 *     the old text that survived its retirement would add 1.
 *
 * KJIT_EXPECT=link also checks the counters:
 *  - the storm ran fragments, retired some (invalidated_fragments) and cleared
 *    table slots that pointed into them (ibtc_clear);
 *  - needs the in-fragment dispatch (A11a): in the steady state afterwards
 *    (no storm) a round of 256 calls makes at most 4 runtime entries (the
 *    svc's resume; the callee and return transfers hit). Without dispatch it
 *    is about 512.
 *
 *   link_race [seconds] [callers]     storm length, default 2 and 3
 */
#include "kjit_test.h"
#include <pthread.h>
#include <stdatomic.h>
#include <sys/mman.h>
#include <time.h>

#define CALLS 256	/* calls per svc */
#define PAGE 4096

/* Callee variants, one page each in the memfd, in the order a, b, c, d. */
enum { VAR_A, VAR_B, VAR_C, VAR_D, VARIANTS };
#define VARIANT_LEN 8	/* two instructions */

uint64_t link_race_run(uint64_t rounds, uint64_t calls, uint64_t fn);
extern char link_race_ret[];
extern char link_race_var[VARIANTS][VARIANT_LEN];

/* x6 += k; ret. a and b have the same effect with different words. */
asm(".text\n"
    ".global link_race_run\n"
    ".type link_race_run, %function\n"
    "link_race_run:\n"
    "	mov	x9, x30\n"
    "	mov	x6, #0\n"
    "	mov	x5, x2\n"
    "	mov	x4, x0\n"
    "1:	mov	x8, #173\n"		/* getppid */
    "	svc	#0\n"
    "	mov	x3, x1\n"
    "2:	blr	x5\n"
    ".global link_race_ret\n"
    "link_race_ret:\n"
    "	subs	x3, x3, #1\n"
    "	b.ne	2b\n"
    "	subs	x4, x4, #1\n"
    "	b.ne	1b\n"
    "	mov	x0, x6\n"
    "	mov	x30, x9\n"
    "	ret\n"
    ".balign 8\n"
    ".global link_race_var\n"
    "link_race_var:\n"
    "	add	x6, x6, #1\n"		/* a */
    "	ret\n"
    "	adds	x6, x6, #1\n"		/* b: also sets the flags, which the loop's subs overwrites */
    "	ret\n"
    "	add	x6, x6, #1000\n"	/* c */
    "	ret\n"
    "	add	x6, x6, #3000\n"	/* d */
    "	ret\n");

static uint8_t *map;
static int memfd;
static atomic_int stop;		/* remapper */
static atomic_int done;		/* callers */

static void map_variant(int v)
{
	/* One call replaces the mapping atomically under the mmap lock. */
	if (mmap(map, PAGE, PROT_READ | PROT_EXEC, MAP_PRIVATE | MAP_FIXED, memfd,
		 (off_t)v * PAGE) != map)
		die("mmap variant %d: %s", v, strerror(errno));
}

static void translate_callee(void)
{
	/* A no-op in auto mode; EEXIST: already translated; others: raced, retried later. */
	if (!kjit_auto_mode())
		kjit_translate_self((uintptr_t)map);
}

/*
 * Changes the callee's mapping, one way after the other, never leaving it
 * unexecutable or writable, until told to stop.
 */
static void *remapper(void *arg)
{
	struct timespec pause = { 0, 400 * 1000 };
	unsigned int i = 0, flip = 0;

	(void)arg;
	while (!atomic_load(&stop)) {
		/* Each change is followed by a translation: fragments exist between them. */
		switch (i++ % 6) {
		case 0:
			map_variant(flip++ & 1 ? VAR_A : VAR_B);
			break;
		case 2:
			if (mprotect(map, PAGE, PROT_EXEC) || mprotect(map, PAGE, PROT_READ | PROT_EXEC))
				die("mprotect: %s", strerror(errno));
			break;
		case 4:
			if (madvise(map, PAGE, MADV_DONTNEED))
				die("madvise: %s", strerror(errno));
			break;
		default:
			translate_callee();
			break;
		}
		nanosleep(&pause, NULL);
	}
	return NULL;
}

#define STORM_BATCH 100	/* rounds per check */

static void *caller_main(void *arg)
{
	uintptr_t id = (uintptr_t)arg;

	while (!atomic_load(&done)) {
		uint64_t sum = link_race_run(STORM_BATCH, CALLS, (uintptr_t)map);

		if (sum != (uint64_t)STORM_BATCH * CALLS)
			die("link_race: storm: caller %lu: sum %llu, want %llu", (unsigned long)id,
			    (unsigned long long)sum, (unsigned long long)STORM_BATCH * CALLS);
	}
	return NULL;
}

/* Runs @rounds rounds of CALLS calls and checks the sum: every call adds @per. */
static uint64_t run_checked(const char *what, uint64_t rounds, uint64_t per)
{
	uint64_t sum = link_race_run(rounds, CALLS, (uintptr_t)map);

	if (sum != rounds * CALLS * per)
		die("link_race: %s: sum %llu, want %llu (calls added %llu each)", what,
		    (unsigned long long)sum, (unsigned long long)(rounds * CALLS * per),
		    (unsigned long long)per);
	return sum;
}

int main(int argc, char **argv)
{
	long seconds = argc > 1 ? atol(argv[1]) : 2;
	long callers = argc > 2 ? atol(argv[2]) : 3;
	long long inval0, clear0, ent0, ent1;
	struct kjit_snap s0, s1;
	pthread_t remap_thread, *threads;
	uint64_t sum;

	if (callers < 1 || seconds < 1)
		die("usage: link_race [seconds] [callers]");
	memfd = memfd_create("link_race", 0);
	if (memfd < 0 || ftruncate(memfd, (off_t)VARIANTS * PAGE))
		die("memfd: %s", strerror(errno));
	for (int v = 0; v < VARIANTS; v++)
		if (pwrite(memfd, link_race_var[v], VARIANT_LEN, (off_t)v * PAGE) != VARIANT_LEN)
			die("pwrite variant %d: %s", v, strerror(errno));
	/*
	 * The callee and the return site must not share a dispatch table main
	 * slot (pc[13:2]): the second one published would move the first into the
	 * victim part, a different steady state than this test counts. Mappings
	 * land anywhere, so retry.
	 */
	do {
		map = mmap(NULL, PAGE, PROT_READ | PROT_EXEC, MAP_PRIVATE, memfd, 0);
		if (map == MAP_FAILED)
			die("mmap: %s", strerror(errno));
	} while ((((uintptr_t)map >> 2) & 0xfff) == (((uintptr_t)link_race_ret >> 2) & 0xfff));

	kjit_register_self();
	if (!kjit_auto_mode()) {
		/* The return site is a branch target, not an SVC resume PC. */
		int err = kjit_translate_self((uintptr_t)link_race_ret);

		if (err && err != EEXIST)
			die("translate return site: %s", strerror(err));
	}
	translate_callee();

	/* 1. storm */
	s0 = kjit_snap();
	inval0 = kjit_stat("invalidated_fragments");
	clear0 = kjit_stat("ibtc_clear");
	threads = calloc(callers, sizeof(*threads));
	if (!threads)
		die("calloc");
	if (pthread_create(&remap_thread, NULL, remapper, NULL))
		die("pthread_create");
	for (long i = 0; i < callers; i++)
		if (pthread_create(&threads[i], NULL, caller_main, (void *)(uintptr_t)i))
			die("pthread_create");
	sleep(seconds);
	atomic_store(&done, 1);
	for (long i = 0; i < callers; i++)
		pthread_join(threads[i], NULL);
	atomic_store(&stop, 1);
	pthread_join(remap_thread, NULL);
	/* A caller that found a wrong sum died. */
	printf("storm: %ld callers ok\n", callers);
	s1 = kjit_snap();
	kjit_report("link_race storm", s0, s1);
	if (kjit_expect("link")) {
		long long inval = kjit_stat("invalidated_fragments") - inval0;
		long long clear = kjit_stat("ibtc_clear") - clear0;

		fprintf(stderr, "link_race: storm: entries=%lld invalidated=%lld ibtc_clear=%lld\n",
			s1.entries - s0.entries, inval, clear);
		if (s1.entries - s0.entries <= 0 || inval < 1 || clear < 1)
			die("link_race: storm: %lld entries, %lld invalidated, %lld ibtc_clear",
			    s1.entries - s0.entries, inval, clear);
	}

	/* 2. staleness: the very next calls after a change run the new code. */
	map_variant(VAR_A);
	translate_callee();
	sum = run_checked("variant a", 300, 1);
	printf("a sum %llu\n", (unsigned long long)sum);
	/* A fragment of variant a exists here (translated, or hot in auto mode). */
	map_variant(VAR_C);
	sum = run_checked("replaced by c", 300, 1000);
	printf("c sum %llu\n", (unsigned long long)sum);
	translate_callee();
	run_checked("c again", 300, 1000);
	/* A fragment of variant c exists here. */
	if (mprotect(map, PAGE, PROT_READ | PROT_WRITE | PROT_EXEC))
		die("mprotect rwx: %s", strerror(errno));
	memcpy(map, link_race_var[VAR_D], VARIANT_LEN);
	__builtin___clear_cache((char *)map, (char *)map + VARIANT_LEN);
	if (mprotect(map, PAGE, PROT_READ | PROT_EXEC))
		die("mprotect rx: %s", strerror(errno));
	sum = run_checked("rewritten to d", 300, 3000);
	printf("d sum %llu\n", (unsigned long long)sum);

	/* 3. steady state: linked runs, no changes. */
	map_variant(VAR_A);
	translate_callee();
	run_checked("steady warmup", 2000, 1);
	ent0 = kjit_stat("fragment_entries");
	sum = run_checked("steady", 2000, 1);
	ent1 = kjit_stat("fragment_entries");
	printf("steady sum %llu\n", (unsigned long long)sum);
	fprintf(stderr, "link_race: steady: %lld fragment entries for %d rounds of %d calls\n",
		ent1 - ent0, 2000, CALLS);
	if (kjit_expect("link") && ent1 - ent0 > 4 * 2000)
		die("link_race: steady: %lld fragment entries for 2000 rounds: calls are not dispatched in fragment code",
		    ent1 - ent0);
	return 0;
}
