// SPDX-License-Identifier: GPL-2.0
/*
 * The image arena (A17; docs/pipeline.md, "Image placement (A17, packed
 * arena)") under churn: slots are freed and reused while other fragments in
 * the same chunks keep running.
 *
 * WORKERS processes (separate mms, so separate kjit_mms, one shared arena) each
 * run hot loops in text pages of their own. A loop makes one static `bl` to
 * each of CALLEES callees, every one in a page of its own, then one `svc`
 * (getpid) per round. The loops (VARIANTS of them) and the callees are padded
 * with `nop`s to different lengths, so fragments of very different sizes take
 * and leave slots of different sizes, and each adds its own constant to the
 * result: a slot that holds, or overlaps, another fragment's code gives a wrong
 * sum or a crash. A second thread of each worker keeps changing random pages
 * without ever making them writable or unexecutable (exec-only <-> read-exec,
 * MADV_DONTNEED, the technique of bl_link_race.c), each change followed by a
 * request for a new translation of that page (not in auto mode, which translates
 * by itself): the change retires that worker's fragment of the page, its slot is
 * filled and released after a grace period, and the next translations take
 * the freed slots again while the other fragments of all workers run.
 *
 * Output must be identical with KJIT on and off:
 *  1. storm, for a fixed time: every round adds the loop's constant plus
 *     the callees' (1 + ... + CALLEES);
 *  2. staleness: in each worker the first callee is rewritten in place (RWX,
 *     store, RX) to add 1000 more; the very next batch of every loop must add
 *     1000 more per round. Code left in a freed slot would add something else.
 *
 * KJIT_EXPECT=arena also checks the arena: the parent (which runs no
 * translated code itself) samples arena_chunks, arena_chunks_pmd and
 * arena_bytes while the workers run and requires fragments installed and
 * retired and the arena in use, every chunk PMD-mapped (A19: the guest has
 * memory to spare, so the kernel helper's 2 MiB block always succeeds; the
 * 4 KiB fallback is a degraded path this check refuses to miss); after the
 * last worker has exited the gauges must return to 0 (the free work runs
 * after grace periods: polled, up to 30 s).
 *
 *   arena_churn [seconds] [workers]     storm length, default 3 and 4
 */
#include "kjit_test.h"
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <time.h>

#define VARIANTS 4
#define CALLEES 6
#define BATCH 256
#define CALLEE_SUM (CALLEES * (CALLEES + 1) / 2)

extern char churn_callee0[], churn_callee1[], churn_callee2[], churn_callee3[], churn_callee4[],
	    churn_callee5[];
extern char churn_page0[], churn_page1[], churn_page2[], churn_page3[];
extern char churn_resume0[], churn_resume1[], churn_resume2[], churn_resume3[];
long churn_run0(long n), churn_run1(long n), churn_run2(long n), churn_run3(long n);

/*
 * churn_runV(n): n times { bl callee0..callee5; add x2, x2, #V; nop * PAD_V;
 * getpid }; returns x2, the sum. Callee c is { add x2, x2, #c + 1; nop * PAD_c; ret }.
 * Every loop and every callee is in a page of its own, 64 KiB-aligned so that a
 * 16 KiB-page kernel's pages are apart too. The pads make the fragments 0.1 to
 * 6 KB.
 */
#define CALLEE(c, pad) \
	".p2align 16\n" \
	".globl churn_callee" #c "\n" \
	"churn_callee" #c ":\n" \
	"	add	x2, x2, #" #c "+1\n" \
	"	.rept	" #pad "\n" \
	"	nop\n" \
	"	.endr\n" \
	"	ret\n"

#define VARIANT(v, pad) \
	".p2align 16\n" \
	".globl churn_page" #v "\n" \
	"churn_page" #v ":\n" \
	".globl churn_run" #v "\n" \
	"churn_run" #v ":\n" \
	"	stp	x29, x30, [sp, #-16]!\n" \
	"	mov	x9, x0\n" \
	"	mov	x2, #0\n" \
	"1:	bl	churn_callee0\n" \
	"	bl	churn_callee1\n" \
	"	bl	churn_callee2\n" \
	"	bl	churn_callee3\n" \
	"	bl	churn_callee4\n" \
	"	bl	churn_callee5\n" \
	"	add	x2, x2, #" #v "\n" \
	"	.rept	" #pad "\n" \
	"	nop\n" \
	"	.endr\n" \
	"	mov	x8, #172\n"	/* getpid */ \
	"	svc	#0\n" \
	".globl churn_resume" #v "\n" \
	"churn_resume" #v ":\n" \
	"	subs	x9, x9, #1\n" \
	"	b.ne	1b\n" \
	"	mov	x0, x2\n" \
	"	ldp	x29, x30, [sp], #16\n" \
	"	ret\n"

asm(".text\n"
    CALLEE(0, 0)
    CALLEE(1, 5)
    CALLEE(2, 12)
    CALLEE(3, 25)
    CALLEE(4, 60)
    CALLEE(5, 130)
    VARIANT(0, 0)
    VARIANT(1, 30)
    VARIANT(2, 200)
    VARIANT(3, 1500)
    ".p2align 16\n");

/* add x2, x2, #imm (llvm-mc) */
#define ADD_X2(imm) (0x91000042U | ((uint32_t)(imm) << 10))

static long (*const run[VARIANTS])(long) = { churn_run0, churn_run1, churn_run2, churn_run3 };
static char *const loop_page[VARIANTS] = { churn_page0, churn_page1, churn_page2, churn_page3 };
static char *const resume[VARIANTS] = { churn_resume0, churn_resume1, churn_resume2,
					churn_resume3 };
static char *const callee[CALLEES] = { churn_callee0, churn_callee1, churn_callee2, churn_callee3,
				       churn_callee4, churn_callee5 };

static atomic_int stop;
static long page_size;
static int worker_id;

static void set_prot(char *p, int prot)
{
	if (mprotect(p, page_size, prot))
		die("mprotect %p: %s", p, strerror(errno));
}

/* A no-op in auto mode; errors: already translated, or raced and retried later. */
static void translate(void *pc)
{
	if (!kjit_auto_mode())
		kjit_translate_self((uintptr_t)pc);
}

/* Every round of loop @v adds v + CALLEE_SUM + @extra. */
static void check_batch(const char *what, int v, long extra)
{
	long want = BATCH * (v + CALLEE_SUM + extra), sum = run[v](BATCH);

	if (sum != want)
		die("arena_churn: worker %d: %s: loop %d: sum %ld, want %ld", worker_id, what, v, sum,
		    want);
}

/* Page @i: the loops first, then the callees. Its entry: what a retired fragment of it is translated from. */
static char *page_of(unsigned int i)
{
	return i < VARIANTS ? loop_page[i] : callee[i - VARIANTS];
}

static char *entry_of(unsigned int i)
{
	return i < VARIANTS ? resume[i] : callee[i - VARIANTS];
}

/* Changes a random page of this worker, then asks for the translation it retired. */
static void *flipper(void *arg)
{
	struct timespec pause = { 0, 300 * 1000 };
	uint32_t x = 2463534242u + worker_id;

	(void)arg;
	while (!atomic_load(&stop)) {
		unsigned int i;

		x ^= x << 13;
		x ^= x >> 17;
		x ^= x << 5;
		i = (x >> 8) % (VARIANTS + CALLEES);
		if (x % 4) {
			set_prot(page_of(i), PROT_EXEC);
			set_prot(page_of(i), PROT_READ | PROT_EXEC);
		} else if (madvise(page_of(i), page_size, MADV_DONTNEED)) {
			die("madvise: %s", strerror(errno));
		}
		translate(entry_of(i));
		nanosleep(&pause, NULL);
	}
	return NULL;
}

/* Callee 0 adds 1 + @more. */
static void set_callee0(uint32_t more)
{
	set_prot(callee[0], PROT_READ | PROT_WRITE | PROT_EXEC);
	*(volatile uint32_t *)callee[0] = ADD_X2(1 + more);
	__builtin___clear_cache(callee[0], callee[0] + 4);
	set_prot(callee[0], PROT_READ | PROT_EXEC);
}

static void translate_all(void)
{
	for (unsigned int i = 0; i < VARIANTS + CALLEES; i++)
		translate(entry_of(i));
}

/* One worker process: storm for @seconds, then the staleness check. Exits. */
static void worker(int id, long seconds)
{
	struct timespec t0, t;
	pthread_t flip_thread;
	long rounds = 0;

	worker_id = id;
	kjit_register_self();
	translate_all();
	for (int i = 0; i < 100; i++)
		for (int v = 0; v < VARIANTS; v++)
			check_batch("warm-up", v, 0);

	if (pthread_create(&flip_thread, NULL, flipper, NULL))
		die("pthread_create");
	clock_gettime(CLOCK_MONOTONIC, &t0);
	do {
		/* Every loop gets the CPU in turn, whichever fragments exist. */
		check_batch("storm", (id + rounds++) % VARIANTS, 0);
		clock_gettime(CLOCK_MONOTONIC, &t);
	} while (t.tv_sec - t0.tv_sec < seconds);
	atomic_store(&stop, 1);
	pthread_join(flip_thread, NULL);
	fprintf(stderr, "arena_churn: worker %d: %ld storm batches\n", id, rounds);

	/* Staleness: rewrite a callee in place, the next batch of each loop must see it. */
	translate_all();
	for (int v = 0; v < VARIANTS; v++)
		check_batch("before rewrite", v, 0);
	set_callee0(1000);
	for (int v = 0; v < VARIANTS; v++)
		check_batch("rewritten", v, 1000);
	for (int i = 0; i < 100; i++)
		for (int v = 0; v < VARIANTS; v++)
			check_batch("rewritten", v, 1000);
	set_callee0(0);
	translate_all();
	for (int i = 0; i < 100; i++)
		for (int v = 0; v < VARIANTS; v++)
			check_batch("steady", v, 0);
	exit(0);
}

static void sleep_ms(long ms)
{
	struct timespec ts = { ms / 1000, (ms % 1000) * 1000000L };

	nanosleep(&ts, NULL);
}

struct arena_gauges {
	long long chunks, pmd, bytes;
};

/* The three gauges from one read of the stats file, so they are one snapshot of the write side's counters. */
static struct arena_gauges arena_gauges(void)
{
	struct arena_gauges g = { -1, -1, -1 };
	char line[128], key[64];
	long long value;
	FILE *f = fopen(KJIT_DEBUGFS "/stats", "r");

	if (!f)
		die("open stats: %s", strerror(errno));
	while (fgets(line, sizeof(line), f)) {
		if (sscanf(line, "%63s %lld", key, &value) != 2)
			continue;
		if (!strcmp(key, "arena_chunks"))
			g.chunks = value;
		else if (!strcmp(key, "arena_chunks_pmd"))
			g.pmd = value;
		else if (!strcmp(key, "arena_bytes"))
			g.bytes = value;
	}
	fclose(f);
	if (g.chunks < 0 || g.pmd < 0 || g.bytes < 0)
		die("arena_churn: an arena gauge is missing from the stats file");
	return g;
}

int main(int argc, char **argv)
{
	long seconds = argc > 1 ? atol(argv[1]) : 3;
	long workers = argc > 2 ? atol(argv[2]) : 4;
	long long installs0 = 0, invalidated0 = 0, peak_bytes = 0, peak_chunks = 0, prev_chunks = 0,
		  pmd_checked = 0;
	bool arena = kjit_expect("arena");
	pid_t *pids;
	long alive;

	if (workers < 1 || seconds < 1)
		die("usage: arena_churn [seconds] [workers]");
	page_size = sysconf(_SC_PAGESIZE);
	/* Every loop and callee in a page of its own: a change to one retires only its fragment. */
	for (unsigned int i = 0; i < VARIANTS + CALLEES; i++) {
		if ((uintptr_t)page_of(i) % page_size)
			die("layout: page %u at %p is not page-aligned", i, page_of(i));
		for (unsigned int j = 0; j < i; j++)
			if (labs(page_of(i) - page_of(j)) < page_size)
				die("layout: pages %u and %u overlap", j, i);
	}
	if (*(volatile uint32_t *)callee[0] != ADD_X2(1))
		die("callee 0 word %#x, want %#x", *(volatile uint32_t *)callee[0], ADD_X2(1));

	if (arena) {
		installs0 = kjit_stat("translate_ok");
		invalidated0 = kjit_stat("invalidated_fragments");
	}
	pids = calloc(workers, sizeof(*pids));
	if (!pids)
		die("calloc");
	/*
	 * No kjit_register_self() here: the parent must hold no fragment, so that
	 * the arena is empty again once the workers are gone.
	 */
	for (long i = 0; i < workers; i++) {
		pids[i] = fork();
		if (pids[i] < 0)
			die("fork: %s", strerror(errno));
		if (!pids[i])
			worker((int)i, seconds);
	}
	for (alive = workers; alive;) {
		for (long i = 0; i < workers; i++) {
			int status;
			pid_t r;

			if (!pids[i])
				continue;
			r = waitpid(pids[i], &status, WNOHANG);
			if (r < 0)
				die("waitpid: %s", strerror(errno));
			if (!r)
				continue;
			if (!WIFEXITED(status) || WEXITSTATUS(status))
				die("arena_churn: worker %ld failed (status %#x)", i, status);
			pids[i] = 0;
			alive--;
		}
		if (arena) {
			struct arena_gauges g = arena_gauges();

			peak_bytes = g.bytes > peak_bytes ? g.bytes : peak_bytes;
			peak_chunks = g.chunks > peak_chunks ? g.chunks : peak_chunks;
			/*
			 * A chunk is counted in arena_chunks and in arena_chunks_pmd by two
			 * increments under one lock; a snapshot taken between them is
			 * skipped by requiring the chunk count to be the same as 20 ms ago.
			 */
			if (g.chunks && g.chunks == prev_chunks) {
				if (g.pmd != g.chunks)
					die("arena_churn: arena_chunks=%lld but arena_chunks_pmd=%lld: a chunk is not PMD-mapped",
					    g.chunks, g.pmd);
				pmd_checked++;
			}
			prev_chunks = g.chunks;
		}
		sleep_ms(20);
	}
	printf("storm: %ld workers ok\n", workers);
	printf("rewritten: ok\n");

	if (arena) {
		long long installs = kjit_stat("translate_ok") - installs0;
		long long invalidated = kjit_stat("invalidated_fragments") - invalidated0;
		struct arena_gauges g = { -1, -1, -1 };
		long long bytes, chunks;

		/* The slots of the last fragments are released after a grace period. */
		for (int i = 0; i < 300; i++) {
			g = arena_gauges();
			if (!g.bytes && !g.chunks && !g.pmd)
				break;
			sleep_ms(100);
		}
		bytes = g.bytes;
		chunks = g.chunks;
		fprintf(stderr,
			"arena_churn: installs=%lld invalidated=%lld peak arena_bytes=%lld peak arena_chunks=%lld pmd-checked samples=%lld after exit: arena_bytes=%lld arena_chunks=%lld arena_chunks_pmd=%lld\n",
			installs, invalidated, peak_bytes, peak_chunks, pmd_checked, bytes, chunks, g.pmd);
		if (installs < 100 || invalidated < 100)
			die("arena_churn: only %lld installs and %lld invalidations: no churn", installs,
			    invalidated);
		if (peak_bytes < 1 || peak_chunks < 1)
			die("arena_churn: the arena was never seen in use");
		if (!pmd_checked)
			die("arena_churn: no stable sample of the arena saw arena_chunks_pmd");
		if (bytes || chunks || g.pmd)
			die("arena_churn: arena_bytes=%lld arena_chunks=%lld arena_chunks_pmd=%lld 30 s after the last worker exited, want 0",
			    bytes, chunks, g.pmd);
	}
	printf("done\n");
	return 0;
}
