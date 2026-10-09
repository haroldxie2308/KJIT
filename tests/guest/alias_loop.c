// SPDX-License-Identifier: GPL-2.0
/*
 * Transfers that always miss the dispatch table (docs/journal/2026-10-02.md,
 * "A11 contract pinned: in-fragment branch dispatch", Kernel tests (A11b)): one
 * `blr x5` rotating over three callees 4 MiB apart. A dispatch table has a main
 * slot (pc[13:2]) and a victim slot (pc[9:2] ^ pc[21:14], A11c) per pc, and pcs
 * 4 MiB apart share both. Two such pcs stay resident (one per slot); the third,
 * visited round-robin, is always the one that is not: publishing it moves the
 * main slot's record to the shared victim slot, dropping the record there, so the
 * transfer to the dropped one misses again, and so on (ibtc_replace). Every blr
 * therefore goes through the runtime, which chains into the callee's fragment
 * (the return transfer, always to the same site, may hit). A hook call chains
 * until it has made chain_budget fragment entries, userspace resumes at the next
 * branch target and finishes the loop natively until the next svc. The loop
 * cannot keep a task in the kernel beyond the chain budget.
 *
 * (With two callees 16 KiB apart the victim part keeps both resident and every
 * transfer hits: that is what the harness's dispatch_alias.s asserts.)
 *
 * KJIT_EXPECT=alias:
 *  - every outer iteration hits the chain budget (chain_cap), unless a run
 *    condition ended its hook call first (run_declined: a timer tick's
 *    need_resched, say);
 *  - no hook call made more entries than chain_budget (chain_max);
 *  - the ping-pong replaced slot records (ibtc_replace), about one per blr.
 *
 *   alias_loop [outer] [calls]     outer 0 = forever (kill test)
 */
#include "kjit_test.h"

void alias_loop_run(uint64_t outer, uint64_t calls, uint64_t *acc);
extern char alias_loop_callee_a[], alias_loop_callee_b[], alias_loop_callee_c[],
	alias_loop_ret[];

/* The callees' spacing: equal pc[21:2], so one main slot and one victim slot. */
#define CALLEE_SPACING (4UL << 20)

/*
 * The callees sit on 4 MiB boundaries, one boundary apart: the same main and
 * victim slot. The return site after the blr is a fourth PC.
 */
asm(".text\n"
    ".global alias_loop_run\n"
    ".type alias_loop_run, %function\n"
    "alias_loop_run:\n"
    "	mov	x9, x30\n"
    "	mov	x4, x0\n"
    "	ldr	x6, [x2]\n"
    "	adrp	x5, alias_loop_callee_a\n"		/* adr reaches 1 MiB only */
    "	add	x5, x5, :lo12:alias_loop_callee_a\n"
    "	adrp	x7, alias_loop_callee_b\n"
    "	add	x7, x7, :lo12:alias_loop_callee_b\n"
    "	adrp	x10, alias_loop_callee_c\n"
    "	add	x10, x10, :lo12:alias_loop_callee_c\n"
    "1:	mov	x8, #173\n"			/* getppid */
    "	svc	#0\n"
    "	mov	x3, x1\n"
    "2:	blr	x5\n"
    ".global alias_loop_ret\n"
    "alias_loop_ret:\n"
    "	mov	x11, x5\n"			/* rotate a -> b -> c -> a */
    "	mov	x5, x7\n"
    "	mov	x7, x10\n"
    "	mov	x10, x11\n"
    "	subs	x3, x3, #1\n"
    "	b.ne	2b\n"
    "	subs	x4, x4, #1\n"
    "	b.ne	1b\n"
    "	str	x6, [x2]\n"
    "	mov	x30, x9\n"
    "	ret\n"
    ".p2align 22\n"
    ".global alias_loop_callee_a\n"
    "alias_loop_callee_a:\n"
    "	add	x6, x6, #1\n"
    "	ret\n"
    ".p2align 22\n"
    ".global alias_loop_callee_b\n"
    "alias_loop_callee_b:\n"
    "	add	x6, x6, #2\n"
    "	ret\n"
    ".p2align 22\n"
    ".global alias_loop_callee_c\n"
    "alias_loop_callee_c:\n"
    "	add	x6, x6, #3\n"
    "	ret\n");

static long long read_debugfs_ll(const char *file)
{
	char path[128], line[32];
	FILE *f;

	snprintf(path, sizeof(path), KJIT_DEBUGFS "/%s", file);
	f = fopen(path, "r");
	if (!f || !fgets(line, sizeof(line), f))
		die("read %s: %s", path, strerror(errno));
	fclose(f);
	return atoll(line);
}

int main(int argc, char **argv)
{
	long outer = argc > 1 ? atol(argv[1]) : 2000;
	long calls = argc > 2 ? atol(argv[2]) : 5000;
	uint64_t a = (uintptr_t)alias_loop_callee_a, b = (uintptr_t)alias_loop_callee_b;
	uint64_t c = (uintptr_t)alias_loop_callee_c;
	long long cap0, cap1, dec0, dec1, rep0, rep1, budget, max;
	uint64_t acc = 0;
	struct kjit_snap s0, s1;
	int err;

	/*
	 * The whole point: one main slot and one victim slot (pc[13:2] and
	 * pc[9:2] ^ pc[21:14]) for all three.
	 */
	if (b != a + CALLEE_SPACING || c != b + CALLEE_SPACING)
		die("alias_loop: callees at %#llx, %#llx and %#llx are not %#lx apart",
		    (unsigned long long)a, (unsigned long long)b, (unsigned long long)c,
		    CALLEE_SPACING);

	kjit_register_self();
	if (!kjit_auto_mode()) {
		/* The callees and the return site are branch targets, not SVC resume PCs. */
		const uint64_t targets[] = { a, b, c, (uintptr_t)alias_loop_ret };

		for (unsigned int i = 0; i < sizeof(targets) / sizeof(targets[0]); i++) {
			err = kjit_translate_self(targets[i]);
			if (err && err != EEXIST)
				die("translate %#llx: %s", (unsigned long long)targets[i], strerror(err));
		}
	}
	s0 = kjit_snap();
	cap0 = kjit_stat("chain_cap");
	dec0 = kjit_stat("run_declined");
	rep0 = kjit_stat("ibtc_replace");
	alias_loop_run(outer, calls, &acc);
	cap1 = kjit_stat("chain_cap");
	dec1 = kjit_stat("run_declined");
	rep1 = kjit_stat("ibtc_replace");
	s1 = kjit_snap();
	kjit_report("alias_loop", s0, s1);
	printf("alias_loop outer=%ld calls=%ld acc=%llu\n", outer, calls, (unsigned long long)acc);
	if (kjit_expect("alias")) {
		budget = read_debugfs_ll("chain_budget");
		max = kjit_stat("chain_max");
		fprintf(stderr, "alias_loop: chain_cap=%lld run_declined=%lld chain_max=%lld chain_budget=%lld ibtc_replace=%lld\n",
			cap1 - cap0, dec1 - dec0, max, budget, rep1 - rep0);
		/* One miss (one chained entry) per call at least: more calls than the budget. */
		if (calls <= budget)
			die("alias_loop: %ld calls per svc do not exceed chain_budget %lld", calls, budget);
		/*
		 * Auto mode learns the three callees, then the return site: four
		 * warmups. run_declined is global: another task's declined hook calls
		 * only loosen this bound, they cannot fail it.
		 */
		if (cap1 - cap0 + dec1 - dec0 < outer - 4 * kjit_auto_warmup())
			die("alias_loop: %lld chain_cap + %lld run_declined for %ld outer iterations",
			    cap1 - cap0, dec1 - dec0, outer);
		if (max > budget)
			die("alias_loop: a hook call made %lld entries, chain_budget is %lld", max, budget);
		/*
		 * A hook call that reached the budget made about budget / 2 blr
		 * misses at least (A10: blr and ret each one entry; A11: the ret
		 * hits, so one entry per blr), each replacing a callee's record in the
		 * shared main slot.
		 */
		if (rep1 - rep0 < (cap1 - cap0) * (budget / 4))
			die("alias_loop: %lld ibtc_replace for %lld budget-capped hook calls of %lld entries",
			    rep1 - rep0, cap1 - cap0, budget);
	}
	return 0;
}
