// SPDX-License-Identifier: GPL-2.0
/*
 * A11 dispatch budget: after a raw svc getppid, a CPU-bound loop of `calls`
 * function calls (bl/ret) and no syscall. Every bl, ret and the loop's
 * back-edge costs one unit of the back-edge budget (KJIT_BACKEDGE_BUDGET,
 * 4096, per run), also when the transfer is dispatched inside fragment code
 * and never reaches the runtime. So one run cannot outlast the budget: it
 * leaves through a Budget exit, userspace resumes at the branch that found
 * the budget empty and finishes the loop natively until the next svc. The
 * loop cannot keep a task in the kernel. KJIT_EXPECT=dispatch: every outer
 * iteration ends in a Budget exit (exit_budget), unless a run condition ended
 * its hook call first (run_declined: a timer tick's need_resched, say).
 * Before A11 the same loop hit chain_budget instead (chain_cap); that check,
 * which needs transfers that always miss, is alias_loop's.
 *
 * Needs the in-fragment dispatch (A11a): the Budget exits only happen when
 * bl/ret hit the dispatch tables.
 *
 *   call_loop [outer] [calls]     outer 0 = forever (kill test)
 */
#include "kjit_test.h"

/* shared/abi: KJIT_BACKEDGE_BUDGET, the units one run may spend. */
#define BACKEDGE_BUDGET 4096

void call_loop_run(uint64_t outer, uint64_t calls, uint64_t *acc);
extern char call_loop_callee[], call_loop_ret[];

asm(".text\n"
    ".global call_loop_run\n"
    ".type call_loop_run, %function\n"
    "call_loop_run:\n"
    "	mov	x9, x30\n"
    "	mov	x4, x0\n"
    "	ldr	x6, [x2]\n"
    "1:	mov	x8, #173\n"		/* getppid */
    "	svc	#0\n"
    "	mov	x3, x1\n"
    "2:	bl	call_loop_callee\n"
    ".global call_loop_ret\n"
    "call_loop_ret:\n"
    "	subs	x3, x3, #1\n"
    "	b.ne	2b\n"
    "	subs	x4, x4, #1\n"
    "	b.ne	1b\n"
    "	str	x6, [x2]\n"
    "	mov	x30, x9\n"
    "	ret\n"
    ".global call_loop_callee\n"
    "call_loop_callee:\n"
    "	add	x6, x6, #1\n"
    "	ret\n");

int main(int argc, char **argv)
{
	long outer = argc > 1 ? atol(argv[1]) : 2000;
	long calls = argc > 2 ? atol(argv[2]) : 5000;
	uint64_t acc = 0;
	long long dec0, dec1;
	struct kjit_snap s0, s1;
	int err;

	kjit_register_self();
	if (!kjit_auto_mode()) {
		/* The callee and the return site are branch targets, not SVC resume PCs. */
		err = kjit_translate_self((uint64_t)call_loop_callee);
		if (err && err != EEXIST)
			die("translate callee: %s", strerror(err));
		err = kjit_translate_self((uint64_t)call_loop_ret);
		if (err && err != EEXIST)
			die("translate return site: %s", strerror(err));
	}
	s0 = kjit_snap();
	dec0 = kjit_stat("run_declined");
	call_loop_run(outer, calls, &acc);
	dec1 = kjit_stat("run_declined");
	s1 = kjit_snap();
	kjit_report("call_loop", s0, s1);
	printf("call_loop outer=%ld calls=%ld acc=%llu\n", outer, calls, (unsigned long long)acc);
	if (kjit_expect("dispatch")) {
		long long bud = s1.exit_budget - s0.exit_budget;

		fprintf(stderr, "call_loop: exit_budget=%lld run_declined=%lld outer=%ld\n",
			bud, dec1 - dec0, outer);
		/* Each call is a bl, a ret and a back-edge: one unit each. */
		if (calls <= BACKEDGE_BUDGET)
			die("call_loop: %ld calls per svc do not exceed the back-edge budget %d",
			    calls, BACKEDGE_BUDGET);
		/*
		 * Auto mode learns the callee, then the return site: two warmups.
		 * run_declined is global: another task's declined hook calls only
		 * loosen this bound, they cannot fail it.
		 */
		if (bud + dec1 - dec0 < outer - 2 * kjit_auto_warmup())
			die("call_loop: %lld Budget exits + %lld run_declined for %ld outer iterations",
			    bud, dec1 - dec0, outer);
	}
	return 0;
}
