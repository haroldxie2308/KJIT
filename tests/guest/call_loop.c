// SPDX-License-Identifier: GPL-2.0
/*
 * A10 chain budget: after a raw svc getppid, a CPU-bound loop of `calls`
 * function calls (bl/ret) and no syscall. Each call is two chained fragment
 * entries (the callee, then the return site), so one hook call chains until it
 * has made chain_budget entries, userspace resumes at the next branch target
 * and finishes the loop natively until the next svc. The loop cannot keep a
 * task in the kernel beyond the budget. KJIT_EXPECT=chain: every outer
 * iteration hits the budget (chain_cap) unless a run condition ended its hook
 * call first (run_declined: a timer tick's need_resched, say), and no hook
 * call made more entries than chain_budget (chain_max).
 *
 *   call_loop [outer] [calls]     outer 0 = forever (kill test)
 */
#include "kjit_test.h"

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
	uint64_t acc = 0;
	long long cap0, cap1, dec0, dec1, budget, max;
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
	cap0 = kjit_stat("chain_cap");
	dec0 = kjit_stat("run_declined");
	call_loop_run(outer, calls, &acc);
	cap1 = kjit_stat("chain_cap");
	dec1 = kjit_stat("run_declined");
	s1 = kjit_snap();
	kjit_report("call_loop", s0, s1);
	printf("call_loop outer=%ld calls=%ld acc=%llu\n", outer, calls, (unsigned long long)acc);
	if (kjit_expect("chain")) {
		budget = read_debugfs_ll("chain_budget");
		max = kjit_stat("chain_max");
		fprintf(stderr, "call_loop: chain_cap=%lld run_declined=%lld chain_max=%lld chain_budget=%lld\n",
			cap1 - cap0, dec1 - dec0, max, budget);
		if (2 * calls <= budget)
			die("call_loop: %ld calls per svc do not exceed chain_budget %lld", calls, budget);
		/* Auto mode learns the callee, then the return site: two warmups. */
		/*
		 * run_declined is global: another task's declined hook calls only
		 * loosen this bound, they cannot fail it.
		 */
		if (cap1 - cap0 + dec1 - dec0 < outer - 2 * kjit_auto_warmup())
			die("call_loop: %lld chain_cap + %lld run_declined for %ld outer iterations",
			    cap1 - cap0, dec1 - dec0, outer);
		if (max > budget)
			die("call_loop: a hook call made %lld entries, chain_budget is %lld", max, budget);
	}
	return 0;
}
