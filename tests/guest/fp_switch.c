// SPDX-License-Identifier: GPL-2.0
/*
 * Context switches between FP/SIMD fragment runs (A9b, the TIF_FOREIGN_FPSTATE
 * path). Parent and child are pinned to CPU 0 and ping-pong a token through
 * two pipes, so every parent read blocks and the child runs in between. The
 * child overwrites v0-v15 with its own values and runs with its own FPCR, so
 * when the parent's syscall returns, the registers hold the child's state
 * (TIF_FOREIGN_FPSTATE): the parent's FP/SIMD fragment must reload its own
 * state first. The parent keeps v8-v15 and FPCR constant and accumulates in
 * v6; the child accumulates in v7 and keeps v16-v23 constant. Both check
 * their state after the loop. Output must be identical with KJIT on/off.
 * KJIT_EXPECT=fpsimd: both loops run in FP/SIMD fragments and the parent's
 * runs reloaded the FP/SIMD state (fpsimd_restores).
 */
#include "kjit_test.h"
#include <sched.h>
#include <sys/wait.h>

#define FPCR_PARENT 0x03400000ull	/* DN | FZ | RMode = 0b01 */
#define FPCR_CHILD 0x00c00000ull	/* RMode = 0b11 */

static void child(long iters, int rfd, int wfd)
{
	uint8_t vin[32][16], vout[8][16], accv[16];
	uint64_t n = iters, fpcr = 0;
	char tok = 'c';

	kjit_vpattern(vin, 0x5c);
	asm volatile(
		"	add	x9, %[vin], #256\n"
		"	ld1	{v16.16b, v17.16b, v18.16b, v19.16b}, [x9], #64\n"
		"	ld1	{v20.16b, v21.16b, v22.16b, v23.16b}, [x9]\n"
		"	mrs	x13, fpcr\n"
		"	msr	fpcr, %[fpcr_set]\n"
		"	movi	v7.16b, #0\n"
		"1:\n"
		"	mov	x0, %[rfd]\n"
		"	mov	x1, %[tok]\n"
		"	mov	x2, #1\n"
		"	mov	x8, #63\n"			/* read(token) */
		"	svc	#0\n"
		/* clobber v0-v15 with this process's values */
		"	dup	v0.16b, %w[n]\n"
		"	movi	v1.16b, #0xa5\n"
		"	eor	v2.16b, v0.16b, v1.16b\n"
		"	mov	v3.16b, v2.16b\n"
		"	mov	v4.16b, v0.16b\n"
		"	mov	v5.16b, v1.16b\n"
		"	mov	v6.16b, v2.16b\n"
		"	mov	v8.16b, v0.16b\n"
		"	mov	v9.16b, v1.16b\n"
		"	mov	v10.16b, v2.16b\n"
		"	mov	v11.16b, v0.16b\n"
		"	mov	v12.16b, v1.16b\n"
		"	mov	v13.16b, v2.16b\n"
		"	mov	v14.16b, v0.16b\n"
		"	mov	v15.16b, v1.16b\n"
		"	add	v7.16b, v7.16b, v2.16b\n"
		"	eor	v7.16b, v7.16b, v16.16b\n"
		"	mov	x0, %[wfd]\n"
		"	mov	x1, %[tok]\n"
		"	mov	x2, #1\n"
		"	mov	x8, #64\n"			/* write(token) */
		"	svc	#0\n"
		"	subs	%[n], %[n], #1\n"
		"	b.ne	1b\n"
		"	mrs	%[fpcr], fpcr\n"
		"	msr	fpcr, x13\n"
		"	add	x9, %[vout], #0\n"
		"	st1	{v16.16b, v17.16b, v18.16b, v19.16b}, [x9], #64\n"
		"	st1	{v20.16b, v21.16b, v22.16b, v23.16b}, [x9]\n"
		"	str	q7, [%[accv]]\n"
		: [n] "+r"(n), [fpcr] "=&r"(fpcr)
		: [vin] "r"(vin), [vout] "r"(vout), [accv] "r"(accv), [rfd] "r"((long)rfd),
		  [wfd] "r"((long)wfd), [tok] "r"(&tok), [fpcr_set] "r"(FPCR_CHILD)
		: "x0", "x1", "x2", "x8", "x9", "x13", "v0", "v1", "v2", "v3", "v4", "v5", "v6",
		  "v7", "v8", "v9", "v10", "v11", "v12", "v13", "v14", "v15", "v16", "v17",
		  "v18", "v19", "v20", "v21", "v22", "v23", "cc", "memory");

	printf("fp_switch child fpcr=%#llx v7=", (unsigned long long)fpcr);
	for (int i = 0; i < 16; i++)
		printf("%02x", accv[i]);
	printf("\n");
	for (int r = 0; r < 8; r++)
		if (memcmp(vout[r], vin[r + 16], 16))
			die("fp_switch child: v%d changed across the loop", r + 16);
	if (fpcr != FPCR_CHILD)
		die("fp_switch child: FPCR %#llx after the loop", (unsigned long long)fpcr);
	fflush(stdout);
	_exit(0);
}

int main(int argc, char **argv)
{
	long iters = argc > 1 ? atol(argv[1]) : 20000;
	uint8_t vin[32][16], vout[8][16], accv[16];
	uint64_t acc = 0, n = iters, fpcr = 0;
	struct kjit_snap s0, s1;
	int p2c[2], c2p[2], status;
	cpu_set_t cpu0;
	char tok = 'p';
	pid_t pid;

	CPU_ZERO(&cpu0);
	CPU_SET(0, &cpu0);
	if (pipe(p2c) || pipe(c2p) || sched_setaffinity(0, sizeof(cpu0), &cpu0))
		die("setup: %s", strerror(errno));
	kjit_vpattern(vin, 0x33);
	fflush(stdout);
	s0 = kjit_snap();
	pid = fork();
	if (pid < 0)
		die("fork: %s", strerror(errno));
	if (pid == 0) {
		kjit_register_self();
		child(iters, p2c[0], c2p[1]);
	}
	kjit_register_self();

	asm volatile(
		"	ldp	q8, q9, [%[vin], #128]\n"
		"	ldp	q10, q11, [%[vin], #160]\n"
		"	ldp	q12, q13, [%[vin], #192]\n"
		"	ldp	q14, q15, [%[vin], #224]\n"
		"	mrs	x13, fpcr\n"
		"	msr	fpcr, %[fpcr_set]\n"
		"	movi	v6.16b, #0\n"
		"1:\n"
		"	dup	v0.2d, %[n]\n"
		"	eor	v1.16b, v0.16b, v8.16b\n"
		"	add	v6.2d, v6.2d, v1.2d\n"
		"	eor	v6.16b, v6.16b, v15.16b\n"
		"	umov	x11, v6.d[0]\n"
		"	add	%[acc], %[acc], x11\n"
		"	mov	x0, %[wfd]\n"
		"	mov	x1, %[tok]\n"
		"	mov	x2, #1\n"
		"	mov	x8, #64\n"			/* write(token) */
		"	svc	#0\n"
		"	mov	x0, %[rfd]\n"
		"	mov	x1, %[tok]\n"
		"	mov	x2, #1\n"
		"	mov	x8, #63\n"			/* read(token): child runs */
		"	svc	#0\n"
		"	subs	%[n], %[n], #1\n"
		"	b.ne	1b\n"
		"	mrs	%[fpcr], fpcr\n"
		"	msr	fpcr, x13\n"
		"	stp	q8, q9, [%[vout]]\n"
		"	stp	q10, q11, [%[vout], #32]\n"
		"	stp	q12, q13, [%[vout], #64]\n"
		"	stp	q14, q15, [%[vout], #96]\n"
		"	str	q6, [%[accv]]\n"
		: [acc] "+r"(acc), [n] "+r"(n), [fpcr] "=&r"(fpcr)
		: [vin] "r"(vin), [vout] "r"(vout), [accv] "r"(accv), [rfd] "r"((long)c2p[0]),
		  [wfd] "r"((long)p2c[1]), [tok] "r"(&tok), [fpcr_set] "r"(FPCR_PARENT)
		: "x0", "x1", "x2", "x8", "x11", "x13", "v0", "v1", "v6", "v8", "v9", "v10",
		  "v11", "v12", "v13", "v14", "v15", "cc", "memory");

	if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status) || WEXITSTATUS(status))
		die("fp_switch: child failed (status %#x)", status);
	s1 = kjit_snap();
	kjit_report("fp_switch", s0, s1);
	printf("fp_switch parent iters=%ld acc=%#llx fpcr=%#llx v6=", iters,
	       (unsigned long long)acc, (unsigned long long)fpcr);
	for (int i = 0; i < 16; i++)
		printf("%02x", accv[i]);
	printf("\n");
	for (int r = 0; r < 8; r++)
		if (memcmp(vout[r], vin[r + 8], 16))
			die("fp_switch: v%d changed across the loop", r + 8);
	if (fpcr != FPCR_PARENT)
		die("fp_switch: FPCR %#llx after the loop", (unsigned long long)fpcr);
	/*
	 * Parent and child: two syscalls and one FP/SIMD run per iteration each,
	 * and each FP/SIMD run follows the other process's run on CPU 0, so it
	 * reloads its state (2 * iters seen on kjit-guest). Loose: a wakeup can
	 * set need_resched, and the runtime then returns to userspace instead.
	 */
	kjit_check_fpsimd("fp_switch", s0, s1, 4 * iters, 2 * iters, 50);
	if (kjit_expect("fpsimd") &&
	    (s1.fp_restores - s0.fp_restores) * 100 < (iters - kjit_auto_warmup()) * 50)
		die("fp_switch: only %lld FP/SIMD state reloads for %ld switches",
		    s1.fp_restores - s0.fp_restores, iters);
	return 0;
}
