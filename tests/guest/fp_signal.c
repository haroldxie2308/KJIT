// SPDX-License-Identifier: GPL-2.0
/*
 * Signals while the hot loop runs in FP/SIMD fragments (A9b): a 1 ms interval
 * timer raises SIGALRM; the handler uses FP/SIMD itself (glibc memset, memcpy,
 * strlen, and asm that overwrites v0-v31, FPCR and FPSR). The signal frame
 * must hold the loop's FP/SIMD state as the fragments left it, and sigreturn
 * must restore it: the loop keeps v8-v15 and FPCR constant and accumulates in
 * v6, so any lost or mixed-up state changes its result. Output must be
 * identical with KJIT on/off. KJIT_EXPECT=fpsimd: the loop runs in FP/SIMD
 * fragments.
 */
#include "kjit_test.h"
#include <signal.h>
#include <sys/time.h>

#define FPCR_SET 0x02c00000ull	/* DN | RMode = 0b11 */

static volatile sig_atomic_t alarms;
static char hbuf[2][512];

static void on_alarm(int sig)
{
	size_t len;

	alarms++;
	memset(hbuf[0], 'a' + alarms % 26, sizeof(hbuf[0]) - 1);
	hbuf[0][100 + alarms % 300] = '\0';
	memcpy(hbuf[1], hbuf[0], sizeof(hbuf[0]));
	len = strlen(hbuf[1]);
	asm volatile(
		"	dup	v0.16b, %w[len]\n"
		"	movi	v1.16b, #0xee\n"
		"	mov	v2.16b, v0.16b\n"
		"	mov	v3.16b, v1.16b\n"
		"	mov	v4.16b, v0.16b\n"
		"	mov	v5.16b, v1.16b\n"
		"	mov	v6.16b, v0.16b\n"
		"	mov	v7.16b, v1.16b\n"
		"	mov	v8.16b, v0.16b\n"
		"	mov	v9.16b, v1.16b\n"
		"	mov	v10.16b, v0.16b\n"
		"	mov	v11.16b, v1.16b\n"
		"	mov	v12.16b, v0.16b\n"
		"	mov	v13.16b, v1.16b\n"
		"	mov	v14.16b, v0.16b\n"
		"	mov	v15.16b, v1.16b\n"
		"	mov	v16.16b, v0.16b\n"
		"	mov	v17.16b, v1.16b\n"
		"	mov	v18.16b, v0.16b\n"
		"	mov	v19.16b, v1.16b\n"
		"	mov	v20.16b, v0.16b\n"
		"	mov	v21.16b, v1.16b\n"
		"	mov	v22.16b, v0.16b\n"
		"	mov	v23.16b, v1.16b\n"
		"	mov	v24.16b, v0.16b\n"
		"	mov	v25.16b, v1.16b\n"
		"	mov	v26.16b, v0.16b\n"
		"	mov	v27.16b, v1.16b\n"
		"	mov	v28.16b, v0.16b\n"
		"	mov	v29.16b, v1.16b\n"
		"	mov	v30.16b, v0.16b\n"
		"	mov	v31.16b, v1.16b\n"
		"	msr	fpcr, xzr\n"
		"	msr	fpsr, xzr\n"
		:
		: [len] "r"(len)
		: "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7", "v8", "v9", "v10", "v11", "v12",
		  "v13", "v14", "v15", "v16", "v17", "v18", "v19", "v20", "v21", "v22", "v23",
		  "v24", "v25", "v26", "v27", "v28", "v29", "v30", "v31");
}

int main(int argc, char **argv)
{
	long iters = argc > 1 ? atol(argv[1]) : 200000;
	struct itimerval it = { { 0, 1000 }, { 0, 1000 } }, off = { { 0, 0 }, { 0, 0 } };
	struct sigaction sa = { .sa_handler = on_alarm, .sa_flags = SA_RESTART };
	uint8_t vin[32][16], vout[8][16], accv[16];
	uint64_t acc = 0, n = iters, fpcr = 0;
	struct kjit_snap s0, s1;
	int fd = open("/dev/null", O_WRONLY);
	char byte = 's';

	if (fd < 0 || sigaction(SIGALRM, &sa, NULL))
		die("setup: %s", strerror(errno));
	kjit_vpattern(vin, 0x47);
	kjit_register_self();
	s0 = kjit_snap();
	if (setitimer(ITIMER_REAL, &it, NULL))
		die("setitimer: %s", strerror(errno));

	asm volatile(
		"	ldp	q8, q9, [%[vin], #128]\n"
		"	ldp	q10, q11, [%[vin], #160]\n"
		"	ldp	q12, q13, [%[vin], #192]\n"
		"	ldp	q14, q15, [%[vin], #224]\n"
		"	mrs	x13, fpcr\n"
		"	msr	fpcr, %[fpcr_set]\n"
		"	movi	v6.16b, #0\n"
		"1:\n"
		"	mov	x8, #173\n"			/* getppid */
		"	svc	#0\n"
		"	add	%[acc], %[acc], x0\n"
		"	dup	v0.2d, %[n]\n"
		"	eor	v1.16b, v0.16b, v8.16b\n"
		"	add	v6.2d, v6.2d, v1.2d\n"
		"	eor	v6.16b, v6.16b, v13.16b\n"
		"	umov	x11, v6.d[1]\n"
		"	add	%[acc], %[acc], x11\n"
		"	mov	x0, %[fd]\n"
		"	mov	x1, %[buf]\n"
		"	mov	x2, #1\n"
		"	mov	x8, #64\n"			/* write(/dev/null) */
		"	svc	#0\n"
		"	add	%[acc], %[acc], x0\n"
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
		: [vin] "r"(vin), [vout] "r"(vout), [accv] "r"(accv), [fd] "r"((long)fd),
		  [buf] "r"(&byte), [fpcr_set] "r"(FPCR_SET)
		: "x0", "x1", "x2", "x8", "x11", "x13", "v0", "v1", "v6", "v8", "v9", "v10", "v11",
		  "v12", "v13", "v14", "v15", "cc", "memory");

	setitimer(ITIMER_REAL, &off, NULL);
	s1 = kjit_snap();
	kjit_report("fp_signal", s0, s1);
	fprintf(stderr, "fp_signal: %d alarms handled\n", (int)alarms);
	printf("fp_signal iters=%ld acc=%#llx fpcr=%#llx handled=%d v6=", iters,
	       (unsigned long long)acc, (unsigned long long)fpcr, alarms > 0);
	for (int i = 0; i < 16; i++)
		printf("%02x", accv[i]);
	printf("\n");
	for (int r = 0; r < 8; r++)
		if (memcmp(vout[r], vin[r + 8], 16))
			die("fp_signal: v%d changed across the loop", r + 8);
	if (fpcr != FPCR_SET)
		die("fp_signal: FPCR %#llx after the loop", (unsigned long long)fpcr);
	kjit_check_fpsimd("fp_signal", s0, s1, 2 * iters, iters, 80);
	return 0;
}
