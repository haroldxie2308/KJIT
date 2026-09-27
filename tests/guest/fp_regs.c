// SPDX-License-Identifier: GPL-2.0
/*
 * User FP/SIMD register state across a hot syscall loop that runs in FP/SIMD
 * fragments (A9b): v8-v23 are set to known patterns and FPCR/FPSR to
 * non-default values (FPCR DN, FZ, RMode = toward minus infinity; FPSR QC and
 * two cumulative flags) before the loop. Each iteration does getppid, SIMD
 * work on v0-v6 that reads v8/v9 (so the fragments use FP/SIMD) and a write
 * to /dev/null. After the loop v8-v23, FPCR and FPSR must be unchanged and
 * the SIMD accumulator must match. Output must be identical with KJIT on/off.
 * KJIT_EXPECT=fpsimd: the loop runs in FP/SIMD fragments.
 */
#include "kjit_test.h"

#define FPCR_SET 0x03800000ull	/* DN | FZ | RMode = 0b10 */
#define FPSR_SET 0x08000011ull	/* QC | IXC | IOC */

int main(int argc, char **argv)
{
	long iters = argc > 1 ? atol(argv[1]) : 100000;
	uint8_t vin[32][16], vout[16][16], accv[16];
	uint64_t acc = 0, n = iters, fpcr = 0, fpsr = 0;
	struct kjit_snap s0, s1;
	int fd = open("/dev/null", O_WRONLY);
	char byte = 'f';

	if (fd < 0)
		die("open: %s", strerror(errno));
	kjit_vpattern(vin, 0x21);
	kjit_register_self();
	s0 = kjit_snap();

	asm volatile(
		"	ldp	q8, q9, [%[vin], #128]\n"
		"	ldp	q10, q11, [%[vin], #160]\n"
		"	ldp	q12, q13, [%[vin], #192]\n"
		"	ldp	q14, q15, [%[vin], #224]\n"
		"	add	x9, %[vin], #256\n"
		"	ld1	{v16.16b, v17.16b, v18.16b, v19.16b}, [x9], #64\n"
		"	ld1	{v20.16b, v21.16b, v22.16b, v23.16b}, [x9]\n"
		"	mrs	x13, fpcr\n"
		"	mrs	x14, fpsr\n"
		"	msr	fpcr, %[fpcr_set]\n"
		"	msr	fpsr, %[fpsr_set]\n"
		"	movi	v6.16b, #0\n"
		"1:\n"
		"	mov	x8, #173\n"			/* getppid */
		"	svc	#0\n"
		"	add	%[acc], %[acc], x0\n"
		"	dup	v0.2d, %[n]\n"
		"	eor	v1.16b, v0.16b, v8.16b\n"
		"	add	v6.2d, v6.2d, v1.2d\n"
		"	ext	v2.16b, v6.16b, v9.16b, #5\n"
		"	umov	x11, v2.d[1]\n"
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
		"	mrs	%[fpsr], fpsr\n"
		"	msr	fpcr, x13\n"
		"	msr	fpsr, x14\n"
		"	stp	q8, q9, [%[vout]]\n"
		"	stp	q10, q11, [%[vout], #32]\n"
		"	stp	q12, q13, [%[vout], #64]\n"
		"	stp	q14, q15, [%[vout], #96]\n"
		"	add	x9, %[vout], #128\n"
		"	st1	{v16.16b, v17.16b, v18.16b, v19.16b}, [x9], #64\n"
		"	st1	{v20.16b, v21.16b, v22.16b, v23.16b}, [x9]\n"
		"	str	q6, [%[accv]]\n"
		: [acc] "+r"(acc), [n] "+r"(n), [fpcr] "=&r"(fpcr), [fpsr] "=&r"(fpsr)
		: [vin] "r"(vin), [vout] "r"(vout), [accv] "r"(accv), [fd] "r"((long)fd),
		  [buf] "r"(&byte), [fpcr_set] "r"(FPCR_SET), [fpsr_set] "r"(FPSR_SET)
		: "x0", "x1", "x2", "x8", "x9", "x11", "x13", "x14", "v0", "v1", "v2", "v6",
		  "v8", "v9", "v10", "v11", "v12", "v13", "v14", "v15", "v16", "v17", "v18",
		  "v19", "v20", "v21", "v22", "v23", "cc", "memory");

	s1 = kjit_snap();
	kjit_report("fp_regs", s0, s1);
	printf("fp_regs iters=%ld acc=%#llx fpcr=%#llx fpsr=%#llx v6=", iters,
	       (unsigned long long)acc, (unsigned long long)fpcr, (unsigned long long)fpsr);
	for (int i = 0; i < 16; i++)
		printf("%02x", accv[i]);
	printf("\n");
	for (int r = 0; r < 16; r++) {
		printf("fp_regs v%d=", r + 8);
		for (int i = 0; i < 16; i++)
			printf("%02x", vout[r][i]);
		printf("\n");
		if (memcmp(vout[r], vin[r + 8], 16))
			die("fp_regs: v%d changed across the loop", r + 8);
	}
	if (fpcr != FPCR_SET)
		die("fp_regs: FPCR %#llx after the loop, want %#llx", (unsigned long long)fpcr,
		    FPCR_SET);
	if (fpsr != FPSR_SET)
		die("fp_regs: FPSR %#llx after the loop, want %#llx", (unsigned long long)fpsr,
		    FPSR_SET);
	kjit_check_fpsimd("fp_regs", s0, s1, 2 * iters, iters, 90);
	return 0;
}
