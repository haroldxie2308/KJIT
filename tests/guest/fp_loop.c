// SPDX-License-Identifier: GPL-2.0
/*
 * FP/SIMD between syscalls (A9b). Per iteration of the asm loop, with a size
 * s from a table (1..4000 bytes) and a misaligned source:
 *   - a SIMD copy src -> buf in glibc memcpy style (ldp/stp q, ldr/str q
 *     post-index, an overlapping ldur/stur q tail; a byte loop below 16);
 *   - write(pipe, buf, s) + read(pipe, rbuf, s);
 *   - a SIMD compare of rbuf with src (ld1 post-index, cmeq, uminv, umov);
 *   - a SIMD fill of mbuf (dup, movi, st1 x2, stp q);
 *   - a strlen-style scan (ldr q post-index, cmeq #0, umaxv, fmov);
 * v7 accumulates buf's first 16 bytes and the fill vector over the whole run,
 * so the V state must survive every syscall and every fragment run.
 * Then a C phase does the same with glibc memcpy/memcmp/memset/strlen (their
 * SIMD code runs in fragments in auto mode). Output must be identical with
 * KJIT on/off. KJIT_EXPECT=fpsimd: the asm loop runs in FP/SIMD fragments.
 */
#include "kjit_test.h"

static const uint32_t sizes[] = { 1, 7, 15, 16, 17, 31, 32, 33, 64, 100, 255, 256, 1024, 4000 };
#define NSIZES (sizeof(sizes) / sizeof(sizes[0]))

static uint64_t fnv(uint64_t h, const void *p, size_t n)
{
	const uint8_t *b = p;

	for (size_t i = 0; i < n; i++)
		h = (h ^ b[i]) * 0x100000001b3ull;
	return h;
}

int main(int argc, char **argv)
{
	long iters = argc > 1 ? atol(argv[1]) : 20000;
	uint8_t *src = malloc(8192), *buf = malloc(8192), *rbuf = malloc(8192), *mbuf = malloc(256);
	char *str = malloc(256);
	uint64_t acc = 0, bad = 0, n = iters, lo, hi, h;
	struct kjit_snap s0, s1;
	int p[2];

	if (!src || !buf || !rbuf || !mbuf || !str || pipe(p))
		die("setup: %s", strerror(errno));
	for (int i = 0; i < 8192; i++)
		src[i] = (uint8_t)(i * 7 + (i >> 8) + 1);
	memset(buf, 0, 8192);
	memset(rbuf, 0, 8192);
	memset(str, 'x', 256);
	str[77] = '\0';
	kjit_register_self();
	s0 = kjit_snap();

	asm volatile(
		"	movi	v7.16b, #0\n"
		"	mov	x12, %[tab]\n"
		"1:\n"
		"	ldr	w3, [x12], #4\n"
		"	cmp	x12, %[tabend]\n"
		"	csel	x12, %[tab], x12, eq\n"
		/* copy src + 3 -> buf, s bytes */
		"	add	x4, %[src], #3\n"
		"	mov	x5, %[buf]\n"
		"	mov	x6, x3\n"
		"	cmp	x6, #16\n"
		"	b.lo	4f\n"
		"2:\n"
		"	cmp	x6, #32\n"
		"	b.lo	3f\n"
		"	ldp	q0, q1, [x4]\n"
		"	stp	q0, q1, [x5]\n"
		"	add	x4, x4, #32\n"
		"	add	x5, x5, #32\n"
		"	sub	x6, x6, #32\n"
		"	b	2b\n"
		"3:\n"
		"	cmp	x6, #16\n"
		"	b.lo	31f\n"
		"	ldr	q0, [x4], #16\n"
		"	str	q0, [x5], #16\n"
		"	sub	x6, x6, #16\n"
		"31:\n"
		"	cbz	x6, 5f\n"
		"	add	x7, %[src], #3\n"
		"	add	x7, x7, x3\n"
		"	add	x9, %[buf], x3\n"
		"	ldur	q0, [x7, #-16]\n"
		"	stur	q0, [x9, #-16]\n"
		"	b	5f\n"
		"4:\n"
		"	ldrb	w7, [x4], #1\n"
		"	strb	w7, [x5], #1\n"
		"	subs	x6, x6, #1\n"
		"	b.ne	4b\n"
		"5:\n"
		"	ldr	q2, [%[buf]]\n"
		"	add	v7.16b, v7.16b, v2.16b\n"
		"	mov	x0, %[wfd]\n"
		"	mov	x1, %[buf]\n"
		"	mov	x2, x3\n"
		"	mov	x8, #64\n"			/* write(pipe) */
		"	svc	#0\n"
		"	add	%[acc], %[acc], x0\n"
		"	mov	x0, %[rfd]\n"
		"	mov	x1, %[rbuf]\n"
		"	mov	x2, x3\n"
		"	mov	x8, #63\n"			/* read(pipe) */
		"	svc	#0\n"
		"	add	%[acc], %[acc], x0\n"
		/* compare the whole 16-byte blocks of rbuf with src + 3 */
		"	add	x4, %[src], #3\n"
		"	mov	x5, %[rbuf]\n"
		"	lsr	x6, x3, #4\n"
		"6:\n"
		"	cbz	x6, 7f\n"
		"	ld1	{v0.16b}, [x4], #16\n"
		"	ld1	{v1.16b}, [x5], #16\n"
		"	cmeq	v2.16b, v0.16b, v1.16b\n"
		"	uminv	b3, v2.16b\n"
		"	umov	w7, v3.b[0]\n"
		"	cmp	w7, #0xff\n"
		"	cinc	%[bad], %[bad], ne\n"
		"	sub	x6, x6, #1\n"
		"	b	6b\n"
		"7:\n"
		/* fill 64 bytes of mbuf */
		"	dup	v4.16b, w3\n"
		"	movi	v5.16b, #0x5a\n"
		"	st1	{v4.16b, v5.16b}, [%[mbuf]]\n"
		"	stp	q5, q4, [%[mbuf], #32]\n"
		/* strlen of str, in 16-byte chunks */
		"	mov	x4, %[str]\n"
		"8:\n"
		"	ldr	q0, [x4], #16\n"
		"	cmeq	v0.16b, v0.16b, #0\n"
		"	umaxv	b1, v0.16b\n"
		"	fmov	w7, s1\n"
		"	cbz	w7, 8b\n"
		"	sub	x4, x4, %[str]\n"
		"	add	%[acc], %[acc], x4\n"
		"	add	v7.16b, v7.16b, v4.16b\n"
		"	subs	%[n], %[n], #1\n"
		"	b.ne	1b\n"
		"	mov	%[lo], v7.d[0]\n"
		"	mov	%[hi], v7.d[1]\n"
		: [acc] "+r"(acc), [bad] "+r"(bad), [n] "+r"(n), [lo] "=&r"(lo), [hi] "=&r"(hi)
		: [tab] "r"(sizes), [tabend] "r"(sizes + NSIZES), [src] "r"(src), [buf] "r"(buf),
		  [rbuf] "r"(rbuf), [mbuf] "r"(mbuf), [str] "r"(str), [wfd] "r"((long)p[1]),
		  [rfd] "r"((long)p[0])
		: "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x12", "v0", "v1",
		  "v2", "v3", "v4", "v5", "v7", "cc", "memory");

	s1 = kjit_snap();
	kjit_report("fp_loop", s0, s1);
	/* The last iteration's data, checked with glibc. */
	{
		uint32_t last = sizes[(iters - 1) % NSIZES];

		if (memcmp(buf, src + 3, last) || memcmp(rbuf, src + 3, last))
			die("fp_loop: last copy (size %u) differs", last);
		if (mbuf[0] != (uint8_t)last || mbuf[16] != 0x5a || mbuf[32] != 0x5a ||
		    mbuf[48] != (uint8_t)last)
			die("fp_loop: fill differs");
	}
	h = fnv(0xcbf29ce484222325ull, mbuf, 64);
	printf("fp_loop asm iters=%ld acc=%llu bad=%llu v7=%#llx,%#llx fill=%#llx\n", iters,
	       (unsigned long long)acc, (unsigned long long)bad, (unsigned long long)lo,
	       (unsigned long long)hi, (unsigned long long)h);
	if (bad)
		die("fp_loop: %llu compare mismatches", (unsigned long long)bad);
	kjit_check_fpsimd("fp_loop", s0, s1, 2 * iters, iters, 90);

	/* C phase: glibc's SIMD string/memory routines between the same syscalls. */
	h = 0xcbf29ce484222325ull;
	acc = 0;
	for (long i = 0; i < iters; i++) {
		uint32_t s = sizes[i % NSIZES], off = i % 13;

		memcpy(buf + off, src + (i % 29), s);
		if (write(p[1], buf + off, s) != (ssize_t)s || read(p[0], rbuf, s) != (ssize_t)s)
			die("fp_loop: pipe io: %s", strerror(errno));
		if (memcmp(rbuf, src + (i % 29), s))
			die("fp_loop: C phase data differs at iteration %ld", i);
		memset(mbuf + (i % 7), (int)(i & 0xff), 128);
		str[40 + i % 200] = '\0';
		acc += strlen(str);
		str[40 + i % 200] = 'x';
		str[77] = '\0';
		h = fnv(h, mbuf, 16);
	}
	printf("fp_loop c iters=%ld strlen_sum=%llu fill=%#llx\n", iters, (unsigned long long)acc,
	       (unsigned long long)h);
	return 0;
}
