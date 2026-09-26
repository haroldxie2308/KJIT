// SPDX-License-Identifier: GPL-2.0
/*
 * G2 gate: C port of tests/arm64/toy_cfg.s's hot loop (toy_hot_loop in
 * kjit_test.h): raw `svc` getppid and write(/dev/null) calls with ALU work
 * between them. The process registers its own SVC resume PCs, then runs the
 * loop. KJIT_EXPECT=inkernel: at least 99% of the loop's syscalls must have
 * been invoked by the kernel on a fragment's Svc exit.
 *
 *   toy_loop [iterations]     0 = run forever (kill tests)
 */
#include "kjit_test.h"

int main(int argc, char **argv)
{
	long iters = argc > 1 ? atol(argv[1]) : 100000;
	uint64_t a = 0, b = 0x9e3779b97f4a7c15ull;
	struct kjit_snap s0, s1;
	int fd = open("/dev/null", O_WRONLY);

	if (fd < 0)
		die("open /dev/null: %s", strerror(errno));
	kjit_register_self();
	s0 = kjit_snap();
	toy_hot_loop(iters, fd, &a, &b);
	s1 = kjit_snap();
	kjit_report("toy_loop", s0, s1);
	printf("toy_loop iters=%ld a=%#llx b=%#llx\n", iters,
	       (unsigned long long)a, (unsigned long long)b);
	if (kjit_expect("inkernel")) {
		long long got = s1.in_kernel - s0.in_kernel, total = 2 * iters;

		fprintf(stderr, "toy_loop: %lld of %lld syscalls in kernel (%.2f%%)\n", got, total,
			100.0 * got / total);
		if (got * 100 < total * 99)
			die("toy_loop: only %lld of %lld syscalls in kernel", got, total);
	}
	return 0;
}
