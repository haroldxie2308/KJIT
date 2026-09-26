// SPDX-License-Identifier: GPL-2.0
/*
 * A seccomp-filtered process (allow-all filter): every syscall has syscall
 * work, so the kernel never calls the KJIT hook for it. KJIT_EXPECT=declined:
 * the translations installed, but no fragment ever ran.
 */
#include "kjit_test.h"
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <sys/syscall.h>

int main(int argc, char **argv)
{
	long iters = argc > 1 ? atol(argv[1]) : 20000;
	struct sock_filter allow[] = { BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW) };
	struct sock_fprog prog = { .len = 1, .filter = allow };
	uint64_t a = 0, b = 1;
	struct kjit_snap s0, s1;
	int fd = open("/dev/null", O_WRONLY);

	if (fd < 0)
		die("open: %s", strerror(errno));
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) ||
	    syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog))
		die("seccomp: %s", strerror(errno));
	s0 = kjit_snap();
	kjit_register_self();
	toy_hot_loop(iters, fd, &a, &b);
	s1 = kjit_snap();
	kjit_report("seccomp_loop", s0, s1);
	printf("seccomp_loop iters=%ld a=%#llx b=%#llx\n", iters, (unsigned long long)a,
	       (unsigned long long)b);
	if (kjit_expect("declined")) {
		if (s1.translate_ok == s0.translate_ok)
			die("seccomp_loop: nothing was translated");
		if (s1.entries != s0.entries || s1.in_kernel != s0.in_kernel)
			die("seccomp_loop: %lld fragment entries under seccomp", s1.entries - s0.entries);
	}
	return 0;
}
