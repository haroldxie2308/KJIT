// SPDX-License-Identifier: GPL-2.0
/*
 * nojit CMD [ARGS...]: run CMD with an allow-all seccomp filter. Every syscall
 * of a seccomp-filtered task has syscall work, so the KJIT hook never runs for
 * it: no profiling, no fragments. run-k3.sh runs load generators with it so
 * the KJIT counters measure only the program under test.
 */
#include "kjit_test.h"
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <sys/syscall.h>

int main(int argc, char **argv)
{
	struct sock_filter allow[] = { BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW) };
	struct sock_fprog prog = { .len = 1, .filter = allow };

	if (argc < 2)
		die("usage: nojit CMD [ARGS...]");
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) ||
	    syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog))
		die("seccomp: %s", strerror(errno));
	execvp(argv[1], argv + 1);
	die("exec %s: %s", argv[1], strerror(errno));
}
