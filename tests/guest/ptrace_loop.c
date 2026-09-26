// SPDX-License-Identifier: GPL-2.0
/*
 * A ptrace-attached process (no syscall tracing, so it has no syscall work):
 * KJIT declines every fragment entry for a traced task. KJIT_EXPECT=declined.
 */
#include "kjit_test.h"
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/wait.h>

int main(int argc, char **argv)
{
	long iters = argc > 1 ? atol(argv[1]) : 20000;
	int status;
	pid_t pid;

	fflush(stdout);
	pid = fork();
	if (pid < 0)
		die("fork: %s", strerror(errno));
	if (pid == 0) {
		uint64_t a = 0, b = 1;
		struct kjit_snap s0, s1;
		int fd = open("/dev/null", O_WRONLY);

		if (fd < 0 || ptrace(PTRACE_TRACEME, 0, NULL, NULL))
			die("traceme: %s", strerror(errno));
		raise(SIGSTOP);
		s0 = kjit_snap();
		kjit_register_self();
		toy_hot_loop(iters, fd, &a, &b);
		s1 = kjit_snap();
		kjit_report("ptrace_loop", s0, s1);
		/* The parent's pid differs between runs; print only whether the
		 * loop summed getppid() + 1 per iteration. */
		printf("ptrace_loop child iters=%ld a_ok=%d\n", iters,
		       a == (uint64_t)iters * (uint64_t)(getppid() + 1));
		if (kjit_expect("declined")) {
			if (s1.translate_ok == s0.translate_ok)
				die("ptrace_loop: nothing was translated");
			if (s1.entries != s0.entries)
				die("ptrace_loop: %lld fragment entries while traced",
				    s1.entries - s0.entries);
		}
		return 0;
	}
	if (waitpid(pid, &status, 0) != pid || !WIFSTOPPED(status))
		die("child did not stop: %#x", status);
	if (ptrace(PTRACE_CONT, pid, NULL, NULL))
		die("PTRACE_CONT: %s", strerror(errno));
	if (waitpid(pid, &status, 0) != pid)
		die("waitpid: %s", strerror(errno));
	printf("ptrace_loop child exit=%d\n", WIFEXITED(status) ? WEXITSTATUS(status) : -1);
	return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : 1;
}
