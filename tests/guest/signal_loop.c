// SPDX-License-Identifier: GPL-2.0
/*
 * Signals delivered while the loop runs in the kernel: a 1 ms interval timer
 * raises SIGALRM; the kernel must return to userspace to run the handler and
 * the loop must continue with the same result as without KJIT.
 * KJIT_EXPECT=inkernel: most of the loop still runs in the kernel.
 */
#include "kjit_test.h"
#include <signal.h>
#include <sys/time.h>

static volatile sig_atomic_t alarms;

static void on_alarm(int sig)
{
	alarms++;
}

int main(int argc, char **argv)
{
	long iters = argc > 1 ? atol(argv[1]) : 200000;
	struct itimerval it = { { 0, 1000 }, { 0, 1000 } }, off = { { 0, 0 }, { 0, 0 } };
	struct sigaction sa = { .sa_handler = on_alarm, .sa_flags = SA_RESTART };
	uint64_t a = 0, b = 1;
	struct kjit_snap s0, s1;
	int fd = open("/dev/null", O_WRONLY);

	if (fd < 0 || sigaction(SIGALRM, &sa, NULL))
		die("setup: %s", strerror(errno));
	kjit_register_self();
	s0 = kjit_snap();
	if (setitimer(ITIMER_REAL, &it, NULL))
		die("setitimer: %s", strerror(errno));
	toy_hot_loop(iters, fd, &a, &b);
	setitimer(ITIMER_REAL, &off, NULL);
	s1 = kjit_snap();
	kjit_report("signal_loop", s0, s1);
	fprintf(stderr, "signal_loop: %d alarms handled\n", (int)alarms);
	printf("signal_loop iters=%ld a=%#llx b=%#llx handled=%d\n", iters, (unsigned long long)a,
	       (unsigned long long)b, alarms > 0);
	if (kjit_expect("inkernel") && (s1.in_kernel - s0.in_kernel) * 100 < 2 * iters * 90)
		die("signal_loop: only %lld of %ld syscalls in kernel", s1.in_kernel - s0.in_kernel,
		    2 * iters);
	return 0;
}
