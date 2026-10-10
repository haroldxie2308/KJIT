// SPDX-License-Identifier: GPL-2.0
/*
 * Scheduling-latency probe (the A13 FP/SIMD bracket).
 *
 * One SCHED_FIFO thread per online CPU, each pinned, each doing absolute
 * CLOCK_MONOTONIC sleeps of `interval` microseconds and recording how late it
 * woke up (wake time - target). A fragment run that cannot be preempted on a
 * CPU (the A9b bracket was local_bh_disable() for the whole run) delays the
 * wake-up of the probe pinned to that CPU by up to the run's length; the
 * distribution under load is the preemption latency the load imposes. Run it
 * next to the load generator (under nojit, like every load generator, so its
 * own syscalls never reach KJIT):
 *
 *   nojit lat_probe <seconds> [interval_us=1000] [fifo_prio=50]
 *
 * SIGTERM/SIGINT end the measurement early (the summary is still printed), so
 * a runner can start the probe with a generous <seconds> and stop it when the
 * load generator is done.
 *
 * Output (stdout, one line): samples and the overshoot distribution in
 * microseconds over all CPUs, plus the worst CPU.
 *   lat cpus=N samples=S interval_us=I p50_us=.. p99_us=.. p999_us=.. max_us=..
 *       gt100us=.. gt1ms=.. gt5ms=.. max_cpu=C
 * Exit status 1 if SCHED_FIFO could not be set (the numbers would be CFS
 * latency, not preemption latency).
 */
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t stop;

static void on_stop(int sig)
{
	(void)sig;
	stop = 1;
}

struct probe {
	int cpu;
	int prio;
	long interval_ns;
	long seconds;
	uint32_t *ns;		/* overshoot per wake-up, saturated at UINT32_MAX */
	size_t n, cap;
	int err;
	pthread_t tid;
};

static long long now_ns(void)
{
	struct timespec t;

	clock_gettime(CLOCK_MONOTONIC, &t);
	return (long long)t.tv_sec * 1000000000LL + t.tv_nsec;
}

static void *probe_main(void *arg)
{
	struct probe *p = arg;
	struct sched_param sp = { .sched_priority = p->prio };
	cpu_set_t set;
	long long next, end, now, late;
	struct timespec ts;

	CPU_ZERO(&set);
	CPU_SET(p->cpu, &set);
	if (sched_setaffinity(0, sizeof(set), &set)) {
		p->err = errno;
		return NULL;
	}
	if (sched_setscheduler(0, SCHED_FIFO, &sp)) {
		p->err = errno;
		return NULL;
	}
	next = now_ns();
	end = next + p->seconds * 1000000000LL;
	while (next < end && !stop) {
		next += p->interval_ns;
		ts.tv_sec = next / 1000000000LL;
		ts.tv_nsec = next % 1000000000LL;
		while (clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &ts, NULL) == EINTR)
			;
		now = now_ns();
		late = now - next;
		if (late < 0)
			late = 0;
		if (p->n < p->cap)
			p->ns[p->n++] = late > UINT32_MAX ? UINT32_MAX : (uint32_t)late;
		/* A late wake-up skips the periods it overslept instead of bursting. */
		if (now > next + p->interval_ns)
			next = now;
	}
	return NULL;
}

static int cmp_u32(const void *a, const void *b)
{
	uint32_t x = *(const uint32_t *)a, y = *(const uint32_t *)b;

	return (x > y) - (x < y);
}

int main(int argc, char **argv)
{
	long seconds = argc > 1 ? atol(argv[1]) : 0;
	long interval_us = argc > 2 ? atol(argv[2]) : 1000;
	int prio = argc > 3 ? atoi(argv[3]) : 50;
	int ncpu = (int)sysconf(_SC_NPROCESSORS_ONLN);
	struct probe *probes;
	uint32_t *all;
	size_t total = 0, k = 0, gt100 = 0, gt1ms = 0, gt5ms = 0;
	uint32_t worst = 0;
	int worst_cpu = 0;

	signal(SIGTERM, on_stop);
	signal(SIGINT, on_stop);
	if (seconds < 1 || interval_us < 50 || ncpu < 1) {
		fprintf(stderr, "usage: lat_probe <seconds> [interval_us>=50] [fifo_prio]\n");
		return 2;
	}
	probes = calloc(ncpu, sizeof(*probes));
	if (!probes)
		return 2;
	for (int i = 0; i < ncpu; i++) {
		probes[i].cpu = i;
		probes[i].prio = prio;
		probes[i].interval_ns = interval_us * 1000L;
		probes[i].seconds = seconds;
		probes[i].cap = (size_t)seconds * 1000000 / interval_us + 1024;
		probes[i].ns = malloc(probes[i].cap * sizeof(uint32_t));
		if (!probes[i].ns)
			return 2;
		if (pthread_create(&probes[i].tid, NULL, probe_main, &probes[i])) {
			fprintf(stderr, "pthread_create: %s\n", strerror(errno));
			return 2;
		}
	}
	for (int i = 0; i < ncpu; i++) {
		pthread_join(probes[i].tid, NULL);
		if (probes[i].err) {
			fprintf(stderr, "lat_probe: cpu %d: %s\n", i, strerror(probes[i].err));
			return 1;
		}
		total += probes[i].n;
	}
	all = malloc(total * sizeof(uint32_t));
	if (!all || !total)
		return 2;
	for (int i = 0; i < ncpu; i++) {
		for (size_t j = 0; j < probes[i].n; j++) {
			uint32_t v = probes[i].ns[j];

			all[k++] = v;
			gt100 += v > 100000;
			gt1ms += v > 1000000;
			gt5ms += v > 5000000;
			if (v > worst) {
				worst = v;
				worst_cpu = i;
			}
		}
	}
	qsort(all, total, sizeof(*all), cmp_u32);
#define PCT(p) (all[(size_t)((double)(total - 1) * (p))] / 1000.0)
	printf("lat cpus=%d samples=%zu interval_us=%ld p50_us=%.1f p99_us=%.1f p999_us=%.1f max_us=%.1f gt100us=%zu gt1ms=%zu gt5ms=%zu max_cpu=%d\n",
	       ncpu, total, interval_us, PCT(0.50), PCT(0.99), PCT(0.999), worst / 1000.0, gt100, gt1ms, gt5ms,
	       worst_cpu);
	return 0;
}
