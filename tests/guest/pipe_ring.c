// SPDX-License-Identifier: GPL-2.0
/*
 * K3 (c): multi-threaded pipe ping-pong. 4 threads in a ring, thread i reads
 * an 8-byte token from pipe i, mixes it with its own state and writes it to
 * pipe (i + 1) % 4, for `rounds` trips around the ring. Plain libc read/write
 * calls, so KJIT's auto mode has to find the hot code itself (syscall resume
 * PCs inside libc, then the callers through exit-target learning). Output:
 * the final token and every thread's state, identical with KJIT on and off.
 *
 *   pipe_ring [rounds]    default 100000
 */
#include "kjit_test.h"
#include <pthread.h>

#define THREADS 4

static int pipes[THREADS][2];
static long rounds;
static uint64_t state[THREADS];

static void read_full(int fd, void *buf, size_t len)
{
	char *p = buf;

	while (len) {
		ssize_t n = read(fd, p, len);

		if (n <= 0)
			die("read: %s", n ? strerror(errno) : "EOF");
		p += n;
		len -= n;
	}
}

static void write_full(int fd, const void *buf, size_t len)
{
	const char *p = buf;

	while (len) {
		ssize_t n = write(fd, p, len);

		if (n <= 0)
			die("write: %s", n ? strerror(errno) : "short");
		p += n;
		len -= n;
	}
}

static void *ring_thread(void *arg)
{
	long id = (long)arg, r;
	uint64_t token, s = 0x9e3779b97f4a7c15ull * (id + 1);

	for (r = 0; r < rounds; r++) {
		read_full(pipes[id][0], &token, sizeof(token));
		s = (s ^ token) * 0x100000001b3ull + (uint64_t)r;
		token = token * 6364136223846793005ull + 1442695040888963407ull + (uint64_t)id;
		/* The last thread of the last round keeps the token. */
		if (r + 1 < rounds || id != THREADS - 1)
			write_full(pipes[(id + 1) % THREADS][1], &token, sizeof(token));
		else
			state[THREADS - 1] ^= token;
	}
	state[id] ^= s;
	return NULL;
}

int main(int argc, char **argv)
{
	pthread_t t[THREADS];
	uint64_t token = 1;
	long i;

	rounds = argc > 1 ? atol(argv[1]) : 100000;
	if (rounds <= 0)
		die("rounds must be positive");
	for (i = 0; i < THREADS; i++)
		if (pipe(pipes[i]))
			die("pipe: %s", strerror(errno));
	for (i = 0; i < THREADS; i++)
		if (pthread_create(&t[i], NULL, ring_thread, (void *)i))
			die("pthread_create");
	write_full(pipes[0][1], &token, sizeof(token));
	for (i = 0; i < THREADS; i++)
		if (pthread_join(t[i], NULL))
			die("pthread_join");
	printf("pipe_ring threads=%d rounds=%ld", THREADS, rounds);
	for (i = 0; i < THREADS; i++)
		printf(" s%ld=%#llx", i, (unsigned long long)state[i]);
	printf("\n");
	return 0;
}
