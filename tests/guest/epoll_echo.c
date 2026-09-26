// SPDX-License-Identifier: GPL-2.0
/*
 * K3 (d): an epoll echo server (child process, nonblocking, level-triggered,
 * partial writes buffered) and a blocking client (parent) doing `trips` round
 * trips over TCP on 127.0.0.1 with message sizes 1..512 from a fixed PRNG.
 * The client checks every echo byte-for-byte. Output: trip count, byte count
 * and a hash of everything received, then the server's own byte count; the
 * same with KJIT on and off.
 *
 *   epoll_echo [trips]    default 100000
 */
#include "kjit_test.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/wait.h>

#define MAX_MSG 512
#define MAX_CONN 8

struct conn {
	int fd;
	char buf[4096];
	size_t len, off;	/* pending echo bytes buf[off..len) */
};

static void set_nonblock(int fd)
{
	int fl = fcntl(fd, F_GETFL);

	if (fl < 0 || fcntl(fd, F_SETFL, fl | O_NONBLOCK))
		die("fcntl: %s", strerror(errno));
}

static void ep_mod(int ep, struct conn *c, uint32_t events)
{
	struct epoll_event ev = { .events = events, .data.ptr = c };

	if (epoll_ctl(ep, EPOLL_CTL_MOD, c->fd, &ev))
		die("epoll_ctl mod: %s", strerror(errno));
}

/* Returns 0 on EOF (connection closed), 1 otherwise. */
static int serve(int ep, struct conn *c, uint32_t events, unsigned long long *echoed)
{
	ssize_t n;

	if (c->off == c->len && (events & (EPOLLIN | EPOLLHUP | EPOLLERR))) {
		n = read(c->fd, c->buf, sizeof(c->buf));
		if (n == 0)
			return 0;
		if (n < 0) {
			if (errno == EAGAIN || errno == EINTR)
				return 1;
			die("server read: %s", strerror(errno));
		}
		c->len = n;
		c->off = 0;
	}
	while (c->off < c->len) {
		n = write(c->fd, c->buf + c->off, c->len - c->off);
		if (n < 0) {
			if (errno == EAGAIN || errno == EINTR)
				break;
			die("server write: %s", strerror(errno));
		}
		c->off += n;
		*echoed += n;
	}
	ep_mod(ep, c, c->off < c->len ? EPOLLOUT : EPOLLIN);
	return 1;
}

static int server(int lfd)
{
	struct epoll_event ev = { .events = EPOLLIN, .data.ptr = NULL }, evs[16];
	static struct conn conns[MAX_CONN];
	unsigned long long echoed = 0;
	int ep = epoll_create1(0), open_conns = 0, accepted = 0, i, n;

	if (ep < 0 || epoll_ctl(ep, EPOLL_CTL_ADD, lfd, &ev))
		die("epoll: %s", strerror(errno));
	while (!accepted || open_conns) {
		n = epoll_wait(ep, evs, 16, -1);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			die("epoll_wait: %s", strerror(errno));
		}
		for (i = 0; i < n; i++) {
			struct conn *c = evs[i].data.ptr;

			if (!c) {
				int fd = accept(lfd, NULL, NULL);

				if (fd < 0)
					die("accept: %s", strerror(errno));
				if (accepted == MAX_CONN)
					die("too many connections");
				c = &conns[accepted++];
				c->fd = fd;
				set_nonblock(fd);
				ev.events = EPOLLIN;
				ev.data.ptr = c;
				if (epoll_ctl(ep, EPOLL_CTL_ADD, fd, &ev))
					die("epoll_ctl add: %s", strerror(errno));
				open_conns++;
				continue;
			}
			if (!serve(ep, c, evs[i].events, &echoed)) {
				close(c->fd);
				open_conns--;
			}
		}
	}
	printf("epoll_echo server echoed=%llu conns=%d\n", echoed, accepted);
	return 0;
}

static void io_full(int fd, char *buf, size_t len, int wr)
{
	while (len) {
		ssize_t n = wr ? write(fd, buf, len) : read(fd, buf, len);

		if (n <= 0) {
			if (n < 0 && errno == EINTR)
				continue;
			die("client %s: %s", wr ? "write" : "read", n ? strerror(errno) : "EOF");
		}
		buf += n;
		len -= n;
	}
}

int main(int argc, char **argv)
{
	long trips = argc > 1 ? atol(argv[1]) : 100000, i;
	struct sockaddr_in addr = { .sin_family = AF_INET };
	socklen_t alen = sizeof(addr);
	char out[MAX_MSG], in[MAX_MSG];
	uint64_t rng = 0x2545f4914f6cdd1dull, hash = 0xcbf29ce484222325ull, bytes = 0;
	int lfd, fd, one = 1, status;
	pid_t pid;

	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	lfd = socket(AF_INET, SOCK_STREAM, 0);
	if (lfd < 0 || bind(lfd, (struct sockaddr *)&addr, sizeof(addr)) || listen(lfd, 8) ||
	    getsockname(lfd, (struct sockaddr *)&addr, &alen))
		die("listen: %s", strerror(errno));
	fflush(stdout);
	pid = fork();
	if (pid < 0)
		die("fork: %s", strerror(errno));
	if (pid == 0) {
		int ret = server(lfd);

		fflush(stdout);
		_exit(ret);
	}
	close(lfd);

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0 || connect(fd, (struct sockaddr *)&addr, sizeof(addr)) ||
	    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)))
		die("connect: %s", strerror(errno));
	for (i = 0; i < trips; i++) {
		size_t len, k;

		rng ^= rng << 13;
		rng ^= rng >> 7;
		rng ^= rng << 17;
		len = 1 + rng % MAX_MSG;
		for (k = 0; k < len; k++)
			out[k] = (char)(rng >> (k % 56)) + (char)k;
		io_full(fd, out, len, 1);
		io_full(fd, in, len, 0);
		if (memcmp(in, out, len))
			die("trip %ld: echo differs", i);
		for (k = 0; k < len; k++)
			hash = (hash ^ (uint8_t)in[k]) * 0x100000001b3ull;
		bytes += len;
	}
	close(fd);
	if (waitpid(pid, &status, 0) != pid)
		die("waitpid: %s", strerror(errno));
	printf("epoll_echo client trips=%ld bytes=%llu hash=%#llx server_exit=%d\n", trips,
	       (unsigned long long)bytes, (unsigned long long)hash,
	       WIFEXITED(status) ? WEXITSTATUS(status) : -1);
	return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : 1;
}
