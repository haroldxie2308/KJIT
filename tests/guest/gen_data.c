// SPDX-License-Identifier: GPL-2.0
/*
 * gen_data MIB: writes MIB MiB of deterministic text to stdout, lines of a
 * 16-digit hex key and 1..12 pseudo-random words (so sort, gzip and wc have
 * real work). The same bytes on every run.
 */
#include "kjit_test.h"

static const char *const words[] = {
	"alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf", "hotel",
	"india", "juliet", "kilo", "lima", "mike", "november", "oscar", "papa",
	"quebec", "romeo", "sierra", "tango", "uniform", "victor", "whiskey", "xray",
	"yankee", "zulu", "kernel", "syscall", "fragment", "verifier", "budget", "epoll",
};

int main(int argc, char **argv)
{
	long long want = (argc > 1 ? atoll(argv[1]) : 64) << 20, done = 0;
	uint64_t rng = 0x853c49e6748fea9bull;
	static char buf[1 << 16];
	size_t len = 0;

	while (done < want) {
		char line[256];
		int n, k, nw;

		rng = rng * 6364136223846793005ull + 1442695040888963407ull;
		n = snprintf(line, sizeof(line), "%016llx", (unsigned long long)(rng ^ (rng >> 29)));
		nw = 1 + (rng >> 60) % 12;
		for (k = 0; k < nw; k++)
			n += snprintf(line + n, sizeof(line) - n, " %s",
				      words[(rng >> (5 * k)) % 32]);
		line[n++] = '\n';
		if (done + n > want)
			n = want - done;
		if (len + n > sizeof(buf)) {
			if (fwrite(buf, 1, len, stdout) != len)
				die("write: %s", strerror(errno));
			len = 0;
		}
		memcpy(buf + len, line, n);
		len += n;
		done += n;
	}
	if (fwrite(buf, 1, len, stdout) != len || fflush(stdout))
		die("write: %s", strerror(errno));
	return 0;
}
