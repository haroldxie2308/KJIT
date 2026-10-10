// SPDX-License-Identifier: GPL-2.0
/*
 * Stale FP/SIMD binding after a bracket (A13, docs/pipeline.md, "FP/SIMD in
 * fragments (A9)", Kernel: "Why the invalidation"). Deterministic: no race has
 * to be won, only a migration schedule has to be followed.
 *
 * The kernel binds a task's user FP/SIMD state to the CPU whose registers hold
 * it (thread.fpsimd_cpu, that CPU's fpsimd_last_state) and, at switch-in, skips
 * the reload when the CPU is still bound to the task. The bracket writes
 * thread.uw behind that bookkeeping, so it must invalidate the binding
 * (thread.fpsimd_cpu = NR_CPUS) or a CPU the task used earlier would give the
 * task its old registers back. One round (M = the tested thread, H = a helper
 * pinned to a third CPU so that it never touches the two CPUs below):
 *
 *   1. M is pinned to CPU X, loads P0 into v0-v7 at EL0 and blocks in a raw
 *      read(pipe A). Its state is bound to X, and X stays FP-idle (nothing
 *      else returns to EL0 on it).
 *   2. H waits until M sleeps in the kernel, moves it to CPU Y
 *      (sched_setaffinity from another thread), and writes pipe A.
 *   3. On Y the syscall's resume runs an FP/SIMD fragment (v0-v7: P0 -> P1) in
 *      a bracket, then its svc: read(pipe B) blocks in the kernel, still on
 *      the hook's in-kernel syscall path, so the task never returned to EL0 on Y.
 *   4. H waits until M sleeps again, moves it back to X and writes pipe B.
 *      X's registers still hold P0 and X is still bound to M.
 *   5. M returns to EL0 on X and stores v0-v7. The first word at the resume pc
 *      is an FP arithmetic instruction (not in the subset), so no fragment
 *      starts there and the state it sees is exactly what the kernel's exit
 *      path loaded. It must be P1, the native result.
 *
 * Without the invalidation step 4 clears TIF_FOREIGN_FPSTATE and step 5 sees P0.
 * Round r uses its own patterns. stdout is identical with KJIT on/off; the
 * reference is the same code run natively without the two syscalls.
 *
 * Only meaningful when the resume pcs are translated up front (self
 * registration): in auto mode (KJIT_AUTO=1) the rounds before the pcs are hot
 * run natively, and once the C code around the asm is hot too the load and
 * the first read run in a bracket, which invalidates the binding by itself.
 * It still must pass there.
 *
 *   fp_stale [rounds=300]
 *
 * Needs three online CPUs (0, 1, 2). glibc's rseq registration is switched off
 * (the program re-executes itself with GLIBC_TUNABLES=glibc.pthread.rseq=0):
 * a registered rseq area makes every migration set TIF_NOTIFY_RESUME, the
 * runtime declines to run (kjit_can_run) and step 3 would run natively.
 */
#include "kjit_test.h"
#include <pthread.h>
#include <sched.h>
#include <sys/syscall.h>
#include <time.h>

/*
 * x0 = 8 x 16 bytes of v0-v7 in and out, x1 = pipe A read fd, x2 = pipe B read
 * fd, x3 = flags[2], x4 = tag, x5 = do_svc.
 */
void fp_stale_run(uint8_t *state, long fd_a, long fd_b, volatile uint64_t *flags, uint64_t tag,
		  uint64_t do_svc);

asm(".text\n"
    ".global fp_stale_run\n"
    ".type fp_stale_run, %function\n"
    "fp_stale_run:\n"
    "	mov	x9, x0\n"
    "	mov	x10, x2\n"
    "	mov	x11, x3\n"
    "	sub	sp, sp, #16\n"
    "	ld1	{v0.16b, v1.16b, v2.16b, v3.16b}, [x0]\n"
    "	add	x7, x0, #64\n"
    "	ld1	{v4.16b, v5.16b, v6.16b, v7.16b}, [x7]\n"
    "	cbz	x5, 3f\n"
    "	str	x4, [x11]\n"
    "	mov	x0, x1\n"
    "	mov	x1, sp\n"
    "	mov	x2, #1\n"
    "	mov	x8, #63\n"			/* read(pipe A): blocks until H moved us */
    "	svc	#0\n"
    "3:	add	v0.2d, v0.2d, v1.2d\n"	/* P0 -> P1, in a fragment */
    "	eor	v2.16b, v2.16b, v0.16b\n"
    "	shl	v3.2d, v2.2d, #7\n"
    "	ushr	v4.2d, v2.2d, #3\n"
    "	orr	v3.16b, v3.16b, v4.16b\n"
    "	add	v1.2d, v1.2d, v3.2d\n"
    "	ext	v5.16b, v0.16b, v1.16b, #3\n"
    "	eor	v6.16b, v6.16b, v5.16b\n"
    "	add	v7.2d, v7.2d, v6.2d\n"
    "	eor	v0.16b, v0.16b, v7.16b\n"
    "	cbz	x5, 4f\n"
    "	str	x4, [x11, #8]\n"
    "	mov	x0, x10\n"
    "	mov	x1, sp\n"
    "	mov	x2, #1\n"
    "	mov	x8, #63\n"			/* read(pipe B): blocks until H moved us back */
    "	svc	#0\n"
    "4:	fadd	s16, s16, s16\n"		/* unsupported: no fragment starts here */
    "	st1	{v0.16b, v1.16b, v2.16b, v3.16b}, [x9]\n"
    "	add	x7, x9, #64\n"
    "	st1	{v4.16b, v5.16b, v6.16b, v7.16b}, [x7]\n"
    "	add	sp, sp, #16\n"
    "	ret\n");

#define CPU_X 0
#define CPU_Y 1
#define CPU_Z 2
#define WAIT_NS (20LL * 1000000000LL)

struct ctl {
	pid_t tid;			/* the tested thread */
	long rounds;
	int pipe_a[2], pipe_b[2];
	volatile uint64_t flags[2];	/* round tag, stored by the asm before each read */
	pthread_t helper;
};

static long long now_ns(void)
{
	struct timespec t;

	clock_gettime(CLOCK_MONOTONIC, &t);
	return (long long)t.tv_sec * 1000000000LL + t.tv_nsec;
}

static void pin(pid_t tid, int cpu)
{
	cpu_set_t set;

	CPU_ZERO(&set);
	CPU_SET(cpu, &set);
	if (sched_setaffinity(tid, sizeof(set), &set))
		die("sched_setaffinity(%d, cpu %d): %s", (int)tid, cpu, strerror(errno));
}

/* The state letter of thread @tid in /proc/self/task/<tid>/stat. */
static char thread_state(int fd)
{
	char buf[512];
	ssize_t n = pread(fd, buf, sizeof(buf) - 1, 0);
	char *p;

	if (n <= 0)
		die("read thread stat: %s", n < 0 ? strerror(errno) : "eof");
	buf[n] = 0;
	p = strrchr(buf, ')');
	if (!p || p[1] != ' ')
		die("unexpected thread stat '%s'", buf);
	return p[2];
}

static void wait_tag(volatile uint64_t *flag, uint64_t tag, long round)
{
	long long end = now_ns() + WAIT_NS;

	while (__atomic_load_n(flag, __ATOMIC_ACQUIRE) != tag) {
		if (now_ns() > end)
			die("round %ld: the tested thread never reached its read", round);
		usleep(20);
	}
}

static void wait_asleep(int fd, long round)
{
	long long end = now_ns() + WAIT_NS;

	while (thread_state(fd) != 'S') {
		if (now_ns() > end)
			die("round %ld: the tested thread never blocked", round);
		usleep(20);
	}
}

static void *helper(void *arg)
{
	struct ctl *c = arg;
	char path[64];
	int fd;

	pin(0, CPU_Z);
	snprintf(path, sizeof(path), "/proc/self/task/%d/stat", (int)c->tid);
	fd = open(path, O_RDONLY);
	if (fd < 0)
		die("open %s: %s", path, strerror(errno));
	for (long r = 0; r < c->rounds; r++) {
		uint64_t tag = (uint64_t)r + 1;

		wait_tag(&c->flags[0], tag, r);
		wait_asleep(fd, r);
		pin(c->tid, CPU_Y);
		if (write(c->pipe_a[1], "a", 1) != 1)
			die("write pipe A: %s", strerror(errno));
		wait_tag(&c->flags[1], tag, r);
		wait_asleep(fd, r);
		pin(c->tid, CPU_X);
		if (write(c->pipe_b[1], "b", 1) != 1)
			die("write pipe B: %s", strerror(errno));
	}
	close(fd);
	return NULL;
}

static uint64_t fnv(const uint8_t *p, size_t n)
{
	uint64_t h = 0xcbf29ce484222325ull;

	for (size_t i = 0; i < n; i++)
		h = (h ^ p[i]) * 0x100000001b3ull;
	return h;
}

int main(int argc, char **argv)
{
	long rounds = argc > 1 ? atol(argv[1]) : 300;
	static struct ctl c;
	struct kjit_snap s0, s1;
	uint64_t digest = 0;

	if (!getenv("FP_STALE_NORSEQ")) {
		setenv("GLIBC_TUNABLES", "glibc.pthread.rseq=0", 1);
		setenv("FP_STALE_NORSEQ", "1", 1);
		execv("/proc/self/exe", argv);
		die("re-exec: %s", strerror(errno));
	}
	if (rounds < 1 || sysconf(_SC_NPROCESSORS_ONLN) < 3)
		die("usage: fp_stale [rounds] (needs 3 online CPUs)");
	c.rounds = rounds;
	c.tid = (pid_t)syscall(SYS_gettid);
	if (pipe(c.pipe_a) || pipe(c.pipe_b))
		die("pipe: %s", strerror(errno));
	kjit_register_self();
	s0 = kjit_snap();
	if (pthread_create(&c.helper, NULL, helper, &c))
		die("pthread_create");
	pin(0, CPU_X);
	for (long r = 0; r < rounds; r++) {
		uint8_t ref[128] __attribute__((aligned(16))), got[128] __attribute__((aligned(16)));

		for (int i = 0; i < 128; i++)
			ref[i] = got[i] = (uint8_t)(r * 29 + i * 13 + 5);
		fp_stale_run(ref, -1, -1, c.flags, 0, 0);
		fp_stale_run(got, c.pipe_a[0], c.pipe_b[0], c.flags, (uint64_t)r + 1, 1);
		if (memcmp(ref, got, sizeof(ref))) {
			int reg = 0;

			while (!memcmp(ref + 16 * reg, got + 16 * reg, 16))
				reg++;
			die("round %ld: v%d differs after the migrations (ref %#llx, got %#llx): stale FP/SIMD state",
			    r, reg, (unsigned long long)fnv(ref, sizeof(ref)),
			    (unsigned long long)fnv(got, sizeof(got)));
		}
		digest ^= fnv(ref, sizeof(ref)) + (uint64_t)r;
	}
	pthread_join(c.helper, NULL);
	s1 = kjit_snap();
	kjit_report("fp_stale", s0, s1);
	printf("fp_stale rounds=%ld digest=%#llx\n", rounds, (unsigned long long)digest);
	/* One bracket per round at least: the run between the two reads. */
	kjit_check_fpsimd("fp_stale", s0, s1, 0, rounds, 80);
	return 0;
}
