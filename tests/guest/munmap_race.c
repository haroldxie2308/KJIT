// SPDX-License-Identifier: GPL-2.0
/*
 * munmap of hot text while another thread runs it: the loop lives in an
 * anonymous RX mapping (copied there), is translated, and runs hot in thread
 * A; the main thread unmaps it. The mmu_notifier drops the fragment (a run in
 * progress finishes its bounded run), thread A returns to userspace at an
 * unmapped PC and the process dies with SIGSEGV, exactly as without KJIT.
 * The kernel must survive; the runner checks the exit status and the log.
 */
#include "kjit_test.h"
#include <pthread.h>
#include <sys/mman.h>

extern char hot_code_start[], hot_code_svc[], hot_code_end[];
asm(".text\n"
    ".p2align 2\n"
    ".globl hot_code_start\n"
    "hot_code_start:\n"
    "1:	mov	x8, #173\n"		/* getppid */
    ".globl hot_code_svc\n"
    "hot_code_svc:\n"
    "	svc	#0\n"
    "	add	x19, x19, #1\n"
    "	b	1b\n"
    ".globl hot_code_end\n"
    "hot_code_end:\n");

static void *code;
static volatile int running;

static void *hot_thread(void *arg)
{
	running = 1;
	((void (*)(void))code)();
	return NULL;
}

int main(void)
{
	size_t len = hot_code_end - hot_code_start;
	uint64_t svc_off = hot_code_svc - hot_code_start;
	struct kjit_snap s0, s1;
	pthread_t t;
	int err;

	code = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (code == MAP_FAILED)
		die("mmap: %s", strerror(errno));
	memcpy(code, hot_code_start, len);
	__builtin___clear_cache(code, (char *)code + len);
	if (mprotect(code, 4096, PROT_READ | PROT_EXEC))
		die("mprotect: %s", strerror(errno));
	err = kjit_translate_self((uintptr_t)code + svc_off + 4);
	if (err)
		die("translate: %s", strerror(err));
	s0 = kjit_snap();
	if (pthread_create(&t, NULL, hot_thread, NULL))
		die("pthread_create");
	while (!running)
		;
	usleep(200 * 1000);
	s1 = kjit_snap();
	kjit_report("munmap_race", s0, s1);
	if (kjit_expect("inkernel") && s1.in_kernel - s0.in_kernel < 1000)
		die("munmap_race: the loop was not hot (%lld)", s1.in_kernel - s0.in_kernel);
	if (write(1, "munmap_race: unmapping\n", 23) != 23)
		die("write: %s", strerror(errno));
	if (munmap(code, 4096))
		die("munmap: %s", strerror(errno));
	/* Thread A faults on its next instruction fetch from the unmapped page. */
	sleep(10);
	die("munmap_race: still alive after munmap");
}
