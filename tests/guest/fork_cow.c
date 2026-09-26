// SPDX-License-Identifier: GPL-2.0
/*
 * Copy-on-write through a fragment: the parent registers, fills a private
 * anonymous page and forks, so the page is write-protected and shared. Both
 * processes (the child registers its own mm) run a hot loop whose fragment
 * stores into the page. Each store must break CoW (a permission fault on the
 * STTR, handled by the normal fault path), never leave through the Mem stub,
 * and each process must see only its own writes. The runner checks exit_mem.
 */
#include "kjit_test.h"
#include <sys/mman.h>
#include <sys/wait.h>

static uint64_t run(uint64_t *page, uint64_t seed, int null)
{
	uint64_t acc = seed, n = 5000;
	char byte = 0;

	asm volatile(
		"1:\n"
		"	mov	x0, %[null]\n"
		"	mov	x1, %[buf]\n"
		"	mov	x2, #1\n"
		"	mov	x8, #64\n"			/* write(/dev/null) */
		"	svc	#0\n"
		"	ldr	x3, [%[page], #8]\n"
		"	add	x3, x3, x0\n"
		"	eor	x3, x3, %[acc]\n"
		"	str	x3, [%[page], #8]\n"
		"	add	%[acc], %[acc], x3\n"
		"	str	%[acc], [%[page], #2048]\n"
		"	subs	%[n], %[n], #1\n"
		"	b.ne	1b\n"
		: [acc] "+r"(acc), [n] "+r"(n)
		: [page] "r"(page), [null] "r"((long)null), [buf] "r"(&byte)
		: "x0", "x1", "x2", "x3", "x8", "cc", "memory");
	return acc;
}

int main(void)
{
	uint64_t *page = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	int null = open("/dev/null", O_WRONLY), status;
	uint64_t acc;
	pid_t pid;

	if (page == MAP_FAILED || null < 0)
		die("setup: %s", strerror(errno));
	page[1] = 0x1111;
	page[256] = 0x2222;
	kjit_register_self();
	fflush(stdout);

	pid = fork();
	if (pid < 0)
		die("fork: %s", strerror(errno));
	if (pid == 0) {
		kjit_register_self();
		acc = run(page, 0xc0ffee, null);
		printf("fork_cow child acc=%#llx page=%#llx,%#llx\n", (unsigned long long)acc,
		       (unsigned long long)page[1], (unsigned long long)page[256]);
		return 0;
	}
	/* Parent writes too, while the child may still share the page. */
	acc = run(page, 0xbeef, null);
	if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status) || WEXITSTATUS(status))
		die("child failed: status %#x", status);
	printf("fork_cow parent acc=%#llx page=%#llx,%#llx\n", (unsigned long long)acc,
	       (unsigned long long)page[1], (unsigned long long)page[256]);
	return 0;
}
