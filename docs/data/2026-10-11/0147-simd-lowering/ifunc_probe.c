#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

int main(void)
{
	static const char *const names[] = { "memcpy", "memmove", "memset", "strlen", "memchr", "strchr", "strcmp",
					     "memcmp", "strnlen", "strrchr", "strcpy", "stpcpy", "strncmp", "rawmemchr" };
	char line[512];
	unsigned long base = 0;
	FILE *f = fopen("/proc/self/maps", "r");

	while (f && fgets(line, sizeof(line), f)) {
		unsigned long lo = 0;
		char *p = line;

		if (!strstr(line, "libc.so.6"))
			continue;
		/* the first mapping of the file (file offset 0): "lo-hi perms 00000000 ..." */
		while (*p && *p != ' ')
			p++;
		while (*p == ' ')
			p++;
		while (*p && *p != ' ')
			p++;
		while (*p == ' ')
			p++;
		if (strncmp(p, "00000000 ", 9))
			continue;
		for (p = line; *p && *p != '-'; p++)
			lo = lo * 16 + (*p <= '9' ? *p - '0' : *p - 'a' + 10);
		base = lo;
		break;
	}
	printf("ifunc libc_base=%#lx\n", base);
	for (unsigned i = 0; i < sizeof(names) / sizeof(names[0]); i++)
		printf("ifunc %s offset=%#lx\n", names[i], (unsigned long)dlsym(RTLD_DEFAULT, names[i]) - base);
	return 0;
}
