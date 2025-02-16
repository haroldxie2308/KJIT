#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <stdint.h>
#include <time.h>

// Define syscall number for getpid on ARM64
#define SYSCALL_GETPID 172

int svc() {
    // SVC in subroutine
    register int x8 __asm__("x8") = SYSCALL_GETPID;
    register int x0 __asm__("x0");
    __asm__ __volatile__("svc 0" : "=r" (x0) : "r" (x8));
    return x0;
}

int main() {
    printf("Syscall subroutine test started\n");
    unsigned long long count = 0;
    clock_t tic = clock();
    register int a __asm__("x4") = 0;
    while (count < (1 << 25)) {
        a = svc();
        ++count;
    }
    clock_t toc = clock();
    printf("easy finished within %ld\n", (toc - tic));
    return 0;
}
