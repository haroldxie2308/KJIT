#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <stdint.h>
#include <time.h>

// Define syscall number for getpid on ARM64
#define SYSCALL_GETPID_MACOS 20
#define SYSCALL_GETPID 172

int svc() {
    // SVC in subroutine
    register int x8 __asm__("x8") = SYSCALL_GETPID;
    register int x0 __asm__("x0");
    __asm__ __volatile__("svc 0" : "=r" (x0) : "r" (x8));
    return x0;
}

int subroutine(int b) {
    unsigned long long count = 0;
    register int a __asm__("x4") = 0;
    while (count < (1 << 25)) {
        a = svc();
        if (a % 3) {
            // a = b - a
            __asm__ __volatile__("sub %0, %1, %0" : "+r" (a) : "r" (b));
        } else {
            // a = a * 5
            __asm__ __volatile__("mul %0, %0, %1" : "+r" (a) : "r" (5));
            // b = b - a
            __asm__ __volatile__("sub %0, %1, %0" : "+r" (b) : "r" (a));
        }

        // Do some operations in Assembly
        __asm__ __volatile__("ldp x5, x12, [sp, #16]!");
        __asm__ __volatile__("sub sp, sp, #16");
        __asm__ __volatile__("add x17, x11, x12");  // x17 = x11 + x12;
        __asm__ __volatile__("sub x11, x11, x12");  // x1 -= x12;

        if (a == 0x9E370001) {  /* Some magic prime number from the book: Understanding the Linux Kernel */
            printf("Branch Reached.\n");
            __asm__ __volatile__("add x4, x11, x12");
            break;
        } else {
            __asm__ __volatile__("mul x4, x17, x0");
        }
        ++count;
    }
    return a * b;
}

int main() {
    printf("Syscall subroutine test started\n");
    int i = 0;
    register int x11 __asm__("x11") = 13;
    register int x12 __asm__("x12") = 0;
    register int x17 __asm__("x17") = 34;
    register int x4 __asm__("x4") = 0;
    clock_t tic = clock();
    subroutine(x17);
    clock_t toc = clock();
    printf("Finished within %fs\n", (double)(toc - tic) / CLOCKS_PER_SEC);
    i++;
    return 0;
}
