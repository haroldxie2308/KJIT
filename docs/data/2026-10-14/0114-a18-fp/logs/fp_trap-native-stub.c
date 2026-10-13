#define KJIT_TEST_H
#define _GNU_SOURCE
#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
static inline void die(const char *fmt, ...) { va_list ap; va_start(ap, fmt); vfprintf(stderr, fmt, ap); va_end(ap); exit(1); }
static inline int kjit_auto_mode(void) { return 1; }
static inline long kjit_auto_warmup(void) { return 0; }
static inline void kjit_register_self(void) {}
static inline int kjit_translate_self(uint64_t pc) { (void)pc; return 0; }
static inline long long kjit_stat(const char *n) { (void)n; return 0; }
static inline int kjit_expect(const char *w) { (void)w; return 0; }
struct kjit_snap { long long fp_entries; };
static inline struct kjit_snap kjit_snap(void) { struct kjit_snap s = {0}; return s; }
static inline void kjit_report(const char *t, struct kjit_snap a, struct kjit_snap b) { (void)t; (void)a; (void)b; }
#include "fp_trap.c"
