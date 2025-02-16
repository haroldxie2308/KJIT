#ifndef KJIT_HELPER_H
#define KJIT_HELPER_H

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/stdarg.h>

// Debugging purposes
#include <linux/stddef.h>
#include <asm/ptrace.h>

// Basic helper functions
void *vkrealloc(void *ptr, size_t size);
void __assert_fail(const char *assertion, const char *file, unsigned int line, const char *function);

// Capstone related helper functions
#include <capstone/capstone.h>
// #define CAPSTONE_KMALLOC
void *kjit_cs_malloc(size_t size);
void *kjit_cs_calloc(size_t nmemb, size_t size);
void *kjit_cs_realloc(void *ptr, size_t size);
void kjit_cs_free(void *ptr);
int kjit_cs_vsnprintf(char *str, size_t size, const char *format, va_list ap);
bool kjit_cs_setup(void);
unsigned int kjit_cs_get_operand_type(struct cs_insn *insn, size_t idx);
unsigned int kjit_cs_get_operand_reg(struct cs_insn *insn, size_t idx);
unsigned long kjit_cs_get_operand_imm(struct cs_insn *insn, size_t idx);
unsigned int kjit_cs_get_cc(struct cs_insn *insn);

// KJIT specific
int kjit_fault_handler(unsigned long addr, struct pt_regs *regs);

#endif