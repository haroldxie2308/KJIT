#include "kjit_helper.h"

// Basic helper functions
/*
 * vkrealloc - Reallocate memory previously allocated by vmalloc.
 * @ptr: Pointer to the previously allocated memory (can be NULL).
 * @size: The new size in bytes.
 *
 * Returns a pointer to the new allocated memory, or NULL on failure.
 * If @ptr is NULL, it behaves like vmalloc. If @size is 0 and @ptr
 * is not NULL, it frees the memory.
 */
void *vkrealloc(void *ptr, size_t size)
{
    void *new_ptr;

    if (ptr == NULL)
        return vmalloc(size);

    if (size == 0) {
        vfree(ptr);
        return NULL;
    }

    new_ptr = vmalloc(size);
    if (new_ptr == NULL)
        return NULL;

    memcpy(new_ptr, ptr, min(size, ksize(ptr)));
    vfree(ptr);

    return new_ptr;
}

void __assert_fail(const char *assertion, const char *file, unsigned int line, const char *function)
{
    printk(KERN_ERR "Assertion failure: %s\n", assertion);
}


// Capstone related helper functions
void *kjit_cs_malloc(size_t size)
{
#ifdef CAPSTONE_KMALLOC
    return kmalloc(size, GFP_ATOMIC);
#else
    return vmalloc(size);
#endif
}

void *kjit_cs_calloc(size_t nmemb, size_t size)
{
#ifdef CAPSTONE_KMALLOC
    return kcalloc(nmemb, size, GFP_ATOMIC);
#else
    void *ptr = vmalloc(nmemb * size);
    memset(ptr, 0, nmemb * size);
    return ptr;
#endif
}

void *kjit_cs_realloc(void *ptr, size_t size)
{
#ifdef CAPSTONE_KMALLOC
    return krealloc(ptr, size, GFP_ATOMIC);
#else
    return vkrealloc(ptr, size);
#endif
}

void kjit_cs_free(void *ptr)
{
#ifdef CAPSTONE_KMALLOC
    kfree(ptr);
#else
    vfree(ptr);
#endif
}

int kjit_cs_vsnprintf(char *str, size_t size, const char *format, va_list ap)
{
    return vsnprintf(str, size, format, ap);
}

bool kjit_cs_setup(void)
{
    cs_opt_mem setup;

    setup.malloc = kjit_cs_malloc;
    setup.calloc = kjit_cs_calloc;
    setup.realloc = kjit_cs_realloc;
    setup.free = kjit_cs_free;
    setup.vsnprintf = kjit_cs_vsnprintf;

    if (!cs_option(0, CS_OPT_MEM, (size_t)&setup)) {
        return true;
    } else {
        return false;
    }
}
EXPORT_SYMBOL_GPL(kjit_cs_setup);

unsigned int kjit_cs_get_operand_type(struct cs_insn *insn, size_t idx)
{
    return insn->detail->arm64.operands[idx].type;
}
EXPORT_SYMBOL_GPL(kjit_cs_get_operand_type);

unsigned long kjit_cs_get_operand_imm(struct cs_insn *insn, size_t idx)
{
    return insn->detail->arm64.operands[idx].imm;
}
EXPORT_SYMBOL_GPL(kjit_cs_get_operand_imm);

unsigned int kjit_cs_get_operand_reg(struct cs_insn *insn, size_t idx)
{
    return (unsigned int)insn->detail->arm64.operands[idx].reg;
}
EXPORT_SYMBOL_GPL(kjit_cs_get_operand_reg);

unsigned int kjit_cs_get_cc(struct cs_insn *insn)
{
    return (unsigned int)insn->detail->arm64.cc;
}
EXPORT_SYMBOL_GPL(kjit_cs_get_cc);

// KJIT specific
int kjit_fault_handler(unsigned long addr, struct pt_regs *regs)
{
    if (regs->regs[18] == 0x1234) {
        return 1;
    } else {
        return 0;
    }
}
EXPORT_SYMBOL_GPL(kjit_fault_handler);
