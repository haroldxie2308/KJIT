#include "uca_helper.h"
#include "kjit_helper.h"

// UCA Allocation helpers
void *uca_vmalloc(size_t size)
{
    return vmalloc(size);
}
EXPORT_SYMBOL_GPL(uca_vmalloc);

void *uca_vcalloc(size_t nmemb, size_t size)
{
    void *ptr = vmalloc(nmemb * size);
    memset(ptr, 0, nmemb * size);
    return ptr;
}
EXPORT_SYMBOL_GPL(uca_vcalloc);

void *uca_vrealloc(void *ptr, size_t size)
{
    return vkrealloc(ptr, size);
}
EXPORT_SYMBOL_GPL(uca_vrealloc);

void uca_vfree(void *ptr)
{
    vfree(ptr);
}
EXPORT_SYMBOL_GPL(uca_vfree);