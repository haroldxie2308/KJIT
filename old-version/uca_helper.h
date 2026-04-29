#ifndef UCA_HELPER_H
#define UCA_HELPER_H

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/stdarg.h>
#include <linux/gfp.h>

// UCA Allocation helpers
void *uca_vmalloc(size_t size);
void *uca_vcalloc(size_t nmemb, size_t size);
void *uca_vrealloc(void *ptr, size_t size);
void uca_vfree(void *ptr);

#endif