#ifndef __PMEM_H
#define __PMEM_H

#include <stddef.h>

void *pmem_mmap(size_t size);
void *pmem_mmap_safe(size_t size);
int pmem_munmap(void *ptr, size_t size);
int pmem_mlock(void *ptr, size_t size);
int pmem_munlock(void *ptr, size_t size);
void pmem_reset(void *ptr, size_t size);

#endif