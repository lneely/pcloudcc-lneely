#ifndef __PMEM_H
#define __PMEM_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
  PMEM_SUBSYS_API,
  PMEM_SUBSYS_CACHE,
  PMEM_SUBSYS_UPLOAD,
  PMEM_SUBSYS_DOWNLOAD,
  PMEM_SUBSYS_SYNC,
  PMEM_SUBSYS_OTHER
} pmem_subsystem_t;

void *pmem_mmap(size_t size);
void *pmem_mmap_safe(size_t size);
int pmem_munmap(void *ptr, size_t size);
int pmem_mlock(void *ptr, size_t size);
int pmem_munlock(void *ptr, size_t size);
void pmem_reset(void *ptr, size_t size);
void *pmem_calloc_safe(size_t nmemb, size_t size);
void *pmem_malloc(pmem_subsystem_t subsystem, size_t size);
void pmem_free(pmem_subsystem_t subsystem, void *ptr);
void *pmem_realloc(pmem_subsystem_t subsystem, void *ptr, size_t size);
void *pmem_malloc_array(pmem_subsystem_t subsystem, size_t nmemb, size_t size);
size_t pmem_get_stats(pmem_subsystem_t subsystem);

#ifdef __cplusplus
}
#endif

#endif