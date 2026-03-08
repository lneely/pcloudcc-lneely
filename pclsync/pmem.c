#include <sys/mman.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "pcompiler.h"
#include "psql.h"
#include "pdbg.h"
#include "pmem.h"

static size_t subsystem_stats[6] = {0};

typedef struct {
  size_t size;
  pmem_subsystem_t subsystem;
} pmem_header_t;

void *pmem_mmap(size_t size) {
  void *ret = mmap(NULL, size, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  return (ret == MAP_FAILED) ? NULL : ret;
}

PSYNC_NOINLINE static void *psync_mmap_anon_emergency(size_t size) {
  void *ret;
  pdbg_logf(D_WARNING, "could not allocate %lu bytes", size);
  psql_try_free();
  ret = pmem_mmap(size);
  if (likely(ret))
    return ret;
  else {
    pdbg_logf(
        D_CRITICAL,
        "could not allocate %lu bytes even after freeing some memory, aborting",
        size);
    abort();
    return NULL;
  }
}

void *pmem_mmap_safe(size_t size) {
  void *ret;
  ret = pmem_mmap(size);
  if (likely(ret))
    return ret;
  else
    return psync_mmap_anon_emergency(size);
}

int pmem_munmap(void *ptr, size_t size) {
  return munmap(ptr, size);
}


int pmem_mlock(void *ptr, size_t size) {
#if defined(_POSIX_MEMLOCK_RANGE)
  return mlock(ptr, size);
#else
  return -1;
#endif
}

int pmem_munlock(void *ptr, size_t size) {
#if defined(_POSIX_MEMLOCK_RANGE)
  return munlock(ptr, size);
#else
  return -1;
#endif
}

void pmem_reset(void *ptr, size_t size) {
  madvise(ptr, size, MADV_DONTNEED);
}

void *pmem_calloc_safe(size_t nmemb, size_t size) {
  if (nmemb != 0 && size > SIZE_MAX / nmemb) {
    return NULL;
  }
  return calloc(nmemb, size);
}

void *pmem_malloc(pmem_subsystem_t subsystem, size_t size) {
  pmem_header_t *hdr;
  size_t total_size = sizeof(pmem_header_t) + size;
  
  hdr = (pmem_header_t *)malloc(total_size);
  if (!hdr) {
    return NULL;
  }
  
  hdr->size = size;
  hdr->subsystem = subsystem;
  __atomic_add_fetch(&subsystem_stats[subsystem], size, __ATOMIC_RELAXED);
  
  return (void *)(hdr + 1);
}

void pmem_free(pmem_subsystem_t subsystem, void *ptr) {
  pmem_header_t *hdr;
  
  if (!ptr) {
    return;
  }
  
  hdr = ((pmem_header_t *)ptr) - 1;
  __atomic_sub_fetch(&subsystem_stats[hdr->subsystem], hdr->size, __ATOMIC_RELAXED);
  free(hdr);
}

void *pmem_realloc(pmem_subsystem_t subsystem, void *ptr, size_t size) {
  pmem_header_t *hdr, *new_hdr;
  size_t old_size;
  size_t total_size = sizeof(pmem_header_t) + size;
  
  if (!ptr) {
    return pmem_malloc(subsystem, size);
  }
  
  hdr = ((pmem_header_t *)ptr) - 1;
  old_size = hdr->size;
  
  new_hdr = (pmem_header_t *)realloc(hdr, total_size);
  if (!new_hdr) {
    return NULL;
  }
  
  __atomic_sub_fetch(&subsystem_stats[hdr->subsystem], old_size, __ATOMIC_RELAXED);
  __atomic_add_fetch(&subsystem_stats[subsystem], size, __ATOMIC_RELAXED);
  
  new_hdr->size = size;
  new_hdr->subsystem = subsystem;
  
  return (void *)(new_hdr + 1);
}

size_t pmem_get_stats(pmem_subsystem_t subsystem) {
  return __atomic_load_n(&subsystem_stats[subsystem], __ATOMIC_RELAXED);
}

void *pmem_malloc_array(pmem_subsystem_t subsystem, size_t nmemb, size_t size) {
  pmem_header_t *hdr;
  size_t alloc_size;
  size_t total_size;
  void *ptr;
  
  if (nmemb != 0 && size > SIZE_MAX / nmemb) {
    return NULL;
  }
  
  alloc_size = nmemb * size;
  total_size = sizeof(pmem_header_t) + alloc_size;
  
  hdr = (pmem_header_t *)malloc(total_size);
  if (!hdr) {
    return NULL;
  }
  
  hdr->size = alloc_size;
  hdr->subsystem = subsystem;
  __atomic_add_fetch(&subsystem_stats[subsystem], alloc_size, __ATOMIC_RELAXED);
  
  ptr = (void *)(hdr + 1);
  memset(ptr, 0, alloc_size);
  
  return ptr;
}
