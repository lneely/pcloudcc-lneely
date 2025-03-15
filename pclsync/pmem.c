#include "pcompiler.h"
#include "psql.h"
#include "pdbg.h"

#include <sys/mman.h>

void *pmem_mmap(size_t size) {
#if defined(MAP_ANONYMOUS)
  return mmap(NULL, size, PROT_READ | PROT_WRITE,
              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
#else
  return malloc(size);
#endif
}

PSYNC_NOINLINE static void *psync_mmap_anon_emergency(size_t size) {
  void *ret;
  pdbg_logf(D_WARNING, "could not allocate %lu bytes", size);
  psync_try_free_memory();
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
#if defined(MAP_ANONYMOUS)
  return munmap(ptr, size);
#else
  free(ptr);
  return 0;
#endif
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
#if defined(MAP_ANONYMOUS) && defined(MADV_DONTNEED)
  madvise(ptr, size, MADV_DONTNEED);
#endif
}
