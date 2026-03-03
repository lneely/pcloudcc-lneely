// debug/psys_debug.c - debug implementations for psys debug helpers

#include <errno.h>
#include <sys/resource.h>

#include "pdbg.h"
#include "psql.h"
#include "psys.h"

void psys_debug_abort_on_sqllock(uint64_t millisec) {
  if (psql_locked()) {
    pdbg_logf(D_CRITICAL, "trying to sleep while holding sql lock, aborting");
    psql_dump_locks();
    abort();
  }
}

void psys_debug_configure_core_dump() {
  struct rlimit limit;
  if (getrlimit(RLIMIT_CORE, &limit))
    pdbg_logf(D_ERROR, "getrlimit failed errno=%d", errno);
  else {
    limit.rlim_cur = limit.rlim_max;
    if (setrlimit(RLIMIT_CORE, &limit))
      pdbg_logf(D_ERROR, "setrlimit failed errno=%d", errno);
  }
}
