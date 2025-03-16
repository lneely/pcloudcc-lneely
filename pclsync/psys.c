#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <sys/resource.h>

#include "pdbg.h"
#include "psql.h"
#include "psys.h"

static uid_t psync_uid;
static gid_t psync_gid;
static gid_t *psync_gids;
static int psync_gids_cnt;

static void abort_on_sqllock(uint64_t millisec) {
#if IS_DEBUG
  if (psql_locked()) {
    pdbg_logf(D_CRITICAL, "trying to sleep while holding sql lock, aborting");
    psql_dump_locks();
    abort();
  }
#endif
}

uid_t psys_get_uid() { return psync_uid; }

gid_t psys_get_gid() { return psync_gid; }

gid_t *psys_get_gids() { return psync_gids; }

int psys_get_gids_cnt() { return psync_gids_cnt; }

void psys_init() {
  struct rlimit limit;
  limit.rlim_cur = limit.rlim_max = 2048;
  if (setrlimit(RLIMIT_NOFILE, &limit))
    pdbg_logf(D_ERROR, "setrlimit failed errno=%d", errno);
#if IS_DEBUG
  if (getrlimit(RLIMIT_CORE, &limit))
    pdbg_logf(D_ERROR, "getrlimit failed errno=%d", errno);
  else {
    limit.rlim_cur = limit.rlim_max;
    if (setrlimit(RLIMIT_CORE, &limit))
      pdbg_logf(D_ERROR, "setrlimit failed errno=%d", errno);
  }
#endif
  signal(SIGPIPE, SIG_IGN);
  psync_uid = getuid();
  psync_gid = getgid();
  psync_gids_cnt = getgroups(0, NULL);
  psync_gids = malloc(sizeof(gid_t) * psync_gids_cnt);
  if (pdbg_unlikely(getgroups(psync_gids_cnt, psync_gids) != psync_gids_cnt))
    psync_gids_cnt = 0;
  pdbg_logf(D_NOTICE, "detected page size %ld", sysconf(_SC_PAGESIZE));
}

time_t psys_time_seconds() {
  struct timespec ts;
  if (pdbg_likely(clock_gettime(CLOCK_REALTIME, &ts) == 0)) {
    return ts.tv_sec;
  } else {
    return time(NULL);
  }
}
uint64_t psys_time_milliseconds() {
  struct timespec tm;
  clock_gettime(CLOCK_REALTIME, &tm);
  return tm.tv_sec * 1000 + tm.tv_nsec / 1000000;
}

void psys_sleep_milliseconds_fast(uint64_t millisec) {
  struct timespec tm;
  tm.tv_sec = millisec / 1000;
  tm.tv_nsec = (millisec % 1000) * 1000000;
  nanosleep(&tm, NULL);
}

void psys_sleep_milliseconds(uint64_t millisec) {
  abort_on_sqllock(millisec);
  psys_sleep_milliseconds_fast(millisec);
}
