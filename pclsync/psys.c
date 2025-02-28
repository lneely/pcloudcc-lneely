#include <errno.h>
#include <signal.h>
#include <sys/resource.h>

#include "psys.h"
#include "plibs.h"
#include "pmemlock.h"

static uid_t psync_uid;
static gid_t psync_gid;
static gid_t *psync_gids;
static int psync_gids_cnt;


static void psync_check_no_sql_lock(uint64_t millisec) {
#if IS_DEBUG
  if (psync_sql_islocked()) {
    debug(D_CRITICAL, "trying to sleep while holding sql lock, aborting");
    psync_sql_dump_locks();
    abort();
  }
#endif
}

uid_t psys_get_uid() {
  return psync_uid;
}

gid_t psys_get_gid() {
  return psync_gid;
}

gid_t *psys_get_gids() {
  return psync_gids;
}

int psys_get_gids_cnt() {
  return psync_gids_cnt;
}

void psys_init() {
  struct rlimit limit;
  limit.rlim_cur = limit.rlim_max = 2048;
  if (setrlimit(RLIMIT_NOFILE, &limit))
    debug(D_ERROR, "setrlimit failed errno=%d", errno);
#if IS_DEBUG
  if (getrlimit(RLIMIT_CORE, &limit))
    debug(D_ERROR, "getrlimit failed errno=%d", errno);
  else {
    limit.rlim_cur = limit.rlim_max;
    if (setrlimit(RLIMIT_CORE, &limit))
      debug(D_ERROR, "setrlimit failed errno=%d", errno);
  }
#endif
  signal(SIGPIPE, SIG_IGN);
  psync_uid = getuid();
  psync_gid = getgid();
  psync_gids_cnt = getgroups(0, NULL);
  psync_gids = psync_new_cnt(gid_t, psync_gids_cnt);
  if (unlikely_log(getgroups(psync_gids_cnt, psync_gids) != psync_gids_cnt))
    psync_gids_cnt = 0;
  pmemlock_set_pagesize(sysconf(_SC_PAGESIZE));
  debug(D_NOTICE, "detected page size %d", pmemlock_get_pagesize());
}

time_t sys_time_seconds() {
#if defined(_POSIX_TIMERS) && _POSIX_TIMERS > 0
  struct timespec ts;
  if (likely_log(clock_gettime(CLOCK_REALTIME, &ts) == 0))
    return ts.tv_sec;
  else
    return time(NULL);
#else
  return time(NULL);
#endif
}

uint64_t sys_time_milliseconds() {
  struct timespec tm;
  clock_gettime(CLOCK_REALTIME, &tm);
  return tm.tv_sec * 1000 + tm.tv_nsec / 1000000;
}

void sys_sleep_milliseconds_fast(uint64_t millisec) {
  struct timespec tm;
  tm.tv_sec = millisec / 1000;
  tm.tv_nsec = (millisec % 1000) * 1000000;
  nanosleep(&tm, NULL);
}

void sys_sleep_milliseconds(uint64_t millisec) {
  psync_check_no_sql_lock(millisec);
  sys_sleep_milliseconds_fast(millisec);
}
