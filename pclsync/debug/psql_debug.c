// debug/psql_debug.c - debug-build strong overrides for psql lock/query functions.
#include "../pmem.h"
// Compiled only when BUILD=debug. Strong symbols here override the weak stubs in psql.c.

#include <sqlite3.h>
#include <time.h>

#include "pcache.h"
#include "pdbg.h"
#include "plocks.h"
#include "pnetlibs.h"
#include "psettings.h"
#include "psql.h"
#include "psql_internal.h"
#include "putil.h"

#undef psql_trylock
#undef psql_lock
#undef psql_rdlock
#undef psql_statement
#undef psql_start
#undef psql_query_nocache
#undef psql_query
#undef psql_rdlock_nocache
#undef psql_query_rdlock
#undef psql_query_nolock_nocache
#undef psql_query_nolock
#undef psql_prepare_nocache
#undef psql_prepare

#define SQL_NO_LOCK 0
#define SQL_READ_LOCK 1
#define SQL_WRITE_LOCK 2

#define PSYNC_TNUMBER 1
#define PSYNC_TSTRING 2
#define PSYNC_TREAL 3
#define PSYNC_TNULL 4

extern PSYNC_THREAD const char *psync_thread_name;

// --------------------------------------------------------------------------
// Debug-only state
// --------------------------------------------------------------------------

typedef struct {
  psync_list list;
  const char *file;
  const char *thread;
  struct timespec tm;
  unsigned line;
} rd_lock_data;

static PSYNC_THREAD rd_lock_data *rdlock = NULL;
static PSYNC_THREAD unsigned long rdlockctr = 0;
static PSYNC_THREAD struct timespec rdlockstart;
unsigned long lockctr = 0;
static struct timespec lockstart;
static const char *wrlockfile = "none";
static const char *wrlockthread = "";
static unsigned wrlockline = 0;
static unsigned wrlocked = 0;
static pthread_t wrlocker;
static psync_list rdlocks = PSYNC_LIST_STATIC_INIT(rdlocks);
static pthread_mutex_t rdmutex = PTHREAD_MUTEX_INITIALIZER;

// --------------------------------------------------------------------------
// Internal helpers
// --------------------------------------------------------------------------

static void record_wrlock(const char *file, unsigned line) {
  if (unlikely(rdlock)) {
    pdbg_logf(D_BUG,
          "trying to get write lock at %s:%u, but read lock is already taken "
          "at %s:%u, aborting",
          file, line, rdlock->file, rdlock->line);
    sendpdbg_logf("trying to get write lock at %s:%u, but read lock is already "
              "taken at %s:%u, aborting",
              file, line, rdlock->file, rdlock->line);
    abort();
  }
  sendpdbg_assert(!wrlocked);
  pdbg_assert(!wrlocked);
  wrlockfile = file;
  wrlockline = line;
  wrlockthread = psync_thread_name;
  wrlocked = 1;
  wrlocker = pthread_self();
}

static void record_wrunlock() {
  sendpdbg_assert(pthread_equal(pthread_self(), wrlocker));
  sendpdbg_assert(wrlocked);
  pdbg_assert(pthread_equal(pthread_self(), wrlocker));
  pdbg_assert(wrlocked);
  wrlocked = 0;
}

static void record_rdlock(const char *file, unsigned line,
                          struct timespec *tm) {
  rd_lock_data *lock;
  lock = pmem_malloc(PMEM_SUBSYS_OTHER, sizeof(rd_lock_data));
  lock->file = file;
  lock->thread = psync_thread_name;
  lock->line = line;
  memcpy(&lock->tm, tm, sizeof(struct timespec));
  pthread_mutex_lock(&rdmutex);
  psync_list_add_tail(&rdlocks, &lock->list);
  pthread_mutex_unlock(&rdmutex);
  rdlock = lock;
}

static rd_lock_data *record_rdunlock() {
  rd_lock_data *lock;
  pdbg_assert(rdlock);
  lock = rdlock;
  rdlock = NULL;
  pthread_mutex_lock(&rdmutex);
  psync_list_del(&lock->list);
  pthread_mutex_unlock(&rdmutex);
  return lock;
}

// --------------------------------------------------------------------------
// Public debug functions
// --------------------------------------------------------------------------

void psql_dump_locks() {
  rd_lock_data *lock;
  char dttime[36];
  if (wrlocked) {
    putil_time_format(lockstart.tv_sec, lockstart.tv_nsec, dttime);
    pdbg_logf(D_ERROR, "write lock taken by thread %s from %s:%u at %s",
          wrlockthread, wrlockfile, wrlockline, dttime);
    sendpdbg_logf("write lock taken by thread %s from %s:%u at %s", wrlockthread,
              wrlockfile, wrlockline, dttime);
  }
  pthread_mutex_lock(&rdmutex);
  psync_list_for_each_element(lock, &rdlocks, rd_lock_data, list) {
    putil_time_format(lock->tm.tv_sec, lock->tm.tv_nsec, dttime);
    pdbg_logf(D_ERROR, "read lock taken by thread %s from %s:%u at %s",
          lock->thread, lock->file, lock->line, dttime);
    sendpdbg_logf("read lock taken by thread %s from %s:%u at %s", lock->thread,
              lock->file, lock->line, dttime);
  }
  pthread_mutex_unlock(&rdmutex);
}

int psql_do_trylock(const char *file, unsigned line) {
  if (plocks_trywrlock(&dblock))
    return -1;
  if (++lockctr == 1) {
    clock_gettime(CLOCK_REALTIME, &lockstart);
    record_wrlock(file, line);
  }
  return 0;
}

void psql_do_lock(const char *file, unsigned line) {
  if (plocks_trywrlock(&dblock)) {
    struct timespec start, end;
    unsigned long msec;
    clock_gettime(CLOCK_REALTIME, &start);
    memcpy(&end, &start, sizeof(end));
    end.tv_sec += PSYNC_DEBUG_LOCK_TIMEOUT;
    if (plocks_timedwrlock(&dblock, &end)) {
      pdbg_logf(D_BUG, "sql write lock timed out called from %s:%u", file, line);
      sendpdbg_logf("sql write lock timed out called from %s:%u", file, line);
      psql_dump_locks();
      abort();
    }
    clock_gettime(CLOCK_REALTIME, &end);
    msec = (end.tv_sec - start.tv_sec) * 1000 + end.tv_nsec / 1000000 -
           start.tv_nsec / 1000000;
    if (msec >= 1000)
      pdbg_logf(D_ERROR, "waited %lu milliseconds for database write lock", msec);
    else if (msec >= 250)
      pdbg_logf(D_WARNING, "waited %lu milliseconds for database write lock", msec);
    else if (msec >= 5)
      pdbg_logf(D_BUG, "waited %lu milliseconds for database write lock", msec);
    pdbg_assert(lockctr == 0);
    lockctr++;
    memcpy(&lockstart, &end, sizeof(struct timespec));
    record_wrlock(file, line);
  } else if (++lockctr == 1) {
    clock_gettime(CLOCK_REALTIME, &lockstart);
    record_wrlock(file, line);
  }
}

void psql_do_rdlock(const char *file, unsigned line) {
  if (plocks_tryrdlock(&dblock)) {
    struct timespec start, end;
    unsigned long msec;
    clock_gettime(CLOCK_REALTIME, &start);
    memcpy(&end, &start, sizeof(end));
    end.tv_sec += PSYNC_DEBUG_LOCK_TIMEOUT;
    if (plocks_timedrdlock(&dblock, &end)) {
      pdbg_logf(D_BUG, "sql read lock timed out, called from %s:%u", file, line);
      sendpdbg_logf("sql read lock timed out, called from %s:%u", file, line);
      psql_dump_locks();
      abort();
    }
    clock_gettime(CLOCK_REALTIME, &end);
    msec = (end.tv_sec - start.tv_sec) * 1000 + end.tv_nsec / 1000000 -
           start.tv_nsec / 1000000;
    if (msec >= 1000)
      pdbg_logf(D_ERROR, "waited %lu milliseconds for database read lock", msec);
    else if (msec >= 250)
      pdbg_logf(D_WARNING, "waited %lu milliseconds for database read lock", msec);
    else if (msec >= 5)
      pdbg_logf(D_BUG, "waited %lu milliseconds for database read lock", msec);
    rdlockctr++;
    memcpy(&rdlockstart, &end, sizeof(struct timespec));
    record_rdlock(file, line, &rdlockstart);
  } else if (++rdlockctr == 1) {
    clock_gettime(CLOCK_REALTIME, &rdlockstart);
    record_rdlock(file, line, &rdlockstart);
  }
}

// --------------------------------------------------------------------------
// Strong overrides for same-named functions (weak in psql.c)
// --------------------------------------------------------------------------

void psql_lock() {
  psql_do_lock(__FILE__, __LINE__);
}

void psql_rdlock() {
  psql_do_rdlock(__FILE__, __LINE__);
}

void psql_unlock() {
  pdbg_assert(lockctr > 0);
  if (--lockctr == 0) {
    struct timespec end;
    unsigned long msec;
    clock_gettime(CLOCK_REALTIME, &end);
    msec = (end.tv_sec - lockstart.tv_sec) * 1000 + end.tv_nsec / 1000000 -
           lockstart.tv_nsec / 1000000;
    if (msec >= 2000)
      pdbg_logf(D_ERROR,
            "held database write lock for %lu milliseconds taken from %s:%u",
            msec, wrlockfile, wrlockline);
    else if (msec >= 500)
      pdbg_logf(D_WARNING,
            "held database write lock for %lu milliseconds taken from %s:%u",
            msec, wrlockfile, wrlockline);
    else if (msec >= 10)
      pdbg_logf(D_BUG,
            "held database write lock for %lu milliseconds taken from %s:%u",
            msec, wrlockfile, wrlockline);
    record_wrunlock();
    plocks_unlock(&dblock);
  } else
    plocks_unlock(&dblock);
}

void psql_rdunlock() {
  if (unlikely(rdlockctr == 0)) {
    psql_unlock();
    return;
  }
  if (--rdlockctr == 0) {
    struct timespec end;
    unsigned long msec;
    rd_lock_data *lock;
    plocks_unlock(&dblock);
    clock_gettime(CLOCK_REALTIME, &end);
    lock = record_rdunlock();
    msec = (end.tv_sec - rdlockstart.tv_sec) * 1000 + end.tv_nsec / 1000000 -
           rdlockstart.tv_nsec / 1000000;
    if (msec >= 2000)
      pdbg_logf(D_ERROR,
            "held database read lock for %lu milliseconds taken at %s:%u", msec,
            lock->file, lock->line);
    else if (msec >= 500)
      pdbg_logf(D_WARNING,
            "held database read lock for %lu milliseconds taken at %s:%u", msec,
            lock->file, lock->line);
    else if (msec >= 20)
      pdbg_logf(D_BUG,
            "held database read lock for %lu milliseconds taken at %s:%u", msec,
            lock->file, lock->line);
    pmem_free(PMEM_SUBSYS_OTHER, lock);
  } else
    plocks_unlock(&dblock);
}

int psql_tryupgradeLock() {
  if (plocks_holding_wrlock(&dblock))
    return 0;
  pdbg_assert(plocks_holding_rdlock(&dblock));
  if (plocks_towrlock(&dblock))
    return -1;
  else {
    rd_lock_data *lock = record_rdunlock();
    lockctr = rdlockctr;
    rdlockctr = 0;
    pdbg_assert(lockctr == 1);
    lockstart = rdlockstart;
    record_wrlock(lock->file, lock->line);
    pmem_free(PMEM_SUBSYS_OTHER, lock);
    return 0;
  }
}

// --------------------------------------------------------------------------
// Debug variants of query/prepare functions (called via psql.h macros)
// --------------------------------------------------------------------------

int psql_statement(const char *sql) {
  char *errmsg;
  int code;
  psql_do_lock(__FILE__, __LINE__);
  code = sqlite3_exec(psync_db, sql, NULL, NULL, &errmsg);
  psql_unlock();
  if (likely(code == SQLITE_OK))
    return 0;
  else {
    pdbg_logf(D_ERROR, "error running sql statement: %s: %s", sql, errmsg);
    sqlite3_free(errmsg);
    return -1;
  }
}

int psql_do_statement(const char *sql, const char *file, unsigned line) {
  char *errmsg;
  int code;
  psql_do_lock(file, line);
  code = sqlite3_exec(psync_db, sql, NULL, NULL, &errmsg);
  psql_unlock();
  if (likely(code == SQLITE_OK))
    return 0;
  else {
    pdbg_logf(D_ERROR, "error running sql statement: %s: %s called from %s:%u",
          sql, errmsg, file, line);
    sqlite3_free(errmsg);
    return -1;
  }
}

int psql_do_start_transaction(const char *file, unsigned line) {
  psync_sql_res *res;
  psql_do_lock(file, line);
  res = psql_do_prepare("BEGIN", file, line);
  pdbg_assert(!in_transaction);
  if (unlikely(!res || psql_run_free(res)))
    return -1;
  in_transaction = 1;
  transaction_failed = 0;
  psync_list_init(&commitcbs);
  return 0;
}

psync_sql_res *psql_do_query_nocache(const char *sql, const char *file,
                                     unsigned line) {
  sqlite3_stmt *stmt;
  psync_sql_res *res;
  int code, cnt;
  psql_do_lock(file, line);
  code = sqlite3_prepare_v2(psync_db, sql, -1, &stmt, NULL);
  if (unlikely(code != SQLITE_OK)) {
    psql_unlock();
    pdbg_logf(D_ERROR, "error running sql statement: %s: %s called from %s:%u",
          sql, sqlite3_errmsg(psync_db), file, line);
    sendpdbg_logf("error running sql statement: %s: %s called from %s:%u",
              sql, sqlite3_errmsg(psync_db), file, line);
    return NULL;
  }
  cnt = sqlite3_column_count(stmt);
  res = (psync_sql_res *)pmem_malloc(PMEM_SUBSYS_OTHER, sizeof(psync_sql_res) +
                                cnt * sizeof(psync_variant));
  res->stmt = stmt;
  res->sql = sql;
  res->column_count = cnt;
  res->locked = SQL_WRITE_LOCK;
  return res;
}

psync_sql_res *psql_do_query(const char *sql, const char *file,
                             unsigned line) {
  psync_sql_res *ret;
  ret = (psync_sql_res *)pcache_get(sql);
  if (ret) {
    ret->locked = SQL_WRITE_LOCK;
    ret->sql = sql;
    psql_do_lock(file, line);
    return ret;
  } else
    return psql_do_query_nocache(sql, file, line);
}

psync_sql_res *psql_do_query_rdlock_nocache(const char *sql,
                                            const char *file,
                                            unsigned line) {
  sqlite3_stmt *stmt;
  psync_sql_res *res;
  int code, cnt;
  psql_do_rdlock(file, line);
  code = sqlite3_prepare_v2(psync_db, sql, -1, &stmt, NULL);
  if (unlikely(code != SQLITE_OK)) {
    psql_rdunlock();
    pdbg_logf(D_ERROR, "error running sql statement: %s: %s called from %s:%u",
          sql, sqlite3_errmsg(psync_db), file, line);
    sendpdbg_logf("error running sql statement: %s: %s called from %s:%u",
              sql, sqlite3_errmsg(psync_db), file, line);
    return NULL;
  }
  cnt = sqlite3_column_count(stmt);
  res = (psync_sql_res *)pmem_malloc(PMEM_SUBSYS_OTHER, sizeof(psync_sql_res) +
                                cnt * sizeof(psync_variant));
  res->stmt = stmt;
  res->sql = sql;
  res->column_count = cnt;
  res->locked = SQL_READ_LOCK;
  return res;
}

psync_sql_res *psql_do_query_rdlock(const char *sql, const char *file,
                                    unsigned line) {
  psync_sql_res *ret;
  ret = (psync_sql_res *)pcache_get(sql);
  if (ret) {
    ret->locked = SQL_READ_LOCK;
    ret->sql = sql;
    psql_do_rdlock(file, line);
    return ret;
  } else
    return psql_do_query_rdlock_nocache(sql, file, line);
}

psync_sql_res *psql_do_query_nolock_nocache(const char *sql, const char *file,
                                            unsigned line) {
  sqlite3_stmt *stmt;
  psync_sql_res *res;
  int code, cnt;
  if (!psql_locked()) {
    pdbg_logf(D_BUG,
          "illegal use of psync_sql_query_nolock, can only be used while "
          "holding lock, invoked from %s:%u, sql: %s",
          file, line, sql);
    sendpdbg_logf("illegal use of psync_sql_query_nolock, can only be used while "
              "holding lock, invoked from %s:%u, sql: %s",
              file, line, sql);
    abort();
  }
  code = sqlite3_prepare_v2(psync_db, sql, -1, &stmt, NULL);
  if (unlikely(code != SQLITE_OK)) {
    pdbg_logf(D_ERROR, "error running sql statement: %s: %s", sql,
          sqlite3_errmsg(psync_db));
    sendpdbg_logf("error running sql statement: %s: %s", sql,
              sqlite3_errmsg(psync_db));
    return NULL;
  }
  cnt = sqlite3_column_count(stmt);
  res = (psync_sql_res *)pmem_malloc(PMEM_SUBSYS_OTHER, sizeof(psync_sql_res) +
                                cnt * sizeof(psync_variant));
  res->stmt = stmt;
  res->sql = sql;
  res->column_count = cnt;
  res->locked = SQL_NO_LOCK;
  return res;
}

psync_sql_res *psql_do_query_nolock(const char *sql, const char *file,
                                    unsigned line) {
  psync_sql_res *ret;
  if (!psql_locked()) {
    pdbg_logf(D_BUG,
          "illegal use of psync_sql_query_nolock, can only be used while "
          "holding lock, invoked from %s:%u, sql: %s",
          file, line, sql);
    sendpdbg_logf("illegal use of psync_sql_query_nolock, can only be used while "
              "holding lock, invoked from %s:%u, sql: %s",
              file, line, sql);
    abort();
  }
  ret = (psync_sql_res *)pcache_get(sql);
  if (ret) {
    ret->locked = SQL_NO_LOCK;
    ret->sql = sql;
    return ret;
  } else
    return psql_do_query_nolock_nocache(sql, file, line);
}

psync_sql_res *psql_do_prepare_nocache(const char *sql, const char *file,
                                       unsigned line) {
  sqlite3_stmt *stmt;
  psync_sql_res *res;
  int code;
  psql_do_lock(file, line);
  code = sqlite3_prepare_v2(psync_db, sql, -1, &stmt, NULL);
  if (unlikely(code != SQLITE_OK)) {
    psql_unlock();
    pdbg_logf(D_ERROR, "error running sql statement: %s: %s called from %s:%u",
          sql, sqlite3_errmsg(psync_db), file, line);
    sendpdbg_logf("error running sql statement: %s: %s called from %s:%u",
              sql, sqlite3_errmsg(psync_db), file, line);
    return NULL;
  }
  res = pmem_malloc(PMEM_SUBSYS_OTHER, sizeof(psync_sql_res));
  res->stmt = stmt;
  res->sql = sql;
  res->column_count = 0;
  res->locked = SQL_WRITE_LOCK;
  return res;
}

psync_sql_res *psql_do_prepare(const char *sql, const char *file,
                               unsigned line) {
  psync_sql_res *ret;
  ret = pcache_get(sql);
  if (ret) {
    ret->locked = SQL_WRITE_LOCK;
    psql_do_lock(file, line);
    return ret;
  } else
    return psql_do_prepare_nocache(sql, file, line);
}
