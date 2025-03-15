#include "pdatabase.h"
#include "pdbg.h"
#include "plocks.h"
#include "prun.h"
#include "psettings.h"
#include "pstatus.h"
#include "psql.h"
#include "pcache.h"
#include "psys.h"
#include "pnetlibs.h"
#include <sqlite3.h>
#include <sys/stat.h>

#define SQL_NO_LOCK 0
#define SQL_READ_LOCK 1
#define SQL_WRITE_LOCK 2

#define PSYNC_TNUMBER 1
#define PSYNC_TSTRING 2
#define PSYNC_TREAL 3
#define PSYNC_TNULL 4
#define PSYNC_TBOOL 5

extern PSYNC_THREAD const char *psync_thread_name; 

const static char *psync_typenames[] = {
    "[invalid type]", "[number]", "[string]", "[float]", "[null]", "[bool]"};

typedef struct {
  psync_list list;
  psync_transaction_callback_t commit_callback;
  psync_transaction_callback_t rollback_callback;
  void *ptr;
} tran_callback_t;

psync_rwlock_t psync_db_lock;
sqlite3 *psync_db;
pstatus_t psync_status;
int psync_do_run = 1;
int psync_recache_contacts = 1;
PSYNC_THREAD uint32_t psync_error = 0;

static pthread_mutex_t psync_db_checkpoint_mutex;

static int in_transaction = 0;
static int transaction_failed = 0;
static psync_list tran_callbacks;

void psync_sql_err_callback(void *ptr, int code, const char *msg) {
  pdbg_logf(D_WARNING, "database warning %d: %s", code, msg);
}

static void psync_sql_wal_checkpoint() {
  int code;
  psync_sql_lock();
  psync_sql_unlock();
  if (pthread_mutex_trylock(&psync_db_checkpoint_mutex)) {
    pdbg_logf(D_NOTICE, "checkpoint already in progress");
    return;
  }
  pdbg_logf(D_NOTICE, "checkpointing database");
  code = sqlite3_wal_checkpoint(psync_db, NULL);
  while (code == SQLITE_LOCKED) {
    psys_sleep_milliseconds(2);
    code = sqlite3_wal_checkpoint(psync_db, NULL);
  }
  pthread_mutex_unlock(&psync_db_checkpoint_mutex);
  if (unlikely(code != SQLITE_OK))
    pdbg_logf(D_CRITICAL, "sqlite3_wal_checkpoint returned error %d", code);
  else
    pdbg_logf(D_NOTICE, "checkpoint finished");
}

static int psync_sql_wal_hook(void *ptr, sqlite3 *db, const char *name,
                              int numpages) {
  if (numpages >= PSYNC_DB_CHECKPOINT_AT_PAGES)
    prun_thread("checkpoint charlie", psync_sql_wal_checkpoint);
  return SQLITE_OK;
}

int psync_sql_connect(const char *db) {
  static int initmutex = 1;
  pthread_mutexattr_t mattr;
  struct stat st;
  uint64_t dbver;
  int initdbneeded = 0;
  int code;

  pdbg_assert(sqlite3_libversion_number() == SQLITE_VERSION_NUMBER);
  pdbg_assert(!strcmp(sqlite3_sourceid(), SQLITE_SOURCE_ID));
  pdbg_assert(!strcmp(sqlite3_libversion(), SQLITE_VERSION));
  pdbg_logf(D_NOTICE, "Using sqlite version %s source %s", sqlite3_libversion(),
        sqlite3_sourceid());
  if (!sqlite3_threadsafe()) {
    pdbg_logf(D_CRITICAL, "sqlite is compiled without thread support");
    return -1;
  }
  if (stat(db, &st) != 0)
    initdbneeded = 1;

  code = sqlite3_open(db, &psync_db);
  if (likely(code == SQLITE_OK)) {
    if (initmutex) {
      plocks_init(&psync_db_lock);
      pthread_mutexattr_init(&mattr);
      pthread_mutexattr_settype(&mattr, PTHREAD_MUTEX_RECURSIVE);
      pthread_mutex_init(&psync_db_checkpoint_mutex, &mattr);
      pthread_mutexattr_destroy(&mattr);
      initmutex = 0;
    }
    if (IS_DEBUG)
      sqlite3_config(SQLITE_CONFIG_LOG, psync_sql_err_callback, NULL);
    sqlite3_wal_hook(psync_db, psync_sql_wal_hook, NULL);
    psync_sql_statement(PSYNC_DATABASE_CONFIG);
    if (initdbneeded == 1)
      return psync_sql_statement(PSYNC_DATABASE_STRUCTURE);
    else if (psync_sql_statement(
                 "DELETE FROM setting WHERE id='justcheckingiflocked'")) {
      pdbg_logf(D_ERROR, "database is locked");
      sqlite3_close(psync_db);
      plocks_destroy(&psync_db_lock);
      return -1;
    }

    dbver =
        psync_sql_cellint("SELECT value FROM setting WHERE id='dbversion'", 0);
    if (dbver < PSYNC_DATABASE_VERSION) {
      uint64_t i;
      pdbg_logf(D_NOTICE, "database version %d detected, upgrading to %d",
            (int)dbver, (int)PSYNC_DATABASE_VERSION);
      for (i = dbver; i < PSYNC_DATABASE_VERSION; i++)
        if (psync_sql_statement(psync_db_upgrade[i])) {
          pdbg_logf(D_ERROR, "error running statement %s on sqlite %s",
                psync_db_upgrade[i], sqlite3_libversion());
          if (IS_DEBUG) {
            psync_error = PERROR_DATABASE_OPEN;
            return -1;            
          }
        }
    }

    return 0;
  } else {
    pdbg_logf(D_CRITICAL, "could not open sqlite database %s: %d", db, code);
    return -1;
  }
}

int psync_sql_close() {
  int code, tries;
  tries = 0;
  while (1) {
    code = sqlite3_close(psync_db);
    if (code == SQLITE_BUSY) {
      pcache_clean();
      tries++;
      if (tries > 100) {
        psys_sleep_milliseconds_fast(tries - 90);
        if (tries > 200) {
          pdbg_logf(D_ERROR, "failed to close database");
          break;
        }
      }
    } else
      break;
  }
  psync_db = NULL;
  if (unlikely(code != SQLITE_OK)) {
    pdbg_logf(D_CRITICAL, "error when closing database: %d", code);
    code = sqlite3_close_v2(psync_db);
    if (unlikely(code != SQLITE_OK)) {
      pdbg_logf(D_CRITICAL,
            "error when closing database even with sqlite3_close_v2: %d", code);
      return -1;
    }
  }
  return 0;
}

int psync_sql_reopen(const char *path) {
  sqlite3 *db;
  int code;
  pdbg_logf(D_NOTICE, "reopening database %s", path);
  code = sqlite3_open(path, &db);
  if (likely(code == SQLITE_OK)) {
    code = sqlite3_wal_checkpoint(db, NULL);
    if (unlikely(code != SQLITE_OK)) {
      pdbg_logf(D_CRITICAL, "sqlite3_wal_checkpoint returned error %d", code);
      sqlite3_close(db);
      return -1;
    }
    code = sqlite3_close(db);
    if (unlikely(code != SQLITE_OK)) {
      pdbg_logf(D_CRITICAL, "sqlite3_close returned error %d", code);
      return -1;
    }
    return 0;
  } else {
    pdbg_logf(D_CRITICAL, "could not open sqlite dabase %s: %d", path, code);
    return -1;
  }
}

void psync_sql_checkpoint_lock() {
  pthread_mutex_lock(&psync_db_checkpoint_mutex);
}

void psync_sql_checkpoint_unlock() {
  pthread_mutex_unlock(&psync_db_checkpoint_mutex);
}

#if IS_DEBUG
typedef struct {
  psync_list list;
  const char *file;
  const char *thread;
  struct timespec tm;
  unsigned line;
} rd_lock_data;

static PSYNC_THREAD rd_lock_data *rdlock = NULL;
static PSYNC_THREAD unsigned long sqlrdlockcnt = 0;
static PSYNC_THREAD struct timespec sqlrdlockstart;
unsigned long sqllockcnt = 0;
static struct timespec sqllockstart;
static const char *wrlockfile = "none";
static const char *wrlockthread = "";
static unsigned wrlockline = 0;
static unsigned wrlocked = 0;
static pthread_t wrlocker;
static psync_list rdlocks = PSYNC_LIST_STATIC_INIT(rdlocks);
static pthread_mutex_t rdmutex = PTHREAD_MUTEX_INITIALIZER;

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
  lock = malloc(sizeof(rd_lock_data));
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

void psync_sql_dump_locks() {
  rd_lock_data *lock;
  char dttime[36];
  if (wrlocked) {
    time_format(sqllockstart.tv_sec, sqllockstart.tv_nsec, dttime);
    pdbg_logf(D_ERROR, "write lock taken by thread %s from %s:%u at %s",
          wrlockthread, wrlockfile, wrlockline, dttime);
    sendpdbg_logf("write lock taken by thread %s from %s:%u at %s", wrlockthread,
              wrlockfile, wrlockline, dttime);
  }
  pthread_mutex_lock(&rdmutex);
  psync_list_for_each_element(lock, &rdlocks, rd_lock_data, list) {
    time_format(lock->tm.tv_sec, lock->tm.tv_nsec, dttime);
    pdbg_logf(D_ERROR, "read lock taken by thread %s from %s:%u at %s",
          lock->thread, lock->file, lock->line, dttime);
    sendpdbg_logf("read lock taken by thread %s from %s:%u at %s", lock->thread,
              lock->file, lock->line, dttime);
  }
  pthread_mutex_unlock(&rdmutex);
}

#endif


#if IS_DEBUG
int psync_sql_do_trylock(const char *file, unsigned line) {
  if (plocks_trywrlock(&psync_db_lock))
    return -1;
  if (++sqllockcnt == 1) {
    clock_gettime(CLOCK_REALTIME, &sqllockstart);
    record_wrlock(file, line);
  }
  return 0;
}
#else
int psync_sql_trylock() { return plocks_trywrlock(&psync_db_lock); }
#endif

#if IS_DEBUG
void psync_sql_do_lock(const char *file, unsigned line) {
  if (plocks_trywrlock(&psync_db_lock)) {
    struct timespec start, end;
    unsigned long msec;
    clock_gettime(CLOCK_REALTIME, &start);
    memcpy(&end, &start, sizeof(end));
    end.tv_sec += PSYNC_DEBUG_LOCK_TIMEOUT;
    if (plocks_timedwrlock(&psync_db_lock, &end)) {
      pdbg_logf(D_BUG, "sql write lock timed out called from %s:%u", file, line);
      sendpdbg_logf("sql write lock timed out called from %s:%u", file, line);
      psync_sql_dump_locks();
      abort();
    }
    clock_gettime(CLOCK_REALTIME, &end);
    msec = (end.tv_sec - start.tv_sec) * 1000 + end.tv_nsec / 1000000 -
           start.tv_nsec / 1000000;
    if (msec >= 5)
      pdbg_logf(D_WARNING, "waited %lu milliseconds for database write lock", msec);
    pdbg_assert(sqllockcnt == 0);
    sqllockcnt++;
    memcpy(&sqllockstart, &end, sizeof(struct timespec));
    record_wrlock(file, line);
  } else if (++sqllockcnt == 1) {
    clock_gettime(CLOCK_REALTIME, &sqllockstart);
    record_wrlock(file, line);
  }
}
#else
void psync_sql_lock() { plocks_wrlock(&psync_db_lock); }
#endif


void psync_sql_unlock() {
#if IS_DEBUG
  pdbg_assert(sqllockcnt > 0);
  if (--sqllockcnt == 0) {
    struct timespec end;
    unsigned long msec;
    clock_gettime(CLOCK_REALTIME, &end);
    msec = (end.tv_sec - sqllockstart.tv_sec) * 1000 + end.tv_nsec / 1000000 -
           sqllockstart.tv_nsec / 1000000;
    if (msec >= 10)
      pdbg_logf(D_WARNING,
            "held database write lock for %lu milliseconds taken from %s:%u",
            msec, wrlockfile, wrlockline);
    record_wrunlock();
    plocks_unlock(&psync_db_lock);
  } else
    plocks_unlock(&psync_db_lock);
#else
  plocks_unlock(&psync_db_lock);
#endif
}

#if IS_DEBUG
void psync_sql_do_rdlock(const char *file, unsigned line) {
  if (plocks_tryrdlock(&psync_db_lock)) {
    struct timespec start, end;
    unsigned long msec;
    clock_gettime(CLOCK_REALTIME, &start);
    memcpy(&end, &start, sizeof(end));
    end.tv_sec += PSYNC_DEBUG_LOCK_TIMEOUT;
    if (plocks_timedrdlock(&psync_db_lock, &end)) {
      pdbg_logf(D_BUG, "sql read lock timed out, called from %s:%u", file, line);
      sendpdbg_logf("sql read lock timed out, called from %s:%u", file, line);
      psync_sql_dump_locks();
      abort();
    }
    clock_gettime(CLOCK_REALTIME, &end);
    msec = (end.tv_sec - start.tv_sec) * 1000 + end.tv_nsec / 1000000 -
           start.tv_nsec / 1000000;
    if (msec >= 5)
      pdbg_logf(D_WARNING, "waited %lu milliseconds for database read lock", msec);
    sqlrdlockcnt++;
    memcpy(&sqlrdlockstart, &end, sizeof(struct timespec));
    record_rdlock(file, line, &sqlrdlockstart);
  } else if (++sqlrdlockcnt == 1) {
    clock_gettime(CLOCK_REALTIME, &sqlrdlockstart);
    record_rdlock(file, line, &sqlrdlockstart);
  }
}
#else
void psync_sql_rdlock() { plocks_rdlock(&psync_db_lock); }
#endif


void psync_list_bulder_add_sql(psync_list_builder_t *builder,
                               psync_sql_res *res,
                               psync_list_builder_sql_callback callback) {
  psync_variant_row row;
  while ((row = psync_sql_fetch_row(res))) {
    if (!builder->last_elements ||
        builder->last_elements->used >= builder->elements_per_list) {
      builder->last_elements = (psync_list_element_list *)malloc(
          offsetof(psync_list_element_list, elements) +
          builder->element_size * builder->elements_per_list);
      psync_list_add_tail(&builder->element_list,
                          &builder->last_elements->list);
      builder->last_elements->used = 0;
    }
    builder->current_element =
        builder->last_elements->elements +
        builder->last_elements->used * builder->element_size;
    builder->cstrcnt = psync_list_bulder_push_num(builder);
    *builder->cstrcnt = 0;
    while (callback(builder, builder->current_element, row)) {
      row = psync_sql_fetch_row(res);
      if (!row)
        break;
      *builder->cstrcnt = 0;
    }
    builder->last_elements->used++;
    builder->cnt++;
  }
  psync_sql_free_result(res);
}

void psync_sql_rdunlock() {
#if IS_DEBUG
  if (unlikely(sqlrdlockcnt == 0)) {
    psync_sql_unlock();
    return;
  }
  if (--sqlrdlockcnt == 0) {
    struct timespec end;
    unsigned long msec;
    rd_lock_data *lock;
    plocks_unlock(&psync_db_lock);
    clock_gettime(CLOCK_REALTIME, &end);
    lock = record_rdunlock();
    msec = (end.tv_sec - sqlrdlockstart.tv_sec) * 1000 + end.tv_nsec / 1000000 -
           sqlrdlockstart.tv_nsec / 1000000;
    if (msec >= 20)
      pdbg_logf(D_WARNING,
            "held database read lock for %lu milliseconds taken at %s:%u", msec,
            lock->file, lock->line);
    free(lock);
  } else
    plocks_unlock(&psync_db_lock);
#else
  plocks_unlock(&psync_db_lock);
#endif
}

int psync_sql_has_waiters() {
  return plocks_num_waiters(&psync_db_lock) > 0;
}

int psync_sql_isrdlocked() {
  return plocks_holding_rdlock(&psync_db_lock);
}

int psync_sql_islocked() { return plocks_holding_lock(&psync_db_lock); }

int psync_sql_tryupgradelock() {
#if IS_DEBUG
  if (plocks_holding_wrlock(&psync_db_lock))
    return 0;
  pdbg_assert(plocks_holding_rdlock(&psync_db_lock));
  if (plocks_towrlock(&psync_db_lock))
    return -1;
  else {
    rd_lock_data *lock = record_rdunlock();
    sqllockcnt = sqlrdlockcnt;
    sqlrdlockcnt = 0;
    pdbg_assert(sqllockcnt == 1);
    sqllockstart = sqlrdlockstart;
    record_wrlock(lock->file, lock->line);
    free(lock);
    return 0;
  }
#else
  return plocks_towrlock(&psync_db_lock);
#endif
}

int psync_sql_sync() {
  int code;
  pthread_mutex_lock(&psync_db_checkpoint_mutex);
  code = sqlite3_wal_checkpoint(psync_db, NULL);
  if (unlikely(code == SQLITE_BUSY || code == SQLITE_LOCKED)) {
    psync_sql_lock();
    code = sqlite3_wal_checkpoint(psync_db, NULL);
    psync_sql_unlock();
  }
  pthread_mutex_unlock(&psync_db_checkpoint_mutex);
  if (unlikely(code != SQLITE_OK)) {
    pdbg_logf(D_CRITICAL, "sqlite3_wal_checkpoint returned error %d", code);
    return -1;
  } else
    return 0;
}

#if IS_DEBUG
int psync_sql_do_statement(const char *sql, const char *file, unsigned line) {
  char *errmsg;
  int code;
  psync_sql_do_lock(file, line);
#else
int psync_sql_statement(const char *sql) {
  char *errmsg;
  int code;
  psync_sql_lock();
#endif
  code = sqlite3_exec(psync_db, sql, NULL, NULL, &errmsg);
  psync_sql_unlock();
  if (likely(code == SQLITE_OK))
    return 0;
  else {
#if IS_DEBUG
    pdbg_logf(D_ERROR, "error running sql statement: %s: %s called from %s:%u", sql,
          errmsg, file, line);
#else
    pdbg_logf(D_ERROR, "error running sql statement: %s: %s", sql, errmsg);
#endif
    sqlite3_free(errmsg);
    return -1;
  }
}

#if IS_DEBUG
int psync_sql_do_start_transaction(const char *file, unsigned line) {
  psync_sql_res *res;
  psync_sql_do_lock(file, line);
  res = psync_sql_do_prep_statement("BEGIN", file, line);
#else
int psync_sql_start_transaction() {
  psync_sql_res *res;
  psync_sql_lock();
  res = psync_sql_prep_statement("BEGIN");
#endif
  pdbg_assert(!in_transaction);
  if (unlikely(!res || psync_sql_run_free(res)))
    return -1;
  in_transaction = 1;
  transaction_failed = 0;
  psync_list_init(&tran_callbacks);
  return 0;
}

static void run_commit_callbacks(int success) {
  tran_callback_t *cb;
  psync_list *l1, *l2;
  psync_list_for_each_safe(l1, l2, &tran_callbacks) {
    cb = psync_list_element(l1, tran_callback_t, list);
    if (success)
      cb->commit_callback(cb->ptr);
    else
      cb->rollback_callback(cb->ptr);
    free(cb);
  }
}

int psync_sql_commit_transaction() {
  pdbg_assert(in_transaction);
  if (likely(!transaction_failed)) {
    psync_sql_res *res = psync_sql_prep_statement("COMMIT");
    if (likely(!psync_sql_run_free(res))) {
      run_commit_callbacks(1);
      in_transaction = 0;
      psync_sql_unlock();
      return 0;
    }
  } else
    pdbg_logf(D_ERROR, "rolling back transaction as some statements failed");
  psync_sql_rollback_transaction();
  return -1;
}

int psync_sql_rollback_transaction() {
  psync_sql_res *res = psync_sql_prep_statement("ROLLBACK");
  pdbg_assert(in_transaction);
  psync_sql_run_free(res);
  run_commit_callbacks(0);
  in_transaction = 0;
  psync_sql_unlock();
  return 0;
}

void psync_sql_transation_add_callbacks(
    psync_transaction_callback_t commit_callback,
    psync_transaction_callback_t rollback_callback, void *ptr) {
  tran_callback_t *cb;
  pdbg_assert(in_transaction);
  cb = malloc(sizeof(tran_callback_t));
  cb->commit_callback = commit_callback;
  cb->rollback_callback = rollback_callback;
  cb->ptr = ptr;
  psync_list_add_tail(&tran_callbacks, &cb->list);
}

char *psync_sql_cellstr(const char *sql) {
  sqlite3_stmt *stmt;
  int code;
  psync_sql_rdlock();
  code = sqlite3_prepare_v2(psync_db, sql, -1, &stmt, NULL);
  if (unlikely(code != SQLITE_OK)) {
    psync_sql_rdunlock();
    pdbg_logf(D_ERROR, "error running sql statement: %s: %s", sql,
          sqlite3_errmsg(psync_db));
    sendtpdbg_logf("error running sql statement: %s: %s", sql,
               sqlite3_errmsg(psync_db));
    return NULL;
  }
  code = sqlite3_step(stmt);
  if (code == SQLITE_ROW) {
    char *ret;
    ret = (char *)sqlite3_column_text(stmt, 0);
    if (ret)
      ret = psync_strdup(ret);
    sqlite3_finalize(stmt);
    psync_sql_rdunlock();
    return ret;
  } else {
    sqlite3_finalize(stmt);
    psync_sql_rdunlock();
    if (unlikely(code != SQLITE_DONE)) {
      pdbg_logf(D_ERROR, "sqlite3_step returned error: %s: %s", sql,
            sqlite3_errmsg(psync_db));
      sendtpdbg_logf("sqlite3_step returned error: %s: %s", sql,
                 sqlite3_errmsg(psync_db));
    }
    return NULL;
  }
}

int64_t psync_sql_cellint(const char *sql, int64_t dflt) {
  sqlite3_stmt *stmt;
  int code;
  psync_sql_rdlock();
  code = sqlite3_prepare_v2(psync_db, sql, -1, &stmt, NULL);
  if (unlikely(code != SQLITE_OK)) {
    pdbg_logf(D_ERROR, "error running sql statement: %s: %s", sql,
          sqlite3_errmsg(psync_db));
    sendtpdbg_logf("error running sql statement: %s: %s", sql,
               sqlite3_errmsg(psync_db));
  } else {
    code = sqlite3_step(stmt);
    if (code == SQLITE_ROW)
      dflt = sqlite3_column_int64(stmt, 0);
    else if (unlikely(code != SQLITE_DONE)) {
      pdbg_logf(D_ERROR, "sqlite3_step returned error: %s: %s", sql,
            sqlite3_errmsg(psync_db));
      sendtpdbg_logf("sqlite3_step returned error: %s: %s", sql,
                 sqlite3_errmsg(psync_db));
    }
    sqlite3_finalize(stmt);
  }
  psync_sql_rdunlock();
  return dflt;
}

char **psync_sql_rowstr(const char *sql) {
  sqlite3_stmt *stmt;
  int code, cnt;
  psync_sql_rdlock();
  code = sqlite3_prepare_v2(psync_db, sql, -1, &stmt, NULL);
  if (unlikely(code != SQLITE_OK)) {
    psync_sql_rdunlock();
    pdbg_logf(D_ERROR, "error running sql statement: %s: %s", sql,
          sqlite3_errmsg(psync_db));
    sendtpdbg_logf("error running sql statement: %s: %s", sql,
               sqlite3_errmsg(psync_db));
    return NULL;
  }
  cnt = sqlite3_column_count(stmt);
  code = sqlite3_step(stmt);
  if (code == SQLITE_ROW) {
    char **arr, *nstr, *str;
    size_t l, ln;
    VAR_ARRAY(lens, size_t, cnt);
    int i;
    ln = 0;
    for (i = 0; i < cnt; i++) {
      l = sqlite3_column_bytes(stmt, i);
      ln += l;
      lens[i] = l;
    }
    ln += (sizeof(char *) + 1) * cnt;
    arr = (char **)malloc(ln);
    nstr = ((char *)arr) + sizeof(char *) * cnt;
    for (i = 0; i < cnt; i++) {
      str = (char *)sqlite3_column_blob(stmt, i);
      if (str) {
        ln = lens[i];
        memcpy(nstr, str, ln);
        nstr[ln] = 0;
        arr[i] = nstr;
        nstr += ln + 1;
      } else
        arr[i] = NULL;
    }
    sqlite3_finalize(stmt);
    psync_sql_rdunlock();
    return arr;
  } else {
    sqlite3_finalize(stmt);
    psync_sql_rdunlock();
    if (unlikely(code != SQLITE_DONE)) {
      pdbg_logf(D_ERROR, "sqlite3_step returned error: %s: %s", sql,
            sqlite3_errmsg(psync_db));
      sendtpdbg_logf("sqlite3_step returned error: %s: %s", sql,
                 sqlite3_errmsg(psync_db));
    }
    return NULL;
  }
}

psync_variant *psync_sql_row(const char *sql) {
  sqlite3_stmt *stmt;
  int code, cnt;
  psync_sql_rdlock();
  code = sqlite3_prepare_v2(psync_db, sql, -1, &stmt, NULL);
  if (unlikely(code != SQLITE_OK)) {
    psync_sql_rdunlock();
    pdbg_logf(D_ERROR, "error running sql statement: %s: %s", sql,
          sqlite3_errmsg(psync_db));
    sendtpdbg_logf("error running sql statement: %s: %s", sql,
               sqlite3_errmsg(psync_db));
    return NULL;
  }
  cnt = sqlite3_column_count(stmt);
  code = sqlite3_step(stmt);
  if (code == SQLITE_ROW) {
    psync_variant *arr;
    char *nstr, *str;
    size_t l, ln;
    VAR_ARRAY(lens, size_t, cnt);
    int i, t;
    VAR_ARRAY(types, int, cnt);
    ln = sizeof(psync_variant) * cnt;
    for (i = 0; i < cnt; i++) {
      t = sqlite3_column_type(stmt, i);
      types[i] = t;
      if (t == SQLITE_TEXT || t == SQLITE_BLOB) {
        l = sqlite3_column_bytes(stmt, i);
        ln += l + 1;
        lens[i] = l;
      }
    }
    arr = (psync_variant *)malloc(ln);
    nstr = ((char *)arr) + sizeof(psync_variant) * cnt;
    for (i = 0; i < cnt; i++) {
      t = types[i];
      if (t == SQLITE_INTEGER) {
        arr[i].type = PSYNC_TNUMBER;
        arr[i].snum = sqlite3_column_int64(stmt, i);
      } else if (t == SQLITE_TEXT || t == SQLITE_BLOB) {
        str = (char *)sqlite3_column_blob(stmt, i);
        ln = lens[i];
        memcpy(nstr, str, ln);
        nstr[ln] = 0;
        arr[i].type = PSYNC_TSTRING;
        arr[i].str = nstr;
        nstr += ln + 1;
      } else if (t == SQLITE_FLOAT) {
        arr[i].type = PSYNC_TREAL;
        arr[i].real = sqlite3_column_double(stmt, i);
      } else {
        arr[i].type = PSYNC_TNULL;
      }
    }
    sqlite3_finalize(stmt);
    psync_sql_rdunlock();
    return arr;
  } else {
    sqlite3_finalize(stmt);
    psync_sql_rdunlock();
    if (unlikely(code != SQLITE_DONE)) {
      pdbg_logf(D_ERROR, "sqlite3_step returned error: %s: %s", sql,
            sqlite3_errmsg(psync_db));
      sendtpdbg_logf("sqlite3_step returned error: %s: %s", sql,
                 sqlite3_errmsg(psync_db));
    }
    return NULL;
  }
}

#if IS_DEBUG
psync_sql_res *psync_sql_do_query_nocache(const char *sql, const char *file,
                                          unsigned line) {
#else
psync_sql_res *psync_sql_query_nocache(const char *sql) {
#endif
  sqlite3_stmt *stmt;
  psync_sql_res *res;
  int code, cnt;
#if IS_DEBUG
  psync_sql_do_lock(file, line);
#else
  psync_sql_lock();
#endif
  code = sqlite3_prepare_v2(psync_db, sql, -1, &stmt, NULL);
  if (unlikely(code != SQLITE_OK)) {
    psync_sql_unlock();
#if IS_DEBUG
    pdbg_logf(D_ERROR, "error running sql statement: %s: %s called from %s:%u", sql,
          sqlite3_errmsg(psync_db), file, line);
    sendpdbg_logf("error running sql statement: %s: %s called from %s:%u", sql,
              sqlite3_errmsg(psync_db), file, line);
#else
    pdbg_logf(D_ERROR, "error running sql statement: %s: %s", sql,
          sqlite3_errmsg(psync_db));
    sendpdbg_logf("error running sql statement: %s: %s", sql,
              sqlite3_errmsg(psync_db));
#endif
    return NULL;
  }
  cnt = sqlite3_column_count(stmt);
  res = (psync_sql_res *)malloc(sizeof(psync_sql_res) +
                                      cnt * sizeof(psync_variant));
  res->stmt = stmt;
  res->sql = sql;
  res->column_count = cnt;
  res->locked = SQL_WRITE_LOCK;
  return res;
}

#if IS_DEBUG
psync_sql_res *psync_sql_do_query(const char *sql, const char *file,
                                  unsigned line) {
#else
psync_sql_res *psync_sql_query(const char *sql) {
#endif
  psync_sql_res *ret;
  ret = (psync_sql_res *)pcache_get(sql);
  if (ret) {
    //    pdbg_logf(D_NOTICE, "got query %s from cache", sql);
    ret->locked = SQL_WRITE_LOCK;
    ret->sql = sql;
#if IS_DEBUG
    psync_sql_do_lock(file, line);
#else
    psync_sql_lock();
#endif
    return ret;
  } else
#if IS_DEBUG
    return psync_sql_do_query_nocache(sql, file, line);
#else
    return psync_sql_query_nocache(sql);
#endif
}

#if IS_DEBUG
psync_sql_res *psync_sql_do_query_rdlock_nocache(const char *sql,
                                                 const char *file,
                                                 unsigned line) {
#else
psync_sql_res *psync_sql_query_rdlock_nocache(const char *sql) {
#endif
  sqlite3_stmt *stmt;
  psync_sql_res *res;
  int code, cnt;
#if IS_DEBUG
  psync_sql_do_rdlock(file, line);
#else
  psync_sql_rdlock();
#endif
  code = sqlite3_prepare_v2(psync_db, sql, -1, &stmt, NULL);
  if (unlikely(code != SQLITE_OK)) {
    psync_sql_rdunlock();
#if IS_DEBUG
    pdbg_logf(D_ERROR, "error running sql statement: %s: %s called from %s:%u", sql,
          sqlite3_errmsg(psync_db), file, line);
    sendpdbg_logf("error running sql statement: %s: %s called from %s:%u", sql,
              sqlite3_errmsg(psync_db), file, line);
#else
    pdbg_logf(D_ERROR, "error running sql statement: %s: %s", sql,
          sqlite3_errmsg(psync_db));
    sendpdbg_logf("error running sql statement: %s: %s", sql,
              sqlite3_errmsg(psync_db));
#endif
    return NULL;
  }
  cnt = sqlite3_column_count(stmt);
  res = (psync_sql_res *)malloc(sizeof(psync_sql_res) +
                                      cnt * sizeof(psync_variant));
  res->stmt = stmt;
  res->sql = sql;
  res->column_count = cnt;
  res->locked = SQL_READ_LOCK;
  return res;
}

#if IS_DEBUG
psync_sql_res *psync_sql_do_query_rdlock(const char *sql, const char *file,
                                         unsigned line) {
#else
psync_sql_res *psync_sql_query_rdlock(const char *sql) {
#endif
  psync_sql_res *ret;
  ret = (psync_sql_res *)pcache_get(sql);
  if (ret) {
    //    pdbg_logf(D_NOTICE, "got query %s from cache", sql);
    ret->locked = SQL_READ_LOCK;
    ret->sql = sql;
#if IS_DEBUG
    psync_sql_do_rdlock(file, line);
#else
    psync_sql_rdlock();
#endif
    return ret;
  } else
#if IS_DEBUG
    return psync_sql_do_query_rdlock_nocache(sql, file, line);
#else
    return psync_sql_query_rdlock_nocache(sql);
#endif
}

#if IS_DEBUG
psync_sql_res *psync_sql_do_query_nolock_nocache(const char *sql,
                                                 const char *file,
                                                 unsigned line) {
#else
psync_sql_res *psync_sql_query_nolock_nocache(const char *sql) {
#endif
  sqlite3_stmt *stmt;
  psync_sql_res *res;
  int code, cnt;
#if IS_DEBUG
  if (!psync_sql_islocked()) {
    pdbg_logf(D_BUG,
          "illegal use of psync_sql_query_nolock, can only be used while "
          "holding lock, invoked from %s:%u, sql: %s",
          file, line, sql);
    sendpdbg_logf("illegal use of psync_sql_query_nolock, can only be used while "
              "holding lock, invoked from %s:%u, sql: %s",
              file, line, sql);
    abort();
  }
#endif
  code = sqlite3_prepare_v2(psync_db, sql, -1, &stmt, NULL);
  if (unlikely(code != SQLITE_OK)) {
    pdbg_logf(D_ERROR, "error running sql statement: %s: %s", sql,
          sqlite3_errmsg(psync_db));
    sendpdbg_logf("error running sql statement: %s: %s", sql,
              sqlite3_errmsg(psync_db));
    return NULL;
  }
  cnt = sqlite3_column_count(stmt);
  res = (psync_sql_res *)malloc(sizeof(psync_sql_res) +
                                      cnt * sizeof(psync_variant));
  res->stmt = stmt;
  res->sql = sql;
  res->column_count = cnt;
  res->locked = SQL_NO_LOCK;
  return res;
}

#if IS_DEBUG
psync_sql_res *psync_sql_do_query_nolock(const char *sql, const char *file,
                                         unsigned line) {
#else
psync_sql_res *psync_sql_query_nolock(const char *sql) {
#endif
  psync_sql_res *ret;
#if IS_DEBUG
  if (!psync_sql_islocked()) {
    pdbg_logf(D_BUG,
          "illegal use of psync_sql_query_nolock, can only be used while "
          "holding lock, invoked from %s:%u, sql: %s",
          file, line, sql);
    sendpdbg_logf("illegal use of psync_sql_query_nolock, can only be used while "
              "holding lock, invoked from %s:%u, sql: %s",
              file, line, sql);
    abort();
  }
#endif
  ret = (psync_sql_res *)pcache_get(sql);
  if (ret) {
    //    pdbg_logf(D_NOTICE, "got query %s from cache", sql);
    ret->locked = SQL_NO_LOCK;
    ret->sql = sql;
    return ret;
  } else
#if IS_DEBUG
    return psync_sql_do_query_nolock_nocache(sql, file, line);
#else
    return psync_sql_query_nolock_nocache(sql);
#endif
}

static void psync_sql_free_cache(void *ptr) {
  psync_sql_res *res = (psync_sql_res *)ptr;
  sqlite3_finalize(res->stmt);
#if IS_DEBUG
  memset(res, 0xff, sizeof(psync_sql_res));
#endif
  free(res);
}

static void psync_sql_res_unlock(psync_sql_res *res) {
  switch (res->locked) {
  case SQL_NO_LOCK:
    break;
  case SQL_READ_LOCK:
    psync_sql_rdunlock();
    break;
  case SQL_WRITE_LOCK:
    psync_sql_unlock();
    break;
#if IS_DEBUG
  default:
    pdbg_logf(D_ERROR, "unknown value for locked %d", res->locked);
    abort();
#endif
  }
}

void psync_sql_free_result(psync_sql_res *res) {
  int code = sqlite3_reset(res->stmt);
  psync_sql_res_unlock(res);
#if IS_DEBUG
  memset(res->row, 0xff, res->column_count * sizeof(psync_variant));
#endif
  if (code == SQLITE_OK)
    pcache_add(res->sql, res, PSYNC_QUERY_CACHE_SEC, psync_sql_free_cache,
                    PSYNC_QUERY_MAX_CNT);
  else
    psync_sql_free_cache(res);
}

void psync_sql_free_result_nocache(psync_sql_res *res) {
  sqlite3_finalize(res->stmt);
  psync_sql_res_unlock(res);
#if IS_DEBUG
  memset(res, 0xff, sizeof(psync_sql_res));
#endif
  free(res);
}

#if IS_DEBUG
psync_sql_res *psync_sql_do_prep_statement_nocache(const char *sql,
                                                   const char *file,
                                                   unsigned line) {
#else
psync_sql_res *psync_sql_prep_statement_nocache(const char *sql) {
#endif
  sqlite3_stmt *stmt;
  psync_sql_res *res;
  int code;
#if IS_DEBUG
  psync_sql_do_lock(file, line);
#else
  psync_sql_lock();
#endif
  code = sqlite3_prepare_v2(psync_db, sql, -1, &stmt, NULL);
  if (unlikely(code != SQLITE_OK)) {
    psync_sql_unlock();
#if IS_DEBUG
    pdbg_logf(D_ERROR, "error running sql statement: %s: %s called from %s:%u", sql,
          sqlite3_errmsg(psync_db), file, line);
    sendpdbg_logf("error running sql statement: %s: %s called from %s:%u", sql,
              sqlite3_errmsg(psync_db), file, line);
#else
    pdbg_logf(D_ERROR, "error running sql statement: %s: %s", sql,
          sqlite3_errmsg(psync_db));
    sendpdbg_logf("error running sql statement: %s: %s", sql,
              sqlite3_errmsg(psync_db));
#endif
    return NULL;
  }
  res = malloc(sizeof(psync_sql_res));
  res->stmt = stmt;
  res->sql = sql;
#if IS_DEBUG
  res->column_count = 0;
#endif
  res->locked = SQL_WRITE_LOCK;
  return res;
}

#if IS_DEBUG
psync_sql_res *psync_sql_do_prep_statement(const char *sql, const char *file,
                                           unsigned line) {
#else
psync_sql_res *psync_sql_prep_statement(const char *sql) {
#endif
  psync_sql_res *ret;
  ret = pcache_get(sql);
  if (ret) {
    //    pdbg_logf(D_NOTICE, "got statement %s from cache", sql);
    ret->locked = SQL_WRITE_LOCK;
#if IS_DEBUG
    psync_sql_do_lock(file, line);
#else
    psync_sql_lock();
#endif
    return ret;
  } else
#if IS_DEBUG
    return psync_sql_do_prep_statement_nocache(sql, file, line);
#else
    return psync_sql_prep_statement_nocache(sql);
#endif
}

int psync_sql_reset(psync_sql_res *res) {
  int code = sqlite3_reset(res->stmt);
  if (unlikely(code != SQLITE_OK)) {
    pdbg_logf(D_ERROR, "sqlite3_reset returned error: %s",
          sqlite3_errmsg(psync_db));
    return -1;
  } else
    return 0;
}

int psync_sql_run(psync_sql_res *res) {
  int code = sqlite3_step(res->stmt);
  if (unlikely(code != SQLITE_DONE)) {
    pdbg_logf(D_ERROR, "sqlite3_step returned error: %s: %s",
          sqlite3_errmsg(psync_db), res->sql);
    sendtpdbg_logf("sqlite3_step returned error (in_transaction=%d): %s: %s",
               in_transaction, sqlite3_errmsg(psync_db), res->sql);
    transaction_failed = 1;
    if (in_transaction)
      pdbg_logf(D_BUG, "transaction query failed, this may lead to restarting "
                   "transaction over and over");
    return -1;
  }
  code = sqlite3_reset(res->stmt);
  if (unlikely(code != SQLITE_OK))
    pdbg_logf(D_ERROR, "sqlite3_reset returned error: %s",
          sqlite3_errmsg(psync_db));
  return 0;
}

int psync_sql_run_free_nocache(psync_sql_res *res) {
  int code = sqlite3_step(res->stmt);
  if (unlikely(code != SQLITE_DONE)) {
    pdbg_logf(D_ERROR, "sqlite3_step returned error: %s: %s",
          sqlite3_errmsg(psync_db), res->sql);
    sendtpdbg_logf("sqlite3_step returned error (in_transaction=%d): %s: %s",
               in_transaction, sqlite3_errmsg(psync_db), res->sql);
    code = -1;
    transaction_failed = 1;
    if (in_transaction)
      pdbg_logf(D_BUG, "transaction query failed, this may lead to restarting "
                   "transaction over and over");
  } else
    code = 0;
  sqlite3_finalize(res->stmt);
  psync_sql_res_unlock(res);
  free(res);
  return code;
}

int psync_sql_run_free(psync_sql_res *res) {
  int code = sqlite3_step(res->stmt);
  if (unlikely(code != SQLITE_DONE ||
               (code = sqlite3_reset(res->stmt)) != SQLITE_OK)) {
    pdbg_logf(D_ERROR, "sqlite3_step returned error: %s: %s",
          sqlite3_errmsg(psync_db), res->sql);
    sendtpdbg_logf("sqlite3_step returned error (in_transaction=%d): %s: %s",
               in_transaction, sqlite3_errmsg(psync_db), res->sql);
    sqlite3_finalize(res->stmt);
    transaction_failed = 1;
    if (in_transaction)
      pdbg_logf(D_BUG, "transaction query failed, this may lead to restarting "
                   "transaction over and over");
    psync_sql_res_unlock(res);
    free(res);
    return -1;
  } else {
    psync_sql_res_unlock(res);
    pcache_add(res->sql, res, PSYNC_QUERY_CACHE_SEC, psync_sql_free_cache,
                    PSYNC_QUERY_MAX_CNT);
    return 0;
  }
}

void psync_sql_bind_int(psync_sql_res *res, int n, int64_t val) {
  int code = sqlite3_bind_int64(res->stmt, n, val);
  if (unlikely(code != SQLITE_OK))
    pdbg_logf(D_ERROR, "error binding value: %s", sqlite3_errmsg(psync_db));
}

void psync_sql_bind_uint(psync_sql_res *res, int n, uint64_t val) {
  int code = sqlite3_bind_int64(res->stmt, n, val);
  if (unlikely(code != SQLITE_OK))
    pdbg_logf(D_ERROR, "error binding value: %s", sqlite3_errmsg(psync_db));
}

void psync_sql_bind_double(psync_sql_res *res, int n, double val) {
  int code = sqlite3_bind_double(res->stmt, n, val);
  if (unlikely(code != SQLITE_OK))
    pdbg_logf(D_ERROR, "error binding value: %s", sqlite3_errmsg(psync_db));
}

void psync_sql_bind_string(psync_sql_res *res, int n, const char *str) {
  int code = sqlite3_bind_text(res->stmt, n, str, -1, SQLITE_STATIC);
  if (unlikely(code != SQLITE_OK))
    pdbg_logf(D_ERROR, "error binding value: %s", sqlite3_errmsg(psync_db));
}

void psync_sql_bind_lstring(psync_sql_res *res, int n, const char *str,
                            size_t len) {
  int code = sqlite3_bind_text(res->stmt, n, str, len, SQLITE_STATIC);
  if (unlikely(code != SQLITE_OK))
    pdbg_logf(D_ERROR, "error binding value: %s", sqlite3_errmsg(psync_db));
}

void psync_sql_bind_blob(psync_sql_res *res, int n, const char *str,
                         size_t len) {
  int code = sqlite3_bind_blob(res->stmt, n, str, len, SQLITE_STATIC);
  if (unlikely(code != SQLITE_OK))
    pdbg_logf(D_ERROR, "error binding value: %s", sqlite3_errmsg(psync_db));
}

void psync_sql_bind_null(psync_sql_res *res, int n) {
  int code = sqlite3_bind_null(res->stmt, n);
  if (unlikely(code != SQLITE_OK))
    pdbg_logf(D_ERROR, "error binding value: %s", sqlite3_errmsg(psync_db));
}

psync_variant_row psync_sql_fetch_row(psync_sql_res *res) {
  int code, i;
  code = sqlite3_step(res->stmt);
  if (code == SQLITE_ROW) {
    for (i = 0; i < res->column_count; i++) {
      code = sqlite3_column_type(res->stmt, i);
      if (code == SQLITE_INTEGER) {
        res->row[i].type = PSYNC_TNUMBER;
        res->row[i].snum = sqlite3_column_int64(res->stmt, i);
      } else if (code == SQLITE_TEXT || code == SQLITE_BLOB) {
        res->row[i].type = PSYNC_TSTRING;
        res->row[i].length = sqlite3_column_bytes(res->stmt, i);
        res->row[i].str = (char *)sqlite3_column_text(res->stmt, i);
      } else if (code == SQLITE_FLOAT) {
        res->row[i].type = PSYNC_TREAL;
        res->row[i].real = sqlite3_column_double(res->stmt, i);
      } else
        res->row[i].type = PSYNC_TNULL;
    }
    return res->row;
  } else {
    if (unlikely(code != SQLITE_DONE))
      pdbg_logf(D_ERROR, "sqlite3_step returned error: %s",
            sqlite3_errmsg(psync_db));
    return NULL;
  }
}

psync_str_row psync_sql_fetch_rowstr(psync_sql_res *res) {
  int code, i;
  const char **strs;
  code = sqlite3_step(res->stmt);
  if (code == SQLITE_ROW) {
    strs = (const char **)res->row;
    for (i = 0; i < res->column_count; i++)
      strs[i] = (const char *)sqlite3_column_text(res->stmt, i);
    return strs;
  } else {
    if (unlikely(code != SQLITE_DONE))
      pdbg_logf(D_ERROR, "sqlite3_step returned error: %s",
            sqlite3_errmsg(psync_db));
    return NULL;
  }
}

const uint64_t *psync_sql_fetch_rowint(psync_sql_res *res) {
  int code, i;
  uint64_t *ret;
  code = sqlite3_step(res->stmt);
  if (code == SQLITE_ROW) {
    ret = (uint64_t *)res->row;
    for (i = 0; i < res->column_count; i++)
      ret[i] = sqlite3_column_int64(res->stmt, i);
    return ret;
  } else {
    if (unlikely(code != SQLITE_DONE))
      pdbg_logf(D_ERROR, "sqlite3_step returned error: %s",
            sqlite3_errmsg(psync_db));
    return NULL;
  }
}

psync_full_result_int *psync_sql_fetchall_int(psync_sql_res *res) {
  uint64_t *data;
  psync_full_result_int *ret;
  unsigned long rows, cols, off, i, all;
  int code;
  cols = res->column_count;
  rows = 0;
  off = 0;
  all = 0;
  data = NULL;
  while ((code = sqlite3_step(res->stmt)) == SQLITE_ROW) {
    if (rows >= all) {
      all = 10 + all * 2;
      data = (uint64_t *)realloc(data, sizeof(uint64_t) * cols * all);
    }
    for (i = 0; i < cols; i++)
      data[off + i] = sqlite3_column_int64(res->stmt, i);
    off += cols;
    rows++;
  }
  if (unlikely(code != SQLITE_DONE))
    pdbg_logf(D_ERROR, "sqlite3_step returned error: %s", sqlite3_errmsg(psync_db));
  psync_sql_free_result(res);
  ret = (psync_full_result_int *)malloc(
      offsetof(psync_full_result_int, data) + sizeof(uint64_t) * off);
  ret->rows = rows;
  ret->cols = cols;
  memcpy(ret->data, data, sizeof(uint64_t) * off);
  free(data);
  return ret;
}

uint32_t psync_sql_affected_rows() { return sqlite3_changes(psync_db); }

uint64_t psync_sql_insertid() { return sqlite3_last_insert_rowid(psync_db); }


static const char *PSYNC_CONST get_type_name(uint32_t t) {
  if (unlikely(t >= ARRAY_SIZE(psync_typenames)))
    t = 0;
  return psync_typenames[t];
}

uint64_t psync_err_number_expected(const char *file, const char *function,
                                   int unsigned line, const psync_variant *v) {
  if (D_CRITICAL <= DEBUG_LEVEL)
    pdbg_printf(file, function, line, D_CRITICAL,
                "type error, wanted %s got %s", get_type_name(PSYNC_TNUMBER),
                get_type_name(v->type));
  return 0;
}

const char *psync_err_string_expected(const char *file, const char *function,
                                      int unsigned line,
                                      const psync_variant *v) {
  if (D_CRITICAL <= DEBUG_LEVEL)
    pdbg_printf(file, function, line, D_CRITICAL,
                "type error, wanted %s got %s", get_type_name(PSYNC_TSTRING),
                get_type_name(v->type));
  return "";
}

const char *psync_lstring_expected(const char *file, const char *function,
                                   int unsigned line, const psync_variant *v,
                                   size_t *len) {
  if (likely(v->type == PSYNC_TSTRING)) {
    *len = v->length;
    return v->str;
  } else {
    if (D_CRITICAL <= DEBUG_LEVEL)
      pdbg_printf(file, function, line, D_CRITICAL,
                  "type error, wanted %s got %s", get_type_name(PSYNC_TSTRING),
                  get_type_name(v->type));
    *len = 0;
    return "";
  }
}

double psync_err_real_expected(const char *file, const char *function,
                               int unsigned line, const psync_variant *v) {
  if (D_CRITICAL <= DEBUG_LEVEL)
    pdbg_printf(file, function, line, D_CRITICAL,
                "type error, wanted %s got %s", get_type_name(PSYNC_TREAL),
                get_type_name(v->type));
  return 0.0;
}

void psync_try_free_memory() {
  sqlite3_db_release_memory(psync_db);
  pcache_clean();
}
