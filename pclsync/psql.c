#include <sqlite3.h>

#include <sys/stat.h>

#include "pcache.h"
#include "pdatabase.h"
#include "pdbg.h"
#include "plocks.h"
#include "pmem.h"
#include "pnetlibs.h"
#include "prun.h"
#include "psettings.h"
#include "psql.h"
#include "psql_internal.h"
#include "psys.h"

// psql.h defines function-like macros (e.g. psql_lock() -> psql_do_lock())
// that would interfere with this file's own function definitions.
// Undefine them here so we can define the actual implementations.
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

// Forward declarations for internal use within this translation unit.
int psql_trylock(void);
void psql_lock(void);
void psql_rdlock(void);
int psql_statement(const char *sql);
int psql_start(void);
psync_sql_res *psql_query_nocache(const char *sql);
psync_sql_res *psql_query(const char *sql);
psync_sql_res *psql_rdlock_nocache(const char *sql);
psync_sql_res *psql_query_rdlock(const char *sql);
psync_sql_res *psql_query_nolock_nocache(const char *sql);
psync_sql_res *psql_query_nolock(const char *sql);
psync_sql_res *psql_prepare_nocache(const char *sql);
psync_sql_res *psql_prepare(const char *sql);

#define SQL_NO_LOCK 0
#define SQL_READ_LOCK 1
#define SQL_WRITE_LOCK 2

#define PSYNC_TNUMBER 1
#define PSYNC_TSTRING 2
#define PSYNC_TREAL 3
#define PSYNC_TNULL 4
#define PSYNC_TBOOL 5

extern PSYNC_THREAD const char *psync_thread_name;

const static char *psync_typenames[] = {"[invalid type]", "[number]", "[string]", "[float]", "[null]", "[bool]"};

typedef struct {
  psync_list list;
  psync_transaction_callback_t commit;
  psync_transaction_callback_t rollback;
  void *ptr;
} tran_callback_t;


int psync_do_run = 1;                   // FIXME: app state. papp.c?
PSYNC_THREAD uint32_t psync_error = 0;  // FIXME: app state. papp.c?

psync_rwlock_t dblock;
sqlite3 *psync_db;
static pthread_mutex_t cpmutex;
int in_transaction = 0;
int transaction_failed = 0;
psync_list commitcbs;

static void on_error(void *ptr, int code, const char *msg) {
  pdbg_logf(D_WARNING, "database warning %d: %s", code, msg);
}

static void psync_sql_free_cache(void *ptr) {
  psync_sql_res *res = (psync_sql_res *)ptr;
  sqlite3_finalize(res->stmt);
  if (IS_DEBUG)
    memset(res, 0xff, sizeof(psync_sql_res));
  pmem_free(PMEM_SUBSYS_OTHER, res);
}

static void psync_sql_res_unlock(psync_sql_res *res) {
  switch (res->locked) {
  case SQL_NO_LOCK:
    break;
  case SQL_READ_LOCK:
    psql_rdunlock();
    break;
  case SQL_WRITE_LOCK:
    psql_unlock();
    break;
  default:
    if (IS_DEBUG) {
      pdbg_logf(D_ERROR, "unknown value for locked %d", res->locked);
      abort();
    }
    break;
  }
}

static void proc_checkpoint() {
  int code;
  psql_lock();
  psql_unlock();
  if (pthread_mutex_trylock(&cpmutex)) {
    pdbg_logf(D_NOTICE, "checkpoint already in progress");
    return;
  }
  pdbg_logf(D_NOTICE, "checkpointing database");
  code = sqlite3_wal_checkpoint(psync_db, NULL);
  while (code == SQLITE_LOCKED) {
    psys_sleep_milliseconds(2);
    code = sqlite3_wal_checkpoint(psync_db, NULL);
  }
  pthread_mutex_unlock(&cpmutex);
  if (unlikely(code != SQLITE_OK))
    pdbg_logf(D_CRITICAL, "sqlite3_wal_checkpoint returned error %d", code);
  else
    pdbg_logf(D_NOTICE, "checkpoint finished");
}

static int wal_hook(void *ptr, sqlite3 *db, const char *name,
                              int numpages) {
  if (numpages >= PSYNC_DB_CHECKPOINT_AT_PAGES)
    prun_thread("checkpoint charlie", proc_checkpoint);
  return SQLITE_OK;
}

static void commit(int success) {
  tran_callback_t *cb;
  psync_list *l1, *l2;
  psync_list_for_each_safe(l1, l2, &commitcbs) {

  cb = psync_list_element(l1, tran_callback_t, list);
    if (success)
      cb->commit(cb->ptr);
    else
      cb->rollback(cb->ptr);
    pmem_free(PMEM_SUBSYS_OTHER, cb);
  }
}

__attribute__((weak)) int psql_trylock() { return plocks_trywrlock(&dblock); }
__attribute__((weak)) void psql_lock() { plocks_wrlock(&dblock); }
__attribute__((weak)) void psql_unlock() { plocks_unlock(&dblock); }
__attribute__((weak)) void psql_rdlock() { plocks_rdlock(&dblock); }
__attribute__((weak)) void psql_rdunlock() { plocks_unlock(&dblock); }

// psql_do_* weak stubs: release-mode forwarding wrappers.
// Callers always use the psql_do_* names (via psql.h macro expansion).
// debug/psql_debug.c provides strong overrides with lock tracking.
__attribute__((weak)) int psql_do_trylock(const char *file, unsigned line) {
  return psql_trylock();
}
__attribute__((weak)) void psql_do_lock(const char *file, unsigned line) {
  psql_lock();
}
__attribute__((weak)) void psql_do_rdlock(const char *file, unsigned line) {
  psql_rdlock();
}

int psql_connect(const char *db) {
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
      plocks_init(&dblock);
      pthread_mutexattr_init(&mattr);
      pthread_mutexattr_settype(&mattr, PTHREAD_MUTEX_RECURSIVE);
      pthread_mutex_init(&cpmutex, &mattr);
      pthread_mutexattr_destroy(&mattr);
      initmutex = 0;
    }
    if (IS_DEBUG) {
      sqlite3_config(SQLITE_CONFIG_LOG, on_error, NULL);
    }
    sqlite3_wal_hook(psync_db, wal_hook, NULL);
    psql_statement(PSYNC_DATABASE_CONFIG);
    if (initdbneeded == 1)
      return psql_statement(PSYNC_DATABASE_STRUCTURE);
    else if (psql_statement(
                 "DELETE FROM setting WHERE id='justcheckingiflocked'")) {
      pdbg_logf(D_ERROR, "database is locked");
      sqlite3_close(psync_db);
      plocks_destroy(&dblock);
      return -1;
    }

    dbver =
        psql_cellint("SELECT value FROM setting WHERE id='dbversion'", 0);
    if (dbver < PSYNC_DATABASE_VERSION) {
      uint64_t i;
      pdbg_logf(D_NOTICE, "database version %d detected, upgrading to %d",
            (int)dbver, (int)PSYNC_DATABASE_VERSION);
      for (i = dbver; i < PSYNC_DATABASE_VERSION; i++)
        if (psql_statement(psync_db_upgrade[i])) {
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

int psql_close() {
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

int psql_reopen(const char *path) {
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

void psql_checkpt_lock() {
  pthread_mutex_lock(&cpmutex);
}

void psql_checkpt_unlock() {
  pthread_mutex_unlock(&cpmutex);
}

void psql_list_add(psync_list_builder_t *builder, psync_sql_res *res, psync_list_builder_sql_callback callback) {
  psync_variant_row row;
  while ((row = psql_fetch(res))) {
    if (!builder->last_elements ||
        builder->last_elements->used >= builder->elements_per_list) {
      builder->last_elements = (psync_list_element_list *)pmem_malloc(PMEM_SUBSYS_OTHER, 
          offsetof(psync_list_element_list, elements) +
          builder->element_size * builder->elements_per_list);
      psync_list_add_tail(&builder->element_list,
                          &builder->last_elements->list);
      builder->last_elements->used = 0;
    }
    builder->current_element =
        builder->last_elements->elements +
        builder->last_elements->used * builder->element_size;
    builder->cstrcnt = psync_list_builder_push_num(builder);
    *builder->cstrcnt = 0;
    while (callback(builder, builder->current_element, row)) {
      row = psql_fetch(res);
      if (!row)
        break;
      *builder->cstrcnt = 0;
    }
    builder->last_elements->used++;
    builder->cnt++;
  }
  psql_free(res);
}

int psql_waiting() {
  return plocks_num_waiters(&dblock) > 0;
}

int psql_rdlocked() {
  return plocks_holding_rdlock(&dblock);
}

int psql_locked() {
  return plocks_holding_lock(&dblock);
}

__attribute__((weak)) int psql_tryupgradeLock() {
  return plocks_towrlock(&dblock);
}

int psql_sync() {
  int code;
  pthread_mutex_lock(&cpmutex);
  code = sqlite3_wal_checkpoint(psync_db, NULL);
  if (unlikely(code == SQLITE_BUSY || code == SQLITE_LOCKED)) {
    psql_lock();
    code = sqlite3_wal_checkpoint(psync_db, NULL);
    psql_unlock();
  }
  pthread_mutex_unlock(&cpmutex);
  if (unlikely(code != SQLITE_OK)) {
    pdbg_logf(D_CRITICAL, "sqlite3_wal_checkpoint returned error %d", code);
    return -1;
  } else
    return 0;
}

int psql_commit() {
  pdbg_assert(in_transaction);
  if (likely(!transaction_failed)) {
    psync_sql_res *res = psql_prepare("COMMIT");
    if (likely(!psql_run_free(res))) {
      commit(1);
      in_transaction = 0;
      psql_unlock();
      return 0;
    }
  } else
    pdbg_logf(D_ERROR, "rolling back transaction as some statements failed");
  psql_rollback();
  return -1;
}

int psql_rollback() {
  psync_sql_res *res = psql_prepare("ROLLBACK");
  pdbg_assert(in_transaction);
  psql_run_free(res);
  commit(0);
  in_transaction = 0;
  psql_unlock();
  return 0;
}

void psql_translation_add_cb(psync_transaction_callback_t commit, psync_transaction_callback_t rollback, void *ptr) {
  tran_callback_t *cb;
  pdbg_assert(in_transaction);
  cb = pmem_malloc(PMEM_SUBSYS_OTHER, sizeof(tran_callback_t));
  cb->commit = commit;
  cb->rollback = rollback;
  cb->ptr = ptr;
  psync_list_add_tail(&commitcbs, &cb->list);
}

char *psql_cellstr(const char *sql) {
  sqlite3_stmt *stmt;
  int code;
  psql_rdlock();
  code = sqlite3_prepare_v2(psync_db, sql, -1, &stmt, NULL);
  if (unlikely(code != SQLITE_OK)) {
    psql_rdunlock();
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
      ret = putil_strdup(ret);
    sqlite3_finalize(stmt);
    psql_rdunlock();
    return ret;
  } else {
    sqlite3_finalize(stmt);
    psql_rdunlock();
    if (unlikely(code != SQLITE_DONE)) {
      pdbg_logf(D_ERROR, "sqlite3_step returned error: %s: %s", sql,
            sqlite3_errmsg(psync_db));
      sendtpdbg_logf("sqlite3_step returned error: %s: %s", sql,
                 sqlite3_errmsg(psync_db));
    }
    return NULL;
  }
}

int64_t psql_cellint(const char *sql, int64_t dflt) {
  sqlite3_stmt *stmt;
  int code;
  psql_rdlock();
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
  psql_rdunlock();
  return dflt;
}

char **psql_rowstr(const char *sql) {
  sqlite3_stmt *stmt;
  int code, cnt;
  psql_rdlock();
  code = sqlite3_prepare_v2(psync_db, sql, -1, &stmt, NULL);
  if (unlikely(code != SQLITE_OK)) {
    psql_rdunlock();
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
    arr = (char **)pmem_malloc(PMEM_SUBSYS_OTHER, ln);
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
    psql_rdunlock();
    return arr;
  } else {
    sqlite3_finalize(stmt);
    psql_rdunlock();
    if (unlikely(code != SQLITE_DONE)) {
      pdbg_logf(D_ERROR, "sqlite3_step returned error: %s: %s", sql,
            sqlite3_errmsg(psync_db));
      sendtpdbg_logf("sqlite3_step returned error: %s: %s", sql,
                 sqlite3_errmsg(psync_db));
    }
    return NULL;
  }
}

psync_variant *psql_row(const char *sql) {
  sqlite3_stmt *stmt;
  int code, cnt;
  psql_rdlock();
  code = sqlite3_prepare_v2(psync_db, sql, -1, &stmt, NULL);
  if (unlikely(code != SQLITE_OK)) {
    psql_rdunlock();
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
    arr = (psync_variant *)pmem_malloc(PMEM_SUBSYS_OTHER, ln);
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
    psql_rdunlock();
    return arr;
  } else {
    sqlite3_finalize(stmt);
    psql_rdunlock();
    if (unlikely(code != SQLITE_DONE)) {
      pdbg_logf(D_ERROR, "sqlite3_step returned error: %s: %s", sql,
            sqlite3_errmsg(psync_db));
      sendtpdbg_logf("sqlite3_step returned error: %s: %s", sql,
                 sqlite3_errmsg(psync_db));
    }
    return NULL;
  }
}

int psql_reset(psync_sql_res *res) {
  int code = sqlite3_reset(res->stmt);
  if (unlikely(code != SQLITE_OK)) {
    pdbg_logf(D_ERROR, "sqlite3_reset returned error: %s",
          sqlite3_errmsg(psync_db));
    return -1;
  } else
    return 0;
}

int psql_run(psync_sql_res *res) {
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

int psql_run_free_nocache(psync_sql_res *res) {
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
  pmem_free(PMEM_SUBSYS_OTHER, res);
  return code;
}

int psql_run_free(psync_sql_res *res) {
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
    pmem_free(PMEM_SUBSYS_OTHER, res);
    return -1;
  } else {
    psync_sql_res_unlock(res);
    pcache_add(res->sql, res, PSYNC_QUERY_CACHE_SEC, psync_sql_free_cache,
                    PSYNC_QUERY_MAX_CNT);
    return 0;
  }
}

void psql_bind_int(psync_sql_res *res, int n, int64_t val) {
  int code = sqlite3_bind_int64(res->stmt, n, val);
  if (unlikely(code != SQLITE_OK))
    pdbg_logf(D_ERROR, "error binding value: %s", sqlite3_errmsg(psync_db));
}

void psql_bind_uint(psync_sql_res *res, int n, uint64_t val) {
  int code = sqlite3_bind_int64(res->stmt, n, val);
  if (unlikely(code != SQLITE_OK))
    pdbg_logf(D_ERROR, "error binding value: %s", sqlite3_errmsg(psync_db));
}

void psql_bind_double(psync_sql_res *res, int n, double val) {
  int code = sqlite3_bind_double(res->stmt, n, val);
  if (unlikely(code != SQLITE_OK))
    pdbg_logf(D_ERROR, "error binding value: %s", sqlite3_errmsg(psync_db));
}

void psql_bind_str(psync_sql_res *res, int n, const char *str) {
  int code = sqlite3_bind_text(res->stmt, n, str, -1, SQLITE_STATIC);
  if (unlikely(code != SQLITE_OK))
    pdbg_logf(D_ERROR, "error binding value: %s", sqlite3_errmsg(psync_db));
}

void psql_bind_lstr(psync_sql_res *res, int n, const char *str,
                            size_t len) {
  int code = sqlite3_bind_text(res->stmt, n, str, len, SQLITE_STATIC);
  if (unlikely(code != SQLITE_OK))
    pdbg_logf(D_ERROR, "error binding value: %s", sqlite3_errmsg(psync_db));
}

void psql_bind_blob(psync_sql_res *res, int n, const char *str,
                         size_t len) {
  int code = sqlite3_bind_blob(res->stmt, n, str, len, SQLITE_STATIC);
  if (unlikely(code != SQLITE_OK))
    pdbg_logf(D_ERROR, "error binding value: %s", sqlite3_errmsg(psync_db));
}

void psql_bind_null(psync_sql_res *res, int n) {
  int code = sqlite3_bind_null(res->stmt, n);
  if (unlikely(code != SQLITE_OK))
    pdbg_logf(D_ERROR, "error binding value: %s", sqlite3_errmsg(psync_db));
}

psync_variant_row psql_fetch(psync_sql_res *res) {
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

psync_str_row psql_fetch_str(psync_sql_res *res) {
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

const uint64_t *psql_fetch_int(psync_sql_res *res) {
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

psync_full_result_int *psql_fetchall_int(psync_sql_res *res) {
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
      data = (uint64_t *)pmem_realloc(PMEM_SUBSYS_OTHER, data, sizeof(uint64_t) * cols * all);
    }
    for (i = 0; i < cols; i++)
      data[off + i] = sqlite3_column_int64(res->stmt, i);
    off += cols;
    rows++;
  }
  if (unlikely(code != SQLITE_DONE))
    pdbg_logf(D_ERROR, "sqlite3_step returned error: %s", sqlite3_errmsg(psync_db));
  psql_free(res);
  ret = (psync_full_result_int *)pmem_malloc(PMEM_SUBSYS_OTHER, 
      offsetof(psync_full_result_int, data) + sizeof(uint64_t) * off);
  ret->rows = rows;
  ret->cols = cols;
  memcpy(ret->data, data, sizeof(uint64_t) * off);
  pmem_free(PMEM_SUBSYS_OTHER, data);
  return ret;
}

uint32_t psql_affected() {
  return sqlite3_changes(psync_db);
}

uint64_t psql_insertid() {
  return sqlite3_last_insert_rowid(psync_db);
}

static const char *PSYNC_CONST get_type_name(uint32_t t) {
  if (unlikely(t >= ARRAY_SIZE(psync_typenames)))
    t = 0;
  return psync_typenames[t];
}

uint64_t psql_expect_num(const char *file, const char *function,
                                   int unsigned line, const psync_variant *v) {
  if (D_CRITICAL <= DEBUG_LEVEL)
    pdbg_printf(file, function, line, D_CRITICAL,
                "type error, wanted %s got %s", get_type_name(PSYNC_TNUMBER),
                get_type_name(v->type));
  return 0;
}

const char *psql_expect_str(const char *file, const char *function,
                                      int unsigned line,
                                      const psync_variant *v) {
  if (D_CRITICAL <= DEBUG_LEVEL)
    pdbg_printf(file, function, line, D_CRITICAL,
                "type error, wanted %s got %s", get_type_name(PSYNC_TSTRING),
                get_type_name(v->type));
  return "";
}

const char *psql_lstring_expected(const char *file, const char *function,
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

double psql_expect_real(const char *file, const char *function,
                               int unsigned line, const psync_variant *v) {
  if (D_CRITICAL <= DEBUG_LEVEL)
    pdbg_printf(file, function, line, D_CRITICAL,
                "type error, wanted %s got %s", get_type_name(PSYNC_TREAL),
                get_type_name(v->type));
  return 0.0;
}

void psql_try_free() {
  sqlite3_db_release_memory(psync_db);
  pcache_clean();
}

__attribute__((weak)) int psql_statement(const char *sql) {
  char *errmsg;
  int code;
  psql_lock();
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

__attribute__((weak)) int psql_start() {
  psync_sql_res *res;
  psql_lock();
  res = psql_prepare("BEGIN");
  pdbg_assert(!in_transaction);
  if (unlikely(!res || psql_run_free(res)))
    return -1;
  in_transaction = 1;
  transaction_failed = 0;
  psync_list_init(&commitcbs);
  return 0;
}

__attribute__((weak)) psync_sql_res *psql_query_nocache(const char *sql) {
  sqlite3_stmt *stmt;
  psync_sql_res *res;
  int code, cnt;
  psql_lock();
  code = sqlite3_prepare_v2(psync_db, sql, -1, &stmt, NULL);
  if (unlikely(code != SQLITE_OK)) {
    psql_unlock();
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
  res->locked = SQL_WRITE_LOCK;
  return res;
}

__attribute__((weak)) psync_sql_res *psql_query(const char *sql) {
  psync_sql_res *ret;
  ret = (psync_sql_res *)pcache_get(sql);
  if (ret) {
    ret->locked = SQL_WRITE_LOCK;
    ret->sql = sql;
    psql_lock();
    return ret;
  } else
    return psql_query_nocache(sql);
}

__attribute__((weak)) psync_sql_res *psql_rdlock_nocache(const char *sql) {
  sqlite3_stmt *stmt;
  psync_sql_res *res;
  int code, cnt;
  psql_rdlock();
  code = sqlite3_prepare_v2(psync_db, sql, -1, &stmt, NULL);
  if (unlikely(code != SQLITE_OK)) {
    psql_rdunlock();
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
  res->locked = SQL_READ_LOCK;
  return res;
}

__attribute__((weak)) psync_sql_res *psql_query_rdlock(const char *sql) {
  psync_sql_res *ret;
  ret = (psync_sql_res *)pcache_get(sql);
  if (ret) {
    ret->locked = SQL_READ_LOCK;
    ret->sql = sql;
    psql_rdlock();
    return ret;
  } else
    return psql_rdlock_nocache(sql);
}

__attribute__((weak)) psync_sql_res *psql_query_nolock_nocache(const char *sql) {
  sqlite3_stmt *stmt;
  psync_sql_res *res;
  int code, cnt;
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

__attribute__((weak)) psync_sql_res *psql_query_nolock(const char *sql) {
  psync_sql_res *ret;
  ret = (psync_sql_res *)pcache_get(sql);
  if (ret) {
    ret->locked = SQL_NO_LOCK;
    ret->sql = sql;
    return ret;
  } else
    return psql_query_nolock_nocache(sql);
}

void psql_free(psync_sql_res *res) {
  int code = sqlite3_reset(res->stmt);
  psync_sql_res_unlock(res);
  if (IS_DEBUG)
    memset(res->row, 0xff, res->column_count * sizeof(psync_variant));
  if (code == SQLITE_OK)
    pcache_add(res->sql, res, PSYNC_QUERY_CACHE_SEC, psync_sql_free_cache,
                    PSYNC_QUERY_MAX_CNT);
  else
    psync_sql_free_cache(res);
}

void psql_free_nocache(psync_sql_res *res) {
  sqlite3_finalize(res->stmt);
  psync_sql_res_unlock(res);
  if (IS_DEBUG)
    memset(res, 0xff, sizeof(psync_sql_res));
  pmem_free(PMEM_SUBSYS_OTHER, res);
}

__attribute__((weak)) psync_sql_res *psql_prepare_nocache(const char *sql) {
  sqlite3_stmt *stmt;
  psync_sql_res *res;
  int code;
  psql_lock();
  code = sqlite3_prepare_v2(psync_db, sql, -1, &stmt, NULL);
  if (unlikely(code != SQLITE_OK)) {
    psql_unlock();
    pdbg_logf(D_ERROR, "error running sql statement: %s: %s", sql,
          sqlite3_errmsg(psync_db));
    sendpdbg_logf("error running sql statement: %s: %s", sql,
              sqlite3_errmsg(psync_db));
    return NULL;
  }
  res = pmem_malloc(PMEM_SUBSYS_OTHER, sizeof(psync_sql_res));
  res->stmt = stmt;
  res->sql = sql;
  res->column_count = 0;
  res->locked = SQL_WRITE_LOCK;
  return res;
}

__attribute__((weak)) psync_sql_res *psql_prepare(const char *sql) {
  psync_sql_res *ret;
  ret = pcache_get(sql);
  if (ret) {
    ret->locked = SQL_WRITE_LOCK;
    psql_lock();
    return ret;
  } else
    return psql_prepare_nocache(sql);
}

// psql_do_* weak stubs for query/statement/prepare variants.
// In release builds these forward directly to the non-do implementations.
// debug/psql_debug.c provides strong overrides with SQL tracing.
__attribute__((weak)) int psql_do_statement(const char *sql, const char *file,
                                            unsigned line) {
  return psql_statement(sql);
}
__attribute__((weak)) int psql_do_start_transaction(const char *file,
                                                    unsigned line) {
  return psql_start();
}
__attribute__((weak)) psync_sql_res *psql_do_query_nocache(const char *sql,
                                                           const char *file,
                                                           unsigned line) {
  return psql_query_nocache(sql);
}
__attribute__((weak)) psync_sql_res *psql_do_query(const char *sql,
                                                   const char *file,
                                                   unsigned line) {
  return psql_query(sql);
}
__attribute__((weak)) psync_sql_res *
psql_do_query_rdlock_nocache(const char *sql, const char *file, unsigned line) {
  return psql_rdlock_nocache(sql);
}
__attribute__((weak)) psync_sql_res *psql_do_query_rdlock(const char *sql,
                                                          const char *file,
                                                          unsigned line) {
  return psql_query_rdlock(sql);
}
__attribute__((weak)) psync_sql_res *
psql_do_query_nolock_nocache(const char *sql, const char *file, unsigned line) {
  return psql_query_nolock_nocache(sql);
}
__attribute__((weak)) psync_sql_res *psql_do_query_nolock(const char *sql,
                                                          const char *file,
                                                          unsigned line) {
  return psql_query_nolock(sql);
}
__attribute__((weak)) psync_sql_res *psql_do_prepare_nocache(const char *sql,
                                                             const char *file,
                                                             unsigned line) {
  return psql_prepare_nocache(sql);
}
__attribute__((weak)) psync_sql_res *psql_do_prepare(const char *sql,
                                                     const char *file,
                                                     unsigned line) {
  return psql_prepare(sql);
}
