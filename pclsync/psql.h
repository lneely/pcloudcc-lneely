// IMPORTANT: include pdbg.h before this file

#ifndef __PSQL_H
#define __PSQL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sqlite3.h>
#include <stddef.h>
#include <stdint.h>

#include "pcompiler.h"
#include "plist.h"

typedef struct {
  uint32_t type;
  uint32_t length;
  union {
    uint64_t num;
    int64_t snum;
    const char *str;
    double real;
  };
} psync_variant;

typedef struct {
  sqlite3_stmt *stmt;
  const char *sql;
  int column_count;
  int locked;
  psync_variant row[];
} psync_sql_res;

typedef struct {
  uint32_t rows;
  uint32_t cols;
  uint64_t data[];
} psync_full_result_int;


typedef const uint64_t *psync_uint_row;
typedef const char *const *psync_str_row;
typedef const psync_variant *psync_variant_row;

typedef int (*psync_list_builder_sql_callback)(psync_list_builder_t *, void *, psync_variant_row);
typedef void (*psync_transaction_callback_t)(void *);

int psql_connect(const char *db) PSYNC_NONNULL(1);
int psql_close();
int psql_reopen(const char *path);
void psql_checkpt_lock();
void psql_checkpt_unlock();

#if IS_DEBUG

#define psql_trylock() psql_do_trylock(__FILE__, __LINE__)
#define psql_lock() psql_do_lock(__FILE__, __LINE__)
#define psql_rdlock() psql_do_rdlock(__FILE__, __LINE__)
#define psql_statement(sql) psql_do_statement(sql, __FILE__, __LINE__)
#define psql_start() psql_do_start_transaction(__FILE__, __LINE__)
#define psql_query_nocache(sql) psql_do_query_nocache(sql, __FILE__, __LINE__)
#define psql_query(sql) psql_do_query(sql, __FILE__, __LINE__)
#define psql_rdlock_nocache(sql) psql_do_query_rdlock_nocache(sql, __FILE__, __LINE__)
#define psql_query_rdlock(sql) psql_do_query_rdlock(sql, __FILE__, __LINE__)
#define psql_query_nolock_nocache(sql) psql_do_query_nolock_nocache(sql, __FILE__, __LINE__)
#define psql_query_nolock(sql) psql_do_query_nolock(sql, __FILE__, __LINE__)
#define psql_prepare_nocache(sql) psql_do_prepare_nocache(sql, __FILE__, __LINE__)
#define psql_prepare(sql) psql_do_prepare(sql, __FILE__, __LINE__)
void psql_dump_locks();

int psql_do_trylock(const char *file, unsigned line);
void psql_do_lock(const char *file, unsigned line);
void psql_do_rdlock(const char *file, unsigned line);
int psql_do_statement(const char *sql, const char *file, unsigned line) PSYNC_NONNULL(1);
int psql_do_start_transaction(const char *file, unsigned line);
psync_sql_res *psql_do_query_nocache(const char *sql, const char *file, unsigned line) PSYNC_NONNULL(1);
psync_sql_res *psql_do_query(const char *sql, const char *file, unsigned line) PSYNC_NONNULL(1);
psync_sql_res *psql_do_query_rdlock_nocache(const char *sql, const char *file, unsigned line) PSYNC_NONNULL(1);
psync_sql_res *psql_do_query_rdlock(const char *sql, const char *file, unsigned line) PSYNC_NONNULL(1);
psync_sql_res *psql_do_query_nolock_nocache(const char *sql, const char *file, unsigned line) PSYNC_NONNULL(1);
psync_sql_res *psql_do_query_nolock(const char *sql, const char *file, unsigned line) PSYNC_NONNULL(1);
psync_sql_res *psql_do_prepare_nocache(const char *sql, const char *file, unsigned line) PSYNC_NONNULL(1);
psync_sql_res *psql_do_prepare(const char *sql, const char *file, unsigned line) PSYNC_NONNULL(1);

#else

int psql_trylock();
void psql_lock();
void psql_rdlock();
int psql_statement(const char *sql) PSYNC_NONNULL(1);
int psql_start();

psync_sql_res *psql_query_nocache(const char *sql) PSYNC_NONNULL(1);
psync_sql_res *psql_query(const char *sql) PSYNC_NONNULL(1);
psync_sql_res *psql_rdlock_nocache(const char *sql) PSYNC_NONNULL(1);
psync_sql_res *psql_query_rdlock(const char *sql) PSYNC_NONNULL(1);
psync_sql_res *psql_query_nolock(const char *sql) PSYNC_NONNULL(1);
psync_sql_res *psql_query_nolock_nocache(const char *sql) PSYNC_NONNULL(1);
psync_sql_res *psql_prepare(const char *sql) PSYNC_NONNULL(1);
psync_sql_res *psql_prepare_nocache(const char *sql) PSYNC_NONNULL(1);

#endif

void psql_unlock();
void psql_rdunlock();
int psql_waiting();
int psql_rdlocked();
int psql_locked();
int psql_tryupgradeLock();
int psql_sync();
int psql_commit();
int psql_rollback();

void psql_translation_add_cb(psync_transaction_callback_t commit_callback, psync_transaction_callback_t rollback_callback, void *ptr);

char *psql_cellstr(const char *sql) PSYNC_NONNULL(1);
int64_t psql_cellint(const char *sql, int64_t dflt) PSYNC_NONNULL(1);
char **psql_rowstr(const char *sql) PSYNC_NONNULL(1);
psync_variant *psql_row(const char *sql) PSYNC_NONNULL(1);
int psql_reset(psync_sql_res *res) PSYNC_NONNULL(1);
int psql_run(psync_sql_res *res) PSYNC_NONNULL(1);
int psql_run_free(psync_sql_res *res) PSYNC_NONNULL(1);
int psql_run_free_nocache(psync_sql_res *res) PSYNC_NONNULL(1);
void psql_bind_uint(psync_sql_res *res, int n, uint64_t val) PSYNC_NONNULL(1);
void psql_bind_int(psync_sql_res *res, int n, int64_t val) PSYNC_NONNULL(1);
void psql_bind_double(psync_sql_res *res, int n, double val) PSYNC_NONNULL(1);
void psql_bind_str(psync_sql_res *res, int n, const char *str) PSYNC_NONNULL(1);
void psql_bind_lstr(psync_sql_res *res, int n, const char *str, size_t len) PSYNC_NONNULL(1);
void psql_bind_blob(psync_sql_res *res, int n, const char *str, size_t len) PSYNC_NONNULL(1);
void psql_bind_null(psync_sql_res *res, int n) PSYNC_NONNULL(1);
void psql_free(psync_sql_res *res) PSYNC_NONNULL(1);
void psql_free_nocache(psync_sql_res *res) PSYNC_NONNULL(1);
psync_variant_row psql_fetch(psync_sql_res *res) PSYNC_NONNULL(1);
psync_str_row psql_fetch_str(psync_sql_res *res) PSYNC_NONNULL(1);
psync_uint_row psql_fetch_int(psync_sql_res *res) PSYNC_NONNULL(1);
psync_full_result_int *psql_fetchall_int(psync_sql_res *res) PSYNC_NONNULL(1);
uint32_t psql_affected() PSYNC_PURE;
uint64_t psql_insertid() PSYNC_PURE;
void psql_list_add(psync_list_builder_t *builder, psync_sql_res *res, psync_list_builder_sql_callback callback);
uint64_t psql_expect_num(const char *file, const char *function, int unsigned line, const psync_variant *v) PSYNC_COLD;
const char *psql_expect_str(const char *file, const char *function, int unsigned line, const psync_variant *v) PSYNC_COLD;
const char *psql_lstring_expected(const char *file, const char *function, int unsigned line, const psync_variant *v, size_t *len) PSYNC_NONNULL(4, 5);
double psql_expect_real(const char *file, const char *function, int unsigned line, const psync_variant *v) PSYNC_COLD;
void psql_try_free();

#ifdef __cplusplus
}
#endif

#endif
