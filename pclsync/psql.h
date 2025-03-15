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

int psync_sql_connect(const char *db) PSYNC_NONNULL(1);
int psync_sql_close();
int psync_sql_reopen(const char *path);
void psync_sql_checkpoint_lock();
void psync_sql_checkpoint_unlock();

#if IS_DEBUG

#define psync_sql_trylock() psync_sql_do_trylock(__FILE__, __LINE__)
#define psync_sql_lock() psync_sql_do_lock(__FILE__, __LINE__)
#define psync_sql_rdlock() psync_sql_do_rdlock(__FILE__, __LINE__)
#define psync_sql_statement(sql) psync_sql_do_statement(sql, __FILE__, __LINE__)
#define psync_sql_start_transaction() psync_sql_do_start_transaction(__FILE__, __LINE__)
#define psync_sql_query_nocache(sql) psync_sql_do_query_nocache(sql, __FILE__, __LINE__)
#define psync_sql_query(sql) psync_sql_do_query(sql, __FILE__, __LINE__)
#define psync_sql_query_rdlock_nocache(sql) psync_sql_do_query_rdlock_nocache(sql, __FILE__, __LINE__)
#define psync_sql_query_rdlock(sql) psync_sql_do_query_rdlock(sql, __FILE__, __LINE__)
#define psync_sql_query_nolock_nocache(sql) psync_sql_do_query_nolock_nocache(sql, __FILE__, __LINE__)
#define psync_sql_query_nolock(sql) psync_sql_do_query_nolock(sql, __FILE__, __LINE__)
#define psync_sql_prep_statement_nocache(sql) psync_sql_do_prep_statement_nocache(sql, __FILE__, __LINE__)
#define psync_sql_prep_statement(sql) psync_sql_do_prep_statement(sql, __FILE__, __LINE__)

int psync_sql_do_trylock(const char *file, unsigned line);
void psync_sql_do_lock(const char *file, unsigned line);
void psync_sql_do_rdlock(const char *file, unsigned line);
int psync_sql_do_statement(const char *sql, const char *file, unsigned line) PSYNC_NONNULL(1);
int psync_sql_do_start_transaction(const char *file, unsigned line);
psync_sql_res *psync_sql_do_query_nocache(const char *sql, const char *file, unsigned line) PSYNC_NONNULL(1);
psync_sql_res *psync_sql_do_query(const char *sql, const char *file, unsigned line) PSYNC_NONNULL(1);
psync_sql_res *psync_sql_do_query_rdlock_nocache(const char *sql, const char *file, unsigned line) PSYNC_NONNULL(1);
psync_sql_res *psync_sql_do_query_rdlock(const char *sql, const char *file, unsigned line) PSYNC_NONNULL(1);
psync_sql_res *psync_sql_do_query_nolock_nocache(const char *sql, const char *file, unsigned line) PSYNC_NONNULL(1);
psync_sql_res *psync_sql_do_query_nolock(const char *sql, const char *file, unsigned line) PSYNC_NONNULL(1);
psync_sql_res *psync_sql_do_prep_statement_nocache(const char *sql, const char *file, unsigned line) PSYNC_NONNULL(1);
psync_sql_res *psync_sql_do_prep_statement(const char *sql, const char *file, unsigned line) PSYNC_NONNULL(1);
void psync_sql_dump_locks();

#else

int psync_sql_trylock();
void psync_sql_lock();
void psync_sql_rdlock();
int psync_sql_statement(const char *sql) PSYNC_NONNULL(1);
int psync_sql_start_transaction();

psync_sql_res *psync_sql_query_nocache(const char *sql) PSYNC_NONNULL(1);
psync_sql_res *psync_sql_query(const char *sql) PSYNC_NONNULL(1);
psync_sql_res *psync_sql_query_rdlock_nocache(const char *sql) PSYNC_NONNULL(1);
psync_sql_res *psync_sql_query_rdlock(const char *sql) PSYNC_NONNULL(1);
psync_sql_res *psync_sql_query_nolock(const char *sql) PSYNC_NONNULL(1);
psync_sql_res *psync_sql_query_nolock_nocache(const char *sql) PSYNC_NONNULL(1);
psync_sql_res *psync_sql_prep_statement(const char *sql) PSYNC_NONNULL(1);
psync_sql_res *psync_sql_prep_statement_nocache(const char *sql) PSYNC_NONNULL(1);

#endif

void psync_sql_unlock();
void psync_sql_rdunlock();
int psync_sql_has_waiters();
int psync_sql_isrdlocked();
int psync_sql_islocked();
int psync_sql_tryupgradelock();
int psync_sql_sync();
int psync_sql_commit_transaction();
int psync_sql_rollback_transaction();

void psync_sql_transation_add_callbacks(psync_transaction_callback_t commit_callback, psync_transaction_callback_t rollback_callback, void *ptr);

char *psync_sql_cellstr(const char *sql) PSYNC_NONNULL(1);
int64_t psync_sql_cellint(const char *sql, int64_t dflt) PSYNC_NONNULL(1);
char **psync_sql_rowstr(const char *sql) PSYNC_NONNULL(1);
psync_variant *psync_sql_row(const char *sql) PSYNC_NONNULL(1);
int psync_sql_reset(psync_sql_res *res) PSYNC_NONNULL(1);
int psync_sql_run(psync_sql_res *res) PSYNC_NONNULL(1);
int psync_sql_run_free(psync_sql_res *res) PSYNC_NONNULL(1);
int psync_sql_run_free_nocache(psync_sql_res *res) PSYNC_NONNULL(1);
void psync_sql_bind_uint(psync_sql_res *res, int n, uint64_t val) PSYNC_NONNULL(1);
void psync_sql_bind_int(psync_sql_res *res, int n, int64_t val) PSYNC_NONNULL(1);
void psync_sql_bind_double(psync_sql_res *res, int n, double val) PSYNC_NONNULL(1);
void psync_sql_bind_string(psync_sql_res *res, int n, const char *str) PSYNC_NONNULL(1);
void psync_sql_bind_lstring(psync_sql_res *res, int n, const char *str, size_t len) PSYNC_NONNULL(1);
void psync_sql_bind_blob(psync_sql_res *res, int n, const char *str, size_t len) PSYNC_NONNULL(1);
void psync_sql_bind_null(psync_sql_res *res, int n) PSYNC_NONNULL(1);
void psync_sql_free_result(psync_sql_res *res) PSYNC_NONNULL(1);
void psync_sql_free_result_nocache(psync_sql_res *res) PSYNC_NONNULL(1);
psync_variant_row psync_sql_fetch_row(psync_sql_res *res) PSYNC_NONNULL(1);
psync_str_row psync_sql_fetch_rowstr(psync_sql_res *res) PSYNC_NONNULL(1);
psync_uint_row psync_sql_fetch_rowint(psync_sql_res *res) PSYNC_NONNULL(1);
psync_full_result_int *psync_sql_fetchall_int(psync_sql_res *res) PSYNC_NONNULL(1);
uint32_t psync_sql_affected_rows() PSYNC_PURE;
uint64_t psync_sql_insertid() PSYNC_PURE;
void psync_list_bulder_add_sql(psync_list_builder_t *builder, psync_sql_res *res, psync_list_builder_sql_callback callback);
uint64_t psync_err_number_expected(const char *file, const char *function, int unsigned line, const psync_variant *v) PSYNC_COLD;
const char *psync_err_string_expected(const char *file, const char *function, int unsigned line, const psync_variant *v) PSYNC_COLD;
const char *psync_lstring_expected(const char *file, const char *function, int unsigned line, const psync_variant *v, size_t *len) PSYNC_NONNULL(4, 5);
double psync_err_real_expected(const char *file, const char *function, int unsigned line, const psync_variant *v) PSYNC_COLD;
void psync_try_free_memory();

#ifdef __cplusplus
}
#endif

#endif
