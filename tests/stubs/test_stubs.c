#define _POSIX_C_SOURCE 200809L
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Include headers before implementation */
#include "../pclsync/psock.h"
#include "../pclsync/papi.h"
#include "../pclsync/psql.h"
#include "../pclsync/psettings.h"

/* Thread-local storage stub */
__thread const char *psync_thread_name = "test";
__thread uint32_t psync_error = 0;

/* Global stubs */
const char *psync_my_auth = "test_auth";
const char *apiserver = "https://api.pcloud.com";

/* psync_setting stubs */
int psync_setting_get_bool(int setting) {
    (void)setting;
    return 0;
}

/* papi stubs */
psock_t *papi_connect(const char *hostname, int usessl) {
    (void)hostname;
    (void)usessl;
    return NULL;
}

binresult *papi_send(psock_t *sock, const char *command, size_t cmdlen, const binparam *params, size_t paramcnt, int64_t datalen, int readres) {
    (void)sock;
    (void)command;
    (void)cmdlen;
    (void)params;
    (void)paramcnt;
    (void)datalen;
    (void)readres;
    return NULL;
}

const binresult *papi_find_result(const binresult *res, const char *name, uint32_t type, const char *file, const char *function, unsigned int line) {
    (void)res;
    (void)name;
    (void)type;
    (void)file;
    (void)function;
    (void)line;
    return NULL;
}

/* psock stubs */
void psock_close(psock_t *sock) {
    (void)sock;
}

/* psql stubs */
int64_t psql_cellint(const char *sql, int64_t dflt) {
    (void)sql;
    return dflt;
}

psync_sql_res *psql_prepare(const char *sql) {
    (void)sql;
    return NULL;
}

void psql_bind_uint(psync_sql_res *res, int n, uint64_t val) {
    (void)res;
    (void)n;
    (void)val;
}

int psql_run_free(psync_sql_res *res) {
    (void)res;
    return -1;
}

psync_sql_res *psql_query(const char *sql) {
    (void)sql;
    return NULL;
}

psync_variant_row psql_fetch(psync_sql_res *res) {
    (void)res;
    return NULL;
}

void psql_free(psync_sql_res *res) {
    (void)res;
}

const char *psql_expect_str(const char *name, const char *sql, uint32_t row, const psync_variant *params) {
    (void)name;
    (void)sql;
    (void)row;
    (void)params;
    return "";
}

uint64_t psql_expect_num(const char *name, const char *sql, uint32_t row, const psync_variant *params) {
    (void)name;
    (void)sql;
    (void)row;
    (void)params;
    return 0;
}

void psql_try_free(void) {
    /* no-op */
}

int psql_reopen(const char *path) {
    (void)path;
    return 0;
}

/* pfile stubs */
int pfile_stat_mode_ok(mode_t mode) {
    (void)mode;
    return 1;
}

int pfile_rename(const char *oldpath, const char *newpath) {
    (void)oldpath;
    (void)newpath;
    return 0;
}

#ifdef __cplusplus
}
#endif
