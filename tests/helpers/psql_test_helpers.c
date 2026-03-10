/*
 * psql_test_helpers.c — in-memory SQLite harness for unit tests.
 *
 * Opens ":memory:" and applies the PSYNC_DATABASE_STRUCTURE schema from
 * pdatabase.h.  All tests that need a live database use this file.
 */

#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stddef.h>
#include <string.h>

#include <sqlite3.h>

#include "pdatabase.h"
#include "psql_test_helpers.h"

static sqlite3 *g_db = NULL;

int psql_test_open(void) {
    if (g_db) {
        sqlite3_close(g_db);
        g_db = NULL;
    }
    if (sqlite3_open(":memory:", &g_db) != SQLITE_OK) {
        fprintf(stderr, "psql_test_open: sqlite3_open failed: %s\n",
                sqlite3_errmsg(g_db));
        sqlite3_close(g_db);
        g_db = NULL;
        return -1;
    }
    /*
     * Enable foreign key enforcement — sqlite3 disables it by default.
     * Must be set before the schema is applied so CASCADE/FK constraints
     * take effect from the start (mirrors psql_connect's DATABASE_CONFIG).
     */
    sqlite3_exec(g_db, "PRAGMA foreign_keys=ON;", NULL, NULL, NULL);

    /*
     * PSYNC_DATABASE_STRUCTURE begins with "PRAGMA page_size=4096;…" and ends
     * with "COMMIT;\n".  For :memory: the pragmas are silently ignored and the
     * DDL is applied inside a BEGIN/COMMIT block.
     */
    char *err = NULL;
    int rc = sqlite3_exec(g_db, PSYNC_DATABASE_STRUCTURE, NULL, NULL, &err);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "psql_test_open: schema error: %s\n",
                err ? err : "(null)");
        sqlite3_free(err);
        sqlite3_close(g_db);
        g_db = NULL;
        return -1;
    }
    return 0;
}

void psql_test_close(void) {
    if (g_db) {
        sqlite3_close(g_db);
        g_db = NULL;
    }
}

sqlite3 *psql_test_db(void) {
    return g_db;
}

int psql_test_exec(const char *sql) {
    char *err = NULL;
    int rc = sqlite3_exec(g_db, sql, NULL, NULL, &err);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "psql_test_exec: %s\n  SQL: %s\n",
                err ? err : "(null)", sql);
        sqlite3_free(err);
    }
    return rc;
}

int64_t psql_test_insert_fstask(int type, int status, int64_t folderid,
                                const char *text1) {
    sqlite3_stmt *stmt;
    const char *sql = "INSERT INTO fstask (type, status, folderid, sfolderid,"
                      " text1) VALUES (?, ?, ?, ?, ?)";
    if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int(stmt,  1, type);
    sqlite3_bind_int(stmt,  2, status);
    sqlite3_bind_int64(stmt, 3, folderid);
    sqlite3_bind_int64(stmt, 4, folderid);
    if (text1)
        sqlite3_bind_text(stmt, 5, text1, -1, SQLITE_STATIC);
    else
        sqlite3_bind_null(stmt, 5);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) return -1;
    return (int64_t)sqlite3_last_insert_rowid(g_db);
}

int psql_test_count_fstask(const char *where_clause) {
    char sql[512];
    if (where_clause && *where_clause)
        snprintf(sql, sizeof(sql),
                 "SELECT COUNT(*) FROM fstask WHERE %s", where_clause);
    else
        snprintf(sql, sizeof(sql), "SELECT COUNT(*) FROM fstask");
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) != SQLITE_OK) return -1;
    int count = -1;
    if (sqlite3_step(stmt) == SQLITE_ROW)
        count = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);
    return count;
}

int psql_test_count_fstaskdepend(const char *where_clause) {
    char sql[512];
    if (where_clause && *where_clause)
        snprintf(sql, sizeof(sql),
                 "SELECT COUNT(*) FROM fstaskdepend WHERE %s", where_clause);
    else
        snprintf(sql, sizeof(sql), "SELECT COUNT(*) FROM fstaskdepend");
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) != SQLITE_OK) return -1;
    int count = -1;
    if (sqlite3_step(stmt) == SQLITE_ROW)
        count = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);
    return count;
}
