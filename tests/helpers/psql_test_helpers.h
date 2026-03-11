/*
 * psql_test_helpers.h — in-memory SQLite harness for unit tests.
 *
 * Provides psql_test_open() / psql_test_close() which open a ":memory:"
 * database and apply the full PSYNC_DATABASE_STRUCTURE schema from
 * pdatabase.h.  Use psql_test_db() to obtain the sqlite3* connection for
 * direct SQL operations in tests.
 *
 * Intentionally bypasses psql.c so tests can link this file alone without
 * pulling in psql.c's heavyweight transitive dependencies (pcache, psignal,
 * psys, pnetlibs, …).
 */
#ifndef PSQL_TEST_HELPERS_H
#define PSQL_TEST_HELPERS_H

#include <sqlite3.h>

/*
 * Open an in-memory SQLite database and apply the full PSYNC_DATABASE_STRUCTURE
 * schema.  Returns 0 on success, -1 on failure.
 * Call this once at the start of each test that needs the DB.
 */
int psql_test_open(void);

/* Close and discard the in-memory database. */
void psql_test_close(void);

/* Return the active sqlite3* connection (valid between open/close). */
sqlite3 *psql_test_db(void);

/* Execute a SQL statement and return the sqlite3 result code. */
int psql_test_exec(const char *sql);

/* Insert one fstask row; returns the inserted rowid on success, -1 on error. */
int64_t psql_test_insert_fstask(int type, int status, int64_t folderid,
                                const char *text1);

/* Count rows matching a simple WHERE clause on fstask. */
int psql_test_count_fstask(const char *where_clause);

/* Count rows matching a simple WHERE clause on fstaskdepend. */
int psql_test_count_fstaskdepend(const char *where_clause);

#endif /* PSQL_TEST_HELPERS_H */
