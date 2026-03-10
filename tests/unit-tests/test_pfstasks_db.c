/*
 * Test: pfstasks DB layer via psql_test_helpers
 *
 * Opens an :memory: SQLite database with the full PSYNC_DATABASE_STRUCTURE
 * schema, then exercises:
 *   1. Schema creation (tables and indices exist)
 *   2. fstask row insertion and retrieval
 *   3. Dependency insertion via fstaskdepend
 *   4. CASCADE DELETE: deleting an fstask removes its fstaskdepend rows
 *   5. FK enforcement: fstaskdepend row with unknown fstaskid is rejected
 *   6. rmdir blocking: SQL query pattern that pfstasks.c uses to detect
 *      non-empty folders (file/folder rows in DB)
 *   7. creat-after-unlink: insert UNLINK then CREAT tasks for the same name
 *      in the same folder, verify both tasks exist and can be queried by type
 */

#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sqlite3.h>

#include "psql_test_helpers.h"

/* Task type constants (mirrors pfstasks.h / PSYNC_FS_TASK_*) */
#define TASK_MKDIR   1
#define TASK_RMDIR   2
#define TASK_CREAT   3
#define TASK_UNLINK  4

/* ------------------------------------------------------------------ */
static int passes = 0, failures = 0;
#define PASS(n)      do { printf("PASS: %s\n", n); passes++; } while (0)
#define FAIL(n, ...) do { printf("FAIL: %s — ", n); printf(__VA_ARGS__); printf("\n"); failures++; } while (0)

static int table_exists(const char *name) {
    char sql[256];
    snprintf(sql, sizeof(sql),
             "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='%s'",
             name);
    sqlite3_stmt *stmt;
    sqlite3 *db = psql_test_db();
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) return 0;
    int ok = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW)
        ok = sqlite3_column_int(stmt, 0) > 0;
    sqlite3_finalize(stmt);
    return ok;
}

/* ------------------------------------------------------------------ */
/* Test 1: Schema creation                                              */
/* ------------------------------------------------------------------ */
static void test_schema_created(void) {
    const char *required[] = {
        "fstask", "fstaskdepend", "folder", "file", "setting",
        "syncfolder", "localfolder", "localfile", NULL
    };
    int ok = 1;
    for (int i = 0; required[i]; i++) {
        if (!table_exists(required[i])) {
            ok = 0;
            FAIL("schema: table exists", "table '%s' missing", required[i]);
        }
    }
    if (ok)
        PASS("schema: all required tables created");
}

/* ------------------------------------------------------------------ */
/* Test 2: fstask insert and query                                      */
/* ------------------------------------------------------------------ */
static void test_fstask_insert_query(void) {
    int64_t id = psql_test_insert_fstask(TASK_MKDIR, 0, 100, "mydir");
    if (id <= 0)
        { FAIL("fstask insert", "rowid=%lld", (long long)id); return; }

    int cnt = psql_test_count_fstask("type=1 AND folderid=100");
    if (cnt == 1)
        PASS("fstask insert: row present with correct type/folderid");
    else
        FAIL("fstask insert/query", "count=%d expected 1", cnt);
}

/* ------------------------------------------------------------------ */
/* Test 3: fstaskdepend insert                                          */
/* ------------------------------------------------------------------ */
static void test_fstaskdepend_insert(void) {
    int64_t task1 = psql_test_insert_fstask(TASK_MKDIR, 0, 200, "parent");
    int64_t task2 = psql_test_insert_fstask(TASK_MKDIR, 0, 200, "child");
    if (task1 <= 0 || task2 <= 0)
        { FAIL("fstaskdepend setup", "tasks=%lld/%lld", (long long)task1,
               (long long)task2); return; }

    char sql[256];
    snprintf(sql, sizeof(sql),
             "INSERT INTO fstaskdepend (fstaskid, dependfstaskid) VALUES (%lld, %lld)",
             (long long)task2, (long long)task1);
    if (psql_test_exec(sql) != SQLITE_OK)
        { FAIL("fstaskdepend insert", "exec failed"); return; }

    char where[128];
    snprintf(where, sizeof(where), "fstaskid=%lld AND dependfstaskid=%lld",
             (long long)task2, (long long)task1);
    int cnt = psql_test_count_fstaskdepend(where);
    if (cnt == 1)
        PASS("fstaskdepend: dependency row inserted");
    else
        FAIL("fstaskdepend insert/count", "count=%d expected 1", cnt);
}

/* ------------------------------------------------------------------ */
/* Test 4: CASCADE DELETE — deleting fstask removes fstaskdepend rows  */
/* ------------------------------------------------------------------ */
static void test_cascade_delete(void) {
    int64_t parent = psql_test_insert_fstask(TASK_MKDIR, 0, 300, "cascade_p");
    int64_t child  = psql_test_insert_fstask(TASK_MKDIR, 0, 300, "cascade_c");
    if (parent <= 0 || child <= 0)
        { FAIL("cascade setup", "ids=%lld/%lld", (long long)parent,
               (long long)child); return; }

    char sql[256];
    snprintf(sql, sizeof(sql),
             "INSERT INTO fstaskdepend (fstaskid, dependfstaskid) VALUES (%lld, %lld)",
             (long long)child, (long long)parent);
    psql_test_exec(sql);

    /* Delete the parent task */
    snprintf(sql, sizeof(sql), "DELETE FROM fstask WHERE id=%lld",
             (long long)parent);
    psql_test_exec(sql);

    /* Both the parent row AND the dependency row should be gone */
    char where[128];
    snprintf(where, sizeof(where), "dependfstaskid=%lld", (long long)parent);
    int dep_cnt = psql_test_count_fstaskdepend(where);
    snprintf(where, sizeof(where), "id=%lld", (long long)parent);
    int task_cnt = psql_test_count_fstask(where);

    if (task_cnt == 0 && dep_cnt == 0)
        PASS("CASCADE DELETE: fstask + fstaskdepend rows removed together");
    else
        FAIL("CASCADE DELETE", "task_cnt=%d dep_cnt=%d (expected 0,0)",
             task_cnt, dep_cnt);
}

/* ------------------------------------------------------------------ */
/* Test 5: FK enforcement — fstaskdepend rejects unknown fstaskid       */
/* ------------------------------------------------------------------ */
static void test_fk_enforcement(void) {
    /*
     * Attempt to insert an fstaskdepend row referencing a non-existent
     * fstask id.  With foreign_keys=ON this should fail.
     */
    int rc = psql_test_exec(
        "INSERT INTO fstaskdepend (fstaskid, dependfstaskid) "
        "VALUES (9999999, 9999998)");
    if (rc != SQLITE_OK)
        PASS("FK enforcement: fstaskdepend rejects unknown fstaskid");
    else
        FAIL("FK enforcement", "insert should have failed with FK violation");
}

/* ------------------------------------------------------------------ */
/* Test 6: rmdir blocking — SQL query pattern used by pfstasks.c        */
/*                                                                      */
/* pfstasks.c checks non-empty folder via:                              */
/*   SELECT name FROM file WHERE parentfolderid=<id>                    */
/*   SELECT name FROM folder WHERE parentfolderid=<id>                  */
/* ------------------------------------------------------------------ */
static void test_rmdir_blocking_sql(void) {
    /*
     * Insert a parent folder (id=500) and a child file inside it.
     * Then simulate the pfstasks.c non-empty check.
     */
    sqlite3 *db = psql_test_db();

    /* Insert parent folder */
    psql_test_exec("INSERT INTO folder (id, parentfolderid, name) "
                   "VALUES (500, 0, 'testfolder')");

    /* Insert a file inside it */
    psql_test_exec("INSERT INTO file (id, parentfolderid, name, size, hash,"
                   " ctime, mtime) VALUES (5001, 500, 'child.txt', 0, 0, 0, 0)");

    /* pfstasks.c query: files in folder */
    sqlite3_stmt *stmt;
    int file_cnt = 0;
    sqlite3_prepare_v2(db,
        "SELECT COUNT(*) FROM file WHERE parentfolderid=500",
        -1, &stmt, NULL);
    if (sqlite3_step(stmt) == SQLITE_ROW)
        file_cnt = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);

    if (file_cnt > 0)
        PASS("rmdir blocking: non-empty folder detected via file query");
    else
        FAIL("rmdir blocking", "file_cnt=%d expected >0", file_cnt);

    /* Now remove the file and verify folder appears empty */
    psql_test_exec("DELETE FROM file WHERE id=5001");
    sqlite3_prepare_v2(db,
        "SELECT COUNT(*) FROM file WHERE parentfolderid=500",
        -1, &stmt, NULL);
    file_cnt = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW)
        file_cnt = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);
    if (file_cnt == 0)
        PASS("rmdir blocking: folder appears empty after file deletion");
    else
        FAIL("rmdir empty check", "file_cnt=%d expected 0", file_cnt);
}

/* ------------------------------------------------------------------ */
/* Test 7: creat-after-unlink — insert UNLINK + CREAT for same name,   */
/*          query both tasks exist and can be distinguished by type     */
/* ------------------------------------------------------------------ */
static void test_creat_after_unlink(void) {
    int64_t unlink_id = psql_test_insert_fstask(TASK_UNLINK, 0, 600, "data.bin");
    int64_t creat_id  = psql_test_insert_fstask(TASK_CREAT,  1, 600, "data.bin");
    if (unlink_id <= 0 || creat_id <= 0)
        { FAIL("creat-after-unlink setup", "ids=%lld/%lld",
               (long long)unlink_id, (long long)creat_id); return; }

    /* Insert CREAT depends on UNLINK (same file, must sequence) */
    char sql[256];
    snprintf(sql, sizeof(sql),
             "INSERT INTO fstaskdepend (fstaskid, dependfstaskid) VALUES (%lld, %lld)",
             (long long)creat_id, (long long)unlink_id);
    psql_test_exec(sql);

    /* Verify both tasks exist for this folderid+name */
    int unlink_cnt = psql_test_count_fstask(
        "type=4 AND folderid=600 AND text1='data.bin'");
    int creat_cnt  = psql_test_count_fstask(
        "type=3 AND folderid=600 AND text1='data.bin'");
    int dep_cnt    = psql_test_count_fstaskdepend(NULL);

    if (unlink_cnt == 1 && creat_cnt == 1)
        PASS("creat-after-unlink: UNLINK and CREAT tasks both recorded");
    else
        FAIL("creat-after-unlink tasks", "unlink=%d creat=%d",
             unlink_cnt, creat_cnt);

    /* CREAT depends on UNLINK */
    char where[256];
    snprintf(where, sizeof(where),
             "fstaskid=%lld AND dependfstaskid=%lld",
             (long long)creat_id, (long long)unlink_id);
    int d = psql_test_count_fstaskdepend(where);
    if (d == 1)
        PASS("creat-after-unlink: CREAT depends on UNLINK in fstaskdepend");
    else
        FAIL("creat-after-unlink dependency", "dep_count=%d expected 1", d);

    (void)dep_cnt;
}

/* ------------------------------------------------------------------ */
/* Test 8: psql_test_open / psql_test_close idempotence                */
/* ------------------------------------------------------------------ */
static void test_open_close_idempotent(void) {
    /* Close and re-open; db should be usable again */
    psql_test_close();
    if (psql_test_db() != NULL)
        { FAIL("open/close: db NULL after close", "still non-null"); return; }
    if (psql_test_open() != 0)
        { FAIL("open/close: re-open", "failed"); return; }
    if (psql_test_db() == NULL)
        { FAIL("open/close: db non-null after re-open", "NULL"); return; }
    if (!table_exists("fstask"))
        FAIL("open/close: fstask table after re-open", "missing");
    else
        PASS("psql_test_open/close idempotent: re-open restores fresh schema");
}

/* ------------------------------------------------------------------ */
int main(void) {
    if (psql_test_open() != 0) {
        fprintf(stderr, "FATAL: psql_test_open() failed\n");
        return 1;
    }

    test_schema_created();
    test_fstask_insert_query();
    test_fstaskdepend_insert();
    test_cascade_delete();
    test_fk_enforcement();
    test_rmdir_blocking_sql();
    test_creat_after_unlink();
    test_open_close_idempotent();

    psql_test_close();

    printf("\n%d passed, %d failed\n", passes, failures);
    return failures ? 1 : 0;
}
