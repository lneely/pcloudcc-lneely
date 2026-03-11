/*
 * Test: pfs_helpers.c — row→stat converters and task overlay
 *
 * Covers:
 *  1. pfs_row_to_folder_stat: st_ino, st_mode, st_nlink, st_mtime populated
 *     from the variant row; st_uid/gid come from pfs_stat_uid/gid globals.
 *  2. pfs_row_to_file_stat: st_ino, st_mode, st_size, st_ctime populated
 *     (non-encrypted path, flags=0).
 *  3. pfs_apply_task_overlay: mkdir pending → stat filled as dir;
 *     rmdir pending → -1; no overlay → 0.
 *  4. pfs_fldr_resolve_path weak override: replacement injects a fake path
 *     without a FUSE mount or psql connection.
 */

#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

#include "pfs_helpers.h"
#include "pfstasks_tree.h"   /* pfs_task_insert_into_tree, pfs_task_find_* */
#include "plibs.h"           /* PSYNC_TNUMBER, psync_variant */

/* ------------------------------------------------------------------ */
/* --wrap stubs: pfs_task_get_folder_tasks_rdlocked, pfs_crpt_plain_size,
 * ptimer_time — none of these should be called in the pure-tree / non-
 * encrypted test paths; return safe no-op values just in case.        */

psync_fstask_folder_t *__wrap_pfs_task_get_folder_tasks_rdlocked(
        psync_fsfolderid_t folderid) {
    (void)folderid;
    return NULL;  /* no in-memory mtime override in tests */
}

uint64_t __wrap_pfs_crpt_plain_size(uint64_t cryptosize) {
    return cryptosize;  /* identity for non-encrypted tests */
}

time_t __wrap_ptimer_time(void) {
    return 9999;  /* fixed timestamp for deterministic tests */
}

/* ------------------------------------------------------------------ */
static int passes = 0, failures = 0;
#define PASS(n)      do { printf("PASS: %s\n", n); passes++; } while (0)
#define FAIL(n, ...) do { printf("FAIL: %s — ", n); printf(__VA_ARGS__); printf("\n"); failures++; } while (0)

/* ------------------------------------------------------------------ */
/* Helper: build a psync_variant holding a uint64_t number             */
/* ------------------------------------------------------------------ */
static psync_variant mknum(uint64_t v) {
    psync_variant pv;
    memset(&pv, 0, sizeof(pv));
    pv.type = PSYNC_TNUMBER;
    pv.num  = v;
    return pv;
}

/* ------------------------------------------------------------------ */
/* Test 1: pfs_row_to_folder_stat                                      */
/* ------------------------------------------------------------------ */
static void test_folder_stat(void) {
    /*
     * Folder row layout: [0]=id [1]=permissions [2]=ctime [3]=mtime [4]=subdircnt
     */
    psync_variant row[5];
    row[0] = mknum(100);   /* folderid = 100 */
    row[1] = mknum(0755);  /* permissions  */
    row[2] = mknum(1000);  /* ctime        */
    row[3] = mknum(2000);  /* mtime        */
    row[4] = mknum(3);     /* subdircnt = 3 → nlink = 5 */

    struct stat st;
    memset(&st, 0, sizeof(st));
    pfs_row_to_folder_stat(row, &st);

    if (st.st_ino != PFS_FOLDERID_TO_INODE(100))
        FAIL("folder_stat: st_ino", "expected %lu got %lu",
             (unsigned long)PFS_FOLDERID_TO_INODE(100), (unsigned long)st.st_ino);
    else if (!S_ISDIR(st.st_mode))
        FAIL("folder_stat: S_ISDIR", "mode=0%o", (unsigned)st.st_mode);
    else if (st.st_nlink != 5)
        FAIL("folder_stat: st_nlink", "expected 5 got %lu", (unsigned long)st.st_nlink);
    else if (st.st_mtime != 2000)
        FAIL("folder_stat: st_mtime", "expected 2000 got %ld", (long)st.st_mtime);
    else if (st.st_uid != pfs_stat_uid || st.st_gid != pfs_stat_gid)
        FAIL("folder_stat: uid/gid", "uid=%d gid=%d",
             (int)st.st_uid, (int)st.st_gid);
    else
        PASS("pfs_row_to_folder_stat: ino/mode/nlink/mtime/uid/gid correct");
}

/* ------------------------------------------------------------------ */
/* Test 2: pfs_row_to_file_stat (non-encrypted, flags=0)               */
/* ------------------------------------------------------------------ */
static void test_file_stat(void) {
    /*
     * File row layout: [0]=name [1]=size [2]=ctime [3]=mtime [4]=id
     */
    psync_variant row[5];
    row[0] = mknum(0);     /* name (unused in stat) */
    row[1] = mknum(4096);  /* size = 4096 bytes     */
    row[2] = mknum(3000);  /* ctime                 */
    row[3] = mknum(3000);  /* mtime                 */
    row[4] = mknum(77);    /* fileid = 77            */

    struct stat st;
    memset(&st, 0, sizeof(st));
    pfs_row_to_file_stat(row, &st, 0 /* non-encrypted */);

    if (st.st_ino != PFS_FILEID_TO_INODE(77))
        FAIL("file_stat: st_ino", "expected %lu got %lu",
             (unsigned long)PFS_FILEID_TO_INODE(77), (unsigned long)st.st_ino);
    else if (!S_ISREG(st.st_mode))
        FAIL("file_stat: S_ISREG", "mode=0%o", (unsigned)st.st_mode);
    else if (st.st_size != 4096)
        FAIL("file_stat: st_size", "expected 4096 got %ld", (long)st.st_size);
    else if (st.st_ctime != 3000)
        FAIL("file_stat: st_ctime", "expected 3000 got %ld", (long)st.st_ctime);
    else if (st.st_nlink != 1)
        FAIL("file_stat: st_nlink", "expected 1 got %lu", (unsigned long)st.st_nlink);
    else
        PASS("pfs_row_to_file_stat: ino/mode/size/ctime/nlink correct");
}

/* ------------------------------------------------------------------ */
/* Test 3: pfs_apply_task_overlay                                       */
/* ------------------------------------------------------------------ */

/* Helper: allocate a psync_fstask_mkdir_t and insert it into folder   */
static psync_fstask_mkdir_t *make_mkdir(psync_fstask_folder_t *f,
                                        const char *name,
                                        uint64_t taskid,
                                        psync_fsfolderid_t folderid) {
    size_t len = strlen(name) + 1;
    psync_fstask_mkdir_t *mk = (psync_fstask_mkdir_t *)
        calloc(1, offsetof(psync_fstask_mkdir_t, name) + len);
    mk->taskid   = taskid;
    mk->folderid = folderid;
    mk->mtime    = 5000;
    mk->flags    = 0;
    memcpy(mk->name, name, len);
    pfs_task_insert_into_tree(&f->mkdirs, offsetof(psync_fstask_mkdir_t, name),
                              &mk->tree);
    return mk;
}

static psync_fstask_rmdir_t *make_rmdir(psync_fstask_folder_t *f,
                                         const char *name,
                                         uint64_t taskid) {
    size_t len = strlen(name) + 1;
    psync_fstask_rmdir_t *rm = (psync_fstask_rmdir_t *)
        calloc(1, offsetof(psync_fstask_rmdir_t, name) + len);
    rm->taskid = taskid;
    memcpy(rm->name, name, len);
    pfs_task_insert_into_tree(&f->rmdirs, offsetof(psync_fstask_rmdir_t, name),
                              &rm->tree);
    return rm;
}

static void test_apply_task_overlay(void) {
    /* NULL folder → 0 */
    struct stat st;
    int rc = pfs_apply_task_overlay(&st, NULL, "any", 0);
    if (rc != 0)
        { FAIL("overlay NULL folder", "expected 0 got %d", rc); }
    else
        PASS("pfs_apply_task_overlay: NULL folder returns 0");

    /* mkdir pending → 1, stbuf filled as directory */
    psync_fstask_folder_t f;
    memset(&f, 0, sizeof(f));
    f.folderid = 200;
    psync_fstask_mkdir_t *mk = make_mkdir(&f, "newdir", 10, -10);

    memset(&st, 0, sizeof(st));
    rc = pfs_apply_task_overlay(&st, &f, "newdir", 0);
    if (rc != 1)
        FAIL("overlay mkdir: rc=1", "got %d", rc);
    else if (!S_ISDIR(st.st_mode))
        FAIL("overlay mkdir: S_ISDIR", "mode=0%o", (unsigned)st.st_mode);
    else
        PASS("pfs_apply_task_overlay: mkdir pending → rc=1, stbuf is a dir");

    /* rmdir pending → -1 */
    psync_fstask_rmdir_t *rm = make_rmdir(&f, "olddir", 20);
    memset(&st, 0, sizeof(st));
    rc = pfs_apply_task_overlay(&st, &f, "olddir", 0);
    if (rc != -1)
        FAIL("overlay rmdir: rc=-1", "got %d", rc);
    else
        PASS("pfs_apply_task_overlay: rmdir pending → rc=-1 (ENOENT)");

    /* no overlay for absent name → 0 */
    rc = pfs_apply_task_overlay(&st, &f, "noentry", 0);
    if (rc != 0)
        FAIL("overlay no match: rc=0", "got %d", rc);
    else
        PASS("pfs_apply_task_overlay: no pending task for name → rc=0");

    free(mk); free(rm);
}

/* ------------------------------------------------------------------ */
/* Test 4: pfs_fldr_resolve_path weak override                         */
/* ------------------------------------------------------------------ */

static psync_fspath_t g_fake_path;
static int g_resolve_called = 0;

psync_fspath_t *pfs_fldr_resolve_path(const char *path) {
    (void)path;
    g_resolve_called++;
    return &g_fake_path;
}

static void test_resolve_path_override(void) {
    g_resolve_called = 0;
    memset(&g_fake_path, 0, sizeof(g_fake_path));
    g_fake_path.folderid = 999;

    psync_fspath_t *r = pfs_fldr_resolve_path("/test/path");
    if (!r || r->folderid != 999)
        FAIL("resolve override: returns fake path", "folderid=%lld",
             r ? (long long)r->folderid : -1LL);
    else if (g_resolve_called != 1)
        FAIL("resolve override: called once", "called=%d", g_resolve_called);
    else
        PASS("pfs_fldr_resolve_path: weak override injects fake path");
}

/* ------------------------------------------------------------------ */
int main(void) {
    /* tests use uid/gid = 0 (default from pfs_helpers.c init) */
    test_folder_stat();
    test_file_stat();
    test_apply_task_overlay();
    test_resolve_path_override();

    printf("\n%d passed, %d failed\n", passes, failures);
    return failures ? 1 : 0;
}
