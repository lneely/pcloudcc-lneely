/*
 * Test: pfstasks_tree.c — pure tree layer for fstask structs
 *
 * Builds psync_fstask_folder_t fixtures directly (no DB, no psql) and
 * verifies pfs_task_find_mkdir, pfs_task_find_rmdir, pfs_task_find_creat,
 * pfs_task_find_unlink, pfs_task_find_mkdir_by_folderid, and
 * pfs_task_find_creat_by_fileid.
 */

#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <stdint.h>

#include "pfstasks_tree.h"

/* ------------------------------------------------------------------ */
/* Harness                                                              */
/* ------------------------------------------------------------------ */

static int passes = 0, failures = 0;
#define PASS(n)      do { printf("PASS: %s\n", n); passes++; } while (0)
#define FAIL(n, ...) do { printf("FAIL: %s — ", n); printf(__VA_ARGS__); printf("\n"); failures++; } while (0)

/* ------------------------------------------------------------------ */
/* Node builders (stack / malloc, NOT pmem)                            */
/* ------------------------------------------------------------------ */

/* Allocate a psync_fstask_mkdir_t with a given name, taskid, folderid */
static psync_fstask_mkdir_t *mk_mkdir(const char *name, uint64_t taskid,
                                       psync_fsfolderid_t folderid) {
    size_t len = strlen(name) + 1;
    psync_fstask_mkdir_t *n = (psync_fstask_mkdir_t *)
        calloc(1, offsetof(psync_fstask_mkdir_t, name) + len);
    n->taskid   = taskid;
    n->folderid = folderid;
    memcpy(n->name, name, len);
    return n;
}

static psync_fstask_rmdir_t *mk_rmdir(const char *name, uint64_t taskid,
                                       psync_fsfolderid_t folderid) {
    size_t len = strlen(name) + 1;
    psync_fstask_rmdir_t *n = (psync_fstask_rmdir_t *)
        calloc(1, offsetof(psync_fstask_rmdir_t, name) + len);
    n->taskid   = taskid;
    n->folderid = folderid;
    memcpy(n->name, name, len);
    return n;
}

static psync_fstask_creat_t *mk_creat(const char *name, uint64_t taskid,
                                       psync_fsfileid_t fileid) {
    size_t len = strlen(name) + 1;
    psync_fstask_creat_t *n = (psync_fstask_creat_t *)
        calloc(1, offsetof(psync_fstask_creat_t, name) + len);
    n->taskid = taskid;
    n->fileid = fileid;
    memcpy(n->name, name, len);
    return n;
}

static psync_fstask_unlink_t *mk_unlink(const char *name, uint64_t taskid,
                                         psync_fsfileid_t fileid) {
    size_t len = strlen(name) + 1;
    psync_fstask_unlink_t *n = (psync_fstask_unlink_t *)
        calloc(1, offsetof(psync_fstask_unlink_t, name) + len);
    n->taskid = taskid;
    n->fileid = fileid;
    memcpy(n->name, name, len);
    return n;
}

/* Build a clean empty folder */
static void folder_init(psync_fstask_folder_t *f, psync_fsfolderid_t folderid) {
    memset(f, 0, sizeof(*f));
    f->folderid = folderid;
}

/* ------------------------------------------------------------------ */
/* Tests                                                                */
/* ------------------------------------------------------------------ */

/* find_mkdir: basic hit and miss */
static void test_find_mkdir_basic(void) {
    psync_fstask_folder_t f;
    folder_init(&f, 1);

    psync_fstask_mkdir_t *a = mk_mkdir("alpha", 10, -10);
    psync_fstask_mkdir_t *b = mk_mkdir("beta",  20, -20);
    psync_fstask_mkdir_t *c = mk_mkdir("gamma", 30, -30);

    pfs_task_insert_into_tree(&f.mkdirs, offsetof(psync_fstask_mkdir_t, name), &a->tree);
    pfs_task_insert_into_tree(&f.mkdirs, offsetof(psync_fstask_mkdir_t, name), &b->tree);
    pfs_task_insert_into_tree(&f.mkdirs, offsetof(psync_fstask_mkdir_t, name), &c->tree);

    psync_fstask_mkdir_t *found = pfs_task_find_mkdir(&f, "beta", 0);
    if (!found || found->taskid != 20)
        FAIL("find_mkdir basic: hit", "found=%p taskid=%llu",
             (void*)found, found ? (unsigned long long)found->taskid : 0);
    else
        PASS("find_mkdir: finds 'beta' by name");

    if (pfs_task_find_mkdir(&f, "delta", 0) != NULL)
        FAIL("find_mkdir basic: miss", "found non-NULL for absent key");
    else
        PASS("find_mkdir: returns NULL for absent name");

    free(a); free(b); free(c);
}

/* find_mkdir: taskid discriminator with same-name duplicates */
static void test_find_mkdir_taskid(void) {
    psync_fstask_folder_t f;
    folder_init(&f, 2);

    /* Two mkdirs with same name "foo" but different taskids */
    psync_fstask_mkdir_t *x = mk_mkdir("foo", 100, -100);
    psync_fstask_mkdir_t *y = mk_mkdir("foo", 200, -200);

    pfs_task_insert_into_tree(&f.mkdirs, offsetof(psync_fstask_mkdir_t, name), &x->tree);
    pfs_task_insert_into_tree(&f.mkdirs, offsetof(psync_fstask_mkdir_t, name), &y->tree);

    psync_fstask_mkdir_t *found100 = pfs_task_find_mkdir(&f, "foo", 100);
    psync_fstask_mkdir_t *found200 = pfs_task_find_mkdir(&f, "foo", 200);

    if (!found100 || found100->taskid != 100)
        FAIL("find_mkdir taskid: find taskid=100", "got %p", (void*)found100);
    else
        PASS("find_mkdir: taskid discriminator finds correct node (100)");

    if (!found200 || found200->taskid != 200)
        FAIL("find_mkdir taskid: find taskid=200", "got %p", (void*)found200);
    else
        PASS("find_mkdir: taskid discriminator finds correct node (200)");

    free(x); free(y);
}

/* find_rmdir: basic */
static void test_find_rmdir_basic(void) {
    psync_fstask_folder_t f;
    folder_init(&f, 3);

    psync_fstask_rmdir_t *a = mk_rmdir("dirA", 11, 101);
    psync_fstask_rmdir_t *b = mk_rmdir("dirB", 22, 102);

    pfs_task_insert_into_tree(&f.rmdirs, offsetof(psync_fstask_rmdir_t, name), &a->tree);
    pfs_task_insert_into_tree(&f.rmdirs, offsetof(psync_fstask_rmdir_t, name), &b->tree);

    psync_fstask_rmdir_t *r = pfs_task_find_rmdir(&f, "dirA", 0);
    if (!r || r->taskid != 11)
        FAIL("find_rmdir basic", "taskid=%llu", r ? (unsigned long long)r->taskid : 0);
    else
        PASS("find_rmdir: finds 'dirA'");

    if (pfs_task_find_rmdir(&f, "dirC", 0) != NULL)
        FAIL("find_rmdir miss", "non-NULL for absent");
    else
        PASS("find_rmdir: NULL for absent name");

    free(a); free(b);
}

/* find_creat: basic */
static void test_find_creat_basic(void) {
    psync_fstask_folder_t f;
    folder_init(&f, 4);

    psync_fstask_creat_t *a = mk_creat("file.txt",  55, 1001);
    psync_fstask_creat_t *b = mk_creat("photo.jpg", 66, 1002);

    pfs_task_insert_into_tree(&f.creats, offsetof(psync_fstask_creat_t, name), &a->tree);
    pfs_task_insert_into_tree(&f.creats, offsetof(psync_fstask_creat_t, name), &b->tree);

    psync_fstask_creat_t *r = pfs_task_find_creat(&f, "photo.jpg", 0);
    if (!r || r->fileid != 1002)
        FAIL("find_creat basic", "fileid=%lld", r ? (long long)r->fileid : 0);
    else
        PASS("find_creat: finds 'photo.jpg'");

    free(a); free(b);
}

/* find_unlink: basic */
static void test_find_unlink_basic(void) {
    psync_fstask_folder_t f;
    folder_init(&f, 5);

    psync_fstask_unlink_t *a = mk_unlink("old.txt", 77, 2001);
    psync_fstask_unlink_t *b = mk_unlink("tmp.log", 88, 2002);

    pfs_task_insert_into_tree(&f.unlinks, offsetof(psync_fstask_unlink_t, name), &a->tree);
    pfs_task_insert_into_tree(&f.unlinks, offsetof(psync_fstask_unlink_t, name), &b->tree);

    psync_fstask_unlink_t *r = pfs_task_find_unlink(&f, "old.txt", 0);
    if (!r || r->fileid != 2001)
        FAIL("find_unlink basic", "fileid=%lld", r ? (long long)r->fileid : 0);
    else
        PASS("find_unlink: finds 'old.txt'");

    if (pfs_task_find_unlink(&f, "missing.txt", 0) != NULL)
        FAIL("find_unlink miss", "non-NULL");
    else
        PASS("find_unlink: NULL for absent name");

    free(a); free(b);
}

/* find_mkdir_by_folderid: walk tree by folderid */
static void test_find_mkdir_by_folderid(void) {
    psync_fstask_folder_t f;
    folder_init(&f, 6);

    psync_fstask_mkdir_t *a = mk_mkdir("one",   1, -101);
    psync_fstask_mkdir_t *b = mk_mkdir("two",   2, -202);
    psync_fstask_mkdir_t *c = mk_mkdir("three", 3, -303);

    pfs_task_insert_into_tree(&f.mkdirs, offsetof(psync_fstask_mkdir_t, name), &a->tree);
    pfs_task_insert_into_tree(&f.mkdirs, offsetof(psync_fstask_mkdir_t, name), &b->tree);
    pfs_task_insert_into_tree(&f.mkdirs, offsetof(psync_fstask_mkdir_t, name), &c->tree);

    psync_fstask_mkdir_t *r = pfs_task_find_mkdir_by_folderid(&f, -202);
    if (!r || strcmp(r->name, "two") != 0)
        FAIL("find_mkdir_by_folderid", "name=%s", r ? r->name : "(null)");
    else
        PASS("find_mkdir_by_folderid: finds node with folderid=-202");

    if (pfs_task_find_mkdir_by_folderid(&f, -999) != NULL)
        FAIL("find_mkdir_by_folderid miss", "non-NULL for absent folderid");
    else
        PASS("find_mkdir_by_folderid: NULL for absent folderid");

    free(a); free(b); free(c);
}

/* find_creat_by_fileid: walk tree by fileid */
static void test_find_creat_by_fileid(void) {
    psync_fstask_folder_t f;
    folder_init(&f, 7);

    psync_fstask_creat_t *a = mk_creat("a.txt", 10, 5001);
    psync_fstask_creat_t *b = mk_creat("b.txt", 20, 5002);
    psync_fstask_creat_t *c = mk_creat("c.txt", 30, 5003);

    pfs_task_insert_into_tree(&f.creats, offsetof(psync_fstask_creat_t, name), &a->tree);
    pfs_task_insert_into_tree(&f.creats, offsetof(psync_fstask_creat_t, name), &b->tree);
    pfs_task_insert_into_tree(&f.creats, offsetof(psync_fstask_creat_t, name), &c->tree);

    psync_fstask_creat_t *r = pfs_task_find_creat_by_fileid(&f, 5002);
    if (!r || strcmp(r->name, "b.txt") != 0)
        FAIL("find_creat_by_fileid", "name=%s", r ? r->name : "(null)");
    else
        PASS("find_creat_by_fileid: finds node with fileid=5002");

    free(a); free(b); free(c);
}

/* Empty folder: all finds return NULL */
static void test_empty_folder(void) {
    psync_fstask_folder_t f;
    folder_init(&f, 8);
    int ok = 1;
    if (pfs_task_find_mkdir(&f, "x", 0)  != NULL) ok = 0;
    if (pfs_task_find_rmdir(&f, "x", 0)  != NULL) ok = 0;
    if (pfs_task_find_creat(&f, "x", 0)  != NULL) ok = 0;
    if (pfs_task_find_unlink(&f, "x", 0) != NULL) ok = 0;
    if (ok)
        PASS("empty folder: all finds return NULL");
    else
        FAIL("empty folder", "unexpected non-NULL");
}

/* ------------------------------------------------------------------ */
int main(void) {
    test_find_mkdir_basic();
    test_find_mkdir_taskid();
    test_find_rmdir_basic();
    test_find_creat_basic();
    test_find_unlink_basic();
    test_find_mkdir_by_folderid();
    test_find_creat_by_fileid();
    test_empty_folder();

    printf("\n%d passed, %d failed\n", passes, failures);
    return failures ? 1 : 0;
}
