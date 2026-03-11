/*
 * Test: plocalscan_helpers.c — sorted-list merge algorithm
 *
 * Covers:
 *  1. plocalscan_folderlist_cmp: name ordering
 *  2. plocalscan_compare_sizeinodemtime: field ordering
 *  3. plocalscan_compare_inode: inode ordering
 *  4. plocalscan_merge_folder_lists:
 *       - new entries (disk only) → NEWFILES / NEWFOLDERS
 *       - deleted entries (db only) → DELFILES / DELFOLDERS
 *       - modified file (same name, different metadata) → MODFILES
 *       - unchanged file (same name, same metadata) → nothing added
 *       - mixed: new + deleted + modified in one call
 *
 * External deps wrapped via --wrap:
 *   psync_is_name_to_ignore   → always 0 (don't ignore any name)
 *   psync_send_backup_del_event → no-op
 */

#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>

#include "plocalscan_helpers.h"

/* ------------------------------------------------------------------ */
static int passes = 0, failures = 0;
#define PASS(n)      do { printf("PASS: %s\n", n); passes++; } while (0)
#define FAIL(n, ...) do { printf("FAIL: %s — ", n); \
                          printf(__VA_ARGS__); printf("\n"); failures++; } while (0)

/* ------------------------------------------------------------------ */
/* Wrap stubs                                                           */
/* ------------------------------------------------------------------ */

int __wrap_psync_is_name_to_ignore(const char *name) {
    (void)name;
    return 0; /* never ignore */
}

void __wrap_psync_send_backup_del_event(psync_fileorfolderid_t id) {
    (void)id;
}

/* ------------------------------------------------------------------ */
/* Helper: allocate a sync_folderlist entry                             */
/* ------------------------------------------------------------------ */

static sync_folderlist *make_entry(const char *name, uint8_t isfolder,
                                   uint64_t inode, uint64_t size,
                                   uint64_t mtimenat, uint64_t deviceid) {
    size_t namelen = strlen(name) + 1;
    size_t sz = offsetof(sync_folderlist, name) + namelen;
    sync_folderlist *e = (sync_folderlist *)malloc(sz);
    memset(e, 0, sz);
    e->isfolder  = isfolder;
    e->inode     = inode;
    e->size      = size;
    e->mtimenat  = mtimenat;
    e->deviceid  = deviceid;
    psync_list_init(&e->list);
    memcpy(e->name, name, namelen);
    return e;
}

/* Append entry to a list head */
static void list_append(psync_list *head, sync_folderlist *e) {
    psync_list_add_tail(head, &e->list);
}

/* Count elements in a psync_list */
static int list_count(psync_list *head) {
    int n = 0;
    psync_list *cur;
    psync_list_for_each(cur, head) n++;
    return n;
}

/* Get the nth element name from an output list */
static const char *list_nth_name(psync_list *head, int n) {
    psync_list *cur;
    int i = 0;
    psync_list_for_each(cur, head) {
        if (i++ == n)
            return psync_list_element(cur, sync_folderlist, list)->name;
    }
    return NULL;
}

/* Free all elements in a list (allocated via plocalscan_copy_element → pmem_malloc).
 * Must use pmem_free, not free(), because pmem_malloc prepends a header. */
static void free_list(psync_list *head) {
    psync_list *cur, *tmp;
    psync_list_for_each_safe(cur, tmp, head)
        pmem_free(PMEM_SUBSYS_SYNC,
                  psync_list_element(cur, sync_folderlist, list));
    psync_list_init(head);
}

/* Initialise PLOCALSCAN_SCAN_LIST_CNT output list heads */
static void init_out(psync_list out[]) {
    int i;
    for (i = 0; i < PLOCALSCAN_SCAN_LIST_CNT; i++)
        psync_list_init(&out[i]);
}

static void free_out(psync_list out[]) {
    int i;
    for (i = 0; i < PLOCALSCAN_SCAN_LIST_CNT; i++)
        free_list(&out[i]);
}

/* ------------------------------------------------------------------ */
/* Test 1: comparators                                                  */
/* ------------------------------------------------------------------ */

static void test_comparators(void) {
    sync_folderlist *a, *b;

    /* folderlist_cmp: strcmp on name */
    a = make_entry("alpha", 0, 1, 100, 1000, 0);
    b = make_entry("beta",  0, 2, 200, 2000, 0);
    if (plocalscan_folderlist_cmp(&a->list, &b->list) >= 0)
        FAIL("folderlist_cmp: alpha < beta", "expected negative, got non-negative");
    else
        PASS("folderlist_cmp: alpha < beta → negative");

    if (plocalscan_folderlist_cmp(&b->list, &a->list) <= 0)
        FAIL("folderlist_cmp: beta > alpha", "expected positive, got non-positive");
    else
        PASS("folderlist_cmp: beta > alpha → positive");

    if (plocalscan_folderlist_cmp(&a->list, &a->list) != 0)
        FAIL("folderlist_cmp: alpha == alpha", "expected 0");
    else
        PASS("folderlist_cmp: alpha == alpha → 0");

    free(a); free(b);

    /* compare_sizeinodemtime */
    {
        sync_folderlist *s1, *s2;
        s1 = make_entry("f", 0, 10, 100, 1000, 0);
        s2 = make_entry("f", 0, 20, 200, 2000, 0);

        /* size differs: s1.size < s2.size */
        if (plocalscan_compare_sizeinodemtime(&s1->list, &s2->list) >= 0)
            FAIL("compare_sim: size s1 < s2", "expected negative");
        else
            PASS("compare_sim: size s1(100) < s2(200) → negative");

        if (plocalscan_compare_sizeinodemtime(&s2->list, &s1->list) <= 0)
            FAIL("compare_sim: size s2 > s1", "expected positive");
        else
            PASS("compare_sim: size s2(200) > s1(100) → positive");

        /* same size, compare inode */
        s2->size = s1->size;
        if (plocalscan_compare_sizeinodemtime(&s1->list, &s2->list) >= 0)
            FAIL("compare_sim: inode s1(10) < s2(20)", "expected negative");
        else
            PASS("compare_sim: inode s1(10) < s2(20) → negative");

        /* same size + inode, compare mtime */
        s2->inode = s1->inode;
        if (plocalscan_compare_sizeinodemtime(&s1->list, &s2->list) >= 0)
            FAIL("compare_sim: mtime s1(1000) < s2(2000)", "expected negative");
        else
            PASS("compare_sim: mtime s1(1000) < s2(2000) → negative");

        /* all equal */
        s2->mtimenat = s1->mtimenat;
        if (plocalscan_compare_sizeinodemtime(&s1->list, &s2->list) != 0)
            FAIL("compare_sim: all equal", "expected 0");
        else
            PASS("compare_sim: all fields equal → 0");

        free(s1); free(s2);
    }

    /* compare_inode */
    {
        sync_folderlist *i1, *i2;
        i1 = make_entry("d", 1, 5,  0, 0, 0);
        i2 = make_entry("d", 1, 15, 0, 0, 0);

        if (plocalscan_compare_inode(&i1->list, &i2->list) >= 0)
            FAIL("compare_inode: 5 < 15", "expected negative");
        else
            PASS("compare_inode: inode 5 < 15 → negative");

        if (plocalscan_compare_inode(&i2->list, &i1->list) <= 0)
            FAIL("compare_inode: 15 > 5", "expected positive");
        else
            PASS("compare_inode: inode 15 > 5 → positive");

        i2->inode = i1->inode;
        if (plocalscan_compare_inode(&i1->list, &i2->list) != 0)
            FAIL("compare_inode: equal", "expected 0");
        else
            PASS("compare_inode: equal inodes → 0");

        free(i1); free(i2);
    }
}

/* ------------------------------------------------------------------ */
/* Test 2: new entries (disk has entries DB doesn't)                    */
/* ------------------------------------------------------------------ */

static void test_merge_new_entries(void) {
    psync_list disklist, dblist;
    psync_list out[PLOCALSCAN_SCAN_LIST_CNT];
    size_t added;

    psync_list_init(&disklist);
    psync_list_init(&dblist);
    init_out(out);

    /* Two new files on disk, not in DB */
    list_append(&disklist, make_entry("file_a.txt", 0, 1, 100, 1000, 1));
    list_append(&disklist, make_entry("file_b.txt", 0, 2, 200, 2000, 1));

    added = plocalscan_merge_folder_lists(&disklist, &dblist, out,
                                           10, 20, 1, 1, 1);
    if (added != 2)
        FAIL("new files: added count", "expected 2, got %zu", added);
    else
        PASS("new files: 2 elements added");

    if (list_count(&out[PLOCALSCAN_SCAN_LIST_NEWFILES]) != 2)
        FAIL("new files: NEWFILES count",
             "expected 2, got %d",
             list_count(&out[PLOCALSCAN_SCAN_LIST_NEWFILES]));
    else
        PASS("new files: both in NEWFILES list");

    if (list_count(&out[PLOCALSCAN_SCAN_LIST_DELFILES]) != 0)
        FAIL("new files: DELFILES should be empty",
             "got %d", list_count(&out[PLOCALSCAN_SCAN_LIST_DELFILES]));
    else
        PASS("new files: DELFILES empty");

    free_out(out);
    /* disklist entries were NOT copied (only their copies are in out[]) */
    psync_list_for_each_element_call(&disklist, sync_folderlist, list, free);
}

/* ------------------------------------------------------------------ */
/* Test 3: new folder entry                                             */
/* ------------------------------------------------------------------ */

static void test_merge_new_folder(void) {
    psync_list disklist, dblist;
    psync_list out[PLOCALSCAN_SCAN_LIST_CNT];
    size_t added;

    psync_list_init(&disklist);
    psync_list_init(&dblist);
    init_out(out);

    /* New folder: deviceid must match for folders to be classified as new */
    list_append(&disklist, make_entry("newdir", 1, 5, 0, 0, 42));

    added = plocalscan_merge_folder_lists(&disklist, &dblist, out,
                                           10, 20, 1, 1, 42 /* same deviceid */);
    if (added != 1)
        FAIL("new folder: added count", "expected 1, got %zu", added);
    else
        PASS("new folder: 1 element added");

    if (list_count(&out[PLOCALSCAN_SCAN_LIST_NEWFOLDERS]) != 1)
        FAIL("new folder: NEWFOLDERS count",
             "expected 1, got %d",
             list_count(&out[PLOCALSCAN_SCAN_LIST_NEWFOLDERS]));
    else
        PASS("new folder: in NEWFOLDERS list");

    free_out(out);
    psync_list_for_each_element_call(&disklist, sync_folderlist, list, free);
}

/* ------------------------------------------------------------------ */
/* Test 4: deleted entries (DB has entries disk doesn't)                */
/* ------------------------------------------------------------------ */

static void test_merge_deleted_entries(void) {
    psync_list disklist, dblist;
    psync_list out[PLOCALSCAN_SCAN_LIST_CNT];
    size_t added;

    psync_list_init(&disklist);
    psync_list_init(&dblist);
    init_out(out);

    /* One deleted file and one deleted folder in DB */
    list_append(&dblist, make_entry("gone_file.txt", 0, 3, 300, 3000, 1));
    list_append(&dblist, make_entry("gone_dir",      1, 4, 0,   0,    1));

    added = plocalscan_merge_folder_lists(&disklist, &dblist, out,
                                           10, 20, 1, 1, 1);
    if (added != 2)
        FAIL("deleted entries: added count", "expected 2, got %zu", added);
    else
        PASS("deleted entries: 2 elements added");

    if (list_count(&out[PLOCALSCAN_SCAN_LIST_DELFILES]) != 1)
        FAIL("deleted entries: DELFILES count",
             "expected 1, got %d",
             list_count(&out[PLOCALSCAN_SCAN_LIST_DELFILES]));
    else
        PASS("deleted entries: 1 in DELFILES");

    if (list_count(&out[PLOCALSCAN_SCAN_LIST_DELFOLDERS]) != 1)
        FAIL("deleted entries: DELFOLDERS count",
             "expected 1, got %d",
             list_count(&out[PLOCALSCAN_SCAN_LIST_DELFOLDERS]));
    else
        PASS("deleted entries: 1 in DELFOLDERS");

    free_out(out);
    psync_list_for_each_element_call(&dblist, sync_folderlist, list, free);
}

/* ------------------------------------------------------------------ */
/* Test 5: modified file                                                */
/* ------------------------------------------------------------------ */

static void test_merge_modified_file(void) {
    psync_list disklist, dblist;
    psync_list out[PLOCALSCAN_SCAN_LIST_CNT];
    size_t added;
    sync_folderlist *disk_e, *db_e;

    psync_list_init(&disklist);
    psync_list_init(&dblist);
    init_out(out);

    /* Same name "data.bin" but different mtime → modified */
    disk_e = make_entry("data.bin", 0, 7, 512, 9999, 1);
    db_e   = make_entry("data.bin", 0, 7, 512, 8888, 1);

    list_append(&disklist, disk_e);
    list_append(&dblist,   db_e);

    added = plocalscan_merge_folder_lists(&disklist, &dblist, out,
                                           10, 20, 1, 1, 1);
    if (added != 1)
        FAIL("modified file: added count", "expected 1, got %zu", added);
    else
        PASS("modified file: 1 element added");

    if (list_count(&out[PLOCALSCAN_SCAN_LIST_MODFILES]) != 1)
        FAIL("modified file: MODFILES count",
             "expected 1, got %d",
             list_count(&out[PLOCALSCAN_SCAN_LIST_MODFILES]));
    else
        PASS("modified file: in MODFILES list");

    if (list_count(&out[PLOCALSCAN_SCAN_LIST_NEWFILES]) != 0 ||
        list_count(&out[PLOCALSCAN_SCAN_LIST_DELFILES]) != 0)
        FAIL("modified file: no spurious new/del entries",
             "NEWFILES=%d DELFILES=%d",
             list_count(&out[PLOCALSCAN_SCAN_LIST_NEWFILES]),
             list_count(&out[PLOCALSCAN_SCAN_LIST_DELFILES]));
    else
        PASS("modified file: no spurious NEWFILES/DELFILES");

    free_out(out);
    free(disk_e);
    free(db_e);
}

/* ------------------------------------------------------------------ */
/* Test 6: unchanged file → nothing added                               */
/* ------------------------------------------------------------------ */

static void test_merge_unchanged_file(void) {
    psync_list disklist, dblist;
    psync_list out[PLOCALSCAN_SCAN_LIST_CNT];
    size_t added;
    sync_folderlist *disk_e, *db_e;

    psync_list_init(&disklist);
    psync_list_init(&dblist);
    init_out(out);

    /* Same name, same inode/size/mtime → no change */
    disk_e = make_entry("stable.txt", 0, 42, 1024, 5000, 1);
    db_e   = make_entry("stable.txt", 0, 42, 1024, 5000, 1);

    list_append(&disklist, disk_e);
    list_append(&dblist,   db_e);

    added = plocalscan_merge_folder_lists(&disklist, &dblist, out,
                                           10, 20, 1, 1, 1);
    if (added != 0)
        FAIL("unchanged file: added count", "expected 0, got %zu", added);
    else
        PASS("unchanged file: 0 elements added");

    {
        int i, total = 0;
        for (i = 0; i < PLOCALSCAN_SCAN_LIST_CNT; i++)
            total += list_count(&out[i]);
        if (total != 0)
            FAIL("unchanged file: all out[] lists empty",
                 "total=%d", total);
        else
            PASS("unchanged file: all output lists remain empty");
    }

    free_out(out);
    free(disk_e);
    free(db_e);
}

/* ------------------------------------------------------------------ */
/* Test 7: mixed scenario                                               */
/* ------------------------------------------------------------------ */

static void test_merge_mixed(void) {
    psync_list disklist, dblist;
    psync_list out[PLOCALSCAN_SCAN_LIST_CNT];
    size_t added;

    psync_list_init(&disklist);
    psync_list_init(&dblist);
    init_out(out);

    /*
     * disk: "aaa" (new file), "bbb" (modified), "ccc" (unchanged folder)
     * db:   "bbb" (old version), "ccc" (folder, same), "ddd" (deleted file)
     *
     * Expected:
     *   NEWFILES:    "aaa"
     *   MODFILES:    "bbb"
     *   DELFILES:    "ddd"
     *   everything else empty
     */
    list_append(&disklist, make_entry("aaa", 0, 1, 100, 1000, 1)); /* new */
    list_append(&disklist, make_entry("bbb", 0, 2, 200, 2000, 1)); /* modified */
    list_append(&disklist, make_entry("ccc", 1, 3, 0,   0,    1)); /* unchanged dir */

    list_append(&dblist, make_entry("bbb", 0, 2, 200, 1111, 1)); /* old mtime */
    list_append(&dblist, make_entry("ccc", 1, 3, 0,   0,    1)); /* same dir */
    list_append(&dblist, make_entry("ddd", 0, 4, 400, 4000, 1)); /* deleted */

    /* Lists are pre-sorted by name (alphabetical) */
    added = plocalscan_merge_folder_lists(&disklist, &dblist, out,
                                           10, 20, 1, 1, 1);

    if (added != 3) /* aaa=new, bbb=modified, ddd=deleted */
        FAIL("mixed: added count", "expected 3, got %zu", added);
    else
        PASS("mixed: 3 elements classified");

    if (list_count(&out[PLOCALSCAN_SCAN_LIST_NEWFILES]) != 1 ||
        strcmp(list_nth_name(&out[PLOCALSCAN_SCAN_LIST_NEWFILES], 0), "aaa") != 0)
        FAIL("mixed: NEWFILES has aaa",
             "count=%d name=%s",
             list_count(&out[PLOCALSCAN_SCAN_LIST_NEWFILES]),
             list_nth_name(&out[PLOCALSCAN_SCAN_LIST_NEWFILES], 0));
    else
        PASS("mixed: NEWFILES contains aaa");

    if (list_count(&out[PLOCALSCAN_SCAN_LIST_MODFILES]) != 1 ||
        strcmp(list_nth_name(&out[PLOCALSCAN_SCAN_LIST_MODFILES], 0), "bbb") != 0)
        FAIL("mixed: MODFILES has bbb",
             "count=%d name=%s",
             list_count(&out[PLOCALSCAN_SCAN_LIST_MODFILES]),
             list_nth_name(&out[PLOCALSCAN_SCAN_LIST_MODFILES], 0));
    else
        PASS("mixed: MODFILES contains bbb");

    if (list_count(&out[PLOCALSCAN_SCAN_LIST_DELFILES]) != 1 ||
        strcmp(list_nth_name(&out[PLOCALSCAN_SCAN_LIST_DELFILES], 0), "ddd") != 0)
        FAIL("mixed: DELFILES has ddd",
             "count=%d name=%s",
             list_count(&out[PLOCALSCAN_SCAN_LIST_DELFILES]),
             list_nth_name(&out[PLOCALSCAN_SCAN_LIST_DELFILES], 0));
    else
        PASS("mixed: DELFILES contains ddd");

    if (list_count(&out[PLOCALSCAN_SCAN_LIST_NEWFOLDERS]) != 0 ||
        list_count(&out[PLOCALSCAN_SCAN_LIST_DELFOLDERS]) != 0)
        FAIL("mixed: no spurious folder entries",
             "NEWFOLDERS=%d DELFOLDERS=%d",
             list_count(&out[PLOCALSCAN_SCAN_LIST_NEWFOLDERS]),
             list_count(&out[PLOCALSCAN_SCAN_LIST_DELFOLDERS]));
    else
        PASS("mixed: NEWFOLDERS and DELFOLDERS empty (ccc unchanged)");

    free_out(out);
    psync_list_for_each_element_call(&disklist, sync_folderlist, list, free);
    psync_list_for_each_element_call(&dblist, sync_folderlist, list, free);
}

/* ------------------------------------------------------------------ */
int main(void) {
    test_comparators();
    test_merge_new_entries();
    test_merge_new_folder();
    test_merge_deleted_entries();
    test_merge_modified_file();
    test_merge_unchanged_file();
    test_merge_mixed();

    printf("\n%d passed, %d failed\n", passes, failures);
    return failures ? 1 : 0;
}
