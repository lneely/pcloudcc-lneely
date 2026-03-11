/*
 * plocalscan_helpers.h — pure, separately-compilable helpers extracted from
 * plocalscan.c to enable unit testing the sorted-list merge algorithm without
 * ppath_ls, psql, or threading.
 *
 * Included by plocalscan.c and tests/unit-tests/test_plocalscan_helpers.c.
 */
#ifndef PLOCALSCAN_HELPERS_H
#define PLOCALSCAN_HELPERS_H

#include <stddef.h>    /* offsetof */
#include <stdint.h>
#include <string.h>    /* strcmp, memcpy */

#include "pfoldersync.h" /* psync_folderid_t, psync_fileorfolderid_t,
                            psync_syncid_t, psync_synctype_t */
#include "plist.h"       /* psync_list, psync_list_compare */
#include "pmem.h"        /* pmem_malloc, PMEM_SUBSYS_SYNC */

/* ------------------------------------------------------------------ */
/* sync_folderlist — one scanned fs entry (file or folder)             */
/* ------------------------------------------------------------------ */

typedef struct {
  psync_list list;
  psync_fileorfolderid_t localid;
  psync_fileorfolderid_t remoteid;
  psync_folderid_t localparentfolderid;
  psync_folderid_t parentfolderid;
  uint64_t inode;
  uint64_t deviceid;
  uint64_t mtimenat;
  uint64_t size;
  psync_syncid_t syncid;
  psync_synctype_t synctype;
  uint8_t isfolder;
  char name[1]; /* flexible: actual allocation carries the full name */
} sync_folderlist;

/* ------------------------------------------------------------------ */
/* Output scan-list slots (index into the out[] array)                 */
/* ------------------------------------------------------------------ */

#define PLOCALSCAN_SCAN_LIST_CNT         9
#define PLOCALSCAN_SCAN_LIST_NEWFILES    0
#define PLOCALSCAN_SCAN_LIST_DELFILES    1
#define PLOCALSCAN_SCAN_LIST_NEWFOLDERS  2
#define PLOCALSCAN_SCAN_LIST_DELFOLDERS  3
#define PLOCALSCAN_SCAN_LIST_MODFILES    4
#define PLOCALSCAN_SCAN_LIST_RENFILESFROM  5
#define PLOCALSCAN_SCAN_LIST_RENFILESTO    6
#define PLOCALSCAN_SCAN_LIST_RENFOLDERSROM 7
#define PLOCALSCAN_SCAN_LIST_RENFOLDERSTO  8

/* ------------------------------------------------------------------ */
/* Comparators (pure functions, no side effects)                        */
/* ------------------------------------------------------------------ */

/*
 * plocalscan_folderlist_cmp — compare by name (for psync_list_sort).
 */
int plocalscan_folderlist_cmp(const psync_list *l1, const psync_list *l2);

/*
 * plocalscan_compare_sizeinodemtime — compare by (size, inode, mtime).
 * Used for file-rename detection.
 */
int plocalscan_compare_sizeinodemtime(const psync_list *l1,
                                      const psync_list *l2);

/*
 * plocalscan_compare_inode — compare by inode.
 * Used for folder-rename detection.
 */
int plocalscan_compare_inode(const psync_list *l1, const psync_list *l2);

/* ------------------------------------------------------------------ */
/* Element allocation                                                   */
/* ------------------------------------------------------------------ */

/*
 * plocalscan_copy_element — deep-copy an entry, setting the parent IDs.
 * Caller owns the returned allocation (pmem_free).
 */
sync_folderlist *plocalscan_copy_element(const sync_folderlist *e,
                                         psync_folderid_t folderid,
                                         psync_folderid_t localfolderid,
                                         psync_syncid_t syncid,
                                         psync_synctype_t synctype);

/* ------------------------------------------------------------------ */
/* Classification helpers — write to injected out[] instead of globals */
/* ------------------------------------------------------------------ */

/*
 * plocalscan_add_new_element — classify a disk entry not found in the DB.
 * Appends to out[NEWFILES] or out[NEWFOLDERS].
 * Returns the number of elements added (0 if filtered, 1 if added).
 */
int plocalscan_add_new_element(const sync_folderlist *e,
                                psync_folderid_t folderid,
                                psync_folderid_t localfolderid,
                                psync_syncid_t syncid,
                                psync_synctype_t synctype,
                                uint64_t deviceid,
                                psync_list *out /* [PLOCALSCAN_SCAN_LIST_CNT] */);

/*
 * plocalscan_add_deleted_element — classify a DB entry missing from disk.
 * Appends to out[DELFILES] or out[DELFOLDERS].
 * Returns 1 (always adds an element).
 */
int plocalscan_add_deleted_element(const sync_folderlist *e,
                                    psync_folderid_t folderid,
                                    psync_folderid_t localfolderid,
                                    psync_syncid_t syncid,
                                    psync_synctype_t synctype,
                                    psync_list *out /* [PLOCALSCAN_SCAN_LIST_CNT] */);

/*
 * plocalscan_add_modified_file — classify a file whose metadata differs.
 * Appends to out[MODFILES].
 * Returns 1.
 */
int plocalscan_add_modified_file(const sync_folderlist *e,
                                  const sync_folderlist *dbe,
                                  psync_folderid_t folderid,
                                  psync_folderid_t localfolderid,
                                  psync_syncid_t syncid,
                                  psync_synctype_t synctype,
                                  psync_list *out /* [PLOCALSCAN_SCAN_LIST_CNT] */);

/* ------------------------------------------------------------------ */
/* Merge algorithm                                                      */
/* ------------------------------------------------------------------ */

/*
 * plocalscan_merge_folder_lists — compare two pre-sorted lists and classify
 * entries into out[].
 *
 * disklist: sorted by name (disk entries, not freed by this function)
 * dblist:   sorted by name (DB entries, not freed by this function)
 * out:      array of PLOCALSCAN_SCAN_LIST_CNT psync_list heads, already
 *           initialised by the caller; new elements are appended.
 *
 * Returns the total number of elements added across all output lists.
 * The caller is responsible for eventually freeing the appended elements.
 */
size_t plocalscan_merge_folder_lists(psync_list *disklist,
                                      psync_list *dblist,
                                      psync_list *out,
                                      psync_folderid_t folderid,
                                      psync_folderid_t localfolderid,
                                      psync_syncid_t syncid,
                                      psync_synctype_t synctype,
                                      uint64_t deviceid);

#endif /* PLOCALSCAN_HELPERS_H */
