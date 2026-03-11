/*
 * plocalscan_helpers.c — sorted-list merge helpers extracted from plocalscan.c.
 *
 * Deps beyond plocalscan_helpers.h: pdbg.h (logging), pdevice.h (deviceid
 * macro), putil.h (UTF-8 validation), and two external declarations for
 * psync_is_name_to_ignore / psync_send_backup_del_event (provided by the real
 * sync library or by test --wrap stubs).
 */

#include <string.h>   /* strcmp, memcpy */
#include <stddef.h>   /* offsetof */

#include "plocalscan_helpers.h"
#include "pdbg.h"     /* pdbg_logf */
#include "pdevice.h"  /* pdevice_id_short macro */
#include "putil.h"    /* putil_is_valid_utf8 */

/* Forward-declare without pulling in the heavy psynclib.h / pdevice headers */
extern int  psync_is_name_to_ignore(const char *name);
extern void psync_send_backup_del_event(psync_fileorfolderid_t remoteFId);

/* ------------------------------------------------------------------ */
/* Comparators                                                          */
/* ------------------------------------------------------------------ */

int plocalscan_folderlist_cmp(const psync_list *l1, const psync_list *l2) {
  return strcmp(
      psync_list_element(l1, sync_folderlist, list)->name,
      psync_list_element(l2, sync_folderlist, list)->name);
}

int plocalscan_compare_sizeinodemtime(const psync_list *l1,
                                      const psync_list *l2) {
  const sync_folderlist *f1, *f2;
  int64_t d;
  f1 = psync_list_element(l1, sync_folderlist, list);
  f2 = psync_list_element(l2, sync_folderlist, list);
  d = (int64_t)(f1->size - f2->size);
  if (d < 0) return -1;
  if (d > 0) return  1;
  d = (int64_t)(f1->inode - f2->inode);
  if (d < 0) return -1;
  if (d > 0) return  1;
  d = (int64_t)(f1->mtimenat - f2->mtimenat);
  if (d < 0) return -1;
  if (d > 0) return  1;
  return 0;
}

int plocalscan_compare_inode(const psync_list *l1, const psync_list *l2) {
  const sync_folderlist *f1, *f2;
  int64_t d;
  f1 = psync_list_element(l1, sync_folderlist, list);
  f2 = psync_list_element(l2, sync_folderlist, list);
  d = (int64_t)(f1->inode - f2->inode);
  if (d < 0) return -1;
  if (d > 0) return  1;
  return 0;
}

/* ------------------------------------------------------------------ */
/* Element allocation                                                   */
/* ------------------------------------------------------------------ */

sync_folderlist *plocalscan_copy_element(const sync_folderlist *e,
                                         psync_folderid_t folderid,
                                         psync_folderid_t localfolderid,
                                         psync_syncid_t syncid,
                                         psync_synctype_t synctype) {
  sync_folderlist *ret;
  size_t l = offsetof(sync_folderlist, name) + strlen(e->name) + 1;
  ret = (sync_folderlist *)pmem_malloc(PMEM_SUBSYS_SYNC, l);
  memcpy(ret, e, l);
  ret->localparentfolderid = localfolderid;
  ret->parentfolderid      = folderid;
  ret->syncid              = syncid;
  ret->synctype            = synctype;
  return ret;
}

/* ------------------------------------------------------------------ */
/* Classification helpers                                               */
/* ------------------------------------------------------------------ */

int plocalscan_add_new_element(const sync_folderlist *e,
                                psync_folderid_t folderid,
                                psync_folderid_t localfolderid,
                                psync_syncid_t syncid,
                                psync_synctype_t synctype,
                                uint64_t deviceid,
                                psync_list *out) {
  sync_folderlist *c;
  if (e->isfolder && e->deviceid != deviceid)
    return 0;
  if (psync_is_name_to_ignore(e->name))
    return 0;
  if (!putil_is_valid_utf8(e->name)) {
    pdbg_logf(D_WARNING, "ignoring %s with invalid UTF8 name %s",
          e->isfolder ? "folder" : "file", e->name);
    return 0;
  }
  pdbg_logf(D_NOTICE, "found new %s %s",
        e->isfolder ? "folder" : "file", e->name);
  c = plocalscan_copy_element(e, folderid, localfolderid, syncid, synctype);
  if (e->isfolder)
    psync_list_add_tail(&out[PLOCALSCAN_SCAN_LIST_NEWFOLDERS], &c->list);
  else
    psync_list_add_tail(&out[PLOCALSCAN_SCAN_LIST_NEWFILES], &c->list);
  return 1;
}

int plocalscan_add_deleted_element(const sync_folderlist *e,
                                    psync_folderid_t folderid,
                                    psync_folderid_t localfolderid,
                                    psync_syncid_t syncid,
                                    psync_synctype_t synctype,
                                    psync_list *out) {
  sync_folderlist *c;
  pdbg_logf(D_NOTICE, "found deleted %s %s",
        e->isfolder ? "folder" : "file", e->name);
  c = plocalscan_copy_element(e, folderid, localfolderid, syncid, synctype);
  if (e->isfolder) {
    psync_list_add_tail(&out[PLOCALSCAN_SCAN_LIST_DELFOLDERS], &c->list);
  } else {
    if (synctype == 7)
      psync_send_backup_del_event(c->remoteid);
    psync_list_add_tail(&out[PLOCALSCAN_SCAN_LIST_DELFILES], &c->list);
  }
  return 1;
}

int plocalscan_add_modified_file(const sync_folderlist *e,
                                  const sync_folderlist *dbe,
                                  psync_folderid_t folderid,
                                  psync_folderid_t localfolderid,
                                  psync_syncid_t syncid,
                                  psync_synctype_t synctype,
                                  psync_list *out) {
  pdbg_logf(D_NOTICE,
        "found modified file %s on disk: size=%llu mtime=%llu inode=%llu "
        "in db: size=%llu mtime=%llu inode=%llu",
        e->name,
        (long long unsigned)e->size,   (long long unsigned)e->mtimenat,
        (long long unsigned)e->inode,  (long long unsigned)dbe->size,
        (long long unsigned)dbe->mtimenat, (long long unsigned)dbe->inode);
  psync_list_add_tail(&out[PLOCALSCAN_SCAN_LIST_MODFILES],
      &plocalscan_copy_element(e, folderid, localfolderid, syncid,
                               synctype)->list);
  return 1;
}

/* ------------------------------------------------------------------ */
/* Merge algorithm                                                      */
/* ------------------------------------------------------------------ */

size_t plocalscan_merge_folder_lists(psync_list *disklist,
                                      psync_list *dblist,
                                      psync_list *out,
                                      psync_folderid_t folderid,
                                      psync_folderid_t localfolderid,
                                      psync_syncid_t syncid,
                                      psync_synctype_t synctype,
                                      uint64_t deviceid) {
  psync_list *ldisk, *ldb;
  sync_folderlist *fdisk, *fdb;
  size_t added = 0;
  int cmp;

  ldisk = disklist->next;
  ldb   = dblist->next;

  while (ldisk != disklist && ldb != dblist) {
    fdisk = psync_list_element(ldisk, sync_folderlist, list);
    fdb   = psync_list_element(ldb,   sync_folderlist, list);
    cmp   = strcmp(fdisk->name, fdb->name);

    if (cmp == 0) {
      if (fdisk->isfolder == fdb->isfolder) {
        fdisk->localid  = fdb->localid;
        fdisk->remoteid = fdb->remoteid;
        if (!fdisk->isfolder &&
            (fdisk->mtimenat != fdb->mtimenat || fdisk->size != fdb->size ||
             fdisk->inode != fdb->inode))
          added += (size_t)plocalscan_add_modified_file(
              fdisk, fdb, folderid, localfolderid, syncid, synctype, out);
        if (fdisk->isfolder &&
            pdevice_id_short(fdisk->deviceid) != fdb->deviceid &&
            fdisk->inode != fdb->inode) {
          if (fdisk->deviceid == deviceid) {
            pdbg_logf(D_NOTICE,
                  "deviceid of localfolder %s %lu is different, skipping",
                  fdisk->name, (unsigned long)fdisk->localid);
            fdisk->localid = 0;
          }
        }
      } else {
        added += (size_t)plocalscan_add_deleted_element(
            fdb, folderid, localfolderid, syncid, synctype, out);
        added += (size_t)plocalscan_add_new_element(
            fdisk, folderid, localfolderid, syncid, synctype, deviceid, out);
      }
      ldisk = ldisk->next;
      ldb   = ldb->next;
    } else if (cmp < 0) { /* new entry on disk */
      added += (size_t)plocalscan_add_new_element(
          fdisk, folderid, localfolderid, syncid, synctype, deviceid, out);
      ldisk = ldisk->next;
    } else { /* entry deleted from disk */
      added += (size_t)plocalscan_add_deleted_element(
          fdb, folderid, localfolderid, syncid, synctype, out);
      ldb = ldb->next;
    }
  }

  /* Remaining disk entries are all new */
  while (ldisk != disklist) {
    fdisk = psync_list_element(ldisk, sync_folderlist, list);
    added += (size_t)plocalscan_add_new_element(
        fdisk, folderid, localfolderid, syncid, synctype, deviceid, out);
    ldisk = ldisk->next;
  }

  /* Remaining DB entries are all deleted */
  while (ldb != dblist) {
    fdb = psync_list_element(ldb, sync_folderlist, list);
    added += (size_t)plocalscan_add_deleted_element(
        fdb, folderid, localfolderid, syncid, synctype, out);
    ldb = ldb->next;
  }

  return added;
}
