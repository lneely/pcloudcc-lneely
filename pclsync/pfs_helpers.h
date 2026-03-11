/*
 * pfs_helpers.h — pure row→stat converters and overlay helpers extracted
 * from pfs.c so they can be unit-tested without a live FUSE mount or psql
 * connection.
 *
 * Included by pfs.c and by tests/unit-tests/test_pfs_helpers.c.
 */
#ifndef PFS_HELPERS_H
#define PFS_HELPERS_H

#include <sys/stat.h>
#include <sys/types.h>
#include <stdint.h>

#include "pfoldersync.h"   /* psync_folderid_t, psync_fileid_t */
#include "pfstasks.h"      /* psync_fstask_folder_t, psync_fstask_mkdir_t, … */
#include "pfsfolder.h"     /* psync_fspath_t */
#include "psql.h"          /* psync_variant_row */

/*
 * Inode-number helpers — must match the definitions used in pfs.c.
 * Put here so pfs_helpers.c and tests share a single definition.
 */
#define PFS_FOLDERID_TO_INODE(fid)  ((fid) * 3)
#define PFS_FILEID_TO_INODE(fid)    ((fid) * 3 + 1)
#define PFS_TASKID_TO_INODE(tid)    ((tid) * 3 + 2)
#define PFS_FS_BLOCK_SIZE           4096

/*
 * Owner uid/gid used when populating struct stat.  Initialised to 0 (root)
 * by pfs_helpers.c.  pfs.c overwrites them with the real process owner at
 * init time; tests leave them at 0.
 */
extern uid_t pfs_stat_uid;
extern gid_t pfs_stat_gid;

/*
 * pfs_row_to_folder_stat — convert a psql folder row to struct stat.
 *
 * Row column layout: [0]=id [1]=permissions [2]=ctime [3]=mtime [4]=subdircnt
 * Applies any pending in-memory mtime from the folder task queue.
 * No SQL, no FUSE calls.
 */
void pfs_row_to_folder_stat(psync_variant_row row, struct stat *stbuf);

/*
 * pfs_row_to_file_stat — convert a psql file row to struct stat.
 *
 * Row column layout: [0]=name [1]=size [2]=ctime [3]=mtime [4]=id
 * flags: PSYNC_FOLDER_FLAG_ENCRYPTED triggers encrypted-size conversion via
 * pfs_crpt_plain_size(); tests pass flags=0 to skip crypto.
 * No SQL, no FUSE calls.
 */
void pfs_row_to_file_stat(psync_variant_row row, struct stat *stbuf,
                          uint32_t flags);

/*
 * pfs_mkdir_to_folder_stat — convert an in-memory mkdir task to struct stat.
 * No SQL, no FUSE calls.
 */
void pfs_mkdir_to_folder_stat(psync_fstask_mkdir_t *mk, struct stat *stbuf);

/*
 * pfs_apply_task_overlay — check an in-memory folder task queue for a
 * pending operation on `name` and update `stbuf` accordingly.
 *
 * Returns:
 *   1   mkdir overlay applied (stbuf filled as a directory)
 *   2   creat overlay applied (stbuf filled as a new file, fileid=0)
 *  -1   rmdir or unlink pending → entry should be hidden (ENOENT)
 *   0   no applicable overlay found
 *
 * No SQL, no network I/O.  folder may be NULL (returns 0 immediately).
 */
int pfs_apply_task_overlay(struct stat *stbuf,
                           psync_fstask_folder_t *folder,
                           const char *name, uint32_t flags);

/*
 * pfs_fldr_resolve_path — declared __attribute__((weak)) in pfsfolder.c so
 * tests can override path resolution without a live FUSE / psql stack.
 * The declaration here is informational only (it lives in pfsfolder.h).
 */

#endif /* PFS_HELPERS_H */
