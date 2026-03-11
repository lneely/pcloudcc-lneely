/*
 * pfs_helpers.c — pure row→stat converters and overlay helpers.
 *
 * Dependencies: pfstasks_tree.c (for find_* functions), pfscrypto.h (for
 * pfs_crpt_plain_size on encrypted files), plibs.h (psync_get_number macro).
 * No psql calls, no FUSE, no network.
 */

#include <string.h>
#include <time.h>
#include <sys/stat.h>

#include "pdbg.h"
#include "pfscrypto.h"
#include "pfs_helpers.h"
#include "plibs.h"   /* psync_get_number */
#include "ptimer.h"  /* ptimer_time */

/* ------------------------------------------------------------------ */
/* Globals — initialised here; overwritten by pfs.c at mount time     */
/* ------------------------------------------------------------------ */

uid_t pfs_stat_uid = 0;
gid_t pfs_stat_gid = 0;

/* ------------------------------------------------------------------ */
/* Row → stat converters                                                */
/* ------------------------------------------------------------------ */

void pfs_row_to_folder_stat(psync_variant_row row, struct stat *stbuf) {
    psync_folderid_t folderid;
    uint64_t mtime;
    psync_fstask_folder_t *folder;

    folderid = (psync_folderid_t)psync_get_number(row[0]);
    mtime    = psync_get_number(row[3]);

    folder = pfs_task_get_folder_tasks_rdlocked(folderid);
    if (folder && folder->mtime)
        mtime = folder->mtime;

    memset(stbuf, 0, sizeof(*stbuf));
    stbuf->st_ino     = PFS_FOLDERID_TO_INODE(folderid);
    stbuf->st_ctime   = (time_t)mtime;
    stbuf->st_mtime   = (time_t)mtime;
    stbuf->st_atime   = (time_t)mtime;
    stbuf->st_mode    = S_IFDIR | 0755;
    stbuf->st_nlink   = (nlink_t)(psync_get_number(row[4]) + 2);
    stbuf->st_size    = PFS_FS_BLOCK_SIZE;
    stbuf->st_blocks  = 1;
    stbuf->st_blksize = PFS_FS_BLOCK_SIZE;
    stbuf->st_uid     = pfs_stat_uid;
    stbuf->st_gid     = pfs_stat_gid;
}

void pfs_row_to_file_stat(psync_variant_row row, struct stat *stbuf,
                          uint32_t flags) {
    uint64_t size = psync_get_number(row[1]);
    psync_fileid_t fileid = (psync_fileid_t)psync_get_number(row[4]);

    if (flags & PSYNC_FOLDER_FLAG_ENCRYPTED)
        size = pfs_crpt_plain_size(size);

    memset(stbuf, 0, sizeof(*stbuf));
    stbuf->st_ino     = PFS_FILEID_TO_INODE(fileid);
    stbuf->st_ctime   = (time_t)psync_get_number(row[3]);
    stbuf->st_mtime   = stbuf->st_ctime;
    stbuf->st_atime   = stbuf->st_ctime;
    stbuf->st_mode    = S_IFREG | 0644;
    stbuf->st_nlink   = 1;
    stbuf->st_size    = (off_t)size;
    stbuf->st_blocks  = (blkcnt_t)((size + 511) / 512);
    stbuf->st_blksize = PFS_FS_BLOCK_SIZE;
    stbuf->st_uid     = pfs_stat_uid;
    stbuf->st_gid     = pfs_stat_gid;
}

void pfs_mkdir_to_folder_stat(psync_fstask_mkdir_t *mk, struct stat *stbuf) {
    uint64_t mtime;
    psync_fstask_folder_t *folder;

    folder = pfs_task_get_folder_tasks_rdlocked(mk->folderid);
    mtime  = (folder && folder->mtime) ? folder->mtime : (uint64_t)mk->mtime;

    memset(stbuf, 0, sizeof(*stbuf));
    stbuf->st_ino = (mk->folderid >= 0)
                    ? PFS_FOLDERID_TO_INODE(mk->folderid)
                    : PFS_TASKID_TO_INODE(-mk->folderid);
    stbuf->st_ctime   = (time_t)mtime;
    stbuf->st_mtime   = (time_t)mtime;
    stbuf->st_atime   = (time_t)mtime;
    stbuf->st_mode    = S_IFDIR | 0755;
    stbuf->st_nlink   = (nlink_t)(mk->subdircnt + 2);
    stbuf->st_size    = PFS_FS_BLOCK_SIZE;
    stbuf->st_blocks  = 1;
    stbuf->st_blksize = PFS_FS_BLOCK_SIZE;
    stbuf->st_uid     = pfs_stat_uid;
    stbuf->st_gid     = pfs_stat_gid;
}

/* ------------------------------------------------------------------ */
/* Task overlay                                                         */
/* ------------------------------------------------------------------ */

int pfs_apply_task_overlay(struct stat *stbuf,
                           psync_fstask_folder_t *folder,
                           const char *name, uint32_t flags) {
    if (!folder)
        return 0;

    /* Pending mkdir: show the directory */
    psync_fstask_mkdir_t *mk = pfs_task_find_mkdir(folder, name, 0);
    if (mk) {
        if (mk->flags & PSYNC_FOLDER_FLAG_INVISIBLE)
            return -1;
        pfs_mkdir_to_folder_stat(mk, stbuf);
        return 1;
    }

    /* Pending rmdir: hide the directory */
    if (pfs_task_find_rmdir(folder, name, 0))
        return -1;

    /* Pending unlink: hide the file */
    if (pfs_task_find_unlink(folder, name, 0))
        return -1;

    /* Pending creat with fileid==0 (new local file, no SQL needed):
     * return a minimal stat for the new file.                          */
    psync_fstask_creat_t *cr = pfs_task_find_creat(folder, name, 0);
    if (cr && cr->fileid == 0) {
        time_t now = ptimer_time();
        memset(stbuf, 0, sizeof(*stbuf));
        stbuf->st_ctime   = now;
        stbuf->st_mtime   = now;
        stbuf->st_atime   = now;
        stbuf->st_mode    = S_IFREG | 0644;
        stbuf->st_nlink   = 1;
        stbuf->st_size    = 0;
        stbuf->st_blocks  = 0;
        stbuf->st_blksize = PFS_FS_BLOCK_SIZE;
        stbuf->st_uid     = pfs_stat_uid;
        stbuf->st_gid     = pfs_stat_gid;
        return 2;
    }

    return 0;
}
