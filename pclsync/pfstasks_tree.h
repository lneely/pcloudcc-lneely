/*
 * pfstasks_tree.h — pure tree layer for the fstask subsystem.
 *
 * Declares functions that operate solely on in-memory psync_tree structures
 * with zero psql calls.  This header is included by pfstasks.c and by the
 * unit test test_pfstasks_tree.c.
 *
 * Do NOT add functions with psql dependencies here.
 */
#ifndef PFSTASKS_TREE_H
#define PFSTASKS_TREE_H

#include "pfstasks.h"

/*
 * Insert `element` into the AVL tree `*tree`, ordering by the NUL-terminated
 * string at offset `nameoff` within each element.
 */
void pfs_task_insert_into_tree(psync_tree **tree, size_t nameoff,
                               psync_tree *element);

/* Find by name (and optional taskid discriminator; pass 0 to match any) */
psync_fstask_mkdir_t  *pfs_task_find_mkdir(psync_fstask_folder_t *folder,
                                           const char *name, uint64_t taskid);
psync_fstask_rmdir_t  *pfs_task_find_rmdir(psync_fstask_folder_t *folder,
                                           const char *name, uint64_t taskid);
psync_fstask_creat_t  *pfs_task_find_creat(psync_fstask_folder_t *folder,
                                           const char *name, uint64_t taskid);
psync_fstask_unlink_t *pfs_task_find_unlink(psync_fstask_folder_t *folder,
                                            const char *name, uint64_t taskid);

/* Find by numeric ID via linear walk */
psync_fstask_mkdir_t *pfs_task_find_mkdir_by_folderid(
    psync_fstask_folder_t *folder, psync_fsfolderid_t folderid);
psync_fstask_creat_t *pfs_task_find_creat_by_fileid(
    psync_fstask_folder_t *folder, psync_fsfileid_t fileid);

#endif /* PFSTASKS_TREE_H */
