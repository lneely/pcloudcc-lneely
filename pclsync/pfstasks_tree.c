/*
 * pfstasks_tree.c — pure tree operations for the fstask subsystem.
 *
 * All functions here are psql-free and operate only on in-memory psync_tree
 * structures.  Extracted so that unit tests can link this file alone without
 * pulling in pfstasks.c's heavy dependencies (psql, pcrypto, pfs*, …).
 */

#include <stddef.h>
#include <string.h>

#include "pdbg.h"
#include "pfstasks_tree.h"

/* ------------------------------------------------------------------ */
/* Static helpers                                                       */
/* ------------------------------------------------------------------ */

/*
 * BST search by name string at `nameoff`.
 * If `taskid` != 0 and a name-equal node has a different taskid,
 * walks prev/next siblings to find the matching one.
 */
static psync_tree *pfs_task_search_tree(psync_tree *tree, size_t nameoff,
                                        const char *name, uint64_t taskid,
                                        size_t taskidoff) {
    int c;
    while (tree) {
        c = strcmp(name, ((char *)tree) + nameoff);
        if      (c < 0) tree = tree->left;
        else if (c > 0) tree = tree->right;
        else            break;
    }
    if (!tree || !taskid ||
        *((uint64_t *)(((char *)tree) + taskidoff)) == taskid)
        return tree;
    /* Walk siblings with the same name to find the matching taskid */
    psync_tree *tn = ptree_get_prev(tree);
    while (tn) {
        if (strcmp(name, ((char *)tn) + nameoff)) break;
        if (*((uint64_t *)(((char *)tn) + taskidoff)) == taskid) return tn;
        tn = ptree_get_prev(tn);
    }
    tn = ptree_get_next(tree);
    while (tn) {
        if (strcmp(name, ((char *)tn) + nameoff)) break;
        if (*((uint64_t *)(((char *)tn) + taskidoff)) == taskid) return tn;
        tn = ptree_get_next(tn);
    }
    return NULL;
}

/*
 * Linear in-order walk to find the first node whose uint64_t field at
 * `taskidoff` equals `taskid`.
 */
static psync_tree *pfs_task_walk_tree(psync_tree *tree, uint64_t taskid,
                                      size_t taskidoff) {
    tree = ptree_get_first(tree);
    while (tree) {
        if (*((uint64_t *)(((char *)tree) + taskidoff)) == taskid) return tree;
        tree = ptree_get_next(tree);
    }
    return NULL;
}

/* ------------------------------------------------------------------ */
/* Exported: tree insertion                                             */
/* ------------------------------------------------------------------ */

void pfs_task_insert_into_tree(psync_tree **tree, size_t nameoff,
                               psync_tree *element) {
    const char *name;
    psync_tree *node;
    int c;

    if (!*tree) {
        ptree_add_after(tree, NULL, element);
        return;
    }

    name = ((char *)element) + nameoff;
    node = *tree;

    while (1) {
        c = strcmp(name, ((char *)node) + nameoff);
        if (c < 0) {
            if (node->left)
                node = node->left;
            else {
                ptree_add_before(tree, node, element);
                return;
            }
        } else {
            if (c == 0)
                pdbg_logf(D_WARNING, "duplicate entry %s, should not happen",
                          name);
            if (node->right)
                node = node->right;
            else {
                ptree_add_after(tree, node, element);
                return;
            }
        }
    }
}

/* ------------------------------------------------------------------ */
/* Exported: find by name (+ optional taskid discriminator)            */
/* ------------------------------------------------------------------ */

psync_fstask_mkdir_t *pfs_task_find_mkdir(psync_fstask_folder_t *folder,
                                          const char *name, uint64_t taskid) {
    return ptree_element(
        pfs_task_search_tree(folder->mkdirs,
                             offsetof(psync_fstask_mkdir_t, name), name,
                             taskid, offsetof(psync_fstask_mkdir_t, taskid)),
        psync_fstask_mkdir_t, tree);
}

psync_fstask_rmdir_t *pfs_task_find_rmdir(psync_fstask_folder_t *folder,
                                          const char *name, uint64_t taskid) {
    return ptree_element(
        pfs_task_search_tree(folder->rmdirs,
                             offsetof(psync_fstask_rmdir_t, name), name,
                             taskid, offsetof(psync_fstask_rmdir_t, taskid)),
        psync_fstask_rmdir_t, tree);
}

psync_fstask_creat_t *pfs_task_find_creat(psync_fstask_folder_t *folder,
                                          const char *name, uint64_t taskid) {
    return ptree_element(
        pfs_task_search_tree(folder->creats,
                             offsetof(psync_fstask_creat_t, name), name,
                             taskid, offsetof(psync_fstask_creat_t, taskid)),
        psync_fstask_creat_t, tree);
}

psync_fstask_unlink_t *pfs_task_find_unlink(psync_fstask_folder_t *folder,
                                            const char *name, uint64_t taskid) {
    return ptree_element(
        pfs_task_search_tree(folder->unlinks,
                             offsetof(psync_fstask_unlink_t, name), name,
                             taskid, offsetof(psync_fstask_unlink_t, taskid)),
        psync_fstask_unlink_t, tree);
}

/* ------------------------------------------------------------------ */
/* Exported: find by numeric ID                                         */
/* ------------------------------------------------------------------ */

psync_fstask_mkdir_t *pfs_task_find_mkdir_by_folderid(
        psync_fstask_folder_t *folder, psync_fsfolderid_t folderid) {
    return ptree_element(
        pfs_task_walk_tree(folder->mkdirs, folderid,
                           offsetof(psync_fstask_mkdir_t, folderid)),
        psync_fstask_mkdir_t, tree);
}

psync_fstask_creat_t *pfs_task_find_creat_by_fileid(
        psync_fstask_folder_t *folder, psync_fsfileid_t fileid) {
    return ptree_element(
        pfs_task_walk_tree(folder->creats, fileid,
                           offsetof(psync_fstask_creat_t, fileid)),
        psync_fstask_creat_t, tree);
}
