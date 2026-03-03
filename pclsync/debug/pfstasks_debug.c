// debug/pfstasks_debug.c - debug implementations for pfstasks debug helpers

#include "pdbg.h"
#include "pfstasks.h"
#include "pfstasks_internal.h"

void pfstasks_debug_check_folder_consistency(psync_fstask_folder_t *folder) {
  if ((!!folder->taskscnt) !=
      (folder->creats || folder->mkdirs || folder->rmdirs || folder->unlinks))
    pdbg_logf(D_ERROR, "taskcnt=%u, c=%p, m=%p, r=%p, u=%p",
          (unsigned)folder->taskscnt, folder->creats, folder->mkdirs,
          folder->rmdirs, folder->unlinks);
}

void pfs_task_dump_state() {
  psync_fstask_folder_t *folder;
  psync_fstask_mkdir_t *mk;
  psync_fstask_rmdir_t *rm;
  psync_fstask_creat_t *cr;
  psync_fstask_unlink_t *un;
  uint32_t cnt;
  ptree_for_each_element(folder, folders, psync_fstask_folder_t, tree) {
    pdbg_logf(D_NOTICE, "open folderid %ld taskcnt %u refcnt %u",
          (long)folder->folderid, (unsigned)folder->taskscnt,
          (unsigned)folder->refcnt);
    cnt = 0;
    ptree_for_each_element(mk, folder->mkdirs, psync_fstask_mkdir_t, tree) {
      pdbg_logf(D_NOTICE, "  mkdir %s folderid %ld taskid %lu", mk->name,
            (long)mk->folderid, (unsigned long)mk->taskid);
      cnt++;
    }
    ptree_for_each_element(rm, folder->rmdirs, psync_fstask_rmdir_t, tree) {
      pdbg_logf(D_NOTICE, "  mkdir %s folderid %ld taskid %lu", rm->name,
            (long)rm->folderid, (unsigned long)rm->taskid);
      cnt++;
    }
    ptree_for_each_element(cr, folder->creats, psync_fstask_creat_t, tree) {
      pdbg_logf(D_NOTICE, "  creat %s fileid %ld taskid %lu", cr->name,
            (long)cr->fileid, (unsigned long)cr->taskid);
      cnt++;
    }
    ptree_for_each_element(un, folder->unlinks, psync_fstask_unlink_t, tree) {
      pdbg_logf(D_NOTICE, "  unlink %s fileid %ld taskid %lu", un->name,
            (long)un->fileid, (unsigned long)un->taskid);
      cnt++;
    }
    if (cnt != folder->taskscnt)
      pdbg_logf(D_ERROR, "inconsistency found, counted taskcnt %u != taskcnt %u",
            (unsigned)cnt, (unsigned)folder->taskscnt);
  }
}
