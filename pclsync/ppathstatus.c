/*
   Copyright (c) 2016 Anton Titov.

   Copyright (c) 2016 pCloud Ltd.  All rights reserved.

   Redistribution and use in source and binary forms, with or without
   modification, are permitted provided that the following conditions
   are met: Redistributions of source code must retain the above
   copyright notice, this list of conditions and the following
   disclaimer.  Redistributions in binary form must reproduce the
   above copyright notice, this list of conditions and the following
   disclaimer in the documentation and/or other materials provided
   with the distribution.  Neither the name of pCloud Ltd nor the
   names of its contributors may be used to endorse or promote
   products derived from this software without specific prior written
   permission.

   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
   FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL pCloud
   Ltd BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
   EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
   PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
   PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
   OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
   USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
   DAMAGE.
*/

#include <pthread.h>
#include <string.h>

#include "pcryptofolder.h"
#include "pfoldersync.h"
#include "plibs.h"
#include "plist.h"
#include "ppathstatus.h"
#include "pstatus.h"
#include "ptask.h"
#include "ptree.h"
#include "psql.h"
#include "pfstasks.h"

#define PATH_CACHE_SIZE 512
#define PATH_HASH_SIZE 512

#define PARENT_CACHE_SIZE 128
#define PARENT_HASH_SIZE 128

#define SYNC_PARENT_CACHE_SIZE 64
#define SYNC_PARENT_HASH_SIZE 64

#define ENTRY_FLAG_FOLDER 1
#define ENTRY_FLAG_ENCRYPTED 2
#define ENTRY_FLAG_PROG 4

typedef struct {
  uint32_t hash[4];
  psync_list list_hash;
  psync_list list_lru;
  uint64_t itemid;
  uint64_t flags;
} path_cache_entry_t;

typedef struct {
  psync_folderid_t folderid;
  psync_folderid_t parentfolderid;
  psync_list list_hash;
  psync_list list_lru;
} parent_cache_entry_t;

typedef struct _folder_tasks_t {
  psync_tree tree;
  psync_folderid_t folderid;
  uint32_t child_task_cnt;
  uint32_t own_tasks; // this is not a count (just 0 or 1), so can be changed to
                      // a "flags" with multiple flags if needed
} folder_tasks_t;

typedef struct {
  psync_tree tree;
  psync_tree *folder_tasks;
  psync_syncid_t syncid;
  psync_list parent_cache_lru;
  psync_list cache_free;
  psync_list parent_cache_hash[SYNC_PARENT_HASH_SIZE];
  parent_cache_entry_t parent_cache_entries[SYNC_PARENT_CACHE_SIZE];
} sync_data_t;

typedef struct {
  char *path;
  size_t path_len;
  psync_folderid_t folderid;
  psync_syncid_t syncid;
  uint32_t flags;
} path_sync_list_entry_t;

typedef struct {
  size_t sync_cnt;
  path_sync_list_entry_t syncs[];
} path_sync_list_t;

typedef struct {
  psync_folderid_t folderid;
  psync_folderid_t old_parent_folderid;
  psync_folderid_t new_parent_folderid;
} folder_moved_params_t;

typedef struct {
  psync_folderid_t folderid;
  psync_folderid_t old_parent_folderid;
  psync_folderid_t new_parent_folderid;
  psync_syncid_t old_syncid;
  psync_syncid_t new_syncid;
} sync_folder_moved_params_t;

static char *drive_path = NULL;
static size_t drive_path_len;
static path_sync_list_t *syncs = NULL;
static psync_tree *sync_data = PSYNC_TREE_EMPTY;

static uint64_t drv_hash_seed;
static uint64_t sync_hash_seed;
static psync_list cache_free;
static psync_list path_cache_lru;
static psync_list path_cache_hash[PATH_HASH_SIZE];
static path_cache_entry_t path_cache_entries[PATH_CACHE_SIZE];
static psync_list parent_cache_lru;
static psync_list parent_cache_hash[PARENT_HASH_SIZE];
static parent_cache_entry_t parent_cache_entries[PARENT_CACHE_SIZE];
static psync_tree *folder_tasks = PSYNC_TREE_EMPTY;

static void sync_data_free(sync_data_t *sd);
static void load_sync_tasks();

static inline int psync_crypto_is_error(const void *ptr) {
  return (uintptr_t)ptr <= PSYNC_CRYPTO_MAX_ERROR;
}

static inline int psync_crypto_to_error(const void *ptr) {
  return -((int)(uintptr_t)ptr);
}

void ppathstatus_init() {
  size_t i;
  psql_lock();
  psync_list_init(&cache_free);
  psync_list_init(&path_cache_lru);
  psync_list_init(&parent_cache_lru);
  for (i = 0; i < PATH_HASH_SIZE; i++)
    psync_list_init(&path_cache_hash[i]);
  for (i = 0; i < PATH_CACHE_SIZE; i++) {
    psync_list_add_tail(&path_cache_lru, &path_cache_entries[i].list_lru);
    psync_list_add_tail(&cache_free, &path_cache_entries[i].list_hash);
  }
  for (i = 0; i < PARENT_HASH_SIZE; i++)
    psync_list_init(&parent_cache_hash[i]);
  for (i = 0; i < PARENT_CACHE_SIZE; i++) {
    psync_list_add_tail(&parent_cache_lru, &parent_cache_entries[i].list_lru);
    psync_list_add_tail(&cache_free, &parent_cache_entries[i].list_hash);
  }
  ptree_for_each_element_call_safe(folder_tasks, folder_tasks_t, tree, free);
  folder_tasks = PSYNC_TREE_EMPTY;
  ptree_for_each_element_call_safe(sync_data, sync_data_t, tree,
                                        sync_data_free);
  sync_data = PSYNC_TREE_EMPTY;
  ppathstatus_reload_syncs();
  ppathstatus_clear_cache();
  load_sync_tasks();
  psql_unlock();
}

static int create_sync_list_entry(psync_list_builder_t *builder, void *element,
                                  psync_variant_row row) {
  path_sync_list_entry_t *entry;
  const char *str;
  size_t len;
  entry = (path_sync_list_entry_t *)element;
  str = psync_get_lstring(row[0], &len);
  entry->path = (char *)str;
  entry->path_len = len;
  psync_list_add_lstring_offset(builder, offsetof(path_sync_list_entry_t, path),
                                len);
  entry->syncid = psync_get_number(row[1]);
  entry->folderid = psync_get_number(row[2]);
  entry->flags = 0;
  return 0;
}

void ppathstatus_reload_syncs() {
  psync_list_builder_t *builder;
  psync_sql_res *res;
  path_sync_list_t *old;
  psql_lock();
  builder = psync_list_builder_create(sizeof(path_sync_list_entry_t),
                                      offsetof(path_sync_list_t, syncs));
  res = psql_query_nolock(
      "SELECT sf.localpath, sf.id, sf.folderid, f.flags FROM syncfolder sf, "
      "folder f WHERE sf.folderid=f.id");
  psql_list_add(builder, res, create_sync_list_entry);
  old = syncs;
  syncs = (path_sync_list_t *)psync_list_builder_finalize(builder);
  ppathstatus_clear_sync_cache();
  psql_unlock();
  if (old)
    psync_free_after_sec(old, 30);
}

void ppathstatus_clear_cache() {
  uint64_t ndrv_hash_seed, nsync_hash_seed;
  do {
    pssl_rand_strong((unsigned char *)&ndrv_hash_seed,
                          sizeof(ndrv_hash_seed));
  } while (unlikely(!ndrv_hash_seed));
  nsync_hash_seed = 0x49916a8e891d1dafULL * ndrv_hash_seed;
  psql_lock();
  drv_hash_seed = ndrv_hash_seed;
  sync_hash_seed = nsync_hash_seed;
  psql_unlock();
}

void ppathstatus_clear_sync_cache() {
  uint64_t nsync_hash_seed;
  do {
    pssl_rand_strong((unsigned char *)&nsync_hash_seed,
                          sizeof(nsync_hash_seed));
  } while (unlikely(nsync_hash_seed == drv_hash_seed));
  psql_lock();
  sync_hash_seed = nsync_hash_seed;
  psql_unlock();
}

static uint32_t hash_folderid(psync_folderid_t folderid) {
  uint32_t h;
  h = (uint32_t)folderid;
  h *= 0x4c8cbb55;
  h ^= h >> 19;
  return h;
}

void ppathstatus_del_from_parent_cache(psync_folderid_t folderid) {
  parent_cache_entry_t *p;
  uint32_t h;
  h = hash_folderid(folderid) % PARENT_HASH_SIZE;
  psync_list_for_each_element(p, &parent_cache_hash[h], parent_cache_entry_t,
                              list_hash) if (p->folderid == folderid) {
    psync_list_del(&p->list_lru);
    psync_list_add_head(&parent_cache_lru, &p->list_lru);
    psync_list_del(&p->list_hash);
    psync_list_add_tail(&cache_free, &p->list_hash);
    break;
  }
}

static folder_tasks_t *get_folder_tasks(psync_folderid_t folderid, int create) {
  psync_tree *tr, **atr;
  folder_tasks_t *ft;
  tr = folder_tasks;
  atr = &folder_tasks;
  while (tr) {
    ft = ptree_element(tr, folder_tasks_t, tree);
    if (folderid < ft->folderid) {
      if (tr->left) {
        tr = tr->left;
      } else {
        atr = &tr->left;
        break;
      }
    } else if (folderid > ft->folderid) {
      if (tr->right) {
        tr = tr->right;
      } else {
        atr = &tr->right;
        break;
      }
    } else {
      return ft;
    }
  }
  if (create) {
    ft = malloc(sizeof(folder_tasks_t));
    *atr = &ft->tree;
    ptree_added_at(&folder_tasks, tr, &ft->tree);
    ft->folderid = folderid;
    ft->child_task_cnt = 0;
    ft->own_tasks = 0;
    pdbg_logf(D_NOTICE, "marking folderid %lu as having (sub)tasks",
          (unsigned long)folderid);
    return ft;
  } else {
    return NULL;
  }
}

static void free_folder_tasks(folder_tasks_t *ft) {
  pdbg_logf(D_NOTICE, "marking folderid %lu as clean", (unsigned long)ft->folderid);
  ptree_del(&folder_tasks, &ft->tree);
  free(ft);
}

static psync_folderid_t get_parent_folder(psync_folderid_t folderid) {
  psync_sql_res *res;
  psync_uint_row row;
  parent_cache_entry_t *p;
  uint32_t h;
  if (folderid == 0)
    return PSYNC_INVALID_FOLDERID;
  h = hash_folderid(folderid) % PARENT_HASH_SIZE;
  psync_list_for_each_element(p, &parent_cache_hash[h], parent_cache_entry_t,
                              list_hash) if (p->folderid == folderid) {
    psync_list_del(&p->list_lru);
    psync_list_add_tail(&parent_cache_lru, &p->list_lru);
    return p->parentfolderid;
  }
  res = psql_query_nolock("SELECT parentfolderid FROM folder WHERE id=?");
  psql_bind_uint(res, 1, folderid);
  row = psql_fetch_int(res);
  if (unlikely(!row)) {
    pdbg_logf(D_WARNING, "can not find parent folder for folderid %lu",
          (unsigned long)folderid);
    psql_free(res);
    return PSYNC_INVALID_FOLDERID;
  }
  p = psync_list_remove_head_element(&parent_cache_lru, parent_cache_entry_t,
                                     list_lru);
  psync_list_del(&p->list_hash);
  p->folderid = folderid;
  p->parentfolderid = row[0];
  psync_list_add_head(&parent_cache_hash[h], &p->list_hash);
  psync_list_add_tail(&parent_cache_lru, &p->list_lru);
  psql_free(res);
  return p->parentfolderid;
}

void ppathstatus_drive_fldr_changed(psync_folderid_t folderid) {
  psync_fstask_folder_t *folder;
  folder_tasks_t *ft;
  int changed;
  psql_lock();
  folder = psync_fstask_get_folder_tasks_rdlocked(folderid);
  changed = folder && (folder->creats || folder->mkdirs);
  ft = get_folder_tasks(folderid, changed);
  if ((!changed && (!ft || ft->child_task_cnt)) ||
      (changed && (ft->own_tasks || ft->child_task_cnt))) {
    if (changed && !ft->own_tasks)
      ft->own_tasks = 1;
    else if (!changed && ft && ft->own_tasks)
      ft->own_tasks = 0;
    psql_unlock();
    return;
  }
  if (changed) {
    pdbg_assert(!ft->own_tasks);
    pdbg_assert(!ft->child_task_cnt);
    ft->own_tasks = 1;
    while ((folderid = get_parent_folder(folderid)) != PSYNC_INVALID_FOLDERID) {
      ft = get_folder_tasks(folderid, 1);
      ft->child_task_cnt++;
      if (ft->child_task_cnt > 1 || ft->own_tasks)
        break;
    }
  } else {
    pdbg_assert(ft);
    pdbg_assert(!ft->child_task_cnt);
    pdbg_assert(ft->own_tasks);
    free_folder_tasks(ft);
    while ((folderid = get_parent_folder(folderid)) != PSYNC_INVALID_FOLDERID) {
      ft = get_folder_tasks(folderid, 0);
      pdbg_assert(ft); // if assert fails, the problem is not the assert, don't
                  // change it to "if (!ft) break;"
      ft->child_task_cnt--;
      if (ft->child_task_cnt || ft->own_tasks)
        break;
      free_folder_tasks(ft);
    }
  }
  psql_unlock();
}

static void folder_moved(psync_folderid_t folderid,
                         psync_folderid_t old_parent_folderid,
                         psync_folderid_t new_parent_folderid) {
  folder_tasks_t *pft;
  pft = get_folder_tasks(new_parent_folderid, 1);
  pft->child_task_cnt++;
  while (pft->child_task_cnt == 1 && !pft->own_tasks &&
         (new_parent_folderid = get_parent_folder(new_parent_folderid)) !=
             PSYNC_INVALID_FOLDERID) {
    pft = get_folder_tasks(new_parent_folderid, 1);
    pft->child_task_cnt++;
  }
  pft = get_folder_tasks(old_parent_folderid, 0);
  pdbg_assert(pft);
  pft->child_task_cnt--;
  while (!pft->child_task_cnt && !pft->own_tasks) {
    free_folder_tasks(pft);
    old_parent_folderid = get_parent_folder(old_parent_folderid);
    if (old_parent_folderid == PSYNC_INVALID_FOLDERID)
      break;
    pft = get_folder_tasks(old_parent_folderid, 0);
    pdbg_assert(pft);
    pft->child_task_cnt--;
  }
}

static void folder_moved_commit(void *ptr) {
  folder_moved_params_t *mp = (folder_moved_params_t *)ptr;
  folder_moved(mp->folderid, mp->old_parent_folderid, mp->new_parent_folderid);
  free(mp);
}

void ppathstatus_fldr_moved(psync_folderid_t folderid,
                                    psync_folderid_t old_parent_folderid,
                                    psync_folderid_t new_parent_folderid) {
  folder_moved_params_t *mp;
  if (old_parent_folderid == new_parent_folderid)
    return;
  ppathstatus_del_from_parent_cache(folderid);
  if (!get_folder_tasks(folderid, 0))
    return;
  mp = malloc(sizeof(folder_moved_params_t));
  mp->folderid = folderid;
  mp->old_parent_folderid = old_parent_folderid;
  mp->new_parent_folderid = new_parent_folderid;
  psql_translation_add_cb(folder_moved_commit, free, mp);
}

void ppathstatus_fldr_deleted(psync_folderid_t folderid) {
  folder_tasks_t *ft;
  ft = get_folder_tasks(folderid, 0);
  if (ft) {
    free_folder_tasks(ft);
    while ((folderid = get_parent_folder(folderid)) != PSYNC_INVALID_FOLDERID) {
      ft = get_folder_tasks(folderid, 0);
      pdbg_assert(ft); // if assert fails, the problem is not the assert, don't
                  // change it to "if (!ft) break;"
      ft->child_task_cnt--;
      if (ft->child_task_cnt || ft->own_tasks)
        break;
      free_folder_tasks(ft);
    }
  }
  ppathstatus_del_from_parent_cache(folderid);
}

static void sync_data_free(sync_data_t *sd) {
  ptree_for_each_element_call_safe(sd->folder_tasks, folder_tasks_t, tree, free);
  free(sd);
}

static sync_data_t *get_sync_data(psync_syncid_t syncid, int create) {
  psync_tree *tr, **atr;
  sync_data_t *sd;
  tr = sync_data;
  atr = &sync_data;
  while (tr) {
    sd = ptree_element(tr, sync_data_t, tree);
    if (syncid < sd->syncid) {
      if (tr->left) {
        tr = tr->left;
      } else {
        atr = &tr->left;
        break;
      }
    } else if (syncid > sd->syncid) {
      if (tr->right) {
        tr = tr->right;
      } else {
        atr = &tr->right;
        break;
      }
    } else {
      return sd;
    }
  }
  if (!create) {
    return NULL;
  } else {
    size_t i;
    sd = malloc(sizeof(sync_data_t));
    sd->syncid = syncid;
    *atr = &sd->tree;
    ptree_added_at(&sync_data, tr, &sd->tree);
    psync_list_init(&sd->cache_free);
    psync_list_init(&sd->parent_cache_lru);
    for (i = 0; i < SYNC_PARENT_HASH_SIZE; i++)
      psync_list_init(&sd->parent_cache_hash[i]);
    for (i = 0; i < SYNC_PARENT_CACHE_SIZE; i++) {
      psync_list_add_tail(&sd->parent_cache_lru,
                          &sd->parent_cache_entries[i].list_lru);
      psync_list_add_tail(&sd->cache_free,
                          &sd->parent_cache_entries[i].list_hash);
    }
    sd->folder_tasks = PSYNC_TREE_EMPTY;
    return sd;
  }
}

static folder_tasks_t *
get_sync_folder_tasks(sync_data_t *sd, psync_folderid_t folderid, int create) {
  psync_tree *tr, **atr;
  folder_tasks_t *ft;
  tr = sd->folder_tasks;
  atr = &sd->folder_tasks;
  while (tr) {
    ft = ptree_element(tr, folder_tasks_t, tree);
    if (folderid < ft->folderid) {
      if (tr->left) {
        tr = tr->left;
      } else {
        atr = &tr->left;
        break;
      }
    } else if (folderid > ft->folderid) {
      if (tr->right) {
        tr = tr->right;
      } else {
        atr = &tr->right;
        break;
      }
    } else {
      return ft;
    }
  }
  if (create) {
    ft = malloc(sizeof(folder_tasks_t));
    *atr = &ft->tree;
    ptree_added_at(&sd->folder_tasks, tr, &ft->tree);
    ft->folderid = folderid;
    ft->child_task_cnt = 0;
    ft->own_tasks = 0;
    pdbg_logf(D_NOTICE, "marking folderid %lu in syncid %u as having (sub)tasks",
          (unsigned long)folderid, (unsigned)sd->syncid);
    return ft;
  } else {
    return NULL;
  }
}

static psync_folderid_t get_sync_parent_folder(sync_data_t *sd,
                                               psync_folderid_t folderid) {
  psync_sql_res *res;
  psync_uint_row row;
  parent_cache_entry_t *p;
  uint32_t h;
  if (folderid == 0)
    return PSYNC_INVALID_FOLDERID;
  h = hash_folderid(folderid) % SYNC_PARENT_HASH_SIZE;
  psync_list_for_each_element(p, &sd->parent_cache_hash[h],
                              parent_cache_entry_t,
                              list_hash) if (p->folderid == folderid) {
    psync_list_del(&p->list_lru);
    psync_list_add_tail(&sd->parent_cache_lru, &p->list_lru);
    return p->parentfolderid;
  }
  res = psql_query_nolock(
      "SELECT localparentfolderid FROM localfolder WHERE id=?");
  psql_bind_uint(res, 1, folderid);
  row = psql_fetch_int(res);
  if (unlikely(!row)) {
    pdbg_logf(D_WARNING, "can not find parent folder for localfolderid %lu",
          (unsigned long)folderid);
    psql_free(res);
    return PSYNC_INVALID_FOLDERID;
  }
  p = psync_list_remove_head_element(&sd->parent_cache_lru,
                                     parent_cache_entry_t, list_lru);
  psync_list_del(&p->list_hash);
  p->folderid = folderid;
  p->parentfolderid = row[0];
  psync_list_add_head(&sd->parent_cache_hash[h], &p->list_hash);
  psync_list_add_tail(&sd->parent_cache_lru, &p->list_lru);
  psql_free(res);
  return p->parentfolderid;
}

void ppath_syncfldr_task_added_locked(
    psync_syncid_t syncid, psync_folderid_t localfolderid) {
  sync_data_t *sd;
  folder_tasks_t *ft;
  //  pdbg_logf(D_NOTICE, "syncid %u localfolderid %lu", (unsigned)syncid, (unsigned
  //  long)localfolderid);
  sd = get_sync_data(syncid, 1);
  ft = get_sync_folder_tasks(sd, localfolderid, 1);
  if (ft->child_task_cnt || ft->own_tasks) {
    ft->own_tasks = 1;
    return;
  }
  ft->own_tasks = 1;
  while ((localfolderid = get_sync_parent_folder(sd, localfolderid)) !=
         PSYNC_INVALID_FOLDERID) {
    ft = get_sync_folder_tasks(sd, localfolderid, 1);
    ft->child_task_cnt++;
    if (ft->child_task_cnt > 1 || ft->own_tasks)
      break;
  }
}

void ppath_syncfldr_task_added(psync_syncid_t syncid,
                                              psync_folderid_t localfolderid) {
  psql_lock();
  ppathstatus_clear_sync_cache();
  ppath_syncfldr_task_added_locked(syncid, localfolderid);
  psql_unlock();
}

static void load_sync_tasks() {
  psync_sql_res *res;
  psync_uint_row row;
  res = psql_query_nolock(
      "SELECT syncid, localitemid FROM task WHERE type=?");
  psql_bind_uint(res, 1, PSYNC_DOWNLOAD_FILE);
  while ((row = psql_fetch_int(res)))
    ppath_syncfldr_task_added_locked(row[0], row[1]);
  psql_free(res);
  res = psql_query_nolock(
      "SELECT lf.syncid, lf.localparentfolderid FROM task t, localfile lf "
      "WHERE t.type=? AND t.localitemid=lf.id AND t.syncid=lf.syncid");
  psql_bind_uint(res, 1, PSYNC_UPLOAD_FILE);
  while ((row = psql_fetch_int(res)))
    ppath_syncfldr_task_added_locked(row[0], row[1]);
  psql_free(res);
}

static int local_folder_has_tasks(psync_syncid_t syncid,
                                  psync_folderid_t localfolderid) {
  psync_sql_res *res;
  psync_uint_row row;
  res = psql_query_nolock(
      "SELECT 1 FROM task WHERE type=? AND syncid=? AND localitemid=?");
  psql_bind_uint(res, 1, PSYNC_DOWNLOAD_FILE);
  psql_bind_uint(res, 2, syncid);
  psql_bind_uint(res, 3, localfolderid);
  row = psql_fetch_int(res);
  psql_free(res);
  if (row)
    return 1;
  res = psql_query_nolock(
      "SELECT 1 FROM localfile lf, task t WHERE lf.syncid=? AND "
      "lf.localparentfolderid=? AND lf.id=t.localitemid AND "
      "t.syncid=? AND t.type=?");
  psql_bind_uint(res, 1, syncid);
  psql_bind_uint(res, 2, localfolderid);
  psql_bind_uint(res, 3, syncid);
  psql_bind_uint(res, 4, PSYNC_UPLOAD_FILE);
  row = psql_fetch_int(res);
  psql_free(res);
  if (row)
    return 1;
  return 0;
}

static void free_sync_folder_tasks(sync_data_t *sd, folder_tasks_t *ft) {
  pdbg_logf(D_NOTICE, "marking folderid %lu from syncid %u as clean",
        (unsigned long)ft->folderid, (unsigned)sd->syncid);
  ptree_del(&sd->folder_tasks, &ft->tree);
  free(ft);
}

void ppathstatus_syncfldr_task_completed(
    psync_syncid_t syncid, psync_folderid_t localfolderid) {
  sync_data_t *sd;
  folder_tasks_t *ft;
  //  pdbg_logf(D_NOTICE, "syncid %u localfolderid %lu lfht %d", (unsigned)syncid,
  //  (unsigned long)localfolderid, local_folder_has_tasks(syncid,
  //  localfolderid));
  psql_lock();
  ppathstatus_clear_sync_cache();
  if (local_folder_has_tasks(syncid, localfolderid) ||
      !(sd = get_sync_data(syncid, 0)) ||
      !(ft = get_sync_folder_tasks(sd, localfolderid, 0))) {
    psql_unlock();
    return;
  }
  ft->own_tasks = 0;
  while (!ft->child_task_cnt && !ft->own_tasks) {
    free_sync_folder_tasks(sd, ft);
    localfolderid = get_sync_parent_folder(sd, localfolderid);
    if (localfolderid == PSYNC_INVALID_FOLDERID)
      break;
    ft = get_sync_folder_tasks(sd, localfolderid, 0);
    pdbg_assert(ft);
    pdbg_assert(ft->child_task_cnt);
    ft->child_task_cnt--;
  }
  psql_unlock();
}

void ppathstatus_syncfldr_delete(psync_syncid_t syncid) {
  sync_data_t *sd;
  psql_lock();
  sd = get_sync_data(syncid, 0);
  if (sd)
    ptree_del(&sync_data, &sd->tree);
  psql_unlock();
  if (sd)
    sync_data_free(sd);
}

static void sync_del_from_parent_cache(sync_data_t *sd,
                                       psync_folderid_t folderid) {
  parent_cache_entry_t *p;
  uint32_t h;
  h = hash_folderid(folderid) % SYNC_PARENT_HASH_SIZE;
  psync_list_for_each_element(p, &sd->parent_cache_hash[h],
                              parent_cache_entry_t,
                              list_hash) if (p->folderid == folderid) {
    psync_list_del(&p->list_lru);
    psync_list_add_head(&sd->parent_cache_lru, &p->list_lru);
    psync_list_del(&p->list_hash);
    psync_list_add_tail(&sd->cache_free, &p->list_hash);
    break;
  }
}

static void sync_folder_moved(psync_folderid_t folderid,
                              psync_syncid_t old_syncid,
                              psync_folderid_t old_parent_folderid,
                              psync_syncid_t new_syncid,
                              psync_folderid_t new_parent_folderid) {
  sync_data_t *sd;
  folder_tasks_t *pft;
  sd = get_sync_data(new_syncid, 1);
  pft = get_sync_folder_tasks(sd, new_parent_folderid, 1);
  pft->child_task_cnt++;
  while (pft->child_task_cnt == 1 && !pft->own_tasks &&
         (new_parent_folderid = get_sync_parent_folder(
              sd, new_parent_folderid)) != PSYNC_INVALID_FOLDERID) {
    pft = get_sync_folder_tasks(sd, new_parent_folderid, 1);
    pft->child_task_cnt++;
  }
  sd = get_sync_data(old_syncid, 0);
  pdbg_assert(sd);
  pft = get_sync_folder_tasks(sd, old_parent_folderid, 0);
  pdbg_assert(pft);
  pft->child_task_cnt--;
  while (!pft->child_task_cnt && !pft->own_tasks) {
    free_sync_folder_tasks(sd, pft);
    old_parent_folderid = get_sync_parent_folder(sd, old_parent_folderid);
    if (old_parent_folderid == PSYNC_INVALID_FOLDERID)
      break;
    pft = get_sync_folder_tasks(sd, old_parent_folderid, 0);
    pdbg_assert(pft);
    pft->child_task_cnt--;
  }
}

static void sync_folder_moved_commit(void *ptr) {
  sync_folder_moved_params_t *mp = (sync_folder_moved_params_t *)ptr;
  sync_folder_moved(mp->folderid, mp->old_syncid, mp->old_parent_folderid,
                    mp->new_syncid, mp->new_parent_folderid);
  free(mp);
}

void ppathstatus_syncfldr_moved(psync_folderid_t folderid,
                                         psync_syncid_t old_syncid,
                                         psync_folderid_t old_parent_folderid,
                                         psync_syncid_t new_syncid,
                                         psync_folderid_t new_parent_folderid) {
  sync_folder_moved_params_t *mp;
  sync_data_t *sd;
  if (old_parent_folderid == new_parent_folderid && old_syncid == new_syncid)
    return;
  sd = get_sync_data(old_syncid, 0);
  if (!sd)
    return;
  sync_del_from_parent_cache(sd, folderid);
  if (!get_folder_tasks(folderid, 0))
    return;
  mp = malloc(sizeof(sync_folder_moved_params_t));
  mp->folderid = folderid;
  mp->old_parent_folderid = old_parent_folderid;
  mp->new_parent_folderid = new_parent_folderid;
  mp->old_syncid = old_syncid;
  mp->new_syncid = new_syncid;
  psql_translation_add_cb(sync_folder_moved_commit, free, mp);
}

void ppathstatus_syncfldr_deleted(psync_syncid_t syncid,
                                           psync_folderid_t folderid) {
  sync_data_t *sd;
  folder_tasks_t *ft;
  if ((sd = get_sync_data(syncid, 0)) &&
      (ft = get_sync_folder_tasks(sd, folderid, 0))) {
    free_sync_folder_tasks(sd, ft);
    while ((folderid = get_sync_parent_folder(sd, folderid)) !=
           PSYNC_INVALID_FOLDERID) {
      ft = get_sync_folder_tasks(sd, folderid, 0);
      pdbg_assert(ft); // if assert fails, the problem is not the assert, don't
                  // change it to "if (!ft) break;"
      ft->child_task_cnt--;
      if (ft->child_task_cnt || ft->own_tasks)
        break;
      free_sync_folder_tasks(sd, ft);
    }
  }
  if (sd)
    sync_del_from_parent_cache(sd, folderid);
}

static inline int is_slash(char ch) { return ch == '/'; }

static inline int valid_last_char(char ch) { return is_slash(ch) || ch == 0; }

static psync_path_status_t rdunlock_return(psync_path_status_t st) {
  psql_rdunlock();
  return st;
}

static psync_path_status_t rdunlock_return_in_prog() {
  static const uint32_t requiredstatuses[] = {
      PSTATUS_COMBINE(PSTATUS_TYPE_RUN, PSTATUS_RUN_RUN),
      PSTATUS_COMBINE(PSTATUS_TYPE_ONLINE, PSTATUS_ONLINE_CONNECTING |
                                               PSTATUS_ONLINE_SCANNING |
                                               PSTATUS_ONLINE_ONLINE),
      PSTATUS_COMBINE(PSTATUS_TYPE_ACCFULL, PSTATUS_ACCFULL_QUOTAOK),
      PSTATUS_COMBINE(PSTATUS_TYPE_DISKFULL, PSTATUS_DISKFULL_OK)};
  psql_rdunlock();
  if (pstatus_ok_status_arr(requiredstatuses, ARRAY_SIZE(requiredstatuses)))
    return PSYNC_PATH_STATUS_IN_PROG;
  else
    return PSYNC_PATH_STATUS_PAUSED; // TODO: fix to return proper status
}

static psync_path_status_t
psync_path_status_drive_folder_locked(psync_folderid_t folderid) {
  if (get_folder_tasks(folderid, 0))
    return rdunlock_return_in_prog();
  psql_rdunlock();
  return PSYNC_PATH_STATUS_IN_SYNC;
}

#define HASH_ROUND()                                                           \
  a += n;                                                                      \
  a *= 0x5724c9d1;                                                             \
  b ^= n;                                                                      \
  b *= 0x6a511717;                                                             \
  c += n;                                                                      \
  c *= 0x76459457;                                                             \
  d ^= n;                                                                      \
  d *= 0x51a97a23;

static void comp_hash(const char *s, size_t len, uint32_t *out, uint64_t seed1,
                      uint64_t seed2) {
  uint32_t a, b, c, d, n;
  a = seed1 & 0xffffffffU;
  b = seed1 >> 32;
  c = seed2 & 0xffffffffU;
  d = seed2 >> 32;
  b ^= len;
  b *= 0x6a511717;
  c += len;
  c *= 0x76459457;
  while (len >= sizeof(uint32_t)) {
    n = *(const uint32_t *)s;
    s += sizeof(uint32_t);
    len -= sizeof(uint32_t);
    HASH_ROUND();
  }
  n = len << 24;
  switch (len) {
  case 3:
    n += 0xffffU * s[2];
  case 2:
    n += 0xffU * s[1];
  case 1:
    n += s[0];
    HASH_ROUND();
  }
  out[0] = a ^ (a >> 17);
  out[1] = b;
  out[2] = c ^ (c >> 15);
  out[3] = d;
}

static int move_encname_to_buff(psync_folderid_t folderid, char *buff,
                                size_t buff_size, const char *name,
                                size_t namelen) {
  pcrypto_textenc_t enc;
  char *encname;
  size_t len;
  if (unlikely(namelen >= buff_size))
    return -1;
  memcpy(buff, name, namelen);
  buff[namelen] = 0;
  enc = pcryptofolder_fldencoder_get(folderid);
  if (unlikely(psync_crypto_is_error(enc)))
    return -1;
  encname = pcryptofolder_fldencode_filename(enc, buff);
  pcryptofolder_fldencoder_release(folderid, enc);
  len = strlen(encname);
  if (unlikely(len >= sizeof(buff)))
    return -1;
  memcpy(buff, encname, len + 1);
  free(encname);
  return 0;
}

static psync_path_status_t psync_path_status_drive(const char *path,
                                                   size_t path_len) {
  char buff[2048];
  uint32_t hash[4], h;
  psync_fstask_folder_t *folder;
  path_cache_entry_t *ce;
  psync_sql_res *res;
  psync_uint_row row;
  psync_folderid_t folderid;
  uint64_t flags;
  size_t off, poff;
  const char *name;
  size_t namelen;
  int wrlocked, found;
  while (is_slash(*path)) {
    path++;
    path_len--;
  }
  wrlocked = 0;
  psql_rdlock();
  if (!get_folder_tasks(0, 0))
    return rdunlock_return(PSYNC_PATH_STATUS_IN_SYNC);
  if (!path_len)
    return psync_path_status_drive_folder_locked(0);
restart:
  poff = 0;
  folderid = 0;
  flags = ENTRY_FLAG_FOLDER;
  for (off = 0; off < path_len; off++)
    if (is_slash(path[off])) {
      if (off && is_slash(path[off - 1])) {
        poff = off + 1;
      } else {
        folder = psync_fstask_get_folder_tasks_rdlocked(folderid);
        if (folder) {
          if (unlikely(off - poff >= sizeof(buff)))
            return rdunlock_return(PSYNC_PATH_STATUS_IN_SYNC);
          if (likely((flags & ENTRY_FLAG_ENCRYPTED) == 0)) {
            memcpy(buff, path + poff, off - poff);
            buff[off - poff] = 0;
          } else {
            if (unlikely(move_encname_to_buff(folderid, buff, sizeof(buff),
                                              path + poff, off - poff)))
              return rdunlock_return(PSYNC_PATH_STATUS_IN_SYNC);
          }
          if (psync_fstask_find_mkdir(folder, buff, 0))
            return rdunlock_return_in_prog();
          if (psync_fstask_find_rmdir(folder, buff, 0))
            return rdunlock_return(PSYNC_PATH_STATUS_NOT_FOUND);
        }
        comp_hash(path + poff, off - poff, hash, folderid, drv_hash_seed);
        h = (hash[0] + hash[2]) % PATH_HASH_SIZE;
        found = 0;
        psync_list_for_each_element(
            ce, &path_cache_hash[h], path_cache_entry_t,
            list_hash) if (!memcmp(hash, ce->hash, sizeof(hash)) &&
                           (ce->flags & ENTRY_FLAG_FOLDER)) {
          if (wrlocked) {
            psync_list_del(&ce->list_lru);
            psync_list_add_tail(&path_cache_lru, &ce->list_lru);
          }
          folderid = ce->itemid;
          flags = ce->flags;
          found = 1;
          poff = off + 1;
          if (!get_folder_tasks(folderid, 0))
            return rdunlock_return(PSYNC_PATH_STATUS_IN_SYNC);
          break;
        }
        if (found)
          continue;
        res =
            psql_query_nolock("SELECT id, permissions, flags, userid FROM "
                                   "folder WHERE parentfolderid=? AND name=?");
        psql_bind_uint(res, 1, folderid);
        if (likely((flags & ENTRY_FLAG_ENCRYPTED) == 0)) {
          psql_bind_lstr(res, 2, path + poff, off - poff);
        } else {
          psql_free(res);
          if (unlikely(move_encname_to_buff(folderid, buff, sizeof(buff),
                                            path + poff, off - poff)))
            return rdunlock_return(PSYNC_PATH_STATUS_IN_SYNC);
          psql_bind_str(res, 2, buff);
        }
        row = psql_fetch_int(res);
        if (!row) {
          psql_free(res);
          return rdunlock_return(PSYNC_PATH_STATUS_NOT_FOUND);
        }
        if (!wrlocked) {
          psql_free(res);
          wrlocked = 1;
          if (psql_tryupgradeLock()) {
            psql_rdunlock();
            psql_lock();
          }
          goto restart;
        }
        folderid = row[0];
        flags = ENTRY_FLAG_FOLDER;
        if (row[2] & PSYNC_FOLDER_FLAG_ENCRYPTED)
          flags |= ENTRY_FLAG_ENCRYPTED;
        psql_free(res);
        ce = psync_list_remove_head_element(&path_cache_lru, path_cache_entry_t,
                                            list_lru);
        psync_list_add_tail(&path_cache_lru, &ce->list_lru);
        psync_list_del(&ce->list_hash);
        psync_list_add_tail(&path_cache_hash[h], &ce->list_hash);
        memcpy(ce->hash, hash, sizeof(hash));
        ce->itemid = folderid;
        ce->flags = flags;
        poff = off + 1;
        if (!get_folder_tasks(folderid, 0))
          return rdunlock_return(PSYNC_PATH_STATUS_IN_SYNC);
      }
    }
  if (poff == path_len)
    return psync_path_status_drive_folder_locked(folderid);
  folder = psync_fstask_get_folder_tasks_rdlocked(folderid);
  name = path + poff;
  namelen = path_len - poff;
  if (folder) {
    if (unlikely(flags & ENTRY_FLAG_ENCRYPTED)) {
      if (unlikely(move_encname_to_buff(folderid, buff, sizeof(buff),
                                        path + poff, path_len - poff)))
        return rdunlock_return(PSYNC_PATH_STATUS_IN_SYNC);
      name = buff;
      namelen = strlen(buff);
    }
    if (psync_fstask_find_mkdir(folder, name, 0))
      return rdunlock_return_in_prog();
    if (psync_fstask_find_creat(folder, name, 0))
      return rdunlock_return_in_prog();
  }
  // we do the hash with the unencrypted name
  comp_hash(path + poff, path_len - poff, hash, folderid, drv_hash_seed);
  h = (hash[0] + hash[2]) % PATH_HASH_SIZE;
  found = 0;
  psync_list_for_each_element(
      ce, &path_cache_hash[h], path_cache_entry_t,
      list_hash) if (!memcmp(hash, ce->hash, sizeof(hash))) {
    if (wrlocked) {
      psync_list_del(&ce->list_lru);
      psync_list_add_tail(&path_cache_lru, &ce->list_lru);
    }
    folderid = ce->itemid;
    flags = ce->flags;
    found = 1;
    break;
  }
  if (found) {
    if (flags & ENTRY_FLAG_FOLDER) {
      if (folder && psync_fstask_find_rmdir(folder, name, 0))
        return rdunlock_return(PSYNC_PATH_STATUS_NOT_FOUND);
      else
        return psync_path_status_drive_folder_locked(folderid);
    } else {
      if (folder && psync_fstask_find_unlink(folder, name, 0))
        return rdunlock_return(PSYNC_PATH_STATUS_NOT_FOUND);
      else
        return rdunlock_return(PSYNC_PATH_STATUS_IN_SYNC);
    }
  }
  if (unlikely(!folder && (flags & ENTRY_FLAG_ENCRYPTED))) {
    if (unlikely(move_encname_to_buff(folderid, buff, sizeof(buff), path + poff,
                                      path_len - poff)))
      return rdunlock_return(PSYNC_PATH_STATUS_IN_SYNC);
    name = buff;
    namelen = strlen(buff);
  }
  res = psql_query_nolock("SELECT id, permissions, flags, userid FROM "
                               "folder WHERE parentfolderid=? AND name=?");
  psql_bind_uint(res, 1, folderid);
  psql_bind_lstr(res, 2, name, namelen);
  row = psql_fetch_int(res);
  if (!row || (folder && psync_fstask_find_rmdir(folder, path + poff, 0))) {
    psql_free(res);
    if (folder && psync_fstask_find_unlink(folder, path + poff, 0))
      return rdunlock_return(PSYNC_PATH_STATUS_NOT_FOUND);
    res = psql_query_nolock(
        "SELECT id FROM file WHERE parentfolderid=? AND name=?");
    psql_bind_uint(res, 1, folderid);
    psql_bind_lstr(res, 2, name, namelen);
    row = psql_fetch_int(res);
    if (!row) {
      psql_free(res);
      return rdunlock_return(PSYNC_PATH_STATUS_NOT_FOUND);
    }
    if (!wrlocked) {
      psql_free(res);
      wrlocked = 1;
      if (psql_tryupgradeLock()) {
        psql_rdunlock();
        psql_lock();
      }
      goto restart;
    }
    folderid = row[0];
    flags &= ~ENTRY_FLAG_FOLDER;
    psql_free(res);
    ce = psync_list_remove_head_element(&path_cache_lru, path_cache_entry_t,
                                        list_lru);
    psync_list_add_tail(&path_cache_lru, &ce->list_lru);
    psync_list_del(&ce->list_hash);
    psync_list_add_tail(&path_cache_hash[h], &ce->list_hash);
    memcpy(ce->hash, hash, sizeof(hash));
    ce->itemid = folderid;
    ce->flags = flags;
    return rdunlock_return(PSYNC_PATH_STATUS_IN_SYNC);
  }
  if (!wrlocked) {
    psql_free(res);
    wrlocked = 1;
    if (psql_tryupgradeLock()) {
      psql_rdunlock();
      psql_lock();
    }
    goto restart;
  }
  folderid = row[0];
  flags = ENTRY_FLAG_FOLDER;
  psql_free(res);
  ce = psync_list_remove_head_element(&path_cache_lru, path_cache_entry_t,
                                      list_lru);
  psync_list_add_tail(&path_cache_lru, &ce->list_lru);
  psync_list_del(&ce->list_hash);
  psync_list_add_tail(&path_cache_hash[h], &ce->list_hash);
  memcpy(ce->hash, hash, sizeof(hash));
  ce->itemid = folderid;
  ce->flags = flags;
  return psync_path_status_drive_folder_locked(folderid);
}

static psync_path_status_t
psync_path_status_sync_folder_locked(psync_syncid_t syncid,
                                     psync_folderid_t folderid) {
  sync_data_t *sd = get_sync_data(syncid, 0);
  if (sd && get_sync_folder_tasks(sd, folderid, 0))
    return rdunlock_return_in_prog();
  psql_rdunlock();
  return PSYNC_PATH_STATUS_IN_SYNC;
}

#define SYNCID_SHIFT 40

static inline uint64_t combine_syncid_lf(psync_syncid_t syncid,
                                         psync_folderid_t localfolderid) {
  return localfolderid | ((uint64_t)syncid << SYNCID_SHIFT);
}

static inline psync_syncid_t extract_syncid(uint64_t combined) {
  return combined >> SYNCID_SHIFT;
}

static inline psync_folderid_t extract_localfolderid(uint64_t combined) {
  return combined & ((1ULL << SYNCID_SHIFT) - 1);
}

static int sync_file_in_progress(psync_syncid_t syncid,
                                 psync_folderid_t localfolderid,
                                 psync_fileid_t localfileid, const char *name,
                                 size_t namelen) {
  sync_data_t *sd;
  folder_tasks_t *ft;
  psync_sql_res *res;
  psync_uint_row row;
  sd = get_sync_data(syncid, 0);
  if (!sd)
    return 0;
  ft = get_sync_folder_tasks(sd, localfolderid, 0);
  if (!ft || !ft->own_tasks)
    return 0;
  res = psql_query_nolock("SELECT 1 FROM task WHERE type=? AND syncid=? "
                               "AND localitemid=? AND name=?");
  psql_bind_uint(res, 1, PSYNC_DOWNLOAD_FILE);
  psql_bind_uint(res, 2, syncid);
  psql_bind_uint(res, 3, localfolderid);
  psql_bind_lstr(res, 4, name, namelen);
  row = psql_fetch_int(res);
  psql_free(res);
  if (row)
    return 1;
  res = psql_query_nolock(
      "SELECT 1 FROM task WHERE type=? AND syncid=? AND localitemid=?");
  psql_bind_uint(res, 1, PSYNC_UPLOAD_FILE);
  psql_bind_uint(res, 2, syncid);
  psql_bind_uint(res, 3, localfileid);
  row = psql_fetch_int(res);
  psql_free(res);
  if (row)
    return 1;
  return 0;
}

static psync_path_status_t psync_path_status_sync(const char *path,
                                                  size_t path_len,
                                                  psync_folderid_t folderid,
                                                  psync_syncid_t syncid,
                                                  uint32_t sflags) {
  uint32_t hash[4], h;
  path_cache_entry_t *ce;
  psync_sql_res *res;
  psync_uint_row row;
  uint64_t flags;
  size_t off, poff;
  int wrlocked, found;
  while (is_slash(*path)) {
    path++;
    path_len--;
  }
  wrlocked = 0;
  psql_rdlock();
  if (!path_len)
    return psync_path_status_sync_folder_locked(syncid, 0);
restart:
  poff = 0;
  folderid = combine_syncid_lf(syncid, 0);
  flags = ENTRY_FLAG_FOLDER;
  for (off = 0; off < path_len; off++)
    if (is_slash(path[off])) {
      if (off && is_slash(path[off - 1])) {
        poff = off + 1;
      } else {
        if (psync_is_lname_to_ignore(path + poff, off - poff))
          return rdunlock_return(PSYNC_PATH_STATUS_IN_SYNC |
                                 PSYNC_PATH_STATUS_IS_IGNORED);
        comp_hash(path + poff, off - poff, hash, folderid, sync_hash_seed);
        h = (hash[0] + hash[2]) % PATH_HASH_SIZE;
        found = 0;
        psync_list_for_each_element(
            ce, &path_cache_hash[h], path_cache_entry_t,
            list_hash) if (!memcmp(hash, ce->hash, sizeof(hash)) &&
                           (ce->flags & ENTRY_FLAG_FOLDER) &&
                           extract_syncid(ce->itemid) == syncid) {
          if (wrlocked) {
            psync_list_del(&ce->list_lru);
            psync_list_add_tail(&path_cache_lru, &ce->list_lru);
          }
          folderid = ce->itemid;
          flags = ce->flags;
          found = 1;
          poff = off + 1;
          break;
        }
        if (found)
          continue;
        res =
            psql_query_nolock("SELECT id FROM localfolder WHERE syncid=? "
                                   "AND localparentfolderid=? AND name=?");
        psql_bind_uint(res, 1, syncid);
        psql_bind_uint(res, 2, extract_localfolderid(folderid));
        psql_bind_lstr(res, 3, path + poff, off - poff);
        row = psql_fetch_int(res);
        if (!row) {
          psql_free(res);
          return rdunlock_return_in_prog();
        }
        if (!wrlocked) {
          psql_free(res);
          wrlocked = 1;
          if (psql_tryupgradeLock()) {
            psql_rdunlock();
            psql_lock();
          }
          goto restart;
        }
        folderid = combine_syncid_lf(syncid, row[0]);
        flags = ENTRY_FLAG_FOLDER;
        psql_free(res);
        ce = psync_list_remove_head_element(&path_cache_lru, path_cache_entry_t,
                                            list_lru);
        psync_list_add_tail(&path_cache_lru, &ce->list_lru);
        psync_list_del(&ce->list_hash);
        psync_list_add_tail(&path_cache_hash[h], &ce->list_hash);
        memcpy(ce->hash, hash, sizeof(hash));
        ce->itemid = folderid;
        ce->flags = flags;
        poff = off + 1;
      }
    }
  if (poff == path_len)
    return psync_path_status_sync_folder_locked(
        syncid, extract_localfolderid(folderid));
  if (psync_is_lname_to_ignore(path + poff, path_len - poff))
    return rdunlock_return(PSYNC_PATH_STATUS_IN_SYNC |
                           PSYNC_PATH_STATUS_IS_IGNORED);
  comp_hash(path + poff, path_len - poff, hash, folderid, sync_hash_seed);
  h = (hash[0] + hash[2]) % PATH_HASH_SIZE;
  found = 0;
  psync_list_for_each_element(
      ce, &path_cache_hash[h], path_cache_entry_t,
      list_hash) if (!memcmp(hash, ce->hash, sizeof(hash)) &&
                     extract_syncid(ce->itemid) == syncid) {
    if (wrlocked) {
      psync_list_del(&ce->list_lru);
      psync_list_add_tail(&path_cache_lru, &ce->list_lru);
    }
    folderid = ce->itemid;
    flags = ce->flags;
    found = 1;
    break;
  }
  if (found) {
    if (flags & ENTRY_FLAG_FOLDER)
      return psync_path_status_sync_folder_locked(
          syncid, extract_localfolderid(folderid));
    else if (flags & ENTRY_FLAG_PROG)
      return rdunlock_return_in_prog();
    else
      return rdunlock_return(PSYNC_PATH_STATUS_IN_SYNC);
  }
  res = psql_query_nolock("SELECT id FROM localfolder WHERE syncid=? AND "
                               "localparentfolderid=? AND name=?");
  psql_bind_uint(res, 1, syncid);
  psql_bind_uint(res, 2, extract_localfolderid(folderid));
  psql_bind_lstr(res, 3, path + poff, path_len - poff);
  if ((row = psql_fetch_int(res))) {
    folderid = row[0];
    psql_free(res);
    if (!wrlocked) {
      wrlocked = 1;
      if (psql_tryupgradeLock()) {
        psql_rdunlock();
        psql_lock();
      }
      goto restart;
    }
    ce = psync_list_remove_head_element(&path_cache_lru, path_cache_entry_t,
                                        list_lru);
    psync_list_add_tail(&path_cache_lru, &ce->list_lru);
    psync_list_del(&ce->list_hash);
    psync_list_add_tail(&path_cache_hash[h], &ce->list_hash);
    memcpy(ce->hash, hash, sizeof(hash));
    ce->itemid = combine_syncid_lf(syncid, folderid);
    ce->flags = ENTRY_FLAG_FOLDER;
    return psync_path_status_sync_folder_locked(syncid, folderid);
  }
  psql_free(res);
  res = psql_query_nolock("SELECT id FROM localfile WHERE syncid=? AND "
                               "localparentfolderid=? AND name=?");
  psql_bind_uint(res, 1, syncid);
  psql_bind_uint(res, 2, extract_localfolderid(folderid));
  psql_bind_lstr(res, 3, path + poff, path_len - poff);
  if ((row = psql_fetch_int(res))) {
    flags = row[0];
    psql_free(res);
    if (!wrlocked) {
      wrlocked = 1;
      if (psql_tryupgradeLock()) {
        psql_rdunlock();
        psql_lock();
      }
      goto restart;
    }
    ce = psync_list_remove_head_element(&path_cache_lru, path_cache_entry_t,
                                        list_lru);
    psync_list_add_tail(&path_cache_lru, &ce->list_lru);
    psync_list_del(&ce->list_hash);
    psync_list_add_tail(&path_cache_hash[h], &ce->list_hash);
    memcpy(ce->hash, hash, sizeof(hash));
    ce->itemid = combine_syncid_lf(syncid, flags);
    ce->flags = sync_file_in_progress(syncid, extract_localfolderid(folderid),
                                      flags, path + poff, path_len - poff)
                    ? ENTRY_FLAG_PROG
                    : 0;
    if (ce->flags & ENTRY_FLAG_PROG)
      return rdunlock_return_in_prog();
    else
      return rdunlock_return(PSYNC_PATH_STATUS_IN_SYNC);
  }
  psql_free(res);
  return rdunlock_return_in_prog();
}

static int psync_path_is_prefix_of(const char *prefix, size_t prefix_len,
                                   const char **ppath, size_t *ppath_len) {
  const char *path = *ppath;
  size_t path_len = *ppath_len;
  while (1) {
    while (prefix_len && path_len && !is_slash(*prefix) && *prefix == *path) {
      prefix++;
      path++;
      prefix_len--;
      path_len--;
    }
    if (!path_len || !prefix_len)
      break;
    if (is_slash(*prefix) != is_slash(*path))
      return 0;
    if (is_slash(*prefix)) {
      do {
        prefix_len--;
        prefix++;
      } while (prefix_len && is_slash(*prefix));
      do {
        path_len--;
        path++;
      } while (path_len && is_slash(*path));
      if (!prefix_len) {
        *ppath = path;
        *ppath_len = path_len;
        return 1;
      } else if (!path_len)
        return 0;
      continue;
    }
    return 0;
  }
  if (!prefix_len && valid_last_char(*path)) {
    *ppath = path;
    *ppath_len = path_len;
    return 1;
  } else {
    return 0;
  }
}

psync_path_status_t ppathstatus_get(const char *path) {
  char *dp;
  path_sync_list_t *sn;
  size_t i, len;
  len = strlen(path);
  if (drive_path) {
    if (len >= drive_path_len && !memcmp(drive_path, path, drive_path_len) &&
        valid_last_char(path[drive_path_len]))
      return psync_path_status_drive(path + drive_path_len,
                                     len - drive_path_len);
  } else {
    dp = psync_fs_getmountpoint();
    if (dp) {
      // assign the len before the mutex, so we use it as a barrier
      drive_path_len = strlen(dp);
      psql_lock();
      if (!drive_path) {
        drive_path = dp;
        dp = NULL;
      }
      psql_unlock();
      free(dp);
      if (len >= drive_path_len && !memcmp(drive_path, path, drive_path_len) &&
          valid_last_char(path[drive_path_len]))
        return psync_path_status_drive(path + drive_path_len,
                                       len - drive_path_len);
    }
  }
  sn = syncs;
  if (!sn) {
    psql_rdlock();
    sn = syncs;
    psql_rdunlock();
    if (!sn)
      goto slower_check;
  }
  for (i = 0; i < sn->sync_cnt; i++)
    if (sn->syncs[i].path_len <= len &&
        !memcmp(sn->syncs[i].path, path, sn->syncs[i].path_len) &&
        valid_last_char(path[sn->syncs[i].path_len]))
      return psync_path_status_sync(
          path + sn->syncs[i].path_len, len - sn->syncs[i].path_len,
          sn->syncs[i].folderid, sn->syncs[i].syncid, sn->syncs[i].flags);
slower_check:
  if (drive_path &&
      psync_path_is_prefix_of(drive_path, drive_path_len, &path, &len))
    return psync_path_status_drive(path, len);
  sn = syncs;
  if (sn)
    for (i = 0; i < sn->sync_cnt; i++)
      if (sn->syncs[i].path_len <= len &&
          psync_path_is_prefix_of(sn->syncs[i].path, sn->syncs[i].path_len,
                                  &path, &len))
        return psync_path_status_sync(path, len, sn->syncs[i].folderid,
                                      sn->syncs[i].syncid, sn->syncs[i].flags);
  return PSYNC_PATH_STATUS_NOT_OURS;
}
