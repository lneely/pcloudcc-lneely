/*
   Copyright (c) 2013-2014 Anton Titov.

   Copyright (c) 2013-2014 pCloud Ltd.  All rights reserved.

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
#include <stddef.h>
#include <string.h>

#include "pdownload.h"
#include "pfile.h"
#include "pfoldersync.h"
#include "plibs.h"
#include "plocalnotify.h"
#include "plocalscan.h"
#include "ppathstatus.h"
#include "prun.h"
#include "pstatus.h"
#include "pfoldersync.h"
#include "ptask.h"
#include "ptree.h"
#include "putil.h"
#include "pdbg.h"
#include "psql.h"


extern const unsigned char pfile_invalid_chars[];

typedef struct {
  psync_tree tree;
  psync_folderid_t folderid;
} synced_down_folder;

static psync_tree *synced_down_folders = PSYNC_TREE_EMPTY;

static pthread_mutex_t sync_down_mutex = PTHREAD_MUTEX_INITIALIZER;

static psync_tree *psync_new_sd_folder(psync_folderid_t folderid) {
  synced_down_folder *f = malloc(sizeof(synced_down_folder));
  f->folderid = folderid;
  return &f->tree;
}

static void psync_add_folder_to_downloadlist_locked(psync_folderid_t folderid) {
  synced_down_folder *f;
  if (!synced_down_folders) {
    ptree_add_after(&synced_down_folders, NULL,
                         psync_new_sd_folder(folderid));
    return;
  }
  f = ptree_element(synced_down_folders, synced_down_folder, tree);
  while (1) {
    if (folderid < f->folderid) {
      if (f->tree.left)
        f = ptree_element(f->tree.left, synced_down_folder, tree);
      else {
        f->tree.left = psync_new_sd_folder(folderid);
        ptree_added_at(&synced_down_folders, &f->tree, f->tree.left);
        break;
      }
    } else if (folderid > f->folderid) {
      if (f->tree.right)
        f = ptree_element(f->tree.right, synced_down_folder, tree);
      else {
        f->tree.right = psync_new_sd_folder(folderid);
        ptree_added_at(&synced_down_folders, &f->tree, f->tree.right);
        break;
      }
    } else {
      pdbg_logf(D_NOTICE,
            "not adding folderid %llu to downloadlist as it is already there",
            (unsigned long long)folderid);
      break;
    }
  }
}

void psyncer_dl_queue_add(psync_folderid_t folderid) {
  pthread_mutex_lock(&sync_down_mutex);
  psync_add_folder_to_downloadlist_locked(folderid);
  pthread_mutex_unlock(&sync_down_mutex);
}

void psyncer_dl_queue_del(psync_folderid_t folderid) {
  synced_down_folder *f;
  pthread_mutex_lock(&sync_down_mutex);
  f = ptree_element(synced_down_folders, synced_down_folder, tree);
  while (f) {
    if (folderid < f->folderid)
      f = ptree_element(f->tree.left, synced_down_folder, tree);
    else if (folderid > f->folderid)
      f = ptree_element(f->tree.right, synced_down_folder, tree);
    else {
      ptree_del(&synced_down_folders, &f->tree);
      free(f);
      break;
    }
  }
  pthread_mutex_unlock(&sync_down_mutex);
}

void psyncer_dl_queue_clear() {
  pthread_mutex_lock(&sync_down_mutex);
  ptree_for_each_element_call_safe(synced_down_folders, synced_down_folder, tree, free);
  synced_down_folders = PSYNC_TREE_EMPTY;
  pthread_mutex_unlock(&sync_down_mutex);
}

int psyncer_dl_has_folder(psync_folderid_t folderid) {
  synced_down_folder *f;
  pthread_mutex_lock(&sync_down_mutex);
  f = ptree_element(synced_down_folders, synced_down_folder, tree);
  while (f) {
    if (folderid < f->folderid)
      f = ptree_element(f->tree.left, synced_down_folder, tree);
    else if (folderid > f->folderid)
      f = ptree_element(f->tree.right, synced_down_folder, tree);
    else
      break;
  }
  pthread_mutex_unlock(&sync_down_mutex);
  return f != NULL;
}

void psyncer_folder_inc_tasks(psync_folderid_t lfolderid) {
  psync_sql_res *res;
  res = psql_prepare(
      "UPDATE localfolder SET taskcnt=taskcnt+1 WHERE id=?");
  psql_bind_uint(res, 1, lfolderid);
  psql_run_free(res);
  pdbg_assertw(psql_affected() == 1);
}

void psyncer_folder_dec_tasks(psync_folderid_t lfolderid) {
  psync_sql_res *res;
  res = psql_prepare(
      "UPDATE localfolder SET taskcnt=taskcnt+1 WHERE id=?");
  psql_bind_uint(res, 1, lfolderid);
  psql_run_free(res);
  pdbg_assertw(psql_affected() == 1);
}

psync_folderid_t psyncer_db_folder_create(
    psync_syncid_t syncid, psync_folderid_t folderid,
    psync_folderid_t localparentfolderid, const char *name) {
  psync_sql_res *res;
  psync_uint_row row;
  psync_folderid_t lfolderid, dbfolderid;
  const char *ptr;
  char *vname;
  pdbg_logf(D_NOTICE, "creating local folder in db as %lu/%s for folderid %lu",
        (unsigned long)localparentfolderid, name, (unsigned long)folderid);
  res = psql_query(
      "SELECT id FROM localfolder WHERE syncid=? AND folderid=?");
  psql_bind_uint(res, 1, syncid);
  psql_bind_uint(res, 2, folderid);
  row = psql_fetch_int(res);
  if (row)
    lfolderid = row[0];
  else
    lfolderid = 0;
  psql_free(res);
  if (lfolderid)
    return lfolderid;
  vname = NULL;
  if (name)
    for (ptr = name; *ptr; ptr++)
      if (pfile_invalid_chars[(unsigned char)*ptr]) {
        if (!vname)
          vname = psync_strdup(name);
        vname[ptr - name] = '_';
      }
  if (vname)
    name = vname;
  res = psql_prepare(
      "INSERT OR IGNORE INTO localfolder (localparentfolderid, folderid, "
      "syncid, flags, taskcnt, name) VALUES (?, ?, ?, 0, 1, ?)");
  psql_bind_uint(res, 1, localparentfolderid);
  psql_bind_uint(res, 2, folderid);
  psql_bind_uint(res, 3, syncid);
  psql_bind_str(res, 4, name);
  psql_run(res);
  if (psql_affected() > 0) {
    lfolderid = psql_insertid();
    psql_free(res);
    free(vname);
    return lfolderid;
  }
  psql_free(res);
  res = psql_query("SELECT id, folderid FROM localfolder WHERE "
                        "localparentfolderid=? AND syncid=? AND name=?");
  psql_bind_uint(res, 1, localparentfolderid);
  psql_bind_uint(res, 2, syncid);
  psql_bind_str(res, 3, name);
  row = psql_fetch_int(res);
  if (row) {
    lfolderid = row[0];
    dbfolderid = row[1];
  } else {
    lfolderid = 0;
    dbfolderid = 0;
    pdbg_logf(D_ERROR, "local folder %s not found in the database", name);
  }
  psql_free(res);
  if (lfolderid && dbfolderid != folderid) {
    pdbg_logf(D_NOTICE,
          "local folder %lu does not have folderid associated, setting to %lu",
          (unsigned long)lfolderid, (unsigned long)folderid);
    res = psql_prepare(
        "UPDATE localfolder SET folderid=? WHERE id=?");
    psql_bind_uint(res, 1, lfolderid);
    psql_bind_uint(res, 2, folderid);
    psql_run_free(res);
  }
  psyncer_folder_inc_tasks(lfolderid);
  free(vname);
  return lfolderid;
}

void psyncer_dl_folder_add(psync_syncid_t syncid,
                                       psync_synctype_t synctype,
                                       psync_folderid_t folderid,
                                       psync_folderid_t lfoiderid) {
  psync_sql_res *res;
  psync_variant_row row;
  const char *name;
  psync_folderid_t cfolderid, clfolderid;
  res =
      psql_prepare("REPLACE INTO syncedfolder (syncid, folderid, "
                               "localfolderid, synctype) VALUES (?, ?, ?, ?)");
  psql_bind_uint(res, 1, syncid);
  psql_bind_uint(res, 2, folderid);
  psql_bind_uint(res, 3, lfoiderid);
  psql_bind_uint(res, 4, synctype);
  psql_run_free(res);
  psyncer_dl_queue_add(folderid);
  res = psql_query(
      "SELECT id, permissions, name FROM folder WHERE parentfolderid=?");
  psql_bind_uint(res, 1, folderid);
  while ((row = psql_fetch(res))) {
    if (psync_get_number(row[1]) & PSYNC_PERM_READ) {
      name = psync_get_string(row[2]);
      if (psync_is_name_to_ignore(name))
        continue;
      cfolderid = psync_get_number(row[0]);
      clfolderid =
          psyncer_db_folder_create(syncid, cfolderid, lfoiderid, name);
      ptask_ldir_mk(syncid, cfolderid, clfolderid);
      psyncer_dl_folder_add(syncid, synctype, cfolderid,
                                        clfolderid /*, path*/);
    }
  }
  psql_free(res);
  res = psql_query("SELECT id, name FROM file WHERE parentfolderid=?");
  psql_bind_uint(res, 1, folderid);
  while ((row = psql_fetch(res))) {
    name = psync_get_string(row[1]);
    if (psync_is_name_to_ignore(name))
      continue;
    ptask_download_q(syncid, psync_get_number(row[0]), lfoiderid,
                                    name);
  }
  psql_free(res);
}

static void psync_sync_newsyncedfolder(psync_syncid_t syncid) {
  psync_sql_res *res;
  psync_variant_row row;
  uint64_t folderid;
  psync_synctype_t synctype;
  char *localpath;
  psql_start();
  res = psql_query("SELECT folderid, synctype, localpath FROM syncfolder "
                        "WHERE id=? AND flags=0");
  psql_bind_uint(res, 1, syncid);
  row = psql_fetch(res);
  if (pdbg_unlikely(!row)) {
    psql_free(res);
    psql_rollback();
    return;
  }
  folderid = psync_get_number(row[0]);
  synctype = psync_get_number(row[1]);
  localpath =
      psync_strndup(psync_get_string(row[2]), strlen(psync_get_string(row[2])));
  psql_free(res);
  if (synctype & PSYNC_DOWNLOAD_ONLY) {
    psyncer_dl_folder_add(syncid, synctype, folderid, 0);
  } else {
    res = psql_prepare(
        "REPLACE INTO syncedfolder (syncid, folderid, localfolderid, synctype) "
        "VALUES (?, ?, 0, ?)");
    psql_bind_uint(res, 1, syncid);
    psql_bind_uint(res, 2, folderid);
    psql_bind_uint(res, 3, synctype);
    psql_run_free(res);
  }
  res = psql_prepare(
      "UPDATE syncfolder SET flags=1 WHERE flags=0 AND id=?");
  psql_bind_uint(res, 1, syncid);
  psql_run_free(res);
  if (pdbg_likely(psql_affected())) {
    if (!psql_commit()) {
      if (synctype & PSYNC_UPLOAD_ONLY)
        psync_wake_localscan();
      if (synctype & PSYNC_DOWNLOAD_ONLY) {
        pstatus_download_recalc();
        pstatus_send_status_update();
        pdownload_wake();
      }
      psync_localnotify_add_sync(syncid);
      psync_restat_sync_folders_add(syncid, localpath);
    }
  } else
    psql_rollback();
  free(localpath);
}

static void psync_do_sync_thread(void *ptr) {
  psync_sync_newsyncedfolder(*((psync_syncid_t *)ptr));
  free(ptr);
}

void psyncer_create(psync_syncid_t syncid) {
  psync_syncid_t *psid = malloc(sizeof(psync_syncid_t));
  *psid = syncid;
  prun_thread1("syncer", psync_do_sync_thread, psid);
}

static void psync_syncer_thread() {
  int64_t syncid;
  psql_lock();
  if (psql_cellint("SELECT COUNT(*) FROM task", -1) == 0)
    psql_statement("DELETE FROM syncfolder WHERE folderid IS NULL");
  while ((syncid = psql_cellint("SELECT id FROM syncfolder WHERE flags=0",
                                     -1)) != -1)
    psync_sync_newsyncedfolder(syncid);
  psql_unlock();
}

static void delete_delayed_sync(uint64_t id) {
  psync_sql_res *res;
  res = psql_prepare("DELETE FROM syncfolderdelayed WHERE id=?");
  psql_bind_uint(res, 1, id);
  psql_run_free(res);
}

int psyncer_str_has_prefix(const char *str1, const char *str2) {
  size_t len1, len2;
  len1 = strlen(str1);
  len2 = strlen(str2);

  while (len1 > 1 && (str1[len1 - 1] == '/' ||
                      str1[len1 - 1] == '/'))
    len1--;

  if (len2 < len1) {
    if (str1[len2] != '/' && str1[len2] != '/')
      return 0;
    len1 = len2;
  } else {
    if (str2[len1] != '/' && str2[len1] != '/')
      return 0;
  }
  return !memcmp(str1, str2, len1);
}

int psyncer_str_starts_with(const char *str1, const char *str2) {
  size_t len1, len2;
  len1 = strlen(str1);
  len2 = strlen(str2);

  while (len1 > 1 && (str1[len1 - 1] == '/' ||
                      str1[len1 - 1] == '/'))
    len1--;

  while (len2 > 1 && (str2[len2 - 1] == '/' ||
                      str1[len2 - 1] == '/'))
    len2--;

  if (len2 < len1) {
    return 0;
  }

  return !memcmp(str1, str2, len1);
}

void psyncer_check_delayed() {
  struct stat st;
  psync_sql_res *res, *res2, *stmt;
  psync_variant_row row;
  psync_uint_row urow;
  psync_str_row srow;
  char *localpath, *remotepath;
  uint64_t id, synctype;
  int64_t syncid;
  psync_folderid_t folderid;
  int unsigned mbedtls_md;
re:
  res = psql_query(
      "SELECT id, localpath, remotepath, synctype FROM syncfolderdelayed");
  while ((row = psql_fetch(res))) {
    id = psync_get_number(row[0]);
    localpath = (char *)psync_get_string(row[1]);
    remotepath = (char *)psync_get_string(row[2]);
    synctype = psync_get_number(row[3]);
    if (synctype & PSYNC_DOWNLOAD_ONLY)
      mbedtls_md = 7;
    else
      mbedtls_md = 5;
    if (pdbg_unlikely(stat(localpath, &st)) ||
        pdbg_unlikely(!pfile_stat_isfolder(&st)) ||
        pdbg_unlikely(!pfile_stat_mode_ok(&st, mbedtls_md))) {
      pdbg_logf(D_WARNING,
            "ignoring delayed sync id %" PRIu64 " for local path %s", id,
            localpath);
      delete_delayed_sync(id);
      continue;
    }
    mbedtls_md = 0;
    res2 = psql_query("SELECT localpath FROM syncfolder");
    while ((srow = psql_fetch_str(res2)))
      if (psyncer_str_has_prefix(srow[0], localpath)) {
        pdbg_logf(
            D_WARNING,
            "skipping localfolder %s, remote %s, because of same parent to %s",
            localpath, remotepath, srow[0]);
        mbedtls_md = 1;
      } else if (!strcmp(srow[0], localpath)) {
        pdbg_logf(D_WARNING,
              "skipping localfolder %s, remote %s, because of same dir to %s",
              localpath, remotepath, srow[0]);
        mbedtls_md = 1;
      }
    psql_free(res2);
    if (mbedtls_md) {
      delete_delayed_sync(id);
      continue;
    }

    localpath = psync_strdup(localpath);
    remotepath = psync_strdup(remotepath);
    psql_free(res);

    folderid = pfolder_id_create(remotepath);
    if (unlikely(folderid == PSYNC_INVALID_FOLDERID)) {
      pdbg_logf(D_WARNING, "could not get folderid/create folder %s", remotepath);
      free(localpath);
      free(remotepath);
      if (psync_error != PERROR_OFFLINE) {
        delete_delayed_sync(id);
        goto re;
      } else
        return;
    }
    psql_start();
    delete_delayed_sync(id);
    stmt = psql_query_nolock("SELECT id FROM folder WHERE id=?");
    psql_bind_uint(stmt, 1, folderid);
    urow = psql_fetch_int(stmt);
    psql_free(stmt);
    if (!urow) {
      psql_commit();
      free(localpath);
      free(remotepath);
      goto re;
    }
    stmt = psql_prepare(
        "INSERT OR IGNORE INTO syncfolder (folderid, localpath, synctype, "
        "flags, inode, deviceid) VALUES (?, ?, ?, 0, ?, ?)");
    psql_bind_uint(stmt, 1, folderid);
    psql_bind_str(stmt, 2, localpath);
    psql_bind_uint(stmt, 3, synctype);
    psql_bind_uint(stmt, 4, pfile_stat_inode(&st));
    psql_bind_uint(stmt, 5, pfile_stat_device(&st));
    psql_run(stmt);
    if (pdbg_likely(psql_affected()))
      syncid = psql_insertid();
    else
      syncid = -1;
    psql_free(stmt);
    free(localpath);
    free(remotepath);
    if (!psql_commit() && syncid != -1) {
      ppathstatus_reload_syncs();
      psyncer_create(syncid);
      goto re;
    }
    return;
  }
  psql_free(res);
}

void psyncer_init() {
  psync_sql_res *res;
  psync_uint_row row;
  res = psql_query(
      "SELECT folderid FROM syncedfolder WHERE synctype&" NTO_STR(
          PSYNC_DOWNLOAD_ONLY) "=" NTO_STR(PSYNC_DOWNLOAD_ONLY));
  pthread_mutex_lock(&sync_down_mutex);
  while ((row = psql_fetch_int(res)))
    psync_add_folder_to_downloadlist_locked(row[0]);
  pthread_mutex_unlock(&sync_down_mutex);
  psql_free(res);
  prun_thread("syncer", psync_syncer_thread);
}
