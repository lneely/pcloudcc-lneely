/*
  Copyright (c) 2013 Anton Titov.

  Copyright (c) 2013 pCloud Ltd.  All rights reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met: Redistributions of source code must retain the above
  copyright notice, this list of conditions and the following
  disclaimer.  Redistributions in binary form must reproduce the above
  copyright notice, this list of conditions and the following
  disclaimer in the documentation and/or other materials provided with
  the distribution.  Neither the name of pCloud Ltd nor the names of
  its contributors may be used to endorse or promote products derived
  from this software without specific prior written permission.

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

#include <errno.h>
#include <pthread.h>
#include <stddef.h>
#include <sys/stat.h>

#include "pqevent.h"
#include "pdownload.h"
#include "pfoldersync.h"
#include "plibs.h"
#include "plocalscan.h"
#include "pnetlibs.h"
#include "pp2p.h"
#include "ppathstatus.h"
#include "prun.h"
#include "psys.h"
#include "pstatus.h"
#include "pfoldersync.h"
#include "ptask.h"
#include "ptimer.h"
#include "pupload.h"
#include "psql.h"
#include "ppath.h"
#include "pfile.h"

extern const unsigned char pfile_invalid_chars[];
pstatus_t psync_status;

typedef struct {
  psync_list list;
  psync_fileid_t fileid;
  psync_syncid_t syncid;
  uint16_t stop;
  uint16_t started; // if set, means that real download is in progress (after
                    // P2P checks, checksum checks and so on)
  unsigned char schecksum[PSYNC_HASH_DIGEST_HEXLEN];
} download_list_t;

typedef struct {
  uint64_t taskid;
  download_list_t dwllist;
  char *localpath;
  char *localname;
  char *tmpname;
  psync_file_lock_t *lock;
  uint64_t size;
  uint64_t downloadedsize;
  uint64_t localsize;
  uint64_t hash;
  time_t crtime;
  time_t mtime;
  psync_folderid_t localfolderid;
  unsigned char checksum[PSYNC_HASH_DIGEST_HEXLEN];
  char indwllist;
  char localexists;
  char filename[];
} download_task_t;

static pthread_mutex_t download_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t download_cond = PTHREAD_COND_INITIALIZER;
static unsigned long download_wakes = 0;
static const uint32_t requiredstatuses[] = {
    PSTATUS_COMBINE(PSTATUS_TYPE_AUTH, PSTATUS_AUTH_PROVIDED),
    PSTATUS_COMBINE(PSTATUS_TYPE_RUN, PSTATUS_RUN_RUN),
    PSTATUS_COMBINE(PSTATUS_TYPE_ONLINE, PSTATUS_ONLINE_ONLINE)};

static unsigned long started_downloads = 0;
static unsigned long current_downloads_waiters = 0;
static pthread_mutex_t current_downloads_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t current_downloads_cond = PTHREAD_COND_INITIALIZER;

static psync_list downloads = PSYNC_LIST_STATIC_INIT(downloads);

static void task_wait_no_downloads() {
  pthread_mutex_lock(&current_downloads_mutex);
  while (started_downloads) {
    current_downloads_waiters++;
    pthread_cond_wait(&current_downloads_cond, &current_downloads_mutex);
    current_downloads_waiters--;
  }
  pthread_mutex_unlock(&current_downloads_mutex);
}

static int task_mkdir(const char *path) {
  int err;
  while (1) {
    if (likely(!mkdir(path, PSYNC_DEFAULT_POSIX_FOLDER_MODE))) { // don't change to likely_log, as it may
                                      // overwrite psync_fs_err;
      psync_set_local_full(0);
      return 0;
    }
    err = errno;
    pdbg_logf(D_WARNING, "mkdir of %s failed, errno=%d", path, (int)err);
    if (err == ENOSPC || err == EDQUOT) {
      psync_set_local_full(1);
      psys_sleep_milliseconds(PSYNC_SLEEP_ON_DISK_FULL);
    } else {
      psync_set_local_full(0);
      if (err == ENOENT)
        return 0; // do we have a choice? the user deleted the directory
      else if (err == EEXIST) {
        struct stat st;
        if (stat(path, &st)) {
          pdbg_logf(D_BUG,
                "mkdir failed with EEXIST, but stat returned error. race?");
          return -1;
        }
        if (pfile_stat_isfolder(&st))
          return 0;
        if (psync_rename_conflicted_file(path))
          return -1;
      } else
        return -1;
    }
    pstatus_wait_statuses_arr(requiredstatuses, ARRAY_SIZE(requiredstatuses));
  }
}

static int task_rmdir(const char *path) {
  task_wait_no_downloads();
  if (pdbg_likely(!psync_rmdir_with_trashes(path)))
    return 0;
  if (errno == EBUSY || errno == EROFS)
    return -1;
  psync_wake_localscan();
  return 0;
}

static void do_move(void *ptr, ppath_stat *st) {
  const char **arr;
  char *oldpath, *newpath;
  arr = (const char **)ptr;
  oldpath = psync_strcat(arr[0], st->name, NULL);
  newpath = psync_strcat(arr[1], st->name, NULL);
  pfile_rename(oldpath, newpath);
  free(newpath);
  free(oldpath);
}

static int move_folder_contents(const char *oldpath, const char *newpath) {
  const char *arr[2];
  arr[0] = oldpath;
  arr[1] = newpath;
  ppath_ls(oldpath, do_move, (void *)arr);
  return psync_rmdir_with_trashes(oldpath);
}

static int task_renamedir(const char *oldpath, const char *newpath) {
  while (1) {
    if (pdbg_likely(!pfile_rename(oldpath, newpath))) {
      psync_set_local_full(0);
      return 0;
    }
    if (errno == ENOSPC || errno == EDQUOT) {
      psync_set_local_full(1);
      psys_sleep_milliseconds(PSYNC_SLEEP_ON_DISK_FULL);
    } else {
      psync_set_local_full(0);
      if (errno == EBUSY || errno == EROFS)
        return -1;
      if (errno == ENOENT)
        return 0;
      else if (errno == EEXIST || errno == ENOTEMPTY ||
               errno == ENOTDIR) {
        struct stat st;
        if (stat(newpath, &st)) {
          pdbg_logf(D_BUG,
                "rename failed with EEXIST, but stat returned error. race?");
          return -1;
        }
        if (pfile_stat_isfolder(&st))
          return move_folder_contents(oldpath, newpath);
        if (psync_rename_conflicted_file(newpath))
          return -1;
      } else
        return -1;
    }
    pstatus_wait_statuses_arr(requiredstatuses, ARRAY_SIZE(requiredstatuses));
  }
}

static void update_local_folder_mtime(const char *localpath,
                                      psync_folderid_t localfolderid) {
  struct stat st;
  psync_sql_res *res;
  if (stat(localpath, &st)) {
    pdbg_logf(D_ERROR, "stat failed for %s", localpath);
    return;
  }
  res = psql_prepare("UPDATE localfolder SET inode=?, deviceid=?, "
                                 "mtime=?, mtimenative=? WHERE id=?");
  psql_bind_uint(res, 1, pfile_stat_inode(&st));
  psql_bind_uint(res, 2, pfile_stat_device(&st));
  psql_bind_uint(res, 3, pfile_stat_mtime(&st));
  psql_bind_uint(res, 4, pfile_stat_mtime_native(&st));
  psql_bind_uint(res, 5, localfolderid);
  psql_run_free(res);
}

static int call_func_for_folder(psync_folderid_t localfolderid,
                                psync_folderid_t folderid,
                                psync_syncid_t syncid, psync_eventtype_t event,
                                int (*func)(const char *), int updatemtime,
                                const char *debug) {
  char *localpath;
  int res;
  localpath = pfolder_lpath_lfldr(localfolderid, syncid, NULL);
  if (likely(localpath)) {
    res = func(localpath);
    if (!res) {
      pqevent_queue_sync_event_id(event, syncid, localpath, folderid);
      if (updatemtime)
        update_local_folder_mtime(localpath, localfolderid);
      psyncer_folder_dec_tasks(localfolderid);
      pdbg_logf(D_NOTICE, "%s %s", debug, localpath);
    }
    free(localpath);
  } else {
    pdbg_logf(D_ERROR, "could not get path for local folder id %lu, syncid %u",
          (long unsigned)localfolderid, (unsigned)syncid);
    res = 0;
  }
  return res;
}

static int call_func_for_folder_name(psync_folderid_t localfolderid,
                                     psync_folderid_t folderid,
                                     const char *name, psync_syncid_t syncid,
                                     psync_eventtype_t event,
                                     int (*func)(const char *), int updatemtime,
                                     const char *debug) {
  char *localpath;
  int res;
  localpath = pfolder_lpath_lfldr(localfolderid, syncid, NULL);
  if (likely(localpath)) {
    res = func(localpath);
    if (!res) {
      pqevent_queue_sync_event_path(event, syncid, localpath, folderid, name);
      if (updatemtime)
        update_local_folder_mtime(localpath, localfolderid);
      psyncer_folder_dec_tasks(localfolderid);
      pdbg_logf(D_NOTICE, "%s %s", debug, localpath);
    }
    free(localpath);
  } else {
    pdbg_logf(D_ERROR, "could not get path for local folder id %lu, syncid %u",
          (long unsigned)localfolderid, (unsigned)syncid);
    res = 0;
  }
  return res;
}

static void delete_local_folder_from_db(psync_folderid_t localfolderid,
                                        psync_syncid_t syncid) {
  psync_sql_res *res;
  psync_uint_row row;
  if (likely(localfolderid)) {
    res = psql_query(
        "SELECT id, syncid FROM localfolder WHERE localparentfolderid=?");
    psql_bind_uint(res, 1, localfolderid);
    while ((row = psql_fetch_int(res)))
      delete_local_folder_from_db(row[0], row[1]);
    psql_free(res);
    res =
        psql_query("SELECT id FROM localfile WHERE localparentfolderid=?");
    psql_bind_uint(res, 1, localfolderid);
    while ((row = psql_fetch_int(res)))
      pupload_del_tasks(row[0]);
    psql_free(res);
    res = psql_prepare(
        "DELETE FROM localfile WHERE localparentfolderid=?");
    psql_bind_uint(res, 1, localfolderid);
    psql_run_free(res);
    res = psql_prepare(
        "DELETE FROM syncedfolder WHERE localfolderid=?");
    psql_bind_uint(res, 1, localfolderid);
    psql_run_free(res);
    res = psql_prepare("DELETE FROM localfolder WHERE id=?");
    psql_bind_uint(res, 1, localfolderid);
    psql_run_free(res);
  }
  ppathstatus_syncfldr_deleted(syncid, localfolderid);
}

static int task_renamefolder(psync_syncid_t newsyncid,
                             psync_folderid_t folderid,
                             psync_folderid_t localfolderid,
                             psync_folderid_t newlocalparentfolderid,
                             const char *newname) {
  psync_sql_res *res;
  psync_variant_row row;
  psync_uint_row urow;
  char *oldpath, *newpath;
  psync_syncid_t oldsyncid;
  int ret;
  pdbg_assert(newname != NULL);
  task_wait_no_downloads();
  res = psql_query(
      "SELECT syncid, localparentfolderid, name FROM localfolder WHERE id=?");
  psql_bind_uint(res, 1, localfolderid);
  row = psql_fetch(res);
  if (unlikely(!row)) {
    psql_free(res);
    pdbg_logf(D_ERROR, "could not find local folder id %lu",
          (unsigned long)localfolderid);
    return 0;
  }
  oldsyncid = psync_get_number(row[0]);
  if (oldsyncid == newsyncid &&
      psync_get_number(row[1]) == newlocalparentfolderid &&
      !strcmp(psync_get_string(row[2]), newname)) {
    psql_free(res);
    pdbg_logf(D_NOTICE,
          "folder %s already renamed locally, probably update initiated from "
          "this client",
          newname);
    return 0;
  }
  psql_free(res);
  oldpath = pfolder_lpath_lfldr(localfolderid, oldsyncid, NULL);
  if (unlikely(!oldpath)) {
    pdbg_logf(D_ERROR, "could not get local path for folder id %lu",
          (unsigned long)localfolderid);
    return 0;
  }
  psql_start();
  psync_restart_localscan();
  res = psql_query_nolock(
      "SELECT syncid, localparentfolderid FROM localfolder WHERE id=?");
  psql_bind_uint(res, 1, localfolderid);
  if ((urow = psql_fetch_int(res))) {
    ppathstatus_syncfldr_moved(localfolderid, urow[0], urow[1],
                                        newsyncid, newlocalparentfolderid);
    psql_free(res);
  } else {
    psql_free(res);
    pdbg_logf(D_NOTICE, "localfolderid %u not found in localfolder",
          (unsigned)localfolderid);
  }
  res = psql_prepare("UPDATE localfolder SET syncid=?, "
                                 "localparentfolderid=?, name=? WHERE id=?");
  psql_bind_uint(res, 1, newsyncid);
  psql_bind_uint(res, 2, newlocalparentfolderid);
  psql_bind_str(res, 3, newname);
  psql_bind_uint(res, 4, localfolderid);
  psql_run_free(res);
  newpath = pfolder_lpath_lfldr(localfolderid, newsyncid, NULL);
  if (unlikely(!newpath)) {
    psql_rollback();
    free(oldpath);
    pdbg_logf(D_ERROR, "could not get local path for folder id %lu",
          (unsigned long)localfolderid);
    return 0;
  }
  ret = task_renamedir(oldpath, newpath);
  if (ret)
    psql_rollback();
  else {
    psyncer_folder_dec_tasks(localfolderid);
    psql_commit();
    pqevent_queue_sync_event_id(PEVENT_LOCAL_FOLDER_RENAMED, newsyncid, newpath,
                           folderid);
    pdbg_logf(D_NOTICE, "local folder renamed from %s to %s", oldpath, newpath);
  }
  free(newpath);
  free(oldpath);
  return ret;
}

static int create_conflicted(const char *name, psync_folderid_t localfolderid,
                             psync_syncid_t syncid, const char *filename) {
  psync_sql_res *res;
  psync_stop_localscan();
  if (psync_rename_conflicted_file(name)) {
    psync_resume_localscan();
    return -1;
  }
  res = psql_prepare("DELETE FROM localfile WHERE syncid=? AND "
                                 "localparentfolderid=? AND name=?");
  psql_bind_uint(res, 1, syncid);
  psql_bind_uint(res, 2, localfolderid);
  psql_bind_str(res, 3, filename);
  psql_run_free(res);
  psync_resume_localscan();
  psync_wake_localscan();
  return 0;
}

static int rename_if_notex(const char *oldname, const char *newname,
                           psync_fileid_t fileid,
                           psync_folderid_t localfolderid,
                           psync_syncid_t syncid, const char *filename) {
  uint64_t filesize;
  int ret, isrev;
  unsigned char localhashhex[PSYNC_HASH_DIGEST_HEXLEN];
  pdbg_logf(D_NOTICE, "renaming %s to %s", oldname, newname);
  if (psync_get_local_file_checksum(newname, localhashhex, &filesize) ==
      PSYNC_NET_OK) {
    pdbg_logf(D_NOTICE, "file %s already exists", newname);
    ret = psync_is_revision_of_file(localhashhex, filesize, fileid, &isrev);
    if (ret == PSYNC_NET_TEMPFAIL) {
      pdbg_logf(D_NOTICE, "got PSYNC_NET_TEMPFAIL for %s", newname);
      return -1;
    }
    if (ret == PSYNC_NET_OK && !isrev) {
      if (create_conflicted(newname, localfolderid, syncid, filename)) {
        pdbg_logf(D_WARNING, "create_conflicted failed for %s", newname);
        return -1;
      }
    } else if (ret == PSYNC_NET_OK && isrev)
      pdbg_logf(D_NOTICE,
            "file %s is found to be old revision of fileid %lu, overwriting",
            newname, (unsigned long)fileid);
  }
  return pfile_rename_overwrite(oldname, newname);
}

static int stat_and_create_local(psync_syncid_t syncid, psync_fileid_t fileid,
                                 psync_folderid_t localfolderid,
                                 const char *filename, const char *name,
                                 unsigned char *checksum, uint64_t serversize,
                                 uint64_t hash) {
  psync_sql_res *sql;
  struct stat st;
  psync_uint_row row;
  psync_fileid_t localfileid;
  if (pdbg_unlikely(stat(name, &st)) ||
      pdbg_unlikely(pfile_stat_size(&st) != serversize))
    return -1;
  localfileid = 0;
  psql_start();
  sql = psql_query_nolock("SELECT id FROM localfile WHERE syncid=? AND "
                               "localparentfolderid=? AND name=?");
  psql_bind_uint(sql, 1, syncid);
  psql_bind_uint(sql, 2, localfolderid);
  psql_bind_str(sql, 3, filename);
  if ((row = psql_fetch_int(sql)))
    localfileid = row[0];
  psql_free(sql);

  sql = psql_query_nolock("SELECT parentfolderid FROM file WHERE id=?");
  psql_bind_uint(sql, 1, fileid);
  row = psql_fetch_int(sql);
  if (!row || !psyncer_dl_has_folder(row[0])) {
    psql_free(sql);
    if (localfileid) {
      sql = psql_prepare("DELETE FROM localfile WHERE id=?");
      psql_bind_uint(sql, 1, localfileid);
      psql_run_free(sql);
    }
    psql_commit();
    pfile_delete(name);
    if (row)
      pdbg_logf(D_NOTICE,
            "fileid %lu (%s) got moved out of download folder while finishing "
            "download, deleting %s",
            (unsigned long)fileid, filename, name);
    else
      pdbg_logf(D_NOTICE,
            "fileid %lu (%s) got deleted while finishing download, deleting %s",
            (unsigned long)fileid, filename, name);
    return 0;
  }
  psql_free(sql);

  if (localfileid) {
    sql = psql_prepare(
        "UPDATE localfile SET localparentfolderid=?, fileid=?, hash=?, "
        "syncid=?, size=?, inode=?, mtime=?, mtimenative=?, "
        "name=?, checksum=? WHERE id=?");
    psql_bind_uint(sql, 1, localfolderid);
    psql_bind_uint(sql, 2, fileid);
    psql_bind_uint(sql, 3, hash);
    psql_bind_uint(sql, 4, syncid);
    psql_bind_uint(sql, 5, pfile_stat_size(&st));
    psql_bind_uint(sql, 6, pfile_stat_inode(&st));
    psql_bind_uint(sql, 7, pfile_stat_mtime(&st));
    psql_bind_uint(sql, 8, pfile_stat_mtime_native(&st));
    psql_bind_str(sql, 9, filename);
    psql_bind_lstr(sql, 10, (char *)checksum, PSYNC_HASH_DIGEST_HEXLEN);
    psql_bind_uint(sql, 11, localfileid);
    psql_run_free(sql);
  } else {
    sql = psql_prepare(
        "REPLACE INTO localfile (localparentfolderid, fileid, hash, syncid, "
        "size, inode, mtime, mtimenative, name, checksum)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
    psql_bind_uint(sql, 1, localfolderid);
    psql_bind_uint(sql, 2, fileid);
    psql_bind_uint(sql, 3, hash);
    psql_bind_uint(sql, 4, syncid);
    psql_bind_uint(sql, 5, pfile_stat_size(&st));
    psql_bind_uint(sql, 6, pfile_stat_inode(&st));
    psql_bind_uint(sql, 7, pfile_stat_mtime(&st));
    psql_bind_uint(sql, 8, pfile_stat_mtime_native(&st));
    psql_bind_str(sql, 9, filename);
    psql_bind_lstr(sql, 10, (char *)checksum, PSYNC_HASH_DIGEST_HEXLEN);
    psql_run_free(sql);
  }
  return psql_commit();
}

// rename_and_create_local(dt->tmpname, dt->localname, dt->dwllist.syncid,
// dt->dwllist.fileid, dt->localfolderid, dt->filename, serverhashhex,
// serversize, hash))
// static int rename_and_create_local(const char *src, const char *dst,
// psync_syncid_t syncid, psync_fileid_t fileid, psync_folderid_t localfolderid,
//                                   const char *filename, unsigned char
//                                   *checksum, uint64_t serversize, uint64_t
//                                   hash){

static int rename_and_create_local(download_task_t *dt, unsigned char *checksum,
                                   uint64_t serversize, uint64_t hash) {
  psync_stop_localscan();
  pfile_set_crtime_mtime(dt->tmpname, dt->crtime, dt->mtime);
  if (rename_if_notex(dt->tmpname, dt->localname, dt->dwllist.fileid,
                      dt->localfolderid, dt->dwllist.syncid, dt->filename)) {
    psync_resume_localscan();
    pdbg_logf(D_WARNING, "failed to rename %s to %s", dt->tmpname, dt->localname);
    psys_sleep_milliseconds(1000);
    return -1;
  }
  if (stat_and_create_local(dt->dwllist.syncid, dt->dwllist.fileid,
                            dt->localfolderid, dt->filename, dt->localname,
                            checksum, serversize, hash)) {
    pdbg_logf(D_WARNING, "stat_and_create_local failed for file %s", dt->localname);
    psync_resume_localscan();
    return -1;
  }
  psync_resume_localscan();
  return 0;
}

static int task_download_file(download_task_t *dt) {
  binparam params[] = {PAPI_STR("auth", psync_my_auth),
                       PAPI_NUM("fileid", dt->dwllist.fileid)};
  struct stat st;
  psync_list ranges;
  psync_range_list_t *range;
  binresult *res;
  psync_sql_res *sql;
  const binresult *hosts;
  char *tmpold;
  char *oldfiles[2];
  uint32_t oldcnt;
  const char *requestpath;
  void *buff;
  psync_http_socket *http;
  uint64_t result, serversize, hash;
  psync_uint_row row;
  psync_hash_ctx hashctx;
  unsigned char serverhashhex[PSYNC_HASH_DIGEST_HEXLEN],
      localhashhex[PSYNC_HASH_DIGEST_HEXLEN],
      localhashbin[PSYNC_HASH_DIGEST_LEN];
  char cookie[128];
  uint32_t i;
  int fd, ifd;
  int rd, rt;

  psync_list_init(&ranges);
  tmpold = NULL;

  rt = psync_get_remote_file_checksum(dt->dwllist.fileid, serverhashhex,
                                      &serversize, &hash);
  if (pdbg_unlikely(rt != PSYNC_NET_OK)) {
    if (rt == PSYNC_NET_TEMPFAIL)
      return -1;
    else
      return 0;
  }
  memcpy(dt->dwllist.schecksum, serverhashhex, PSYNC_HASH_DIGEST_HEXLEN);

  if (serversize != dt->size) {
    pthread_mutex_lock(&current_downloads_mutex);
    psync_status.bytestodownloadcurrent -= dt->size;
    psync_status.bytestodownloadcurrent += serversize;
    pthread_mutex_unlock(&current_downloads_mutex);
    dt->size = serversize;
    pstatus_send_update();
  }

  sql = psql_query_rdlock(
      "SELECT fileid, id, hash FROM localfile WHERE size=? AND checksum=? AND "
      "localparentfolderid=? AND syncid=? AND name=?");
  psql_bind_uint(sql, 1, serversize);
  psql_bind_lstr(sql, 2, (char *)serverhashhex,
                         PSYNC_HASH_DIGEST_HEXLEN);
  psql_bind_uint(sql, 3, dt->localfolderid);
  psql_bind_uint(sql, 4, dt->dwllist.syncid);
  psql_bind_str(sql, 5, dt->filename);
  if ((row = psql_fetch_int(sql))) {
    rt = row[0] != dt->dwllist.fileid || row[2] != hash;
    result = row[1];
    psql_free(sql);
    if (rt) {
      sql = psql_prepare(
          "UPDATE localfile SET fileid=?, hash=? WHERE id=?");
      psql_bind_uint(sql, 1, dt->dwllist.fileid);
      psql_bind_uint(sql, 2, hash);
      psql_bind_uint(sql, 3, result);
      psql_run_free(sql);
    }
    return 0;
  }
  psql_free(sql);

  if (dt->localexists && dt->localsize == serversize &&
      !memcmp(dt->checksum, serverhashhex, PSYNC_HASH_DIGEST_HEXLEN)) {
    if (stat_and_create_local(dt->dwllist.syncid, dt->dwllist.fileid,
                              dt->localfolderid, dt->filename, dt->localname,
                              serverhashhex, serversize, hash)) {
      pdbg_logf(D_NOTICE,
            "file %s, already exists but stat_and_create_local failed",
            dt->filename);
      return -1;
    } else {
      pdbg_logf(D_NOTICE, "file already exists %s, not downloading", dt->filename);
      return 0;
    }
  }

  sql = psql_query_rdlock(
      "SELECT id FROM localfile WHERE size=? AND checksum=?");
  psql_bind_uint(sql, 1, serversize);
  psql_bind_lstr(sql, 2, (char *)serverhashhex,
                         PSYNC_HASH_DIGEST_HEXLEN);
  while ((row = psql_fetch_int(sql))) {
    tmpold = pfolder_lpath_lfile(row[0], NULL);
    if (pdbg_unlikely(!tmpold))
      continue;
    psql_free(sql);
    sql = NULL;
    rt = psync_copy_local_file_if_checksum_matches(tmpold, dt->tmpname,
                                                   serverhashhex, serversize);
    if (likely(rt == PSYNC_NET_OK)) {
      if (rename_and_create_local(dt, serverhashhex, serversize, hash))
        rt = PSYNC_NET_TEMPFAIL;
      else
        pdbg_logf(D_NOTICE, "file %s copied from %s", dt->localname, tmpold);
    } else
      pdbg_logf(D_WARNING, "failed to copy %s from %s", dt->localname, tmpold);
    free(tmpold);
    tmpold = NULL;
    if (pdbg_likely(rt == PSYNC_NET_OK))
      return 0;
    else
      break;
  }
  if (sql)
    psql_free(sql);

  if (dt->dwllist.stop)
    return 0;

  //  pqevent_queue_sync_event_id(PEVENT_FILE_DOWNLOAD_STARTED, syncid, name,
  //  fileid);
  if (serversize >= PSYNC_MIN_SIZE_FOR_P2P) {
    rt = pp2p_check_download(dt->dwllist.fileid, serverhashhex, serversize,
                                  dt->tmpname);
    if (rt == PSYNC_NET_OK) {
      if (rename_and_create_local(dt, serverhashhex, serversize, hash))
        return -1;
      else
        return 0;
    } else if (rt == PSYNC_NET_TEMPFAIL)
      return -1;
  }
  res = psync_api_run_command("getfilelink", params);
  if (pdbg_unlikely(!res))
    return -1;
  result = papi_find_result2(res, "result", PARAM_NUM)->num;
  if (unlikely(result)) {
    pdbg_logf(D_WARNING, "got error %lu from getfilelink", (long unsigned)result);
    psync_process_api_error(result);
    if (psync_handle_api_result(result) == PSYNC_NET_TEMPFAIL) {
      free(res);
      return -1;
    } else {
      free(res);
      return 0;
    }
  }

  dt->dwllist.started = 1;

  oldcnt = 0;
  if (serversize >= PSYNC_MIN_SIZE_FOR_CHECKSUMS) {
    if (!stat(dt->tmpname, &st) &&
        pfile_stat_size(&st) >= PSYNC_MIN_SIZE_FOR_CHECKSUMS) {
      tmpold =
          psync_strcat(dt->localpath, "/", dt->filename,
                       "-old", PSYNC_APPEND_PARTIAL_FILES, NULL);
      if (pfile_rename_overwrite(dt->tmpname, tmpold)) {
        free(tmpold);
        tmpold = NULL;
      } else
        oldfiles[oldcnt++] = tmpold;
    }
    if (dt->localexists && dt->localsize >= PSYNC_MIN_SIZE_FOR_CHECKSUMS)
      oldfiles[oldcnt++] = dt->localname;
  }

  fd = pfile_open(dt->tmpname, O_WRONLY, O_CREAT | O_TRUNC);
  if (pdbg_unlikely(fd == INVALID_HANDLE_VALUE))
    goto err0;

  rt = psync_net_download_ranges(&ranges, dt->dwllist.fileid, hash, serversize,
                                 oldfiles, oldcnt);
  if (rt == PSYNC_NET_TEMPFAIL)
    goto err1;

  hosts = papi_find_result2(res, "hosts", PARAM_ARRAY);
  requestpath = papi_find_result2(res, "path", PARAM_STR)->str;
  psync_slprintf(cookie, sizeof(cookie), "Cookie: dwltag=%s\015\012",
                 papi_find_result2(res, "dwltag", PARAM_STR)->str);
  buff = malloc(PSYNC_COPY_BUFFER_SIZE);
  http = NULL;
  psync_hash_init(&hashctx);
  psync_list_for_each_element(range, &ranges, psync_range_list_t, list) {
    if (!range->len)
      continue;
    if (range->type == PSYNC_RANGE_TRANSFER) {
      pdbg_logf(D_NOTICE, "downloading %lu bytes from offset %lu of fileid %lu",
            (unsigned long)range->len, (unsigned long)range->off,
            (unsigned long)dt->dwllist.fileid);
      for (i = 0; i < hosts->length; i++)
        if ((http = psync_http_connect(
                 hosts->array[i]->str, requestpath, range->off,
                 (range->len == serversize && range->off == 0)
                     ? 0
                     : (range->len + range->off - 1),
                 cookie)))
          break;
      if (pdbg_unlikely(!http))
        goto err2;

      while (!dt->dwllist.stop) {
        rd = psync_http_readall(http, buff, PSYNC_COPY_BUFFER_SIZE);
        if (rd == 0)
          break;
        if (pdbg_unlikely(rd < 0) ||
            pdbg_unlikely(psync_file_writeall_checkoverquota(fd, buff, rd)))
          goto err2;
        psync_hash_update(&hashctx, buff, rd);
        pthread_mutex_lock(&current_downloads_mutex);
        psync_status.bytesdownloaded += rd;
        if (current_downloads_waiters && psync_status.bytestodownloadcurrent -
                                                 psync_status.bytesdownloaded <=
                                             PSYNC_START_NEW_DOWNLOADS_TRESHOLD)
          pthread_cond_signal(&current_downloads_cond);
        pthread_mutex_unlock(&current_downloads_mutex);
        pstatus_send_status_update();
        dt->downloadedsize += rd;
        if (unlikely(!pstatus_ok_status_arr(requiredstatuses,
                                              ARRAY_SIZE(requiredstatuses))))
          goto err2;
      }
      psync_http_close(http);
      http = NULL;
    } else {
      pdbg_logf(D_NOTICE, "copying %lu bytes from %s offset %lu",
            (unsigned long)range->len, range->filename,
            (unsigned long)range->off);
      ifd = pfile_open(range->filename, O_RDONLY, 0);
      if (pdbg_unlikely(ifd == INVALID_HANDLE_VALUE))
        goto err2;
      if (pdbg_unlikely(pfile_seek(ifd, range->off, SEEK_SET) == -1)) {
        pfile_close(ifd);
        goto err2;
      }
      result = range->len;
      while (!dt->dwllist.stop && result) {
        if (result > PSYNC_COPY_BUFFER_SIZE)
          rd = PSYNC_COPY_BUFFER_SIZE;
        else
          rd = result;
        rd = pfile_read(ifd, buff, rd);
        if (pdbg_unlikely(rd <= 0) ||
            pdbg_unlikely(psync_file_writeall_checkoverquota(fd, buff, rd)) ||
            unlikely(!pstatus_ok_status_arr(requiredstatuses,
                                              ARRAY_SIZE(requiredstatuses)))) {
          pfile_close(ifd);
          goto err2;
        }
        result -= rd;
        psync_hash_update(&hashctx, buff, rd);
        pthread_mutex_lock(&current_downloads_mutex);
        psync_status.bytesdownloaded += rd;
        if (current_downloads_waiters && psync_status.bytestodownloadcurrent -
                                                 psync_status.bytesdownloaded <=
                                             PSYNC_START_NEW_DOWNLOADS_TRESHOLD)
          pthread_cond_signal(&current_downloads_cond);
        pthread_mutex_unlock(&current_downloads_mutex);
        pstatus_send_status_update();
        dt->downloadedsize += rd;
      }
      pfile_close(ifd);
    }
    if (dt->dwllist.stop)
      break;
  }
  if (unlikely(dt->dwllist.stop)) {
    if (dt->dwllist.stop == 2) {
      pdbg_logf(D_NOTICE, "deleting file %s as stop is detected", dt->tmpname);
      pfile_delete(dt->tmpname);
    }
    goto err2;
  }
  if (pdbg_unlikely(pfile_sync(fd)))
    goto err2;
  free(buff);
  psync_hash_final(localhashbin, &hashctx);
  if (pdbg_unlikely(pfile_close(fd)))
    goto err0;
  psync_binhex(localhashhex, localhashbin, PSYNC_HASH_DIGEST_LEN);
  if (pdbg_unlikely(
          memcmp(localhashhex, serverhashhex, PSYNC_HASH_DIGEST_HEXLEN))) {
    pdbg_logf(D_WARNING, "got wrong file checksum for file %s", dt->filename);
    if (dt->dwllist.stop == 2) {
      pdbg_logf(D_NOTICE, "deleting file %s as stop is detected", dt->tmpname);
      pfile_delete(dt->tmpname);
    }
    goto err0;
  }
  if (dt->dwllist.stop == 2) {
    pdbg_logf(D_NOTICE, "deleting file %s as stop is detected", dt->tmpname);
    pfile_delete(dt->tmpname);
    goto err0;
  }
  if (rename_and_create_local(dt, serverhashhex, serversize, hash))
    goto err0;
  //  pqevent_queue_sync_event_id(PEVENT_FILE_DOWNLOAD_FINISHED, syncid, name,
  //  fileid);
  pdbg_logf(D_NOTICE, "file downloaded %s", dt->localname);
  psync_list_for_each_element_call(&ranges, psync_range_list_t, list, free);
  if (tmpold) {
    pfile_delete(tmpold);
    free(tmpold);
  }
  free(res);
  return 0;
err2:
  psync_hash_final(localhashbin, &hashctx); /* just in case */
  free(buff);
  if (http)
    psync_http_close(http);
err1:
  pfile_close(fd);
err0:
  psync_list_for_each_element_call(&ranges, psync_range_list_t, list, free);
  if (tmpold) {
    pfile_delete(tmpold);
    free(tmpold);
  }
  free(res);
  return -1;
}

static int task_delete_file(psync_syncid_t syncid, psync_fileid_t fileid,
                            const char *remotepath) {
  psync_sql_res *res, *stmt;
  psync_uint_row row;
  char *name;
  int ret;
  ret = 0;
  task_wait_no_downloads();
  if (syncid) {
    res = psql_query(
        "SELECT id, syncid FROM localfile WHERE fileid=? AND syncid=?");
    psql_bind_uint(res, 2, syncid);
  } else
    res = psql_query("SELECT id, syncid FROM localfile WHERE fileid=?");
  psql_bind_uint(res, 1, fileid);
  psync_restart_localscan();
  while ((row = psql_fetch_int(res))) {
    name = pfolder_lpath_lfile(row[0], NULL);
    if (pdbg_likely(name)) {
      if (unlikely(pfile_delete(name))) {
        pdbg_logf(D_WARNING, "error deleting local file %s error %d", name,
              (int)errno);
        if (errno == EBUSY || errno == EROFS) {
          ret = -1;
          free(name);
          continue;
        }
      } else
        pdbg_logf(D_NOTICE, "local file %s deleted", name);
      //      threre are some reports about crashes here, comment out for now as
      //      events are not fully implemented anyway
      //      pqevent_queue_sync_event_path(PEVENT_LOCAL_FILE_DELETED, row[1], name,
      //      fileid, remotepath);
      free(name);
    }
    stmt = psql_prepare("DELETE FROM localfile WHERE id=?");
    psql_bind_uint(stmt, 1, row[0]);
    psql_run_free(stmt);
  }
  psql_free(res);
  return ret;
}

static int task_rename_file(psync_syncid_t oldsyncid, psync_syncid_t newsyncid,
                            psync_fileid_t fileid,
                            psync_folderid_t oldlocalfolderid,
                            psync_folderid_t newlocalfolderid,
                            const char *newname) {
  char *oldpath, *newfolder, *newpath;
  psync_sql_res *res;
  psync_variant_row row;
  psync_fileid_t lfileid;
  struct stat st;
  psync_syncid_t syncid;
  int ret;
  task_wait_no_downloads();
  res = psql_query("SELECT id, localparentfolderid, syncid, name FROM "
                        "localfile WHERE fileid=?");
  psql_bind_uint(res, 1, fileid);
  lfileid = 0;
  while ((row = psql_fetch(res))) {
    syncid = psync_get_number(row[2]);
    if (psync_get_number(row[1]) == newlocalfolderid && syncid == newsyncid &&
        !strcmp(psync_get_string(row[3]), newname)) {
      pdbg_logf(D_NOTICE,
            "file %s already renamed locally, probably update initiated from "
            "this client",
            newname);
      psql_free(res);
      return 0;
    } else if (syncid == oldsyncid) {
      lfileid = psync_get_number(row[0]);
      break;
    }
  }
  psql_free(res);
  if (pdbg_unlikely(!lfileid)) {
    ptask_download(newsyncid, fileid, newlocalfolderid, newname);
    return 0;
  }
  newfolder =
      pfolder_lpath_lfldr(newlocalfolderid, newsyncid, NULL);
  if (pdbg_unlikely(!newfolder))
    return 0;
  oldpath = pfolder_lpath_lfile(lfileid, NULL);
  if (pdbg_unlikely(!oldpath)) {
    free(newfolder);
    return 0;
  }
  newpath = psync_strcat(newfolder, "/", newname, NULL);
  ret = 0;
  psync_stop_localscan();
  if (pfile_rename_overwrite(oldpath, newpath)) {
    psync_resume_localscan();
    if (errno == ENOENT) {
      pdbg_logf(D_WARNING, "renamed from %s to %s failed, downloading", oldpath,
            newpath);
      ptask_download(newsyncid, fileid, newlocalfolderid, newname);
    } else
      ret = -1;
  } else {
    if (pdbg_likely(!stat(newpath, &st))) {
      res = psql_prepare(
          "UPDATE OR REPLACE localfile SET localparentfolderid=?, syncid=?, "
          "name=?, inode=?, mtime=?, mtimenative=? WHERE id=?");
      psql_bind_uint(res, 1, newlocalfolderid);
      psql_bind_uint(res, 2, newsyncid);
      psql_bind_str(res, 3, newname);
      psql_bind_uint(res, 4, pfile_stat_inode(&st));
      psql_bind_uint(res, 5, pfile_stat_mtime(&st));
      psql_bind_uint(res, 6, pfile_stat_mtime_native(&st));
      psql_bind_uint(res, 7, lfileid);
      psql_run_free(res);
      pdbg_logf(D_NOTICE, "renamed %s to %s", oldpath, newpath);
    }
    psync_resume_localscan();
  }
  free(newpath);
  free(oldpath);
  free(newfolder);
  return ret;
}

static void set_task_inprogress(uint64_t taskid, uint32_t val) {
  psync_sql_res *res;
  res = psql_prepare("UPDATE task SET inprogress=? WHERE id=?");
  psql_bind_uint(res, 1, val);
  psql_bind_uint(res, 2, taskid);
  psql_run_free(res);
}

static void delete_task(uint64_t taskid) {
  psync_sql_res *res;
  res = psql_prepare("DELETE FROM task WHERE id=?");
  psql_bind_uint(res, 1, taskid);
  psql_run_free(res);
}

static void free_download_task(download_task_t *dt) {
  if (dt->indwllist) {
    pthread_mutex_lock(&current_downloads_mutex);
    psync_list_del(&dt->dwllist.list);
    started_downloads--;
    psync_status.filesdownloading--;
    psync_status.bytestodownloadcurrent -= dt->size;
    psync_status.bytesdownloaded -= dt->downloadedsize;
    if (current_downloads_waiters)
      pthread_cond_broadcast(&current_downloads_cond);
    pthread_mutex_unlock(&current_downloads_mutex);
  }
  if (dt->lock)
    psync_unlock_file(dt->lock);
  free(dt->localpath);
  free(dt->localname);
  free(dt->tmpname);
  free(dt);
}

static void free_task_timer_thread(void *ptr) {
  download_task_t *dt = (download_task_t *)ptr;
  set_task_inprogress(dt->taskid, 0);
  free_download_task(dt);
  pstatus_send_status_update();
  pdownload_wake();
}

static void free_task_timer(psync_timer_t timer, void *ptr) {
  ptimer_stop(timer);
  prun_thread1("free task", free_task_timer_thread, ptr);
}

static void handle_async_error(download_task_t *dt, psync_async_result_t *res) {
  if (res->error == PSYNC_SERVER_ERROR_TOO_BIG) {
    psync_sql_res *sres;
    pdbg_assert(res->file.size > PSYNC_MAX_SIZE_FOR_ASYNC_DOWNLOAD);
    sres =
        psql_prepare("UPDATE file SET size=?, hash=? WHERE id=?");
    psql_bind_uint(sres, 1, res->file.size);
    psql_bind_uint(sres, 2, res->file.hash);
    psql_bind_uint(sres, 3, dt->dwllist.fileid);
    psql_run_free(sres);
    set_task_inprogress(dt->taskid, 0);
    free_download_task(dt);
    pstatus_send_status_update();
    pdownload_wake();
  } else if ((res->errorflags & PSYNC_ASYNC_ERR_FLAG_PERM) ||
             !(res->errorflags & PSYNC_ASYNC_ERR_FLAG_RETRY_AS_IS)) {
    delete_task(dt->taskid);
    free_download_task(dt);
    pstatus_download_recalc_async();
  } else
    ptimer_register(free_task_timer, 1, dt);
}

static void finish_async_download(void *ptr, psync_async_result_t *res) {
  download_task_t *dt = (download_task_t *)ptr;
  if (res->error)
    handle_async_error(dt, res);
  else {
    if (dt->dwllist.stop == 2) {
      pdbg_logf(D_NOTICE, "deleting file %s as stop is detected", dt->tmpname);
      pfile_delete(dt->tmpname);
      return;
    }
    if (rename_and_create_local(dt, res->file.sha1hex, res->file.size,
                                res->file.hash))
      ptimer_register(free_task_timer, 1, dt);
    else {
      delete_task(dt->taskid);
      ppathstatus_syncfldr_task_completed(dt->dwllist.syncid,
                                                   dt->localfolderid);
      free_download_task(dt);
      pstatus_download_recalc_async();
    }
  }
}

static void finish_async_download_existing_not_mod(download_task_t *dt,
                                                   psync_async_result_t *res) {
  pdbg_logf(D_NOTICE, "file %s not modified", dt->localname);
  if (stat_and_create_local(dt->dwllist.syncid, dt->dwllist.fileid,
                            dt->localfolderid, dt->filename, dt->localname,
                            res->file.sha1hex, res->file.size,
                            res->file.hash)) {
    pdbg_logf(D_WARNING, "stat_and_create_local failed for %s", dt->localname);
    ptimer_register(free_task_timer, 1, dt);
  } else {
    delete_task(dt->taskid);
    ppathstatus_syncfldr_task_completed(dt->dwllist.syncid,
                                                 dt->localfolderid);
    free_download_task(dt);
    pstatus_download_recalc_async();
  }
}

static void finish_async_download_existing(void *ptr,
                                           psync_async_result_t *res) {
  if (res->error == PSYNC_SERVER_ERROR_NOT_MOD)
    finish_async_download_existing_not_mod((download_task_t *)ptr, res);
  else
    finish_async_download(ptr, res);
}

static void task_run_download_file_thread(void *ptr) {
  download_task_t *dt;
  dt = (download_task_t *)ptr;
  if (task_download_file(dt)) {
    psys_sleep_milliseconds(PSYNC_SLEEP_ON_FAILED_DOWNLOAD);
    set_task_inprogress(dt->taskid, 0);
    pdownload_wake();
  } else {
    delete_task(dt->taskid);
    ppathstatus_syncfldr_task_completed(dt->dwllist.syncid,
                                                 dt->localfolderid);
  }
  free_download_task(dt);
  pstatus_download_recalc_async();
}

static int task_run_download_file(uint64_t taskid, psync_syncid_t syncid,
                                  psync_fileid_t fileid,
                                  psync_folderid_t localfolderid,
                                  const char *filename) {
  psync_sql_res *res;
  psync_uint_row row;
  psync_str_row srow;
  download_task_t *dt;
  char *localpath, *localname, *tmpname;
  psync_file_lock_t *lock;
  uint64_t size, minfree, hash, csize;
  time_t crtime, mtime;
  int64_t freespace;
  size_t len;
  unsigned char targetchecksum[PSYNC_HASH_DIGEST_HEXLEN];
  int hastargetchecksum, ret;
  res = psql_query_rdlock(
      "SELECT size, hash, ctime, mtime FROM file WHERE id=?");
  psql_bind_uint(res, 1, fileid);
  row = psql_fetch_int(res);
  if (row) {
    size = row[0];
    hash = row[1];
    crtime = row[2];
    mtime = row[3];
  } else {
    // make compiler happy :)
    size = 0;
    hash = 0;
    crtime = 0;
    mtime = 0;
  }
  psql_free(res);
  if (!row) {
    pdbg_logf(D_NOTICE, "possible race, fileid %lu not found in file table",
          (unsigned long)size);
    return 0; // this will delete the task
  }
  res = psql_query_rdlock(
      "SELECT checksum FROM hashchecksum WHERE hash=? AND size=?");
  psql_bind_uint(res, 1, hash);
  psql_bind_uint(res, 2, size);
  srow = psql_fetch_str(res);
  if (srow) {
    memcpy(targetchecksum, srow[0], PSYNC_HASH_DIGEST_HEXLEN);
    hastargetchecksum = 1;
  } else
    hastargetchecksum = 0;
  psql_free(res);
  localpath = pfolder_lpath_lfldr(localfolderid, syncid, NULL);
  if (pdbg_unlikely(!localpath))
    return 0;
  localname =
      psync_strcat(localpath, "/", filename, NULL);
  tmpname = psync_strcat(localpath, "/", filename,
                         PSYNC_APPEND_PARTIAL_FILES, NULL);
  len = strlen(filename);
  dt = (download_task_t *)malloc(offsetof(download_task_t, filename) +
                                       len + 1);
  memset(dt, 0, offsetof(download_task_t, filename));
  dt->taskid = taskid;
  dt->dwllist.fileid = fileid;
  dt->dwllist.syncid = syncid;
  dt->localpath = localpath;
  dt->localname = localname;
  dt->tmpname = tmpname;
  dt->size = size;
  dt->hash = hash;
  dt->crtime = crtime;
  dt->mtime = mtime;
  dt->localfolderid = localfolderid;
  memcpy(dt->filename, filename, len + 1);
  pthread_mutex_lock(&current_downloads_mutex);
  psync_list_add_tail(&downloads, &dt->dwllist.list);
  while (!dt->dwllist.stop &&
         (started_downloads >= PSYNC_MAX_PARALLEL_DOWNLOADS ||
          psync_status.bytestodownloadcurrent - psync_status.bytesdownloaded >
              PSYNC_START_NEW_DOWNLOADS_TRESHOLD)) {
    current_downloads_waiters++;
    pthread_cond_wait(&current_downloads_cond, &current_downloads_mutex);
    current_downloads_waiters--;
  }
  if (unlikely(dt->dwllist.stop)) {
    dt->indwllist = 0;
    psync_list_del(&dt->dwllist.list);
  } else {
    dt->indwllist = 1;
    psync_status.bytestodownloadcurrent += size;
    psync_status.filesdownloading++;
    started_downloads++;
  }
  pthread_mutex_unlock(&current_downloads_mutex);
  if (unlikely(!dt->indwllist)) {
    free_download_task(dt);
    return -1;
  }
  pstatus_send_status_update();
  if (hastargetchecksum &&
      psync_get_local_file_checksum(tmpname, dt->checksum, &csize) ==
          PSYNC_NET_OK &&
      csize == size &&
      !memcmp(dt->checksum, targetchecksum, PSYNC_HASH_DIGEST_HEXLEN)) {
    pdbg_logf(D_NOTICE,
          "found file %s, candidate for %s with the right size and checksum",
          tmpname, localname);
    ret = rename_and_create_local(dt, targetchecksum, size, hash);
    free_download_task(dt);
    return ret;
  }
  if (psync_get_local_file_checksum(localname, dt->checksum, &dt->localsize) ==
      PSYNC_NET_OK)
    dt->localexists = 1;
  else
    dt->localexists = 0;
  if (hastargetchecksum && dt->localexists && size == dt->localsize &&
      !memcmp(dt->checksum, targetchecksum, PSYNC_HASH_DIGEST_HEXLEN)) {
    pdbg_logf(D_NOTICE,
          "file %s already exists and has correct checksum, not downloading",
          localname);
    ret = stat_and_create_local(dt->dwllist.syncid, dt->dwllist.fileid,
                                dt->localfolderid, dt->filename, dt->localname,
                                targetchecksum, size, hash);
    free_download_task(dt);
    return ret;
  }
  minfree = psync_setting_get_uint(_PS(minlocalfreespace));
  freespace = ppath_free_space(localpath);
  pdbg_logf(D_NOTICE, "free space is %llu, needed %llu+%llu",
        (unsigned long long)freespace, (unsigned long long)minfree,
        (unsigned long long)size);
  if (likely(freespace != -1)) {
    if (freespace >= minfree + size)
      psync_set_local_full(0);
    else {
      free_download_task(dt);
      psync_set_local_full(1);
      pdbg_logf(D_NOTICE, "disk is full, sleeping 10 seconds");
      psys_sleep_milliseconds(PSYNC_SLEEP_ON_DISK_FULL);
      return -1;
    }
  } else {
    pdbg_logf(D_WARNING,
          "could not get free space for %s, maybe it is locally deleted, "
          "sleeping a bit and failing task",
          localpath);
    free_download_task(dt);
    psys_sleep_milliseconds(PSYNC_SLEEP_ON_FAILED_DOWNLOAD);
    return -1;
  }
  lock = psync_lock_file(localname);
  if (!lock) {
    pdbg_logf(D_NOTICE, "file %s is currently locked, skipping for now", localname);
    free_download_task(dt);
    psys_sleep_milliseconds(PSYNC_SLEEP_ON_LOCKED_FILE);
    return -1;
  }
  dt->lock = lock;
  set_task_inprogress(taskid, 1);
  if (size <= PSYNC_MAX_SIZE_FOR_ASYNC_DOWNLOAD) {
    if (dt->localexists)
      ret = ptask_download_needed_async(
          fileid, dt->tmpname, dt->localsize, dt->checksum,
          finish_async_download_existing, dt);
    else
      ret = ptask_download_async(fileid, dt->tmpname,
                                      finish_async_download, dt);
    if (ret) {
      pdbg_logf(D_WARNING, "async download start failed for %s", dt->localname);
      free_download_task(dt);
      set_task_inprogress(taskid, 0);
      psys_sleep_milliseconds(PSYNC_SLEEP_ON_FAILED_DOWNLOAD);
    }
  } else {
    prun_thread1("download file", task_run_download_file_thread, dt);
    psys_sleep_milliseconds(25); // do not run downloads strictly in parallel so we
                         // reuse some API connections
  }
  return -1;
}

static void task_del_folder_rec_do(const char *localpath,
                                   psync_folderid_t localfolderid,
                                   psync_syncid_t syncid) {
  psync_sql_res *res;
  psync_variant_row vrow;
  char *nm;
  res = psql_query("SELECT id, name FROM localfile WHERE "
                        "localparentfolderid=? AND syncid=?");
  psql_bind_uint(res, 1, localfolderid);
  psql_bind_uint(res, 2, syncid);
  while ((vrow = psql_fetch(res))) {
    pupload_del_tasks(psync_get_number(vrow[0]));
    nm = psync_strcat(localpath, "/",
                      psync_get_string(vrow[1]), NULL);
    pdbg_logf(D_NOTICE, "deleting %s", nm);
    pfile_delete(nm);
    free(nm);
  }
  psql_free(res);
  res = psql_prepare(
      "DELETE FROM localfile WHERE localparentfolderid=? AND syncid=?");
  psql_bind_uint(res, 1, localfolderid);
  psql_bind_uint(res, 2, syncid);
  psql_run_free(res);
  res = psql_query("SELECT id, name FROM localfolder WHERE "
                        "localparentfolderid=? AND syncid=?");
  psql_bind_uint(res, 1, localfolderid);
  psql_bind_uint(res, 2, syncid);
  while ((vrow = psql_fetch(res))) {
    nm = psync_strcat(localpath, "/",
                      psync_get_string(vrow[1]), NULL);
    task_del_folder_rec_do(nm, psync_get_number(vrow[0]), syncid);
    free(nm);
  }
  psql_free(res);
  res = psql_prepare(
      "DELETE FROM localfolder WHERE localparentfolderid=? AND syncid=?");
  psql_bind_uint(res, 1, localfolderid);
  psql_bind_uint(res, 2, syncid);
  psql_run_free(res);
  if (psql_affected()) {
    res = psql_prepare(
        "DELETE FROM syncedfolder WHERE localfolderid=?");
    psql_bind_uint(res, 1, localfolderid);
    psql_run_free(res);
  }
  ppathstatus_syncfldr_deleted(syncid, localfolderid);
}

static int task_del_folder_rec(psync_folderid_t localfolderid,
                               psync_folderid_t folderid,
                               psync_syncid_t syncid) {
  char *localpath;
  psync_sql_res *res;
  task_wait_no_downloads();
  psync_stop_localscan();
  localpath = pfolder_lpath_lfldr(localfolderid, syncid, NULL);
  if (pdbg_unlikely(!localpath)) {
    psync_resume_localscan();
    return 0;
  }
  pdbg_logf(D_NOTICE, "got recursive delete for localfolder %lu %s",
        (unsigned long)localfolderid, localpath);
  psql_start();
  task_del_folder_rec_do(localpath, localfolderid, syncid);
  res = psql_prepare(
      "DELETE FROM localfolder WHERE id=? AND syncid=?");
  psql_bind_uint(res, 1, localfolderid);
  psql_bind_uint(res, 2, syncid);
  psql_run_free(res);
  if (psql_affected()) {
    res = psql_prepare(
        "DELETE FROM syncedfolder WHERE localfolderid=?");
    psql_bind_uint(res, 1, localfolderid);
    psql_run_free(res);
  }
  psql_commit();
  psync_rmdir_with_trashes(localpath);
  psync_resume_localscan();
  return 0;
}

static int download_task(uint64_t taskid, uint32_t type, psync_syncid_t syncid,
                         uint64_t itemid, uint64_t localitemid,
                         uint64_t newitemid, const char *name,
                         psync_syncid_t newsyncid) {
  int res;
  const char *ptr;
  char *vname;
  vname = NULL;
  if (name && type != PSYNC_DELETE_LOCAL_FILE &&
      type != PSYNC_DELETE_LOCAL_FOLDER)
    for (ptr = name; *ptr; ptr++)
      if (pfile_invalid_chars[(unsigned char)*ptr]) {
        if (!vname)
          vname = psync_strdup(name);
        vname[ptr - name] = PSYNC_REPLACE_INV_CH_IN_FILENAMES;
      }
  if (vname) {
    pdbg_logf(D_NOTICE, "%u %s as %s", (unsigned)type, name, vname);
    name = vname;
  }
  switch (type) {
  case PSYNC_CREATE_LOCAL_FOLDER:
    res = call_func_for_folder(localitemid, itemid, syncid,
                               PEVENT_LOCAL_FOLDER_CREATED, task_mkdir, 1,
                               "local folder created");
    break;
  case PSYNC_DELETE_LOCAL_FOLDER:
    res = call_func_for_folder_name(localitemid, itemid, name, syncid,
                                    PEVENT_LOCAL_FOLDER_DELETED, task_rmdir, 0,
                                    "local folder deleted");
    if (!res) {
      psql_start();
      delete_local_folder_from_db(localitemid, syncid);
      psql_commit();
    }
    break;
  case PSYNC_DELREC_LOCAL_FOLDER:
    res = task_del_folder_rec(localitemid, itemid, syncid);
    break;
  case PSYNC_RENAME_LOCAL_FOLDER:
    res = task_renamefolder(syncid, itemid, localitemid, newitemid, name);
    break;
  case PSYNC_DOWNLOAD_FILE:
    res = task_run_download_file(taskid, syncid, itemid, localitemid, name);
    break;
  case PSYNC_DELETE_LOCAL_FILE:
    res = task_delete_file(syncid, itemid, name);
    break;
  case PSYNC_RENAME_LOCAL_FILE:
    res = task_rename_file(syncid, newsyncid, itemid, localitemid, newitemid,
                           name);
    break;
  default:
    pdbg_logf(D_BUG, "invalid task type %u", (unsigned)type);
    res = 0;
  }
  if (res && type != PSYNC_DOWNLOAD_FILE)
    pdbg_logf(D_WARNING, "task of type %u, syncid %u, id %lu localid %lu failed",
          (unsigned)type, (unsigned)syncid, (unsigned long)itemid,
          (unsigned long)localitemid);
  free(vname);
  return res;
}

static void download_thread() {
  psync_variant *row;
  uint64_t taskid;
  uint32_t type;
  while (psync_do_run) {
    pstatus_wait_statuses_arr(requiredstatuses, ARRAY_SIZE(requiredstatuses));

    row = psql_row(
        "SELECT id, type, syncid, itemid, localitemid, newitemid, name, "
        "newsyncid FROM task WHERE "
        "inprogress=0 AND type&" NTO_STR(PSYNC_TASK_DWLUPL_MASK) "=" NTO_STR(
            PSYNC_TASK_DOWNLOAD) " ORDER BY id LIMIT 1");
    if (row) {
      taskid = psync_get_number(row[0]);
      type = psync_get_number(row[1]);
      if (!download_task(taskid, type, psync_get_number_or_null(row[2]),
                         psync_get_number(row[3]), psync_get_number(row[4]),
                         psync_get_number_or_null(row[5]),
                         psync_get_string_or_null(row[6]),
                         psync_get_number_or_null(row[7]))) {
        delete_task(taskid);
        if (type == PSYNC_DOWNLOAD_FILE) {
          pstatus_download_recalc_async();
          ppathstatus_syncfldr_task_completed(
              psync_get_number(row[2]), psync_get_number(row[4]));
        }
      } else if (type != PSYNC_DOWNLOAD_FILE)
        psys_sleep_milliseconds(PSYNC_SLEEP_ON_FAILED_DOWNLOAD);
      free(row);
      continue;
    }

    pthread_mutex_lock(&download_mutex);
    if (!download_wakes)
      pthread_cond_wait(&download_cond, &download_mutex);
    download_wakes = 0;
    pthread_mutex_unlock(&download_mutex);
  }
}

void pdownload_wake() {
  pthread_mutex_lock(&download_mutex);
  if (!download_wakes++)
    pthread_cond_signal(&download_cond);
  pthread_mutex_unlock(&download_mutex);
}

void pdownload_init() {
  ptimer_exception_handler(pdownload_wake);
  prun_thread("download main", download_thread);
}

void pdownload_tasks_delete(psync_fileid_t fileid,
                                          psync_syncid_t syncid, int deltemp) {
  psync_sql_res *res;
  download_list_t *dwl;
  uint32_t aff;
  if (syncid)
    res = psql_prepare(
        "DELETE FROM task WHERE type=? AND itemid=? AND syncid=?");
  else
    res =
        psql_prepare("DELETE FROM task WHERE type=? AND itemid=?");
  psql_bind_uint(res, 1, PSYNC_DOWNLOAD_FILE);
  psql_bind_uint(res, 2, fileid);
  if (syncid)
    psql_bind_uint(res, 3, syncid);
  psql_run(res);
  aff = psql_affected();
  psql_free(res);
  if (aff)
    pstatus_download_recalc_async();
  if (deltemp)
    deltemp = 2;
  else
    deltemp = 1;
  pthread_mutex_lock(&current_downloads_mutex);
  psync_list_for_each_element(dwl, &downloads, download_list_t,
                              list) if (dwl->fileid == fileid &&
                                        (syncid == 0 || dwl->syncid == syncid))
      dwl->stop = deltemp;
  pthread_mutex_unlock(&current_downloads_mutex);
}

void pdownload_stop_file(psync_fileid_t fileid, psync_syncid_t syncid) {
  download_list_t *dwl;
  pthread_mutex_lock(&current_downloads_mutex);
  psync_list_for_each_element(dwl, &downloads, download_list_t,
                              list) if (dwl->fileid == fileid &&
                                        dwl->syncid == syncid) dwl->stop = 1;
  pthread_mutex_unlock(&current_downloads_mutex);
}

void pdownload_stop_sync(psync_syncid_t syncid) {
  download_list_t *dwl;
  psync_sql_res *res;
  res = psql_prepare(
      "DELETE FROM task WHERE syncid=? AND type&" NTO_STR(
          PSYNC_TASK_DWLUPL_MASK) "=" NTO_STR(PSYNC_TASK_DOWNLOAD));
  psql_bind_uint(res, 1, syncid);
  psql_run_free(res);
  pstatus_download_recalc_async();
  pthread_mutex_lock(&current_downloads_mutex);
  psync_list_for_each_element(dwl, &downloads, download_list_t,
                              list) if (dwl->syncid == syncid) dwl->stop = 1;
  pthread_mutex_unlock(&current_downloads_mutex);
}

void pdownload_stop_all() {
  download_list_t *dwl;
  pthread_mutex_lock(&current_downloads_mutex);
  psync_list_for_each_element(dwl, &downloads, download_list_t, list)
      dwl->stop = 1;
  pthread_mutex_unlock(&current_downloads_mutex);
}

download_hashes_t *pdownload_get_hashes() {
  download_list_t *dwl;
  download_hashes_t *ret;
  size_t cnt;
  cnt = 0;
  pthread_mutex_lock(&current_downloads_mutex);
  psync_list_for_each_element(dwl, &downloads, download_list_t, list) cnt++;
  ret = (download_hashes_t *)malloc(
      offsetof(download_hashes_t, hashes) +
      sizeof(psync_hex_hash) * cnt);
  cnt = 0;
  psync_list_for_each_element(dwl, &downloads, download_list_t,
                              list) if (dwl->schecksum[0] && dwl->started) {
    memcpy(ret->hashes[cnt], dwl->schecksum, PSYNC_HASH_DIGEST_HEXLEN);
    cnt++;
  }
  ret->hashcnt = cnt;
  pthread_mutex_unlock(&current_downloads_mutex);
  return ret;
}
