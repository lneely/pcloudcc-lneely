/*
  Copyright (c) 2013-2016 Anton Titov.

  Copyright (c) 2013-2016 pCloud Ltd.  All rights reserved.

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
#include <fuse.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <stdatomic.h>

#include "pcompiler.h"
#include "pcryptofolder.h"
#include "pfile.h"
#include "pfoldersync.h"
#include "pfs.h"
#include "pfscrypto.h"
#include "pfsfolder.h"
#include "pfsstatic.h"
#include "pfstasks.h"
#include "pfsupload.h"
#include "pfsxattr.h"
#include "plibs.h"
#include "pnetlibs.h"
#include "ppagecache.h"
#include "ppath.h"
#include "prun.h"
#include "psettings.h"
#include "psql.h"
#include "pssl.h"
#include "pstatus.h"
#include "psys.h"
#include "ptimer.h"


#ifndef FUSE_STAT
#define FUSE_STAT stat
#endif

#ifndef HAS_FUSE_OFF_T
typedef off_t fuse_off_t;
#endif

#include <signal.h>

#include <sys/mount.h>

#define pfs_set_thread_name()                                             \
  do {                                                                         \
    if (IS_DEBUG) psync_thread_name = __FUNCTION__;                            \
  } while (0)

#define fh_to_openfile(x) ((psync_openfile_t *)((uintptr_t)x))
#define openfile_to_fh(x) ((uintptr_t)x)

#define FS_BLOCK_SIZE 4096
// #define FS_MAX_WRITE  16*1024*1024 // unused, maybe important later

#define PSYNC_FS_ERR_CRYPTO_EXPIRED EROFS
#define PSYNC_FS_ERR_MOVE_ACROSS_CRYPTO EXDEV

static int shutdown_in_progress = 0;
static struct fuse *psync_fuse = NULL;
#if FUSE_USE_VERSION < 30
static struct fuse_chan *psync_fuse_channel = NULL;
#endif
static char *psync_current_mountpoint = NULL;
static psync_generic_callback_t psync_start_callback = NULL;
char *pfs_fake_prefix = NULL;
size_t pfs_fake_prefix_len = 0;
static int64_t psync_fake_fileid = INT64_MIN;

static pthread_mutex_t start_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t start_cond = PTHREAD_COND_INITIALIZER;
static int started = 0;
static int initonce = 0;
static int waitingforlogin = 0;

static uid_t myuid = 0;
static gid_t mygid = 0;

extern int errno;

psync_tree *openfiles = PSYNC_TREE_EMPTY;

__attribute__((weak)) void pfs_debug_init_file_mutex(pthread_mutex_t *m) {
  pthread_mutex_init(m, NULL);
}
__attribute__((weak)) void pfs_debug_dump_internals() {}
__attribute__((weak)) void pfs_debug_register_signal_handlers() {}

static int pfs_ftruncate_of_locked(psync_openfile_t *of, fuse_off_t size);

static inline int psync_crypto_is_error(const void *ptr) {
  return (uintptr_t)ptr <= PSYNC_CRYPTO_MAX_ERROR;
}

static inline int psync_crypto_to_error(const void *ptr) {
  return -((int)(uintptr_t)ptr);
}

static void delete_log_files(psync_openfile_t *of) {
  char fileidhex[sizeof(psync_fsfileid_t) * 2 + 2];
  const char *cachepath;
  char *filename;
  psync_fsfileid_t fileid;
  cachepath = psync_setting_get_string(_PS(fscachepath));
  fileid = -of->fileid;
  psync_binhex(fileidhex, &fileid, sizeof(psync_fsfileid_t));
  fileidhex[sizeof(psync_fsfileid_t)] = 'l';
  fileidhex[sizeof(psync_fsfileid_t) + 1] = 0;
  filename =
      putil_strcat(cachepath, "/", fileidhex, NULL);
  pfile_delete(filename);
  free(filename);
  fileidhex[sizeof(psync_fsfileid_t)] = 'f';
  filename =
      putil_strcat(cachepath, "/", fileidhex, NULL);
  pfile_delete(filename);
  free(filename);
}

int pfs_update_openfile(uint64_t taskid, uint64_t writeid,
                             psync_fileid_t newfileid, uint64_t hash,
                             uint64_t size, time_t ctime) {
  psync_sql_res *res;
  psync_uint_row row;
  psync_openfile_t *fl;
  psync_tree *tr;
  psync_fsfileid_t fileid;
  int64_t d;
  int ret;
  fileid = -(psync_fsfileid_t)taskid;
  psql_lock();
  tr = openfiles;
  while (tr) {
    d = fileid - ptree_element(tr, psync_openfile_t, tree)->fileid;
    if (d < 0)
      tr = tr->left;
    else if (d > 0)
      tr = tr->right;
    else {
      fl = ptree_element(tr, psync_openfile_t, tree);
      pfs_lock_file(fl);
      if (fl->writeid == writeid) {
        if (fl->encrypted) {
          if (fl->logfile) {
            pfile_close(fl->logfile);
            fl->logfile = INVALID_HANDLE_VALUE;
          }
          delete_log_files(fl);
          if (fl->authenticatedints) {
            psync_interval_tree_free(fl->authenticatedints);
            fl->authenticatedints = NULL;
          }
          size = pfs_crpt_plain_size(size);
        }
        pdbg_logf(D_NOTICE, "updating fileid %ld to %lu, hash %lu size %lu",
              (long)fileid, (unsigned long)newfileid, (unsigned long)hash,
              (unsigned long)size);
        fl->fileid = newfileid;
        fl->remotefileid = newfileid;
        fl->hash = hash;
        fl->modified = 0;
        fl->newfile = 0;
        fl->currentsize = size;
        fl->initialsize = size;
        fl->releasedforupload = 0;
        fl->origctime = ctime;
        if (fl->datafile != INVALID_HANDLE_VALUE) {
          pfile_close(fl->datafile);
          fl->datafile = INVALID_HANDLE_VALUE;
        }
        if (fl->indexfile != INVALID_HANDLE_VALUE) {
          pfile_close(fl->indexfile);
          fl->indexfile = INVALID_HANDLE_VALUE;
        }
        ptree_del(&openfiles, &fl->tree);
        tr = openfiles;
        d = -1;
        while (tr) {
          d = newfileid -
              ptree_element(tr, psync_openfile_t, tree)->fileid;
          if (d < 0) {
            if (tr->left)
              tr = tr->left;
            else
              break;
          } else if (d > 0) {
            if (tr->right)
              tr = tr->right;
            else
              break;
          } else {
            pdbg_logf(D_BUG, "found already open file %lu, re-inserting old fileid",
                  (unsigned long)newfileid);
            tr = openfiles;
            d = -1;
            while (tr) {
              d = fileid - ptree_element(tr, psync_openfile_t, tree)->fileid;
              if (d < 0) {
                if (tr->left)
                  tr = tr->left;
                else
                  break;
              } else if (d > 0) {
                if (tr->right)
                  tr = tr->right;
                else
                  break;
              } else
                break;
            }
            if (d < 0)
              ptree_add_before(&openfiles, tr, &fl->tree);
            else
              ptree_add_after(&openfiles, tr, &fl->tree);
            ret = -1;
            goto unlock_ret;
          }
        }
        fl->fileid = newfileid;
        if (d < 0)
          ptree_add_before(&openfiles, tr, &fl->tree);
        else
          ptree_add_after(&openfiles, tr, &fl->tree);
        ret = 0;
      } else {
        pdbg_logf(D_NOTICE, "writeid of fileid %ld (%s) differs %lu!=%lu",
              (long)fileid, fl->currentname, (unsigned long)fl->writeid,
              (unsigned long)writeid);
        if (fl->newfile) {
          res = psql_prepare(
              "REPLACE INTO fstaskfileid (fstaskid, fileid) VALUES (?, ?)");
          psql_bind_uint(res, 1, taskid);
          psql_bind_uint(res, 2, newfileid);
          psql_run_free(res);
        }
        ret = -1;
      }
unlock_ret:
      pthread_mutex_unlock(&fl->mutex);
      psql_unlock();
      return ret;
    }
  }
  res = psql_query("SELECT int1 FROM fstask WHERE id=?");
  psql_bind_uint(res, 1, taskid);
  if ((row = psql_fetch_int(res)) && row[0] == writeid)
    ret = 0;
  else {
    if (row)
      pdbg_logf(D_NOTICE, "writeid of fileid %ld differs %lu!=%lu", (long)fileid,
            (unsigned long)row[0], (unsigned long)writeid);
    ret = -1;
  }
  psql_free(res);
  psql_unlock();
  return ret;
}

/*void pfs_uploading_openfile(uint64_t taskid){
  psync_openfile_t *fl;
  psync_tree *tr;
  psync_fsfileid_t fileid;
  int64_t d;
  fileid=-taskid;
  psql_lock();
  tr=openfiles;
  while (tr){
    d=fileid-ptree_element(tr, psync_openfile_t, tree)->fileid;
    if (d<0)
      tr=tr->left;
    else if (d>0)
      tr=tr->right;
    else{
      fl=ptree_element(tr, psync_openfile_t, tree);
      pfs_lock_file(fl);
      fl->uploading=1;
      pthread_mutex_unlock(&fl->mutex);
      break;
    }
  }
  psql_unlock();
}*/

int pfs_rename_openfile_locked(psync_fsfileid_t fileid,
                                    psync_fsfolderid_t folderid,
                                    const char *name) {
  psync_openfile_t *fl;
  psync_tree *tr;
  int64_t d;
  tr = openfiles;
  while (tr) {
    d = fileid - ptree_element(tr, psync_openfile_t, tree)->fileid;
    if (d < 0)
      tr = tr->left;
    else if (d > 0)
      tr = tr->right;
    else {
      fl = ptree_element(tr, psync_openfile_t, tree);
      pfs_lock_file(fl);
      if (fl->currentfolder->folderid != folderid) {
        pfs_task_release_folder_tasks_locked(fl->currentfolder);
        fl->currentfolder =
            pfs_task_get_or_create_folder_tasks_locked(folderid);
      }
      char *newname = putil_strdup(name);
      if (!newname) {
        pthread_mutex_unlock(&fl->mutex);
        return -ENOMEM;
      }
      free(fl->currentname);
      fl->currentname = newname;
      pthread_mutex_unlock(&fl->mutex);
      return 1;
    }
  }
  return 0;
}

void pfs_mark_openfile_deleted(uint64_t taskid) {
  psync_sql_res *res;
  psync_openfile_t *fl;
  psync_tree *tr;
  int64_t d;
  psync_fsfileid_t fileid;
  fileid = -(psync_fsfileid_t)taskid;
  psql_lock();
  tr = openfiles;
  while (tr) {
    d = fileid - ptree_element(tr, psync_openfile_t, tree)->fileid;
    if (d < 0)
      tr = tr->left;
    else if (d > 0)
      tr = tr->right;
    else {
      fl = ptree_element(tr, psync_openfile_t, tree);
      pdbg_logf(D_NOTICE, "file being deleted %s is still open, marking as deleted",
            fl->currentname);
      pfs_lock_file(fl);
      fl->deleted = 1;
      pthread_mutex_unlock(&fl->mutex);
      res = psql_prepare("UPDATE fstask SET status=12 WHERE id=?");
      psql_bind_uint(res, 1, taskid);
      psql_run_free(res);
      break;
    }
  }
  psql_unlock();
}

int64_t pfs_get_file_writeid(uint64_t taskid) {
  psync_openfile_t *fl;
  psync_tree *tr;
  psync_sql_res *res;
  psync_uint_row row;
  psync_fsfileid_t fileid;
  int64_t d;
  fileid = -(psync_fsfileid_t)taskid;
  psql_rdlock();
  tr = openfiles;
  while (tr) {
    d = fileid - ptree_element(tr, psync_openfile_t, tree)->fileid;
    if (d < 0)
      tr = tr->left;
    else if (d > 0)
      tr = tr->right;
    else {
      fl = ptree_element(tr, psync_openfile_t, tree);
      pfs_lock_file(fl);
      d = fl->writeid;
      pthread_mutex_unlock(&fl->mutex);
      psql_rdunlock();
      return d;
    }
  }
  res = psql_query_nolock("SELECT int1 FROM fstask WHERE id=?");
  psql_bind_uint(res, 1, taskid);
  if ((row = psql_fetch_int(res)))
    d = row[0];
  else
    d = -1;
  psql_free(res);
  psql_rdunlock();
  return d;
}

static void pfs_update_openfile_fileid_locked(psync_openfile_t *of,
                                            psync_fsfileid_t fileid) {
  psync_tree *tr;
  int64_t d;
  pdbg_assertw(of->fileid != fileid);
  ptree_del(&openfiles, &of->tree);
  of->fileid = fileid;
  tr = openfiles;
  if (tr)
    while (1) {
      d = fileid - ptree_element(tr, psync_openfile_t, tree)->fileid;
      if (d < 0) {
        if (tr->left)
          tr = tr->left;
        else {
          tr->left = &of->tree;
          break;
        }
      } else {
        pdbg_assertw(d > 0);
        if (tr->right)
          tr = tr->right;
        else {
          tr->right = &of->tree;
          break;
        }
      }
    }
  else
    openfiles = &of->tree;
  ptree_added_at(&openfiles, tr, &of->tree);
}

#define folderid_to_inode(folderid) ((folderid) * 3)
#define fileid_to_inode(fileid) ((fileid) * 3 + 1)
#define taskid_to_inode(taskid) ((taskid) * 3 + 2)

static void psync_row_to_folder_stat(psync_variant_row row,
                                     struct FUSE_STAT *stbuf) {
  psync_folderid_t folderid;
  uint64_t mtime;
  psync_fstask_folder_t *folder;
  folderid = psync_get_number(row[0]);
  mtime = psync_get_number(row[3]);
  folder = pfs_task_get_folder_tasks_rdlocked(folderid);
  if (folder && folder->mtime)
    mtime = folder->mtime;
  memset(stbuf, 0, sizeof(struct FUSE_STAT));
  stbuf->st_ino = folderid_to_inode(folderid);
#ifdef FUSE_STAT_HAS_BIRTHTIME
  stbuf->st_birthtime = psync_get_number(row[2]);
#endif
  stbuf->st_ctime = mtime;
  stbuf->st_mtime = mtime;
  stbuf->st_atime = mtime;
  stbuf->st_mode = S_IFDIR | 0755;
  stbuf->st_nlink = psync_get_number(row[4]) + 2;
  stbuf->st_size = FS_BLOCK_SIZE;
  stbuf->st_blocks = 1;
  stbuf->st_blksize = FS_BLOCK_SIZE;
  stbuf->st_uid = myuid;
  stbuf->st_gid = mygid;
}

static void psync_row_to_file_stat(psync_variant_row row,
                                   struct FUSE_STAT *stbuf, uint32_t flags) {
  uint64_t size;
  stbuf->st_ino = fileid_to_inode(psync_get_number(row[4]));
  size = psync_get_number(row[1]);
  if (flags & PSYNC_FOLDER_FLAG_ENCRYPTED)
    size = pfs_crpt_plain_size(size);
  memset(stbuf, 0, sizeof(struct FUSE_STAT));
#ifdef FUSE_STAT_HAS_BIRTHTIME
  stbuf->st_birthtime = psync_get_number(row[2]);
#endif
  stbuf->st_ctime = psync_get_number(row[3]);
  stbuf->st_mtime = stbuf->st_ctime;
  stbuf->st_atime = stbuf->st_ctime;
  stbuf->st_mode = S_IFREG | 0644;
  stbuf->st_nlink = 1;
  stbuf->st_size = size;
  stbuf->st_blocks = (size + 511) / 512;
  stbuf->st_blksize = FS_BLOCK_SIZE;
  stbuf->st_uid = myuid;
  stbuf->st_gid = mygid;
}

static void psync_mkdir_to_folder_stat(psync_fstask_mkdir_t *mk,
                                       struct FUSE_STAT *stbuf) {
  uint64_t mtime;
  psync_fstask_folder_t *folder;
  folder = pfs_task_get_folder_tasks_rdlocked(mk->folderid);
  if (folder && folder->mtime)
    mtime = folder->mtime;
  else
    mtime = mk->mtime;
  memset(stbuf, 0, sizeof(struct FUSE_STAT));
  if (mk->folderid >= 0)
    stbuf->st_ino = folderid_to_inode(mk->folderid);
  else
    stbuf->st_ino = taskid_to_inode(-mk->folderid);
#ifdef FUSE_STAT_HAS_BIRTHTIME
  stbuf->st_birthtime = mk->ctime;
#endif
  stbuf->st_ctime = mtime;
  stbuf->st_mtime = mtime;
  stbuf->st_atime = mtime;
  stbuf->st_mode = S_IFDIR | 0755;
  stbuf->st_nlink = mk->subdircnt + 2;
  stbuf->st_size = FS_BLOCK_SIZE;
  stbuf->st_blocks = 1;
  stbuf->st_blksize = FS_BLOCK_SIZE;
  stbuf->st_uid = myuid;
  stbuf->st_gid = mygid;
}

static int psync_creat_db_to_file_stat(psync_fileid_t fileid,
                                       struct FUSE_STAT *stbuf,
                                       uint32_t flags) {
  psync_sql_res *res;
  psync_variant_row row;
  res = psql_query_rdlock("SELECT name, size, ctime, mtime, id, "
                               "parentfolderid FROM file WHERE id=?");
  psql_bind_uint(res, 1, fileid);
  if ((row = psql_fetch(res)))
    psync_row_to_file_stat(row, stbuf, flags);
  else
    pdbg_logf(D_NOTICE, "fileid %lu not found in database", (unsigned long)fileid);
  psql_free(res);
  return row ? 0 : -1;
}

static int psync_creat_stat_fake_file(struct FUSE_STAT *stbuf) {
  time_t ctime;
  memset(stbuf, 0, sizeof(struct FUSE_STAT));
  ctime = ptimer_time();
#ifdef FUSE_STAT_HAS_BIRTHTIME
  stbuf->st_birthtime = ctime;
#endif
  stbuf->st_ctime = ctime;
  stbuf->st_mtime = ctime;
  stbuf->st_atime = ctime;
  stbuf->st_mode = S_IFREG | 0644;
  stbuf->st_nlink = 1;
  stbuf->st_size = 0;
  stbuf->st_blocks = 0;
  stbuf->st_blksize = FS_BLOCK_SIZE;
  stbuf->st_uid = myuid;
  stbuf->st_gid = mygid;
  return 0;
}

static int fill_stat_from_open_file(psync_fsfileid_t fileid,
                                    struct FUSE_STAT *stbuf) {
  psync_openfile_t *fl;
  psync_tree *tr;
  struct stat st;
  int64_t d;
  psql_rdlock();
  tr = openfiles;
  while (tr) {
    d = fileid - ptree_element(tr, psync_openfile_t, tree)->fileid;
    if (d < 0)
      tr = tr->left;
    else if (d > 0)
      tr = tr->right;
    else {
      fl = ptree_element(tr, psync_openfile_t, tree);
      pfs_lock_file(fl);
      stbuf->st_size = fl->currentsize;
      pdbg_logf(D_NOTICE, "found open file with size %lu",
            (unsigned long)fl->currentsize);
      if (!fstat(fl->logfile, &st))
        stbuf->st_mtime = pfile_stat_mtime(&st);
      pthread_mutex_unlock(&fl->mutex);
      psql_rdunlock();
      return 1;
    }
  }
  psql_rdunlock();
  return 0;
}

static int psync_creat_local_to_file_stat(psync_fstask_creat_t *cr,
                                          struct FUSE_STAT *stbuf,
                                          uint32_t folderflags) {
  struct stat st;
  psync_fsfileid_t fileid;
  uint64_t size;
  const char *cachepath;
  char *filename;
  psync_openfile_t *fl;
  psync_tree *tr;
  int64_t d;
  //  int fd;
  char fileidhex[sizeof(psync_fsfileid_t) * 2 + 2];
  int stret;
  if (unlikely(pfs_need_per_folder_refresh_const() &&
               cr->fileid < psync_fake_fileid))
    return psync_creat_stat_fake_file(stbuf);
  fl = NULL;
  fileid = -cr->fileid;
  psql_rdlock();
  tr = openfiles;
  while (tr) {
    d = cr->fileid - ptree_element(tr, psync_openfile_t, tree)->fileid;
    if (d < 0)
      tr = tr->left;
    else if (d > 0)
      tr = tr->right;
    else {
      fl = ptree_element(tr, psync_openfile_t, tree);
      pfs_lock_file(fl);
      break;
    }
  }
  psql_rdunlock();
  if (fl && fl->datafile != INVALID_HANDLE_VALUE) {
    stret = fstat(fl->datafile, &st);
    pthread_mutex_unlock(&fl->mutex);
    if (stret)
      pdbg_logf(D_NOTICE, "could not stat open file %ld", (long)cr->fileid);
    else
      pdbg_logf(D_NOTICE, "got stat from open file %ld", (long)cr->fileid);
  } else {
    if (fl)
      pthread_mutex_unlock(&fl->mutex);
    psync_binhex(fileidhex, &fileid, sizeof(psync_fsfileid_t));
    fileidhex[sizeof(psync_fsfileid_t)] = 'd';
    fileidhex[sizeof(psync_fsfileid_t) + 1] = 0;
    cachepath = psync_setting_get_string(_PS(fscachepath));
    filename =
        putil_strcat(cachepath, "/", fileidhex, NULL);
    stret = stat(filename, &st);
    if (stret)
      pdbg_logf(D_NOTICE, "could not stat file %s", filename);
    free(filename);
  }
  if (stret)
    return -1;
  /*  if (cr->newfile)
      osize=0;
    else{
      fileidhex[sizeof(psync_fsfileid_t)]='i';
      filename=putil_strcat(cachepath, "/", fileidhex,
    NULL); fd=pfile_open(filename, O_RDONLY, 0); free(filename); if
    (fd==INVALID_HANDLE_VALUE) return -EIO; stret=pfile_pread(fd, &osize,
    sizeof(osize), offsetof(index_header, copyfromoriginal));
      pfile_close(fd);
      if (stret!=sizeof(osize))
        return -EIO;
    }*/
  memset(stbuf, 0, sizeof(struct FUSE_STAT));
  stbuf->st_ino = taskid_to_inode(fileid);
#ifdef FUSE_STAT_HAS_BIRTHTIME
  stbuf->st_birthtime = pfile_stat_birthtime(&st);
#endif
  stbuf->st_mtime = pfile_stat_mtime(&st);
  stbuf->st_ctime = stbuf->st_mtime;
  stbuf->st_atime = stbuf->st_mtime;
  stbuf->st_mode = S_IFREG | 0644;
  stbuf->st_nlink = 1;
  if (folderflags & PSYNC_FOLDER_FLAG_ENCRYPTED) {
    if (fill_stat_from_open_file(cr->fileid, stbuf))
      size = stbuf->st_size;
    else {
      size = pfs_crpt_plain_size(pfile_stat_size(&st));
      stbuf->st_size = size;
    }
  } else {
    size = pfile_stat_size(&st);
    stbuf->st_size = size;
  }
  stbuf->st_blocks = (size + 511) / 512;
  stbuf->st_blksize = FS_BLOCK_SIZE;
  stbuf->st_uid = myuid;
  stbuf->st_gid = mygid;
  return 0;
}

static int psync_creat_static_to_file_stat(psync_fstask_creat_t *cr,
                                           struct FUSE_STAT *stbuf,
                                           uint32_t folderflags) {
  psync_fstask_local_creat_t *lc;
  lc = pfs_task_creat_get_local(cr);
  memset(stbuf, 0, sizeof(struct FUSE_STAT));
  stbuf->st_ino = cr->taskid;
#ifdef FUSE_STAT_HAS_BIRTHTIME
  stbuf->st_birthtime = lc->ctime;
#endif
  stbuf->st_ctime = lc->ctime;
  stbuf->st_mtime = lc->ctime;
  stbuf->st_atime = lc->ctime;
  stbuf->st_mode = S_IFREG | 0644;
  stbuf->st_nlink = 1;
  stbuf->st_size = lc->datalen;
  stbuf->st_blocks = (lc->datalen + 511) / 512;
  stbuf->st_blksize = FS_BLOCK_SIZE;
  stbuf->st_uid = myuid;
  stbuf->st_gid = mygid;
  return 0;
}

static int psync_creat_to_file_stat(psync_fstask_creat_t *cr,
                                    struct FUSE_STAT *stbuf,
                                    uint32_t folderflags) {
  pdbg_logf(D_NOTICE, "getting stat from creat for file %s fileid %ld taskid %lu",
        cr->name, (long)cr->fileid, (unsigned long)cr->taskid);
  if (cr->fileid > 0)
    return psync_creat_db_to_file_stat(cr->fileid, stbuf, folderflags);
  else if (cr->fileid < 0)
    return psync_creat_local_to_file_stat(cr, stbuf, folderflags);
  else
    return psync_creat_static_to_file_stat(cr, stbuf, folderflags);
}

int pfs_crypto_err_to_errno(int cryptoerr) {
  switch (cryptoerr) {
  case PSYNC_CRYPTO_NOT_STARTED:
    return EACCES;
  case PSYNC_CRYPTO_RSA_ERROR:
    return EIO;
  case PSYNC_CRYPTO_FOLDER_NOT_FOUND:
    return ENOENT;
  case PSYNC_CRYPTO_FILE_NOT_FOUND:
    return ENOENT;
  case PSYNC_CRYPTO_INVALID_KEY:
    return EIO;
  case PSYNC_CRYPTO_CANT_CONNECT:
    return ENOTCONN;
  case PSYNC_CRYPTO_FOLDER_NOT_ENCRYPTED:
    return EINVAL;
  case PSYNC_CRYPTO_INTERNAL_ERROR:
    return EINVAL;
  default:
    return EINVAL;
  }
}

static int pfs_getrootattr(struct FUSE_STAT *stbuf) {
  psync_sql_res *res;
  psync_variant_row row;
  res = psql_query_rdlock(
      "SELECT 0, 0, IFNULL(s.value, 1414766136)*1, f.mtime, f.subdircnt FROM "
      "folder f LEFT JOIN setting s ON s.id='registered' WHERE f.id=0");
  if ((row = psql_fetch(res)))
    psync_row_to_folder_stat(row, stbuf);
  psql_free(res);
  return 0;
}

#define CHECK_LOGIN_LOCKED()                                                   \
  do {                                                                         \
    if (unlikely(waitingforlogin)) {                                           \
      psql_unlock();                                                      \
      pdbg_logf(D_NOTICE, "returning EACCES for not logged in");                   \
      return -EACCES;                                                          \
    }                                                                          \
  } while (0)

#define CHECK_LOGIN_RDLOCKED()                                                 \
  do {                                                                         \
    if (unlikely(waitingforlogin)) {                                           \
      psql_rdunlock();                                                    \
      pdbg_logf(D_NOTICE, "returning EACCES for not logged in");                   \
      return -EACCES;                                                          \
    }                                                                          \
  } while (0)

static int pfs_getattr(const char *path, struct FUSE_STAT *stbuf) {
  psync_sql_res *res;
  psync_variant_row row;
  psync_fspath_t *fpath;
  psync_fstask_folder_t *folder;
  psync_fstask_creat_t *cr;
  int crr;
  pfs_set_thread_name();
  //  pdbg_logf(D_NOTICE, "getattr %s", path);
  if (path[1] == 0 && path[0] == '/')
    return pfs_getrootattr(stbuf);
  psql_rdlock();
  CHECK_LOGIN_RDLOCKED();
  fpath = pfs_fldr_resolve_path(path);
  if (!fpath) {
    psql_rdunlock();
    crr = pfs_fldr_crypto_error();
    if (crr) {
      crr = -pfs_crypto_err_to_errno(crr);
      pdbg_logf(D_NOTICE, "got crypto error for %s, returning %d", path, crr);
      return crr;
    } else {
      pdbg_logf(D_NOTICE, "could not find path component of %s, returning ENOENT",
            path);
      return -ENOENT;
    }
  }
  folder = pfs_task_get_folder_tasks_rdlocked(fpath->folderid);
  if (folder) {
    psync_fstask_mkdir_t *mk;
    mk = pfs_task_find_mkdir(folder, fpath->name, 0);
    if (mk) {
      if (mk->flags & PSYNC_FOLDER_FLAG_INVISIBLE) {
        psql_rdunlock();
        free(fpath);
        return -ENOENT;
      }
      psync_mkdir_to_folder_stat(mk, stbuf);
      psql_rdunlock();
      free(fpath);
      return 0;
    }
  }
  if (!folder || !pfs_task_find_rmdir(folder, fpath->name, 0)) {
    res = psql_query_nolock(
        "SELECT id, permissions, ctime, mtime, subdircnt FROM folder WHERE "
        "parentfolderid=? AND name=?");
    psql_bind_uint(res, 1, fpath->folderid);
    psql_bind_str(res, 2, fpath->name);
    if ((row = psql_fetch(res)))
      psync_row_to_folder_stat(row, stbuf);
    psql_free(res);
    if (row) {
      psql_rdunlock();
      free(fpath);
      return 0;
    }
  }
  res = psql_query_nolock("SELECT name, size, ctime, mtime, id FROM file "
                               "WHERE parentfolderid=? AND name=?");
  psql_bind_uint(res, 1, fpath->folderid);
  psql_bind_str(res, 2, fpath->name);
  if ((row = psql_fetch(res)))
    psync_row_to_file_stat(row, stbuf, fpath->flags);
  psql_free(res);
  if (folder) {
    if (pfs_task_find_unlink(folder, fpath->name, 0))
      row = NULL;
    if (!row && (cr = pfs_task_find_creat(folder, fpath->name, 0)))
      crr = psync_creat_to_file_stat(cr, stbuf, fpath->flags);
    else
      crr = -1;
  } else
    crr = -1;
  psql_rdunlock();
  free(fpath);
  if (row || !crr)
    return 0;
  pdbg_logf(D_NOTICE, "returning ENOENT for %s", path);
  return -ENOENT;
}

static int filler_decoded(pcrypto_textdec_t dec,
                          fuse_fill_dir_t filler, void *buf, const char *name,
                          struct FUSE_STAT *st, fuse_off_t off) {
  if (dec) {
    char *namedec;
    int ret;
    namedec = pcryptofolder_flddecode_filename(dec, name);
    if (!namedec)
      return 0;
#if FUSE_USE_VERSION >= 30
    ret = filler(buf, namedec, st, off, FUSE_FILL_DIR_PLUS);
#else
    ret = filler(buf, namedec, st, off);
#endif
    free(namedec);
    return ret;
  } else
#if FUSE_USE_VERSION >= 30
    return filler(buf, name, st, off, FUSE_FILL_DIR_PLUS);
#else
    return filler(buf, name, st, off);
#endif
}

#if FUSE_USE_VERSION >= 30
static int pfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                            fuse_off_t offset, struct fuse_file_info *fi,
                            enum fuse_readdir_flags readdir_flags) {
#else
static int pfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                            fuse_off_t offset, struct fuse_file_info *fi) {
#endif
  psync_sql_res *res;
  psync_variant_row row;
  psync_fsfolderid_t folderid;
  psync_fstask_folder_t *folder;
  psync_tree *trel;
  const char *name;
  pcrypto_textdec_t dec;
  uint32_t flags;
  size_t namelen;
  struct FUSE_STAT st;
  pfs_set_thread_name();
  pdbg_logf(D_NOTICE, "readdir %s", path);
  psql_rdlock();
  CHECK_LOGIN_RDLOCKED();
  folderid = pfs_fldr_id_by_path(path, &flags);
  if (pdbg_unlikely(folderid == PSYNC_INVALID_FSFOLDERID)) {
    psql_rdunlock();
    if (pfs_fldr_crypto_error())
      return pdbg_return(
          -pfs_crypto_err_to_errno(pfs_fldr_crypto_error()));
    else
      return -pdbg_return_const(ENOENT);
  }
  if (flags & PSYNC_FOLDER_FLAG_ENCRYPTED) {
    dec = pcryptofolder_flddecoder_get(folderid);
    if (psync_crypto_is_error(dec)) {
      psql_rdunlock();
      return pdbg_return(
          -pfs_crypto_err_to_errno(psync_crypto_to_error(dec)));
    }
  } else
    dec = NULL;
#if FUSE_USE_VERSION >= 30
  filler(buf, ".", NULL, 0, FUSE_FILL_DIR_PLUS);
  if (folderid != 0)
    filler(buf, "..", NULL, 0, FUSE_FILL_DIR_PLUS);
#else
  filler(buf, ".", NULL, 0);
  if (folderid != 0)
    filler(buf, "..", NULL, 0);
#endif
  folder = pfs_task_get_folder_tasks_rdlocked(folderid);
  if (folderid >= 0) {
    res = psql_query_nolock(
        "SELECT id, permissions, ctime, mtime, subdircnt, name FROM folder "
        "WHERE parentfolderid=?");
    psql_bind_uint(res, 1, folderid);
    while ((row = psql_fetch(res))) {
      name = psync_get_lstring(row[5], &namelen);
#if defined(FS_MAX_ACCEPTABLE_FILENAME_LEN)
      if (pdbg_unlikely(namelen > FS_MAX_ACCEPTABLE_FILENAME_LEN))
        continue;
#endif
      if (!name || !name[0])
        continue;
      if (folder && (pfs_task_find_rmdir(folder, name, 0) ||
                     pfs_task_find_mkdir(folder, name, 0)))
        continue;
      psync_row_to_folder_stat(row, &st);
      filler_decoded(dec, filler, buf, name, &st, 0);
    }
    psql_free(res);
    res = psql_query_nolock(
        "SELECT name, size, ctime, mtime, id FROM file WHERE parentfolderid=?");
    psql_bind_uint(res, 1, folderid);
    while ((row = psql_fetch(res))) {
      name = psync_get_lstring(row[0], &namelen);
#if defined(FS_MAX_ACCEPTABLE_FILENAME_LEN)
      if (pdbg_unlikely(namelen > FS_MAX_ACCEPTABLE_FILENAME_LEN))
        continue;
#endif
      if (!name || !name[0])
        continue;
      if (folder && pfs_task_find_unlink(folder, name, 0))
        continue;
      psync_row_to_file_stat(row, &st, flags);
      filler_decoded(dec, filler, buf, name, &st, 0);
    }
    psql_free(res);
  }
  if (folder) {
    ptree_for_each(trel, folder->mkdirs) {
#if defined(FS_MAX_ACCEPTABLE_FILENAME_LEN)
      if (pdbg_unlikely(
              strlen(
                  ptree_element(trel, psync_fstask_mkdir_t, tree)->name) >
              FS_MAX_ACCEPTABLE_FILENAME_LEN))
        continue;
#endif
      if (ptree_element(trel, psync_fstask_mkdir_t, tree)->flags &
          PSYNC_FOLDER_FLAG_INVISIBLE)
        continue;
      psync_mkdir_to_folder_stat(
          ptree_element(trel, psync_fstask_mkdir_t, tree), &st);
      filler_decoded(dec, filler, buf,
                     ptree_element(trel, psync_fstask_mkdir_t, tree)->name,
                     &st, 0);
    }
    ptree_for_each(trel, folder->creats) {
#if defined(FS_MAX_ACCEPTABLE_FILENAME_LEN)
      if (pdbg_unlikely(
              strlen(
                  ptree_element(trel, psync_fstask_creat_t, tree)->name) >
              FS_MAX_ACCEPTABLE_FILENAME_LEN))
        continue;
#endif
      if (!psync_creat_to_file_stat(
              ptree_element(trel, psync_fstask_creat_t, tree), &st, flags))
        filler_decoded(
            dec, filler, buf,
            ptree_element(trel, psync_fstask_creat_t, tree)->name, &st, 0);
    }
  }
  psql_rdunlock();
  if (dec)
    pcryptofolder_flddecoder_release(folderid, dec);
  return pdbg_return(0);
}

static psync_openfile_t *
pfs_create_file(psync_fsfileid_t fileid, psync_fsfileid_t remotefileid,
                     uint64_t size, uint64_t hash, int lock, uint32_t writeid,
                     psync_fstask_folder_t *folder, const char *name,
                     pcrypto_sector_encdec_t encoder) {
  psync_openfile_t *fl;
  psync_tree *tr;
  int64_t d;
  psql_lock();
  tr = openfiles;
  d = -1;
  while (tr) {
    d = fileid - ptree_element(tr, psync_openfile_t, tree)->fileid;
    if (d < 0) {
      if (tr->left)
        tr = tr->left;
      else
        break;
    } else if (d > 0) {
      if (tr->right)
        tr = tr->right;
      else
        break;
    } else {
      fl = ptree_element(tr, psync_openfile_t, tree);
      if (lock) {
        pfs_lock_file(fl);
        pfs_inc_of_refcnt_locked(fl);
      } else
        pfs_inc_of_refcnt(fl);
      pdbg_assertw(fl->currentfolder == folder);
      pdbg_assertw(!strcmp(fl->currentname, name));
      pfs_task_release_folder_tasks_locked(folder);
      psql_unlock();
      if (encoder != PSYNC_CRYPTO_INVALID_ENCODER &&
          encoder != PSYNC_CRYPTO_UNLOADED_SECTOR_ENCODER)
        pcryptofolder_filencoder_release(fileid, hash, encoder);
      pdbg_logf(D_NOTICE, "found open file %ld, refcnt %u, currentsize=%lu",
            (long int)fileid, (unsigned)fl->refcnt,
            (unsigned long)fl->currentsize);
      return fl;
    }
  }
  if (encoder == PSYNC_CRYPTO_INVALID_ENCODER) {
    fl = (psync_openfile_t *)malloc(offsetof(psync_openfile_t, encoder));
    memset(fl, 0, offsetof(psync_openfile_t, encoder));
  } else {
    fl = malloc(sizeof(psync_openfile_t));
    memset(fl, 0, sizeof(psync_openfile_t));
    size = pfs_crpt_plain_size(size);
  }
  if (d < 0)
    ptree_add_before(&openfiles, tr, &fl->tree);
  else
    ptree_add_after(&openfiles, tr, &fl->tree);
  pfs_debug_init_file_mutex(&fl->mutex);
  fl->currentfolder = folder;
  fl->currentname = putil_strdup(name);
  fl->fileid = fileid;
  fl->remotefileid = remotefileid;
  fl->hash = hash;
  fl->initialsize = size;
  fl->currentsize = size;
  fl->writeid = writeid;
  fl->datafile = INVALID_HANDLE_VALUE;
  fl->indexfile = INVALID_HANDLE_VALUE;
  fl->writetimer = PSYNC_INVALID_TIMER;
  fl->refcnt = 1;
  fl->modified = fileid < 0 ? 1 : 0;
  if (encoder != PSYNC_CRYPTO_INVALID_ENCODER) {
    fl->encrypted = 1;
    fl->encoder = encoder;
    fl->logfile = INVALID_HANDLE_VALUE;
  }
  if (lock)
    pfs_lock_file(fl);
  psql_unlock();
  return fl;
}

int64_t pfs_load_interval_tree(int fd, uint64_t size,
                                    psync_interval_tree_t **tree) {
  pfs_index_record records[512];
  uint64_t cnt;
  uint64_t i;
  ssize_t rrd, rd, j;
  if (unlikely(size < sizeof(pfs_index_header)))
    return 0;
  size -= sizeof(pfs_index_header);
  pdbg_assertw(size % sizeof(pfs_index_record) == 0);
  cnt = size / sizeof(pfs_index_record);
  pdbg_logf(D_NOTICE, "loading %lu intervals", (unsigned long)cnt);
  for (i = 0; i < cnt; i += ARRAY_SIZE(records)) {
    rd = ARRAY_SIZE(records) > cnt - i ? cnt - i : ARRAY_SIZE(records);
    rrd = pfile_pread(fd, records, rd * sizeof(pfs_index_record),
                           i * sizeof(pfs_index_record) +
                               sizeof(pfs_index_header));
    if (pdbg_unlikely(rrd != rd * sizeof(pfs_index_record)))
      return -1;
    for (j = 0; j < rd; j++)
      psync_interval_tree_add(tree, records[j].offset,
                              records[j].offset + records[j].length);
  }
  if (IS_DEBUG && *tree) {
    psync_interval_tree_t *tr;
    tr = *tree;
    pdbg_logf(D_NOTICE, "loaded approx %lu intervals",
          (unsigned long)1 << (tr->tree.height - 1));
    tr = psync_interval_tree_get_first(*tree);
    pdbg_logf(D_NOTICE, "first interval from %lu to %lu", (unsigned long)tr->from,
          (unsigned long)tr->to);
    //    while ((tr=psync_interval_tree_get_next(tr)))
    //      pdbg_logf(D_NOTICE, "next interval from %lu to %lu", (unsigned
    //      long)tr->from, (unsigned long)tr->to);
    tr = psync_interval_tree_get_last(*tree);
    pdbg_logf(D_NOTICE, "last interval from %lu to %lu", (unsigned long)tr->from,
          (unsigned long)tr->to);
  }
  return cnt;
}

static int load_interval_tree(psync_openfile_t *of) {
  pfs_index_header hdr;
  int64_t ifs;
  ifs = pfile_size(of->indexfile);
  if (pdbg_unlikely(ifs == -1))
    return -1;
  if (ifs < sizeof(pfs_index_header)) {
    pdbg_assertw(ifs == 0);
    if (pfile_pwrite(of->indexfile, &hdr, sizeof(pfs_index_header),
                          0) != sizeof(pfs_index_header))
      return -1;
    else
      return 0;
  }
  ifs = pfs_load_interval_tree(of->indexfile, ifs, &of->writeintervals);
  if (ifs == -1)
    return -1;
  else {
    of->indexoff = ifs;
    return 0;
  }
}

static int open_write_files(psync_openfile_t *of, int trunc) {
  psync_fsfileid_t fileid;
  const char *cachepath;
  char *filename;
  char fileidhex[sizeof(psync_fsfileid_t) * 2 + 2];
  int64_t fs;
  int ret;
  pdbg_logf(D_NOTICE, "opening write files of %s, trunc=%d", of->currentname,
        trunc != 0);
  fileid = -of->fileid;
  psync_binhex(fileidhex, &fileid, sizeof(psync_fsfileid_t));
  fileidhex[sizeof(psync_fsfileid_t)] = 'd';
  fileidhex[sizeof(psync_fsfileid_t) + 1] = 0;
  cachepath = psync_setting_get_string(_PS(fscachepath));
  if (of->datafile == INVALID_HANDLE_VALUE) {
    filename =
        putil_strcat(cachepath, "/", fileidhex, NULL);
    of->datafile = pfile_open(filename, O_RDWR,
                                   O_CREAT | (trunc ? O_TRUNC : 0));
    free(filename);
    if (of->datafile == INVALID_HANDLE_VALUE) {
      pdbg_logf(D_ERROR, "could not open cache file for fileid %ld",
            (long)of->fileid);
      return -EIO;
    }
    fs = pfile_size(of->datafile);
    if (pdbg_unlikely(fs == -1))
      return -EIO;
    if (of->encrypted)
      of->currentsize = pfs_crpt_plain_size(fs);
    else
      of->currentsize = fs;
  } else {
    pdbg_logf(D_NOTICE, "data file already open");
    if (trunc)
      return pfs_ftruncate_of_locked(of, 0);
    else
      return 0;
  }
  if (!of->newfile && of->indexfile == INVALID_HANDLE_VALUE) {
    fileidhex[sizeof(psync_fsfileid_t)] = 'i';
    filename =
        putil_strcat(cachepath, "/", fileidhex, NULL);
    of->indexfile = pfile_open(filename, O_RDWR,
                                    O_CREAT | (trunc ? O_TRUNC : 0));
    free(filename);
    if (of->indexfile == INVALID_HANDLE_VALUE) {
      pdbg_logf(D_ERROR, "could not open cache index file for fileid %ld",
            (long)of->fileid);
      return -EIO;
    }
    if (load_interval_tree(of)) {
      pdbg_logf(D_ERROR,
            "could not load cache file for fileid %ld to interval tree",
            (long)of->fileid);
      return -EIO;
    }
  }
  if (of->encrypted) {
    if (of->logfile == INVALID_HANDLE_VALUE) {
      fileidhex[sizeof(psync_fsfileid_t)] = 'l';
      filename =
          putil_strcat(cachepath, "/", fileidhex, NULL);
      of->logfile = pfile_open(filename, O_RDWR, O_CREAT | O_TRUNC);
      free(filename);
      if (of->logfile == INVALID_HANDLE_VALUE) {
        pdbg_logf(D_ERROR, "could not open log file for fileid %ld",
              (long)of->fileid);
        return -EIO;
      }
      ret = pfs_crpt_init_log(of);
      if (ret) {
        pdbg_logf(D_ERROR, "could not init log file for fileid %ld",
              (long)of->fileid);
        return ret;
      }
    }
  }
  return 0;
}

static void pfs_del_creat(psync_fspath_t *fpath, psync_openfile_t *of) {
  psync_fstask_creat_t *cr;
  psync_fstask_folder_t *folder;
  psync_sql_res *res;
  psql_lock();
  psql_start();
  res = psql_prepare(
      "DELETE FROM fstaskdepend WHERE dependfstaskid=?");
  psql_bind_uint(res, 1, -of->fileid);
  psql_run_free(res);
  if (psql_affected())
    pfs_upld_wake();
  res = psql_prepare("DELETE FROM fstask WHERE id=?");
  psql_bind_uint(res, 1, -of->fileid);
  psql_run_free(res);
  psql_commit();
  folder = pfs_task_get_or_create_folder_tasks_locked(fpath->folderid);
  if (likely(folder)) {
    if (likely((cr = pfs_task_find_creat(folder, fpath->name, 0)))) {
      ptree_del(&folder->creats, &cr->tree);
      folder->taskscnt--;
      free(cr);
    }
    pfs_task_release_folder_tasks_locked(folder);
  }
  pfs_dec_of_refcnt(of);
  psql_unlock();
  free(fpath);
}

static int pfs_open(const char *path, struct fuse_file_info *fi) {
  psync_sql_res *res;
  psync_uint_row row;
  psync_fsfileid_t fileid;
  uint64_t size, hash, writeid;
  psync_fspath_t *fpath;
  psync_fstask_creat_t *cr;
  psync_fstask_folder_t *folder;
  psync_openfile_t *of;
  pcrypto_sector_encdec_t encoder;
  char *encsymkey;
  size_t encsymkeylen;
  time_t ctime;
  int ret, status, type;
  pfs_set_thread_name();
  pdbg_logf(D_NOTICE, "open %s", path);
  fileid = writeid = hash = size = ctime = 0;
  psql_lock();
  CHECK_LOGIN_LOCKED();
  fpath = pfs_fldr_resolve_path(path);
  if (!fpath) {
    psql_unlock();
    ret = pfs_fldr_crypto_error();
    if (ret) {
      ret = -pfs_crypto_err_to_errno(ret);
      return pdbg_return(ret);
    } else {
      pdbg_logf(D_NOTICE, "returning ENOENT for %s, folder not found", path);
      return -ENOENT;
    }
  }
  if ((fi->flags & 3) != O_RDONLY &&
      !(fpath->permissions & PSYNC_PERM_MODIFY)) {
    psql_unlock();
    free(fpath);
    return -EACCES;
  }
  // even if there are existing files there, just don't allow opening those
  if (fpath->flags & (PSYNC_FOLDER_FLAG_BACKUP_DEVICE_LIST |
                      PSYNC_FOLDER_FLAG_BACKUP_DEVICE)) {
    psql_unlock();
    free(fpath);
    return -EACCES;
  }
  folder = pfs_task_get_or_create_folder_tasks_locked(fpath->folderid);
  row = NULL;
  if ((cr = pfs_task_find_creat(folder, fpath->name, 0))) {
    if (cr->fileid > 0) {
      res =
          psql_query("SELECT id, size, hash, ctime FROM file WHERE id=?");
      psql_bind_uint(res, 1, cr->fileid);
      row = psql_fetch_int(res);
      if (row) {
        fileid = row[0];
        size = row[1];
        hash = row[2];
        ctime = row[3];
        pdbg_logf(D_NOTICE, "opening moved regular file %lu %s size %lu hash %lu",
              (unsigned long)fileid, fpath->name, (unsigned long)size,
              (unsigned long)hash);
      }
      psql_free(res);
      if (pdbg_unlikely(!row)) {
        ret = -ENOENT;
        goto ex0;
      }
    } else if (cr->fileid < 0) {
      status = type = 0; // prevent (stupid) warnings
      res = psql_query(
          "SELECT type, status, fileid, int1, int2 FROM fstask WHERE id=?");
      psql_bind_uint(res, 1, -cr->fileid);
      row = psql_fetch_int(res);
      if (row) {
        type = row[0];
        status = row[1];
        fileid = row[2];
        writeid = row[3];
        hash = row[4];
      }
      psql_free(res);
      if (pdbg_unlikely(!row)) {
        ret = -ENOENT;
        goto ex0;
      }
      if (type == PSYNC_FS_TASK_CREAT) {
        fileid = cr->fileid;
        if (fpath->flags & PSYNC_FOLDER_FLAG_ENCRYPTED) {
          encoder = pcryptofolder_filencoder_get(fileid, hash, 1);
          if (pdbg_unlikely(psync_crypto_is_error(encoder))) {
            ret = -pfs_crypto_err_to_errno(psync_crypto_to_error(encoder));
            goto ex0;
          }
        } else
          encoder = PSYNC_CRYPTO_INVALID_ENCODER;
        of = pfs_create_file(fileid, 0, 0, 0, 1, writeid,
                                  pfs_task_get_ref_locked(folder),
                                  fpath->name, encoder);
        of->canmodify = (fpath->permissions & PSYNC_PERM_MODIFY) != 0;
        pfs_task_release_folder_tasks_locked(folder);
        psql_unlock();
        pdbg_logf(D_NOTICE, "opening new file %ld %s", (long)fileid, fpath->name);
        free(fpath);
        of->newfile = 1;
        of->releasedforupload = status != 1;
        ret = open_write_files(of, fi->flags & O_TRUNC);
        pthread_mutex_unlock(&of->mutex);
        fi->fh = openfile_to_fh(of);
        if (pdbg_unlikely(ret)) {
          pfs_dec_of_refcnt(of);
          return ret;
        } else
          return ret;
      } else if (type == PSYNC_FS_TASK_MODIFY) {
        pdbg_logf(D_NOTICE, "opening sparse file %ld %s", (long)cr->fileid,
              fpath->name);
        if (fi->flags & O_TRUNC)
          size = 0;
        else {
          res = psql_query(
              "SELECT size FROM filerevision WHERE fileid=? AND hash=?");
          psql_bind_uint(res, 1, fileid);
          psql_bind_uint(res, 2, hash);
          row = psql_fetch_int(res);
          if (row)
            size = row[0];
          psql_free(res);
          if (unlikely(!row)) {
            pdbg_logf(
                D_WARNING,
                "could not find fileid %lu with hash %lu (%ld) in filerevision",
                (unsigned long)fileid, (unsigned long)hash, (long)hash);
            ret = -ENOENT;
            goto ex0;
          }
        }
      } else {
        pdbg_logf(D_BUG, "trying to open file %s with id %ld but task type is %d",
              fpath->name, (long)cr->fileid, type);
        ret = -EIO;
        goto ex0;
      }
      if (fpath->flags & PSYNC_FOLDER_FLAG_ENCRYPTED) {
        encoder = pcryptofolder_filencoder_get(fileid, hash, 1);
        if (pdbg_unlikely(psync_crypto_is_error(encoder))) {
          ret = -pfs_crypto_err_to_errno(psync_crypto_to_error(encoder));
          goto ex0;
        }
      } else
        encoder = PSYNC_CRYPTO_INVALID_ENCODER;
      of = pfs_create_file(cr->fileid, fileid, size, hash, 1, writeid,
                                pfs_task_get_ref_locked(folder),
                                fpath->name, encoder);
      of->canmodify = (fpath->permissions & PSYNC_PERM_MODIFY) != 0;
      pfs_task_release_folder_tasks_locked(folder);
      psql_unlock();
      free(fpath);
      of->newfile = 0;
      of->releasedforupload = status != 1;
      ret = open_write_files(of, fi->flags & O_TRUNC);
      pthread_mutex_unlock(&of->mutex);
      fi->fh = openfile_to_fh(of);
      if (pdbg_unlikely(ret)) {
        pfs_dec_of_refcnt(of);
        return ret;
      } else
        return ret;

    } else { /* cr->fileid==0 */
      psync_fstask_local_creat_t *lc;
      int64_t fake_fileid;
      lc = pfs_task_creat_get_local(cr);
      fake_fileid = INT64_MIN + (int64_t)cr->taskid;
      of = pfs_create_file(fake_fileid, 0,
                                lc->datalen, 0, 1, 0,
                                pfs_task_get_ref_locked(folder),
                                fpath->name, PSYNC_CRYPTO_INVALID_ENCODER);
      of->canmodify = (fpath->permissions & PSYNC_PERM_MODIFY) != 0;
      pfs_task_release_folder_tasks_locked(folder);
      psql_unlock();
      free(fpath);
      of->modified = 1;
      of->staticfile = 1;
      of->staticdata = (const char *)lc->data;
      of->staticctime = lc->ctime;
      pthread_mutex_unlock(&of->mutex);
      fi->fh = openfile_to_fh(of);
      return 0;
    }
  }
  if (!row && fpath->folderid >= 0 &&
      !pfs_task_find_unlink(folder, fpath->name, 0)) {
    res = psql_query("SELECT id, size, hash, ctime FROM file WHERE "
                          "parentfolderid=? AND name=?");
    psql_bind_uint(res, 1, fpath->folderid);
    psql_bind_str(res, 2, fpath->name);
    row = psql_fetch_int(res);
    if (row) {
      fileid = row[0];
      size = row[1];
      hash = row[2];
      ctime = row[3];
      pdbg_logf(D_NOTICE, "opening regular file %lu %s size %lu hash %lu",
            (unsigned long)fileid, fpath->name, (unsigned long)size,
            (unsigned long)hash);
    }
    psql_free(res);
  }
  if (fi->flags & O_TRUNC || (fi->flags & O_CREAT && !row)) {
    if (fi->flags & O_TRUNC)
      pdbg_logf(D_NOTICE, "truncating file %s", path);
    else
      pdbg_logf(D_NOTICE, "creating file %s", path);
    if (fpath->flags & PSYNC_FOLDER_FLAG_ENCRYPTED) {
      if (row) {
        encoder = pcryptofolder_filencoder_get(fileid, hash, 0);
        if (pdbg_unlikely(psync_crypto_is_error(encoder))) {
          ret = -pfs_crypto_err_to_errno(psync_crypto_to_error(encoder));
          goto ex0;
        }
        encsymkey = pcryptofolder_filencoder_key_get(fileid, hash,
                                                            &encsymkeylen);
        if (pdbg_unlikely(psync_crypto_is_error(encsymkey))) {
          pcryptofolder_filencoder_release(fileid, hash, encoder);
          ret = -pfs_crypto_err_to_errno(psync_crypto_to_error(encsymkey));
          goto ex0;
        }
      } else {
        psync_symmetric_key_t symkey;
        encsymkey = pcryptofolder_filencoder_key_newplain(
            0, &encsymkeylen, &symkey);
        if (pdbg_unlikely(psync_crypto_is_error(encsymkey))) {
          ret = -pfs_crypto_err_to_errno(psync_crypto_to_error(encsymkey));
          goto ex0;
        }
        encoder = pcrypto_sec_encdec_create(symkey);
        psymkey_free(symkey);
        if (pdbg_unlikely(encoder == PSYNC_CRYPTO_INVALID_ENCODER)) {
          free(encsymkey);
          ret = -ENOMEM;
          goto ex0;
        }
      }
    } else {
      encoder = PSYNC_CRYPTO_INVALID_ENCODER;
      encsymkey = NULL;
      encsymkeylen = 0;
    }
    cr =
        pfs_task_add_creat(folder, fpath->name, 0, encsymkey, encsymkeylen);
    free(encsymkey);
    if (pdbg_unlikely(!cr)) {
      ret = -EIO;
      goto ex0;
    }
    of = pfs_create_file(cr->fileid, 0, 0, 0, 1, 0,
                              pfs_task_get_ref_locked(folder), fpath->name,
                              encoder);
    of->canmodify = (fpath->permissions & PSYNC_PERM_MODIFY) != 0;
    pfs_task_release_folder_tasks_locked(folder);
    psql_unlock();
    of->newfile = 1;
    of->modified = 1;
    ret = open_write_files(of, 1);
    pthread_mutex_unlock(&of->mutex);
    if (pdbg_unlikely(ret)) {
      pfs_del_creat(fpath, of);
      return ret;
    }
    free(fpath);
    fi->fh = openfile_to_fh(of);
    return 0;
  } else if (row) {
    if (fpath->flags & PSYNC_FOLDER_FLAG_ENCRYPTED) {
      encoder = pcryptofolder_filencoder_get(fileid, hash, 1);
      if (pdbg_unlikely(psync_crypto_is_error(encoder))) {
        ret = -pfs_crypto_err_to_errno(psync_crypto_to_error(encoder));
        goto ex0;
      }
    } else
      encoder = PSYNC_CRYPTO_INVALID_ENCODER;
    of = pfs_create_file(fileid, fileid, size, hash, 0, 0,
                              pfs_task_get_ref_locked(folder), fpath->name,
                              encoder);
    of->canmodify = (fpath->permissions & PSYNC_PERM_MODIFY) != 0;
    of->origctime = ctime;
    fi->fh = openfile_to_fh(of);
    ret = 0;
  } else
    ret = -ENOENT;
ex0:
  pfs_task_release_folder_tasks_locked(folder);
  psql_unlock();
  free(fpath);
  return ret;
}

static int pfs_file_exists_in_folder(psync_fstask_folder_t *folder,
                                          const char *name) {
  psync_fstask_creat_t *cr;
  psync_sql_res *res;
  psync_uint_row row;
  cr = pfs_task_find_creat(folder, name, 0);
  if (cr)
    return 1;
  if (folder->folderid < 0)
    return 0;
  if (pfs_task_find_unlink(folder, name, 0))
    return 0;
  res =
      psql_query("SELECT id FROM file WHERE parentfolderid=? AND name=?");
  psql_bind_uint(res, 1, folder->folderid);
  psql_bind_str(res, 2, name);
  row = psql_fetch_int(res);
  psql_free(res);
  return row ? 1 : 0;
}

static int pfs_creat_fake_locked(psync_fspath_t *fpath,
                                      struct fuse_file_info *fi) {
  psync_fstask_creat_t *cr;
  psync_fstask_folder_t *folder;
  psync_openfile_t *of;
  psync_fsfileid_t fileid;
  size_t len;
  fileid = psync_fake_fileid++;
  len = strlen(fpath->name) + 1;
  cr = (psync_fstask_creat_t *)malloc(
      offsetof(psync_fstask_creat_t, name) + len);
  cr->fileid = fileid;
  cr->rfileid = 0;
  cr->taskid = fileid;
  memcpy(cr->name, fpath->name, len);
  folder = pfs_task_get_or_create_folder_tasks_locked(fpath->folderid);
  pfs_task_inject_creat(folder, cr);
  of = pfs_create_file(fileid, 0, 0, 0, 0, 0,
                            pfs_task_get_ref_locked(folder), fpath->name,
                            PSYNC_CRYPTO_INVALID_ENCODER);
  pfs_task_release_folder_tasks_locked(folder);
  of->newfile = 0;
  of->modified = 0;
  psql_unlock();
  free(fpath);
  fi->fh = openfile_to_fh(of);
  return 0;
}

static int pfs_creat(const char *path, mode_t mode,
                          struct fuse_file_info *fi) {
  psync_fspath_t *fpath;
  psync_fstask_folder_t *folder;
  psync_fstask_creat_t *cr;
  psync_symmetric_key_t symkey;
  pcrypto_sector_encdec_t encoder;
  char *encsymkey;
  size_t encsymkeylen;
  psync_openfile_t *of;
  int ret;
  pfs_set_thread_name();
  pdbg_logf(D_NOTICE, "creat %s", path);
  psql_lock();
  CHECK_LOGIN_LOCKED();
  fpath = pfs_fldr_resolve_path(path);
  if (!fpath) {
    psql_unlock();
    ret = pfs_fldr_crypto_error();
    if (ret) {
      ret = pfs_crypto_err_to_errno(ret);
      return pdbg_return(-ret);
    } else {
      pdbg_logf(D_NOTICE, "returning ENOENT for %s, folder not found", path);
      return -ENOENT;
    }
  }
  if (unlikely(pfs_need_per_folder_refresh_const() &&
               !strncmp(pfs_fake_prefix, fpath->name, pfs_fake_prefix_len)))
    return pfs_creat_fake_locked(fpath, fi);
  if (!(fpath->permissions & PSYNC_PERM_CREATE) ||
      (fpath->flags & (PSYNC_FOLDER_FLAG_BACKUP_DEVICE_LIST |
                       PSYNC_FOLDER_FLAG_BACKUP_DEVICE))) {
    psql_unlock();
    free(fpath);
    return -EACCES;
  }
  folder = pfs_task_get_or_create_folder_tasks_locked(fpath->folderid);
  if (pfs_file_exists_in_folder(folder, fpath->name)) {
    pfs_task_release_folder_tasks_locked(folder);
    pdbg_logf(D_NOTICE, "file %s already exists, processing as open", path);
    ret = pfs_open(path, fi);
    psql_unlock();
    free(fpath);
    return ret;
  }
  if (fpath->flags & PSYNC_FOLDER_FLAG_ENCRYPTED) {
    if (psync_crypto_isexpired()) {
      pfs_task_release_folder_tasks_locked(folder);
      psql_unlock();
      free(fpath);
      return -pdbg_return_const(PSYNC_FS_ERR_CRYPTO_EXPIRED);
    }
    encsymkey = pcryptofolder_filencoder_key_newplain(
        0, &encsymkeylen, &symkey);
    if (pdbg_unlikely(psync_crypto_is_error(encsymkey))) {
      pfs_task_release_folder_tasks_locked(folder);
      psql_unlock();
      free(fpath);
      return -pfs_crypto_err_to_errno(psync_crypto_to_error(encsymkey));
    }
    encoder = pcrypto_sec_encdec_create(symkey);
    psymkey_free(symkey);
    if (pdbg_unlikely(encoder == PSYNC_CRYPTO_INVALID_ENCODER)) {
      pfs_task_release_folder_tasks_locked(folder);
      psql_unlock();
      free(fpath);
      free(encsymkey);
      return -ENOMEM;
    }
  } else {
    encoder = PSYNC_CRYPTO_INVALID_ENCODER;
    encsymkey = NULL;
    encsymkeylen = 0;
  }
  cr = pfs_task_add_creat(folder, fpath->name, 0, encsymkey, encsymkeylen);
  if (encsymkey)
    free(encsymkey);
  if (pdbg_unlikely(!cr)) {
    pfs_task_release_folder_tasks_locked(folder);
    psql_unlock();
    free(fpath);
    return -EIO;
  }
  of = pfs_create_file(cr->fileid, 0, 0, 0, 1, 0,
                            pfs_task_get_ref_locked(folder), fpath->name,
                            encoder);
  pfs_task_release_folder_tasks_locked(folder);
  psql_unlock();
  of->newfile = 1;
  of->modified = 1;
  ret = open_write_files(of, 1);
  pthread_mutex_unlock(&of->mutex);
  if (pdbg_unlikely(ret)) {
    pfs_del_creat(fpath, of);
    return ret;
  }
  free(fpath);
  fi->fh = openfile_to_fh(of);
  return 0;
}

void pfs_inc_of_refcnt_locked(psync_openfile_t *of) { of->refcnt++; }

void pfs_inc_of_refcnt(psync_openfile_t *of) {
  pfs_lock_file(of);
  pfs_inc_of_refcnt_locked(of);
  pthread_mutex_unlock(&of->mutex);
}

static void close_if_valid(int fd) {
  if (fd != INVALID_HANDLE_VALUE)
    pfile_close(fd);
}

static void pfs_free_openfile(psync_openfile_t *of) {
  pdbg_logf(D_NOTICE, "releasing file %s", of->currentname);
  if (unlikely(of->writetimer != PSYNC_INVALID_TIMER))
    pdbg_logf(D_BUG,
          "file %s with active timer is set to free, this is not supposed to "
          "happen",
          of->currentname);
  if (of->deleted && of->fileid < 0) {
    psync_sql_res *res;
    pdbg_logf(D_NOTICE, "file %s marked for deletion, releasing cancel tasks",
          of->currentname);
    res = psql_prepare(
        "UPDATE fstask SET status=11 WHERE id=? AND status=12");
    psql_bind_uint(res, 1, -of->fileid);
    psql_run_free(res);
    pfs_upld_wake();
  }
  if (of->encrypted) {
    if (of->encoder != PSYNC_CRYPTO_UNLOADED_SECTOR_ENCODER &&
        of->encoder != PSYNC_CRYPTO_FAILED_SECTOR_ENCODER) {
      pdbg_assert(of->encoder != PSYNC_CRYPTO_LOADING_SECTOR_ENCODER);
      pcrypto_sec_encdec_free(of->encoder);
    }
    close_if_valid(of->logfile);
    ptree_for_each_element_call_safe(
        of->sectorsinlog, psync_sector_inlog_t, tree, free);
    delete_log_files(of);
    if (of->authenticatedints)
      psync_interval_tree_free(of->authenticatedints);
  }
  pthread_mutex_destroy(&of->mutex);
  close_if_valid(of->datafile);
  close_if_valid(of->indexfile);
  if (of->writeintervals)
    psync_interval_tree_free(of->writeintervals);
  if (unlikely(pfs_need_per_folder_refresh_const() &&
               of->fileid < psync_fake_fileid)) {
    psync_fstask_creat_t *cr;
    psql_lock();
    cr = pfs_task_find_creat(of->currentfolder, of->currentname, 0);
    if (cr) {
      ptree_del(&of->currentfolder->creats, &cr->tree);
      of->currentfolder->taskscnt--;
      free(cr);
    }
    psql_unlock();
  }
  pfs_task_release_folder_tasks(of->currentfolder);
  free(of->currentname);
  free(of);
}

static void pfs_get_both_locks(psync_openfile_t *of) {
  psql_lock();
  pfs_lock_file(of);
}

void pfs_dec_of_refcnt(psync_openfile_t *of) {
  uint32_t refcnt;
  pfs_get_both_locks(of);
  refcnt = --of->refcnt;
  if (!refcnt) {
    ptree_del(&openfiles, &of->tree);
    psql_unlock();
    pthread_mutex_unlock(&of->mutex);
    pfs_free_openfile(of);
  } else {
    psql_unlock();
    pthread_mutex_unlock(&of->mutex);
  }
}

void pfs_inc_of_refcnt_and_readers(psync_openfile_t *of) {
  pfs_lock_file(of);
  of->refcnt++;
  of->runningreads++;
  pthread_mutex_unlock(&of->mutex);
}

void pfs_dec_of_refcnt_and_readers(psync_openfile_t *of) {
  uint32_t refcnt;
  pfs_get_both_locks(of);
  of->runningreads--;
  refcnt = --of->refcnt;
  if (refcnt == 0)
    ptree_del(&openfiles, &of->tree);
  psql_unlock();
  pthread_mutex_unlock(&of->mutex);
  if (!refcnt)
    pfs_free_openfile(of);
}

typedef struct {
  psync_openfile_t *of;
  uint64_t writeid;
} psync_openfile_writeid_t;

static void pfs_upload_release_timer(void *ptr) {
  psync_sql_res *res;
  psync_openfile_writeid_t *ofw;
  uint32_t aff;
  ofw = (psync_openfile_writeid_t *)ptr;
  pdbg_logf(D_NOTICE, "releasing file %s for upload, size=%lu, writeid=%u",
        ofw->of->currentname, (unsigned long)ofw->of->currentsize,
        (unsigned)ofw->writeid);
  res = psql_prepare(
      "UPDATE fstask SET status=0, int1=? WHERE id=? AND status=1");
  psql_bind_uint(res, 1, ofw->writeid);
  psql_bind_uint(res, 2, -ofw->of->fileid);
  psql_run(res);
  aff = psql_affected();
  psql_free(res);
  if (aff)
    pfs_upld_wake();
  else {
    res = psql_prepare(
        "UPDATE fstask SET int1=? WHERE id=? AND int1<?");
    psql_bind_uint(res, 1, ofw->writeid);
    psql_bind_uint(res, 2, -ofw->of->fileid);
    psql_bind_uint(res, 3, ofw->writeid);
    psql_run_free(res);
  }
  pfs_dec_of_refcnt(ofw->of);
  free(ofw);
  pstatus_upload_recalc_async();
}

static void pfs_write_timer(psync_timer_t timer, void *ptr) {
  psync_openfile_t *of;
  of = (psync_openfile_t *)ptr;
  pfs_lock_file(of);
  ptimer_stop(timer);
  of->writetimer = PSYNC_INVALID_TIMER;
  pdbg_logf(D_NOTICE, "got write timer for file %s", of->currentname);
  if (of->releasedforupload)
    pdbg_logf(D_NOTICE, "file seems to be already released for upload");
  else if (of->modified) {
    psync_openfile_writeid_t *ofw;
    if (unlikely(of->staticfile)) {
      pdbg_logf(D_ERROR, "file is static file, which should not generally happen");
      goto unlock_ex;
    }
    if (unlikely(of->encrypted && pfs_crpt_flush(of))) {
      pdbg_logf(D_WARNING,
            "we are in timer and we failed to flush crypto file, life sux");
      goto unlock_ex;
    }
    of->releasedforupload = 1;
    ofw = malloc(sizeof(psync_openfile_writeid_t));
    ofw->of = of;
    ofw->writeid = of->writeid;
    pthread_mutex_unlock(&of->mutex);
    pdbg_logf(D_NOTICE, "running separate thread to release file for upload");
    prun_thread1("upload release timer", pfs_upload_release_timer,
                      ofw);
    return;
  } else
    pdbg_logf(D_NOTICE, "file seems to be already uploaded");
unlock_ex:
  pthread_mutex_unlock(&of->mutex);
  pfs_dec_of_refcnt(of);
}

static int pfs_flush(const char *path, struct fuse_file_info *fi) {
  psync_openfile_t *of;
  pfs_set_thread_name();
  pdbg_logf(D_NOTICE, "flush %s", path);
  of = fh_to_openfile(fi->fh);
  pfs_lock_file(of);
  if (of->modified) {
    psync_sql_res *res;
    uint64_t writeid;
    uint32_t aff;
    int ret;
    if (of->staticfile) {
      pthread_mutex_unlock(&of->mutex);
      return 0;
    }
    writeid = of->writeid;
    if (of->encrypted) {
      ret = pfs_crpt_flush(of);
      if (pdbg_unlikely(ret)) {
        pthread_mutex_unlock(&of->mutex);
        return ret;
      }
    }
    of->releasedforupload = 1;
    if (of->writetimer && !ptimer_stop(of->writetimer)) {
      if (--of->refcnt == 0) {
        pdbg_logf(D_BUG, "zero refcnt in flush after canceling timer");
        pdbg_assert(of->refcnt);
      }
      of->writetimer = PSYNC_INVALID_TIMER;
    }
    pthread_mutex_unlock(&of->mutex);
    pdbg_logf(D_NOTICE, "releasing file %s for upload, size=%lu, writeid=%u", path,
          (unsigned long)of->currentsize, (unsigned)writeid);
    res = psql_prepare(
        "UPDATE fstask SET status=0, int1=? WHERE id=? AND status=1");
    psql_bind_uint(res, 1, writeid);
    psql_bind_uint(res, 2, -of->fileid);
    psql_run(res);
    aff = psql_affected();
    psql_free(res);
    if (aff)
      pfs_upld_wake();
    else {
      res = psql_prepare(
          "UPDATE fstask SET int1=? WHERE id=? AND int1<?");
      psql_bind_uint(res, 1, writeid);
      psql_bind_uint(res, 2, -of->fileid);
      psql_bind_uint(res, 3, writeid);
      psql_run_free(res);
    }
    pstatus_upload_recalc_async();
    return 0;
  }
  pthread_mutex_unlock(&of->mutex);
  return 0;
}

static int pfs_release(const char *path, struct fuse_file_info *fi) {
  pfs_set_thread_name();
  pdbg_logf(D_NOTICE, "release %s", path);
  pfs_flush(path, fi);
  pfs_dec_of_refcnt(fh_to_openfile(fi->fh));
  return 0;
}

static int pfs_fsync(const char *path, int datasync,
                          struct fuse_file_info *fi) {
  psync_openfile_t *of;
  int ret;
  pfs_set_thread_name();
  pdbg_logf(D_NOTICE, "fsync %s", path);
  of = fh_to_openfile(fi->fh);
  pfs_lock_file(of);
  if (!of->modified || of->staticfile) {
    pthread_mutex_unlock(&of->mutex);
    return 0;
  }
  if (of->encrypted) {
    ret = pfs_crpt_flush(of);
    if (pdbg_unlikely(ret)) {
      pthread_mutex_unlock(&of->mutex);
      return ret;
    }
  }
  if (pdbg_unlikely(pfile_sync(of->datafile)) ||
      pdbg_unlikely(!of->newfile && pfile_sync(of->indexfile))) {
    pthread_mutex_unlock(&of->mutex);
    return -EIO;
  }
  pthread_mutex_unlock(&of->mutex);
  if (pdbg_unlikely(psql_sync()))
    return -EIO;
  return 0;
}

static int pfs_fsyncdir(const char *path, int datasync,
                             struct fuse_file_info *fi) {
  pfs_set_thread_name();
  pdbg_logf(D_NOTICE, "fsyncdir %s", path);
  if (pdbg_unlikely(psql_sync()))
    return -EIO;
  else
    return 0;
}

static int psync_read_newfile(psync_openfile_t *of, char *buf, uint64_t size,
                              uint64_t offset) {
  ssize_t br = pfile_pread(of->datafile, buf, size, offset);
  pthread_mutex_unlock(&of->mutex);
  if (br == -1) {
    pdbg_logf(D_NOTICE,
          "error reading from new file offset %lu, size %lu, error %d",
          (unsigned long)offset, (unsigned long)size, (int)errno);
    br = -EIO;
  }
  return br;
}

static int psync_read_staticfile(psync_openfile_t *of, char *buf, uint64_t size,
                                 uint64_t offset) {
  int ret;
  if (of->currentsize < offset)
    ret = 0;
  else {
    if (offset + size > of->currentsize)
      ret = of->currentsize - offset;
    else
      ret = size;
    memcpy(buf, of->staticdata + offset, ret);
  }
  pthread_mutex_unlock(&of->mutex);
  return ret;
}

static int pfs_read(const char *path, char *buf, size_t size,
                         fuse_off_t offset, struct fuse_file_info *fi) {
  psync_openfile_t *of;
  time_t currenttime;
  pfs_set_thread_name();
  of = fh_to_openfile(fi->fh);
  currenttime = ptimer_time();
  pfs_lock_file(of);
  if (of->currentsec == currenttime) {
    of->bytesthissec += size;
    if (of->currentspeed < of->bytesthissec)
      of->currentspeed = of->bytesthissec;
  } else {
    if (of->currentsec < currenttime - 10)
      of->currentspeed = size;
    else if (of->currentspeed == 0)
      of->currentspeed = of->bytesthissec;
    else
      of->currentspeed = (of->bytesthissec / (currenttime - of->currentsec) +
                          of->currentspeed * 3) /
                         4;
    of->currentsec = currenttime;
    of->bytesthissec = size;
  }
  if (of->encrypted) {
    if (of->newfile)
      return pfs_crpt_read_new(of, buf, size, offset);
    else if (of->modified)
      return pfs_crpt_read_mod(of, buf, size, offset);
    else
      return ppagecache_read_unmod_enc_locked(of, buf, size,
                                                              offset);
  } else {
    if (of->newfile)
      return psync_read_newfile(of, buf, size, offset);
    else if (of->modified) {
      if (unlikely(of->staticfile))
        return psync_read_staticfile(of, buf, size, offset);
      else
        return ppagecache_read_mod_locked(of, buf, size, offset);
    } else
      return ppagecache_read_unmod_locked(of, buf, size, offset);
  }
}

static void pfs_inc_writeid_locked(psync_openfile_t *of) {
  if (unlikely(of->releasedforupload)) {
    if (unlikely(psql_trylock())) {
      pthread_mutex_unlock(&of->mutex);
      psql_lock();
      pfs_lock_file(of);
    }
    if (of->releasedforupload) {
      of->releasedforupload = 0;
      pdbg_logf(D_NOTICE, "stopping upload of file %s as new write arrived",
            of->currentname);
      pdbg_assertw(of->fileid < 0);
      pfs_upld_stop_upload_locked(-of->fileid);
    }
    psql_unlock();
  }
  of->writeid++;
  if (of->writetimer == PSYNC_INVALID_TIMER ||
      !ptimer_stop(of->writetimer)) {
    if (of->writetimer == PSYNC_INVALID_TIMER)
      pfs_inc_of_refcnt_locked(of);
    of->writetimer = ptimer_register(pfs_write_timer,
                                          PSYNC_UPLOAD_NOWRITE_TIMER, of);
  }
}

static int pfs_modfile_check_size_ok(psync_openfile_t *of, uint64_t size) {
  if (unlikely(of->currentsize < size)) {
    pdbg_logf(D_NOTICE, "extending file %s from %lu to %lu bytes", of->currentname,
          (unsigned long)of->currentsize, (unsigned long)size);
    if (pfile_seek(of->datafile, size, SEEK_SET) == -1 ||
        pfile_truncate(of->datafile))
      return -1;
    if (of->newfile)
      return 0;
    else {
      pfs_index_record rec;
      uint64_t ioff;
      pdbg_assertw(of->modified);
      ioff = of->indexoff++;
      rec.offset = of->currentsize;
      rec.length = size - of->currentsize;
      if (pdbg_unlikely(pfile_pwrite(of->indexfile, &rec, sizeof(rec),
                                         sizeof(rec) * ioff +
                                             sizeof(pfs_index_header)) !=
                       sizeof(rec)))
        return -1;
      psync_interval_tree_add(&of->writeintervals, of->currentsize, size);
      of->currentsize = size;
    }
  }
  return 0;
}

PSYNC_NOINLINE static int
pfs_reopen_file_for_writing(psync_openfile_t *of) {
  psync_fstask_creat_t *cr;
  uint64_t size;
  char *encsymkey;
  size_t encsymkeylen;
  int ret;
  pdbg_logf(D_NOTICE, "reopening file %s for writing size %lu", of->currentname,
        (unsigned long)of->currentsize);
  if (unlikely(of->encrypted &&
               of->encoder == PSYNC_CRYPTO_UNLOADED_SECTOR_ENCODER)) {
    pcrypto_sector_encdec_t enc;
    psync_fsfileid_t remotefileid;
    uint64_t hash;
    // Save values before unlock
    remotefileid = of->remotefileid;
    hash = of->hash;
    // we should unlock of->mutex as it can deadlock with sqllock and taking
    // sqllock before network operation is not a good idea
    pthread_mutex_unlock(&of->mutex);
    enc = pcryptofolder_filencoder_get(remotefileid, hash, 0);
    if (unlikely(psync_crypto_is_error(enc)))
      return -pfs_crypto_err_to_errno(psync_crypto_to_error(enc));
    pfs_lock_file(of);
    // Check if state changed while unlocked
    if (of->encoder == PSYNC_CRYPTO_UNLOADED_SECTOR_ENCODER &&
        of->remotefileid == remotefileid && of->hash == hash)
      of->encoder = enc;
    else
      pcryptofolder_filencoder_release(remotefileid, hash, enc);
    if (of->newfile || of->modified)
      return 1;
  }
  if (unlikely(psql_trylock())) {
    // we have to take sql_lock and retake of->mutex AFTER, then check if the
    // case is still !of->newfile && !of->modified
    pthread_mutex_unlock(&of->mutex);
    psql_lock();
    pfs_lock_file(of);
    if (of->newfile || of->modified) {
      psql_unlock();
      return 1;
    }
  }
  if (of->encrypted) {
    if (unlikely(psync_crypto_isexpired())) {
      psql_unlock();
      return -pdbg_return_const(PSYNC_FS_ERR_CRYPTO_EXPIRED);
    }
    size = pfs_crpt_crypto_size(of->initialsize);
    encsymkey = pcryptofolder_filencoder_key_get(of->fileid, of->hash,
                                                        &encsymkeylen);
    if (pdbg_unlikely(psync_crypto_is_error(encsymkey))) {
      psql_unlock();
      return -pfs_crypto_err_to_errno(psync_crypto_to_error(encsymkey));
    }
  } else {
    encsymkey = NULL;
    encsymkeylen = 0;
    size = of->initialsize;
  }
  if (size == 0 || (size <= PSYNC_FS_MAX_SIZE_CONVERT_NEWFILE &&
                    ppagecache_have_all_pages(of->hash, size) &&
                    !ppagecache_lock_pages())) {
    pdbg_logf(D_NOTICE,
          "we have all pages of file %s, convert it to new file as they are "
          "cheaper to work with",
          of->currentname);
    cr = pfs_task_add_creat(of->currentfolder, of->currentname, of->fileid,
                                encsymkey, encsymkeylen);
    if (pdbg_unlikely(!cr)) {
      psql_unlock();
      ppagecache_unlock_pages();
      free(encsymkey);
      return -EIO;
    }
    pfs_update_openfile_fileid_locked(of, cr->fileid);
    pfs_xatr_file_to_task(of->remotefileid, cr->taskid);
    psql_unlock();
    of->newfile = 1;
    of->modified = 1;
    ret = open_write_files(of, 0);
    if (pdbg_unlikely(ret)) {
      ppagecache_unlock_pages();
      free(encsymkey);
      return ret;
    }
    if (of->origctime)
      pfile_set_creation(of->datafile, of->origctime);
    if (size) {
      ret = ppagecache_copy_to_file_locked(
          of, of->hash, size);
      ppagecache_unlock_pages();
      if (pdbg_unlikely(ret)) {
        free(encsymkey);
        return -EIO;
      }
    }
    of->currentsize = of->initialsize;
    return 1;
  }
  cr = pfs_task_add_modified_file(of->currentfolder, of->currentname,
                                      of->fileid, of->hash, encsymkey,
                                      encsymkeylen);
  free(encsymkey);
  if (pdbg_unlikely(!cr)) {
    psql_unlock();
    return -EIO;
  }
  pfs_update_openfile_fileid_locked(of, cr->fileid);
  psql_unlock();
  ret = open_write_files(of, 0);
  if (pdbg_unlikely(ret) ||
      pfile_seek(of->datafile, size, SEEK_SET) == -1 ||
      pfile_truncate(of->datafile)) {
    if (!ret)
      ret = -EIO;
    return ret;
  }
  if (of->origctime)
    pfile_set_creation(of->datafile, of->origctime);
  of->modified = 1;
  of->indexoff = 0;
  of->currentsize = of->initialsize;
  return 0;
}

PSYNC_NOINLINE static int
pfs_reopen_static_file_for_writing(psync_openfile_t *of) {
  psync_fstask_creat_t *cr;
  psync_fstask_unlink_t *un;
  uint64_t taskid;
  int ret;
  pdbg_assert(!of->encrypted);
  pdbg_assert(of->staticfile);
  if (unlikely(psql_trylock())) {
    // we have to take sql_lock and retake of->mutex AFTER, then check if the
    // case is still !of->newfile && !of->modified
    pthread_mutex_unlock(&of->mutex);
    psql_lock();
    pfs_lock_file(of);
    if (!of->staticfile) {
      psql_unlock();
      return 1;
    }
  }
  taskid = UINT64_MAX - (INT64_MAX - of->fileid);
  pdbg_logf(D_NOTICE, "reopening static file %s for writing size %lu, taskid %lu",
        of->currentname, (unsigned long)of->currentsize, (unsigned long)taskid);
  cr = pfs_task_add_creat(of->currentfolder, of->currentname, 0, NULL, 0);
  if (pdbg_unlikely(!cr)) {
    psql_unlock();
    return -EIO;
  }
  pfs_update_openfile_fileid_locked(of, cr->fileid);
  pfs_xatr_static_to_task(taskid, cr->taskid);
  cr = pfs_task_find_creat(of->currentfolder, of->currentname, taskid);
  if (pdbg_likely(cr)) {
    ptree_del(&of->currentfolder->creats, &cr->tree);
    of->currentfolder->taskscnt--;
    free(cr);
  }
  un = pfs_task_find_unlink(of->currentfolder, of->currentname, taskid);
  if (pdbg_likely(un)) {
    ptree_del(&of->currentfolder->unlinks, &un->tree);
    of->currentfolder->taskscnt--;
    free(un);
  }
  psql_unlock();
  of->writeid = 0;
  of->newfile = 1;
  of->modified = 1;
  of->staticfile = 0;
  ret = open_write_files(of, 1);
  if (pdbg_unlikely(ret))
    return ret;
  if (pfile_pwrite(of->datafile, of->staticdata, of->currentsize, 0) !=
      of->currentsize)
    ret = -pdbg_return_const(EIO);
  else
    ret = 1;
  return ret;
}

PSYNC_NOINLINE static int
pfs_check_modified_file_write_space(psync_openfile_t *of, size_t size,
                                         fuse_off_t offset) {
  uint64_t from, to;
  psync_interval_tree_t *tr;
  if (of->encrypted) {
    from = pfs_crpt_sector_id(offset /
                                                     PSYNC_CRYPTO_SECTOR_SIZE) *
           PSYNC_CRYPTO_SECTOR_SIZE;
    to = pfs_crpt_sector_id((offset + size) /
                                                   PSYNC_CRYPTO_SECTOR_SIZE) *
             PSYNC_CRYPTO_SECTOR_SIZE +
         (offset + size) % PSYNC_CRYPTO_SECTOR_SIZE;
  } else {
    from = offset;
    to = offset + size;
  }
  tr = psync_interval_tree_first_interval_containing_or_after(
      of->writeintervals, from);
  if (tr && tr->from <= from && tr->to >= to)
    return 1;
  else
    return 0;
}

static void pfs_throttle(size_t size, uint64_t speed) {
  static pthread_mutex_t throttle_mutex = PTHREAD_MUTEX_INITIALIZER;
  static uint64_t writtenthissec = 0;
  static time_t thissec = 0;
  time_t currsec;
  int cnt;
  pdbg_assert(speed > 0);
  cnt = 0;
  while (++cnt <= PSYNC_FS_MAX_SHAPER_SLEEP_SEC) {
    currsec = ptimer_time();
    pthread_mutex_lock(&throttle_mutex);
    if (currsec != thissec) {
      thissec = currsec;
      writtenthissec = 0;
    }
    if (writtenthissec < speed) {
      if (writtenthissec + size > speed) {
        size -= speed - writtenthissec;
        writtenthissec = speed;
      } else {
        writtenthissec += size;
        pthread_mutex_unlock(&throttle_mutex);
        pdbg_assert(size <= speed);
        psys_sleep_milliseconds(size * 1000 / speed);
        return;
      }
    }
    pthread_mutex_unlock(&throttle_mutex);
    ptimer_wait_next_sec();
  }
}

PSYNC_NOINLINE static int pfs_do_check_write_space(psync_openfile_t *of,
                                                        size_t size) {
  const char *cachepath;
  uint64_t minlocal, mult, speed;
  int64_t freespc;
  int freed;
  cachepath = psync_setting_get_string(_PS(fscachepath));
  minlocal = psync_setting_get_uint(_PS(minlocalfreespace));
  freespc = ppath_free_space(cachepath);
  if (unlikely(freespc == -1)) {
    pdbg_logf(D_WARNING, "could not get free space of path %s", cachepath);
    return 1;
  }
  //  pdbg_logf(D_NOTICE, "free space of %s is %lld minlocal %llu", cachepath,
  //  freespc, minlocal);
  if (freespc >= minlocal + size) {
    psync_set_local_full(0);
    of->throttle = 0;
    return 1;
  }
  of->throttle = 1;
  pthread_mutex_unlock(&of->mutex);
  pdbg_logf(D_NOTICE, "free space is %lu, less than minimum %lu+%lu",
        (unsigned long)freespc, (unsigned long)minlocal, (unsigned long)size);
  psync_set_local_full(1);
  if ((freespc <= minlocal / 2 || minlocal <= PSYNC_FS_PAGE_SIZE ||
       freespc <= size)) {
    if (ppagecache_free_read(size * 2) < size * 2) {
      pdbg_logf(D_WARNING,
            "free space is %lu, less than half of minimum %lu+%lu, returning "
            "error",
            (unsigned long)freespc, (unsigned long)minlocal,
            (unsigned long)size);
      psys_sleep_milliseconds(5000);
      return -EINTR;
    } else {
      pdbg_logf(D_NOTICE,
            "free space is %lu, less than half of minimum %lu+%lu, but we "
            "managed to free from read cache",
            (unsigned long)freespc, (unsigned long)minlocal,
            (unsigned long)size);
      freespc = minlocal / 2 + 1;
      freed = 1;
    }
  } else if (freespc <= minlocal / 4 * 3) {
    pdbg_logf(D_NOTICE,
          "free space is %lu, less than 3/4 of minimum %lu+%lu, will try to "
          "free read cache pages",
          (unsigned long)freespc, (unsigned long)minlocal, (unsigned long)size);
    freed = ppagecache_free_read(size) >= size;
  } else
    freed = 0;
  if (psync_status.uploadspeed == 0) {
    if (freed || ppagecache_free_read(size) >= size) {
      pdbg_logf(D_NOTICE, "there is no active upload and we managed to free from "
                      "cache, not throttling write");
      pfs_lock_file(of);
      return 1;
    }
  }
  minlocal /= 2;
  mult = (freespc - minlocal) * 1023 / minlocal + 1;
  pdbg_assert(mult >= 1 && mult <= 1024);
  speed = psync_status.uploadspeed * 3 / 2;
  if (speed < PSYNC_FS_MIN_INITIAL_WRITE_SHAPER)
    speed = PSYNC_FS_MIN_INITIAL_WRITE_SHAPER;
  speed = speed * mult / 1024;
  pdbg_logf(D_NOTICE,
        "limiting write speed to %luKb (%lub)/sec, speed multiplier %lu",
        (unsigned long)speed / 1024, (unsigned long)speed, (unsigned long)mult);
  pfs_throttle(size, speed);
  pdbg_logf(D_NOTICE, "continuing write");
  if (pfs_lock_file(of))
    return -EINTR;
  return 1;
}

static int pfs_check_write_space(psync_openfile_t *of, size_t size,
                                      fuse_off_t offset) {
  if (!of->throttle && of->writeid % 64 != 0)
    return 1;
  if (of->currentsize >= offset + size) {
    //    if (of->newfile)
    //      return 1;
    if (of->modified &&
        pfs_check_modified_file_write_space(of, size, offset))
      return 1;
  }
  return pfs_do_check_write_space(of, size);
}

static int pfs_write_modified(psync_openfile_t *of, const char *buf,
                                   size_t size, fuse_off_t offset) {
  pfs_index_record rec;
  uint64_t ioff;
  ssize_t bw;
  if (pdbg_unlikely(pfs_modfile_check_size_ok(of, offset)))
    return -EIO;
  ioff = of->indexoff++;
  bw = pfile_pwrite(of->datafile, buf, size, offset);
  if (pdbg_unlikely(bw == -1))
    return -EIO;
  rec.offset = offset;
  rec.length = bw;
  if (pdbg_unlikely(pfile_pwrite(of->indexfile, &rec, sizeof(rec),
                                     sizeof(rec) * ioff +
                                         sizeof(pfs_index_header)) !=
                   sizeof(rec)))
    return -EIO;
  psync_interval_tree_add(&of->writeintervals, offset, offset + bw);
  if (of->currentsize < offset + size)
    of->currentsize = offset + size;
  return bw;
}

static int pfs_write_newfile(psync_openfile_t *of, const char *buf,
                                  size_t size, fuse_off_t offset) {
  ssize_t bw;
  bw = pfile_pwrite(of->datafile, buf, size, offset);
  if (of->currentsize < offset + size && bw != -1)
    of->currentsize = offset + size;
  return bw;
}

static int pfs_write(const char *path, const char *buf, size_t size,
                          fuse_off_t offset, struct fuse_file_info *fi) {
  psync_openfile_t *of;
  int ret;
  pfs_set_thread_name();
  //  pdbg_logf(D_NOTICE, "write to %s of %lu at %lu", path, (unsigned long)size,
  //  (unsigned long)offset);
  of = fh_to_openfile(fi->fh);
  pfs_lock_file(of);
  if (!of->canmodify) {
    pthread_mutex_unlock(&of->mutex);
    return -EACCES;
  }
  ret = pfs_check_write_space(of, size, offset);
  if (pdbg_unlikely(ret <= 0))
    return ret;
  pfs_inc_writeid_locked(of);
retry:
  if (of->newfile) {
    if (of->encrypted)
      return pfs_crpt_write_new(of, buf, size, offset);
    else
      ret = pfs_write_newfile(of, buf, size, offset);
    pthread_mutex_unlock(&of->mutex);
    if (pdbg_unlikely(ret == -1))
      return -EIO;
    else
      return ret;
  } else {
    if (unlikely(!of->modified)) {
      ret = pfs_reopen_file_for_writing(of);
      if (ret == 1)
        goto retry;
      else if (ret < 0) {
        pthread_mutex_unlock(&of->mutex);
        return ret;
      }
    }
    if (of->encrypted)
      return pfs_crpt_write_mod(of, buf, size, offset);
    else {
      pdbg_logf(D_NOTICE, "write of %lu bytes at offset %lu", (unsigned long)size,
            (unsigned long)offset);
      if (unlikely(of->staticfile)) {
        ret = pfs_reopen_static_file_for_writing(of);
        if (ret == 1)
          goto retry;
        else {
          pthread_mutex_unlock(&of->mutex);
          return ret;
        }
      } else
        ret = pfs_write_modified(of, buf, size, offset);
    }
    pthread_mutex_unlock(&of->mutex);
    return ret;
  }
}

static int pfs_mkdir(const char *path, mode_t mode) {
  psync_fspath_t *fpath;
  int ret;
  pfs_set_thread_name();
  pdbg_logf(D_NOTICE, "mkdir %s", path);
  psql_lock();
  CHECK_LOGIN_LOCKED();
  fpath = pfs_fldr_resolve_path(path);
  if (!fpath)
    ret = -ENOENT;
  else if (!(fpath->permissions & PSYNC_PERM_CREATE))
    ret = -EACCES;
  else if (fpath->flags & (PSYNC_FOLDER_FLAG_BACKUP_DEVICE_LIST |
                           PSYNC_FOLDER_FLAG_BACKUP_DEVICE))
    ret = -EACCES;
  else if (fpath->flags & PSYNC_FOLDER_FLAG_ENCRYPTED &&
           psync_crypto_isexpired())
    ret = -PSYNC_FS_ERR_CRYPTO_EXPIRED;
  else
    ret = pfs_task_mkdir(fpath->folderid, fpath->name, fpath->flags);
  psql_unlock();
  free(fpath);
  pdbg_logf(D_NOTICE, "mkdir %s=%d", path, ret);
  return ret;
}

#if defined(FUSE_HAS_CAN_UNLINK)
static int pfs_can_rmdir(const char *path) {
  psync_fspath_t *fpath;
  int ret;
  pfs_set_thread_name();
  pdbg_logf(D_NOTICE, "can_rmdir %s", path);
  psql_lock();
  fpath = pfs_fldr_resolve_path(path);
  if (!fpath)
    ret = -ENOENT;
  else if (!(fpath->permissions & PSYNC_PERM_DELETE))
    ret = -EACCES;
  else
    ret = pfs_task_can_rmdir(fpath->folderid, fpath->flags, fpath->name);
  psql_unlock();
  free(fpath);
  pdbg_logf(D_NOTICE, "can_rmdir %s=%d", path, ret);
  return ret;
}
#endif

static int pfs_rmdir(const char *path) {
  psync_fspath_t *fpath;
  int ret;
  pfs_set_thread_name();
  pdbg_logf(D_NOTICE, "rmdir %s", path);
  psql_lock();
  CHECK_LOGIN_LOCKED();
  fpath = pfs_fldr_resolve_path(path);
  if (!fpath)
    ret = -ENOENT;
  else if (!(fpath->permissions & PSYNC_PERM_DELETE))
    ret = -EACCES;
  else
    ret = pfs_task_rmdir(fpath->folderid, fpath->flags, fpath->name);
  psql_unlock();
  free(fpath);
  pdbg_logf(D_NOTICE, "rmdir %s=%d", path, ret);
  return ret;
}

#if defined(FUSE_HAS_CAN_UNLINK)
static int pfs_can_unlink(const char *path) {
  psync_fspath_t *fpath;
  int ret;
  pfs_set_thread_name();
  pdbg_logf(D_NOTICE, "can_unlink %s", path);
  psql_lock();
  fpath = pfs_fldr_resolve_path(path);
  if (!fpath)
    ret = -ENOENT;
  else if (!(fpath->permissions & PSYNC_PERM_DELETE))
    ret = -EACCES;
  else
    ret = pfs_task_can_unlink(fpath->folderid, fpath->name);
  psql_unlock();
  free(fpath);
  pdbg_logf(D_NOTICE, "can_unlink %s=%d", path, ret);
  return ret;
}
#endif

static int pfs_unlink(const char *path) {
  psync_fspath_t *fpath;
  int ret;
  pfs_set_thread_name();
  pdbg_logf(D_NOTICE, "unlink %s", path);
  psql_lock();
  CHECK_LOGIN_LOCKED();
  fpath = pfs_fldr_resolve_path(path);
  if (!fpath)
    ret = -ENOENT;
  else if (!(fpath->permissions & PSYNC_PERM_DELETE))
    ret = -EACCES;
  else
    ret = pfs_task_unlink(fpath->folderid, fpath->name);
  psql_unlock();

  if ((fpath->flags & PSYNC_FOLDER_FLAG_BACKUP) && ret == 0) {
    // Send async event to UI to notify the user that he is deleting a backedup
    // file.
    pdbg_logf(D_NOTICE, "Backedup file deleted in P drive. Send event. Flags: [%d]",
          fpath->flags);
    prun_thread1("psync_async_sync_delete", psync_async_ui_callback,
                      (void *)PEVENT_BKUP_F_DEL_DRIVE);
  }

  free(fpath);
  pdbg_logf(D_NOTICE, "unlink %s=%d", path, ret);
  return ret;
}

static int pfs_rename_static_file(psync_fstask_folder_t *srcfolder,
                                       psync_fstask_creat_t *srccr,
                                       psync_fsfolderid_t to_folderid,
                                       const char *new_name) {
  psync_fstask_creat_t *cr;
  psync_fstask_unlink_t *un;
  psync_fstask_folder_t *dstfolder;
  size_t len, addlen;
  dstfolder = pfs_task_get_or_create_folder_tasks_locked(to_folderid);
  cr = pfs_task_find_creat(dstfolder, new_name, 0);
  if (unlikely(cr)) {
    pdbg_logf(D_NOTICE, "renaming over creat of file %s in folderid %ld", new_name,
          (long)to_folderid);
    un = pfs_task_find_unlink(dstfolder, new_name, cr->taskid);
    if (un) {
      ptree_del(&dstfolder->unlinks, &un->tree);
      free(un);
      dstfolder->taskscnt--;
    }
    ptree_del(&dstfolder->creats, &cr->tree);
    free(cr);
    dstfolder->taskscnt--;
  }
  len = strlen(new_name) + 1;
  un = (psync_fstask_unlink_t *)malloc(
      offsetof(psync_fstask_unlink_t, name) + len);
  un->fileid = 0;
  un->taskid = srccr->taskid;
  memcpy(un->name, new_name, len);
  pfs_task_inject_unlink(dstfolder, un);
  addlen = pfs_task_creat_local_offset(len - 1);
  cr = (psync_fstask_creat_t *)malloc(addlen +
                                            sizeof(psync_fstask_local_creat_t));
  cr->fileid = 0;
  cr->rfileid = 0;
  cr->taskid = srccr->taskid;
  memcpy(cr->name, new_name, len);
  memcpy(((char *)cr) + addlen, pfs_task_creat_get_local(srccr),
         sizeof(psync_fstask_local_creat_t));
  pfs_task_inject_creat(dstfolder, cr);
  pfs_task_release_folder_tasks_locked(dstfolder);
  un = pfs_task_find_unlink(srcfolder, srccr->name, srccr->taskid);
  if (pdbg_likely(un)) {
    ptree_del(&srcfolder->unlinks, &un->tree);
    free(un);
    srcfolder->taskscnt--;
  }
  ptree_del(&srcfolder->creats, &srccr->tree);
  free(srccr);
  srcfolder->taskscnt--;
  return 0;
}

static int pfs_can_move(psync_fsfolderid_t fromfolderid,
                             uint32_t frompermissions,
                             psync_fsfolderid_t tofolderid,
                             uint32_t topermissions, int sameshare) {
  if (fromfolderid == tofolderid)
    return (frompermissions & PSYNC_PERM_MODIFY) == PSYNC_PERM_MODIFY;
  if ((frompermissions & PSYNC_PERM_ALL) == PSYNC_PERM_ALL &&
      (topermissions & PSYNC_PERM_ALL) == PSYNC_PERM_ALL)
    return 1;
  if ((frompermissions & (PSYNC_PERM_DELETE | PSYNC_PERM_MODIFY)) == 0 ||
      (topermissions & (PSYNC_PERM_CREATE | PSYNC_PERM_MODIFY)) == 0)
    return 0;
  if (sameshare)
    return (frompermissions & PSYNC_PERM_MODIFY) != 0;
  else
    return (frompermissions & PSYNC_PERM_DELETE) &&
           (topermissions & PSYNC_PERM_CREATE);
}

static int pfs_rename_folder(psync_fsfolderid_t folderid,
                                  psync_fsfolderid_t parentfolderid,
                                  const char *name, uint32_t srcpermissions,
                                  psync_fsfolderid_t to_folderid,
                                  const char *new_name, uint32_t targetperms,
                                  uint32_t targetflags, int sameshare) {
  if (!pfs_can_move(folderid, srcpermissions, to_folderid, targetperms,
                         sameshare))
    return -EACCES;
  return pfs_task_rename_folder(folderid, parentfolderid, name, to_folderid,
                                    new_name, targetflags);
}

static int pfs_rename_file(psync_fsfileid_t fileid,
                                psync_fsfolderid_t parentfolderid,
                                const char *name, uint32_t srcpermissions,
                                psync_fsfolderid_t to_folderid,
                                const char *new_name, uint32_t targetperms,
                                int sameshare) {
  if (!pfs_can_move(parentfolderid, srcpermissions, to_folderid,
                         targetperms, sameshare))
    return -EACCES;
  return pfs_task_rename_file(fileid, parentfolderid, name, to_folderid,
                                  new_name);
}

static int pfs_is_file(psync_fsfolderid_t folderid, const char *name) {
  psync_fstask_folder_t *folder;
  psync_sql_res *res;
  int ret;
  folder = pfs_task_get_folder_tasks_locked(folderid);
  if (folder) {
    if (pfs_task_find_creat(folder, name, 0))
      ret = 2;
    else if (pfs_task_find_unlink(folder, name, 0))
      ret = 1;
    else
      ret = 0;
    pfs_task_release_folder_tasks_locked(folder);
    if (ret)
      return ret - 1;
  }
  res =
      psql_query("SELECT id FROM file WHERE parentfolderid=? AND name=?");
  psql_bind_uint(res, 1, folderid);
  psql_bind_str(res, 2, name);
  if (psql_fetch_int(res))
    ret = 1;
  else
    ret = 0;
  psql_free(res);
  return ret;
}

static int pfs_is_folder(psync_fsfolderid_t folderid, const char *name) {
  psync_fstask_folder_t *folder;
  psync_sql_res *res;
  int ret;
  folder = pfs_task_get_folder_tasks_locked(folderid);
  if (folder) {
    if (pfs_task_find_mkdir(folder, name, 0))
      ret = 2;
    else if (pfs_task_find_rmdir(folder, name, 0))
      ret = 1;
    else
      ret = 0;
    pfs_task_release_folder_tasks_locked(folder);
    if (ret)
      return ret - 1;
  }
  res = psql_query(
      "SELECT id FROM folder WHERE parentfolderid=? AND name=?");
  psql_bind_uint(res, 1, folderid);
  psql_bind_str(res, 2, name);
  if (psql_fetch_int(res))
    ret = 1;
  else
    ret = 0;
  psql_free(res);
  return ret;
}

static int pfs_is_folder_nonempty(psync_fsfolderid_t folderid) {
  psync_fstask_folder_t *folder;
  psync_sql_res *res;
  psync_str_row row;
  folder = pfs_task_get_folder_tasks_locked(folderid);
  if (folder && (folder->creats || folder->mkdirs)) {
    pfs_task_release_folder_tasks_locked(folder);
    return 1;
  }
  if (folderid >= 0) {
    res = psql_query("SELECT name FROM file WHERE parentfolderid=?");
    psql_bind_uint(res, 1, folderid);
    while ((row = psql_fetch_str(res)))
      if (!folder || !pfs_task_find_unlink(folder, row[0], 0)) {
        psql_free(res);
        if (folder)
          pfs_task_release_folder_tasks_locked(folder);
        return 1;
      }
    psql_free(res);
    res = psql_query("SELECT name FROM folder WHERE parentfolderid=?");
    psql_bind_uint(res, 1, folderid);
    while ((row = psql_fetch_str(res)))
      if (!folder || !pfs_task_find_rmdir(folder, row[0], 0)) {
        psql_free(res);
        if (folder)
          pfs_task_release_folder_tasks_locked(folder);
        return 1;
      }
    psql_free(res);
  }
  if (folder)
    pfs_task_release_folder_tasks_locked(folder);
  return 0;
}

static int pfs_is_nonempty_folder(psync_fsfolderid_t parent_folderid,
                                       const char *name) {
  psync_fstask_folder_t *folder;
  psync_fstask_mkdir_t *mk;
  psync_sql_res *res;
  psync_uint_row row;
  int ret;

  folder = pfs_task_get_folder_tasks_locked(parent_folderid);

  if (folder) {
    if ((mk = pfs_task_find_mkdir(folder, name, 0))) {
      ret = pfs_is_folder_nonempty(mk->folderid) + 1;
    } else if (pfs_task_find_rmdir(folder, name, 0)) {
      ret = 1;
    } else {
      ret = 0;
    }

    pfs_task_release_folder_tasks_locked(folder);

    if (ret)
      return ret - 1;
  }

  res = psql_query(
      "SELECT id FROM folder WHERE parentfolderid=? AND name=?");
  psql_bind_uint(res, 1, parent_folderid);
  psql_bind_str(res, 2, name);

  if ((row = psql_fetch_int(res))) {
    ret = pfs_is_folder_nonempty(row[0]);
  } else {
    ret = 0;
  }

  psql_free(res);

  return ret;
}

#if FUSE_USE_VERSION >= 30
static int pfs_rename(const char *old_path, const char *new_path, unsigned int rename_flags) {
#else
static int pfs_rename(const char *old_path, const char *new_path) {
#endif
  psync_fspath_t *fold_path, *fnew_path;
  psync_sql_res *res;
  psync_fstask_folder_t *folder;
  psync_fstask_mkdir_t *mkdir;
  psync_fstask_creat_t *creat;
  psync_uint_row row;
  psync_fileorfolderid_t fid;
  uint64_t flags;

  psync_fsfolderid_t new_fid, old_fid;

  int ret;

  pfs_set_thread_name();
  pdbg_logf(D_NOTICE, "rename %s to %s", old_path, new_path);
  folder = NULL;
  psql_lock();
  CHECK_LOGIN_LOCKED();
  fold_path = pfs_fldr_resolve_path(old_path);
  fnew_path = pfs_fldr_resolve_path(new_path);

  if (!fold_path || !fnew_path)
    goto err_enoent;

  if ((fold_path->flags & PSYNC_FOLDER_FLAG_ENCRYPTED) !=
      (fnew_path->flags & PSYNC_FOLDER_FLAG_ENCRYPTED)) {
    ret = -PSYNC_FS_ERR_MOVE_ACROSS_CRYPTO;
    goto finish;
  }

  if (fold_path->folderid != fnew_path->folderid &&
      ((fold_path->flags | fnew_path->flags) &
       (PSYNC_FOLDER_FLAG_BACKUP_DEVICE_LIST |
        PSYNC_FOLDER_FLAG_BACKUP_DEVICE))) {
    ret = -EACCES;
    goto finish;
  }

  folder = pfs_task_get_folder_tasks_locked(fold_path->folderid);

  new_fid = pfs_fldr_get_folderid(fnew_path->folderid, fnew_path->name);
  old_fid = pfs_fldr_get_folderid(fold_path->folderid, fold_path->name);

  if (folder) {
    if ((mkdir = pfs_task_find_mkdir(folder, fold_path->name, 0))) {
      if (pfs_is_file(fnew_path->folderid, fnew_path->name)) {
        ret = -ENOTDIR;
      } else if (pfs_is_nonempty_folder(fnew_path->folderid,
                                             fnew_path->name) &&
                 (new_fid != old_fid)) {
        ret = -ENOTEMPTY;
      } else {
        ret = pfs_rename_folder(mkdir->folderid, fold_path->folderid,
                                     fold_path->name, fold_path->permissions,
                                     fnew_path->folderid, fnew_path->name,
                                     fnew_path->permissions, fnew_path->flags,
                                     fold_path->shareid == fnew_path->shareid);
      }

      goto finish;
    } else if ((creat = pfs_task_find_creat(folder, fold_path->name, 0))) {
      if (pfs_is_folder(fnew_path->folderid, fnew_path->name))
        ret = -EISDIR;
      else if (unlikely(creat->fileid == 0))
        ret = pfs_rename_static_file(folder, creat, fnew_path->folderid,
                                          fnew_path->name);
      else
        ret = pfs_rename_file(
            creat->fileid, fold_path->folderid, fold_path->name,
            fold_path->permissions, fnew_path->folderid, fnew_path->name,
            fnew_path->permissions, fold_path->shareid == fnew_path->shareid);
      goto finish;
    }
  }

  if (!folder || !pfs_task_find_rmdir(folder, fold_path->name, 0)) {
    res = psql_query(
        "SELECT id, flags FROM folder WHERE parentfolderid=? AND name=?");
    psql_bind_uint(res, 1, fold_path->folderid);
    psql_bind_str(res, 2, fold_path->name);

    if ((row = psql_fetch_int(res))) {
      fid = row[0];
      flags = row[1];
      psql_free(res);

      if (fold_path->folderid != fnew_path->folderid &&
          (flags &
           (PSYNC_FOLDER_FLAG_PUBLIC_ROOT |
            PSYNC_FOLDER_FLAG_BACKUP_DEVICE_LIST |
            PSYNC_FOLDER_FLAG_BACKUP_DEVICE | PSYNC_FOLDER_FLAG_BACKUP_ROOT)))
        ret = -EPERM;
      else if (pfs_is_file(fnew_path->folderid, fnew_path->name))
        ret = -ENOTDIR;
      else if (pfs_is_nonempty_folder(fnew_path->folderid,
                                           fnew_path->name) &&
               (new_fid != old_fid)) {
        ret = -ENOTEMPTY;
      } else
        ret = pfs_rename_folder(
            fid, fold_path->folderid, fold_path->name, fold_path->permissions,
            fnew_path->folderid, fnew_path->name, fnew_path->permissions,
            fnew_path->flags, fold_path->shareid == fnew_path->shareid);
      goto finish;
    }
    psql_free(res);
  }

  if (!folder || !pfs_task_find_unlink(folder, fold_path->name, 0)) {
    res = psql_query(
        "SELECT id FROM file WHERE parentfolderid=? AND name=?");
    psql_bind_uint(res, 1, fold_path->folderid);
    psql_bind_str(res, 2, fold_path->name);
    if ((row = psql_fetch_int(res))) {
      fid = row[0];
      psql_free(res);
      if (pfs_is_folder(fnew_path->folderid, fnew_path->name))
        ret = -EISDIR;
      else
        ret = pfs_rename_file(fid, fold_path->folderid, fold_path->name,
                                   fold_path->permissions, fnew_path->folderid,
                                   fnew_path->name, fnew_path->permissions,
                                   fold_path->shareid == fnew_path->shareid);
      goto finish;
    }
    psql_free(res);
  }

  goto err_enoent;
finish:
  if (folder)
    pfs_task_release_folder_tasks_locked(folder);
  psql_unlock();
  free(fold_path);
  free(fnew_path);
  return pdbg_returnf(ret, " for rename from %s to %s", old_path,
                             new_path);
err_enoent:
  if (folder)
    pfs_task_release_folder_tasks_locked(folder);
  psql_unlock();
  free(fold_path);
  free(fnew_path);
  pdbg_logf(D_NOTICE, "returning ENOENT, folder not found");
  return -ENOENT;
}

static int pfs_statfs(const char *path, struct statvfs *stbuf) {
  uint64_t q, uq;
  pfs_set_thread_name();
  pdbg_logf(D_NOTICE, "statfs %s", path);
  if (waitingforlogin)
    return -EACCES;
  /* TODO:
     return -ENOENT if path is invalid if fuse does not call getattr first
     */
  memset(stbuf, 0, sizeof(struct statvfs));
  q = psync_get_uint_value("quota");
  uq = psync_get_uint_value("usedquota");
  if (uq > q)
    uq = q;
  stbuf->f_bsize = FS_BLOCK_SIZE;
  stbuf->f_frsize = FS_BLOCK_SIZE;
  stbuf->f_blocks = q / FS_BLOCK_SIZE;
  stbuf->f_bfree = stbuf->f_blocks - uq / FS_BLOCK_SIZE;
  stbuf->f_bavail = stbuf->f_bfree;
  stbuf->f_flag = ST_NOSUID;
  stbuf->f_namemax = 1024;
  return 0;
}

static int pfs_chmod(const char *path, mode_t mode) {
  pfs_set_thread_name();
  pdbg_logf(D_NOTICE, "chmod %s %u", path, (unsigned)mode);
  return 0;
}

static int pfs_chown(const char *path, uid_t uid, gid_t gid) {
  pfs_set_thread_name();
  pdbg_logf(D_NOTICE, "chown %s %u %u", path, (unsigned)uid, (unsigned)gid);
  return 0;
}

static int pfs_set_filetime_locked(psync_fsfileid_t fileid,
                                        const struct timespec *tv, int crtime,
                                        uint64_t current) {
  if (fileid > 0)
    return pfs_task_set_mtime(fileid, current, tv->tv_sec, crtime);
  else {
    char fileidhex[sizeof(psync_fsfileid_t) * 2 + 2], *filename;
    const char *cachepath;
    psync_tree *tr;
    psync_openfile_t *fl;
    int64_t d;
    int ret;
    tr = openfiles;
    fl = NULL;
    while (tr) {
      d = fileid - ptree_element(tr, psync_openfile_t, tree)->fileid;
      if (d < 0)
        tr = tr->left;
      else if (d > 0)
        tr = tr->right;
      else {
        fl = ptree_element(tr, psync_openfile_t, tree);
        break;
      }
    }
    fileid = -fileid;
    psync_binhex(fileidhex, &fileid, sizeof(psync_fsfileid_t));
    fileidhex[sizeof(psync_fsfileid_t)] = 'd';
    fileidhex[sizeof(psync_fsfileid_t) + 1] = 0;
    cachepath = psync_setting_get_string(_PS(fscachepath));
    filename =
        putil_strcat(cachepath, "/", fileidhex, NULL);
    if (fl && fl->datafile != INVALID_HANDLE_VALUE) {
      pdbg_logf(D_NOTICE, "found open file for file id %ld", (long)fl->fileid);
      if (crtime)
        ret =
            pfile_set_crtime_mtime_by_fd(fl->datafile, filename, tv->tv_sec, 0);
      else
        ret =
            pfile_set_crtime_mtime_by_fd(fl->datafile, filename, 0, tv->tv_sec);
    } else {
      if (crtime)
        ret = pfile_set_crtime_mtime(filename, tv->tv_sec, 0);
      else
        ret = pfile_set_crtime_mtime(filename, 0, tv->tv_sec);
    }
    pdbg_logf(D_NOTICE, "setting %s time of %s to %lu=%d",
          crtime ? "creation" : "modification", filename,
          (unsigned long)tv->tv_sec, ret);
    free(filename);
    return ret ? -EACCES : 0;
  }
}

static int pfs_set_foldertime_locked(psync_fsfolderid_t folderid,
                                          const struct timespec *tv, int crtime,
                                          uint64_t current) {
  pdbg_logf(D_NOTICE, "request to set time of folderid %ld ignored",
        (long)folderid);
  return 0;
}

static int pfs_set_time_locked(psync_fsfolderid_t folderid,
                                    const char *name, const struct timespec *tv,
                                    int crtime) {
  psync_fstask_folder_t *folder;
  psync_fstask_creat_t *creat;
  psync_fstask_mkdir_t *mkdir;
  psync_fstask_unlink_t *un;
  psync_fstask_rmdir_t *rm;
  psync_sql_res *res;
  psync_uint_row row;
  folder = pfs_task_get_folder_tasks_rdlocked(folderid);
  if (folder) {
    if ((creat = pfs_task_find_creat(folder, name, 0))) {
      if (creat->fileid > 0) {
        res =
            psql_query_nolock("SELECT mtime, ctime FROM file WHERE id=?");
        psql_bind_uint(res, 1, creat->fileid);
        if ((row = psql_fetch_int(res))) {
          uint64_t ctm = row[crtime];
          psql_free(res);
          return pfs_set_filetime_locked(creat->fileid, tv, crtime, ctm);
        } else {
          psql_free(res);
          pdbg_logf(D_WARNING,
                "found creat in folderid %lu for %s with fileid %lu not "
                "present in the database",
                (unsigned long)folderid, name, (unsigned long)creat->fileid);
          return -ENOENT;
        }
      } else
        return pfs_set_filetime_locked(creat->fileid, tv, crtime, 0);
    }
    if ((mkdir = pfs_task_find_mkdir(folder, name, 0)))
      return pfs_set_foldertime_locked(mkdir->folderid, tv, crtime, 0);
    un = pfs_task_find_unlink(folder, name, 0);
    rm = pfs_task_find_rmdir(folder, name, 0);
  } else {
    un = NULL;
    rm = NULL;
  }
  if (!un && folderid >= 0) {
    res = psql_query_nolock(
        "SELECT id, mtime, ctime FROM file WHERE parentfolderid=? AND name=?");
    psql_bind_uint(res, 1, folderid);
    psql_bind_str(res, 2, name);
    if ((row = psql_fetch_int(res))) {
      uint64_t fileid = row[0];
      uint64_t ctm = row[1 + crtime];
      psql_free(res);
      return pfs_set_filetime_locked(fileid, tv, crtime, ctm);
    }
    psql_free(res);
  }
  if (!rm && folderid >= 0) {
    res = psql_query_nolock("SELECT id, permissions, mtime, ctime FROM "
                                 "folder WHERE parentfolderid=? AND name=?");
    psql_bind_uint(res, 1, folderid);
    psql_bind_str(res, 2, name);
    if ((row = psql_fetch_int(res))) {
      uint64_t folderid = row[0];
      uint64_t permissions = row[1];
      uint64_t ctm = row[2 + crtime];
      psql_free(res);
      if (!(permissions & PSYNC_PERM_MODIFY))
        return -EACCES;
      return pfs_set_foldertime_locked(folderid, tv, crtime, ctm);
    }
    psql_free(res);
  }
  return -ENOENT;
}

static int pfs_set_time(const char *path, const struct timespec *tv,
                             int crtime) {
  psync_fspath_t *fpath;
  int ret;
  psql_lock();
  CHECK_LOGIN_LOCKED();
  fpath = pfs_fldr_resolve_path(path);
  if (!fpath)
    ret = -ENOENT;
  else if (!(fpath->permissions & PSYNC_PERM_MODIFY))
    ret = -EACCES;
  else
    ret = pfs_set_time_locked(fpath->folderid, fpath->name, tv, crtime);
  psql_unlock();
  free(fpath);
  return ret;
}

#if defined(FUSE_HAS_SETCRTIME)
static int pfs_setcrtime(const char *path, const struct timespec *tv) {
  pfs_set_thread_name();
  pdbg_logf(D_NOTICE, "setcrtime %s %lu", path, tv->tv_sec);
  return pfs_set_time(path, tv, 1);
}
#endif

static int pfs_utimens(const char *path, const struct timespec tv[2]) {
  pfs_set_thread_name();
  pdbg_logf(D_NOTICE, "utimens %s %lu", path, tv[1].tv_sec);
  return pfs_set_time(path, &tv[1], 0);
}

static int pfs_ftruncate_of_locked(psync_openfile_t *of, fuse_off_t size) {
  int ret;
  if (of->currentsize == size) {
    pdbg_logf(D_NOTICE, "not truncating as size is already %lu",
          (long unsigned)size);
    return 0;
  }
  pfs_inc_writeid_locked(of);
retry:
  if (unlikely(!of->newfile && !of->modified)) {
    ret = pfs_reopen_file_for_writing(of);
    if (ret == 1)
      goto retry;
    else if (ret < 0)
      return ret;
  }
  if (of->encrypted)
    return pfs_crpt_truncate(of, size);
  else {
    if (pfs_modfile_check_size_ok(of, size))
      ret = -pdbg_return_const(EIO);
    else if (of->currentsize != size &&
             (pfile_seek(of->datafile, size, SEEK_SET) == -1 ||
              pfile_truncate(of->datafile)))
      ret = -pdbg_return_const(EIO);
    else {
      ret = 0;
      of->currentsize = size;
    }
  }
  return ret;
}

static int pfs_ftruncate(const char *path, fuse_off_t size,
                              struct fuse_file_info *fi) {
  psync_openfile_t *of;
  int ret;
  pfs_set_thread_name();
  pdbg_logf(D_NOTICE, "ftruncate %s %lu", path, (unsigned long)size);
  of = fh_to_openfile(fi->fh);
  pfs_lock_file(of);
  if (!of->canmodify) {
    pthread_mutex_unlock(&of->mutex);
    return -EACCES;
  }
  ret = pfs_ftruncate_of_locked(of, size);
  pthread_mutex_unlock(&of->mutex);
  return pdbg_returnf(ret, " for ftruncate of %s to %lu", path,
                             (unsigned long)size);
}

#if FUSE_USE_VERSION >= 30
static int pfs_truncate(const char *path, fuse_off_t size, struct fuse_file_info *fi) {
  struct fuse_file_info fi_local;
  int ret;
  pfs_set_thread_name();
  pdbg_logf(D_NOTICE, "truncate %s %lu", path, (unsigned long)size);
  
  if (fi) {
    return pfs_ftruncate(path, size, fi);
  }
  
  memset(&fi_local, 0, sizeof(fi_local));
  ret = pfs_open(path, &fi_local);
  if (ret)
    return ret;
  ret = pfs_ftruncate(path, size, &fi_local);
  pfs_flush(path, &fi_local);
  pfs_release(path, &fi_local);
  return ret;
}
#else
static int pfs_truncate(const char *path, fuse_off_t size) {
  struct fuse_file_info fi;
  int ret;
  pfs_set_thread_name();
  pdbg_logf(D_NOTICE, "truncate %s %lu", path, (unsigned long)size);
  memset(&fi, 0, sizeof(fi));
  ret = pfs_open(path, &fi);
  if (ret)
    return ret;
  ret = pfs_ftruncate(path, size, &fi);
  pfs_flush(path, &fi);
  pfs_release(path, &fi);
  return ret;
}
#endif

static void pfs_start_callback_timer(psync_timer_t timer, void *ptr) {
  psync_generic_callback_t callback;
  ptimer_stop(timer);
  callback = psync_start_callback;
  if (callback)
    prun_thread("fs start callback", callback);
}

#if FUSE_USE_VERSION >= 30
static void *pfs_init(struct fuse_conn_info *conn, struct fuse_config *cfg) {
#else
static void *pfs_init(struct fuse_conn_info *conn) {
#endif
#if defined(FUSE_CAP_ASYNC_READ)
  conn->want |= FUSE_CAP_ASYNC_READ;
#endif
#if defined(FUSE_CAP_ATOMIC_O_TRUNC)
  conn->want |= FUSE_CAP_ATOMIC_O_TRUNC;
#endif
#if defined(FUSE_CAP_BIG_WRITES)
  conn->want |= FUSE_CAP_BIG_WRITES;
#endif
  conn->max_readahead = 1024 * 1024;
  if (psync_start_callback)
    ptimer_register(pfs_start_callback_timer, 1, NULL);
  return 0;
}

static pthread_mutex_t fsrefreshmutex = PTHREAD_MUTEX_INITIALIZER;
static time_t lastfsrefresh = 0;
static int fsrefreshtimerscheduled = 0;
#define REFRESH_SEC 3

static void psync_invalidate_os_cache_noret() {
  char *path;
  pthread_mutex_lock(&start_mutex);
  if (started == 1)
    path = putil_strdup(psync_current_mountpoint);
  else
    path = NULL;
  pthread_mutex_unlock(&start_mutex);
  if (path) {
    pfile_invalidate_os_cache(path);
    free(path);
  }
}

static void pfs_refresh_timer(psync_timer_t timer, void *ptr) {
  time_t ct;
  ct = ptimer_time();
  ptimer_stop(timer);
  pthread_mutex_lock(&fsrefreshmutex);
  fsrefreshtimerscheduled = 0;
  lastfsrefresh = ct;
  pthread_mutex_unlock(&fsrefreshmutex);
  prun_thread("os cache invalidate timer",
                   psync_invalidate_os_cache_noret);
}

void pfs_refresh() {
  time_t ct;
  int todo;
  if (!pfile_invalidate_os_cache_needed())
    return;
  ct = ptimer_time();
  todo = 0;
  pthread_mutex_lock(&fsrefreshmutex);
  if (fsrefreshtimerscheduled)
    todo = 2;
  else if (lastfsrefresh + REFRESH_SEC < ct)
    lastfsrefresh = ct;
  else {
    todo = 1;
    fsrefreshtimerscheduled = 1;
  }
  pthread_mutex_unlock(&fsrefreshmutex);
  if (todo == 0) {
    pdbg_logf(D_NOTICE, "running cache invalidate direct");
    prun_thread("os cache invalidate", psync_invalidate_os_cache_noret);
  } else if (todo == 1) {
    pdbg_logf(D_NOTICE, "setting timer to invalidate cache");
    ptimer_register(pfs_refresh_timer, REFRESH_SEC, NULL);
  }
}

int pfs_need_per_folder_refresh_f() {
#if pfs_need_per_folder_refresh_const()
  return started == 1;
#else
  return 0;
#endif
}

void pfs_refresh_folder(psync_folderid_t folderid) {
  char *path, *fpath;
  unsigned char rndbuff[20];
  char rndhex[42];
  int fd;

  path =
      pfolder_path_sep(folderid, "/", NULL);
  if (path == PSYNC_INVALID_PATH)
    return;
  pssl_rand_strong(rndbuff, sizeof(rndbuff));
  psync_binhex(rndhex, rndbuff, sizeof(rndbuff));
  rndhex[2 * sizeof(rndbuff)] = 0;
  pthread_mutex_lock(&start_mutex);
  if (started == 1) {
    if (pfile_invalidate_os_cache_needed())
      fpath = putil_strcat(psync_current_mountpoint, path, NULL);
    else
      fpath = putil_strcat(psync_current_mountpoint, path, "/",
                           pfs_fake_prefix, rndhex, NULL);
  } else
    fpath = NULL;
  pthread_mutex_unlock(&start_mutex);
  free(path);
  if (!fpath)
    return;
  if (pfile_invalidate_os_cache_needed())
    pfile_invalidate_os_cache(fpath);
  else {
    pdbg_logf(D_NOTICE, "creating fake file %s", fpath);
    fd = pfile_open(fpath, O_WRONLY, O_CREAT);
    if (fd != INVALID_HANDLE_VALUE) {
      pfile_close(fd);
      pfile_delete(fpath);
    }
  }
  free(fpath);
}

static char *psync_fuse_get_mountpoint() {
  struct stat st;
  char *mp;
  int stat_result;
  int stat_errno;

  mp = putil_strdup(psync_setting_get_string(_PS(fsroot)));

  stat_result = stat(mp, &st);
  stat_errno = errno;

  if (stat_result != 0) {
    /* Provide detailed error message based on errno */
    if (stat_errno == ENOTCONN) {
      pdbg_logf(D_CRITICAL,
                "Mount point %s has a stale FUSE mount (Transport endpoint is not connected). "
                "Please unmount it first with: fusermount -u %s", mp, mp);
    } else if (stat_errno == ENOENT) {
      pdbg_logf(D_CRITICAL,
                "Mount point %s does not exist. "
                "Please create the directory first with: mkdir -p %s", mp, mp);
    } else {
      pdbg_logf(D_CRITICAL,
                "Cannot access mount point %s (errno=%d: %s). "
                "Please verify the path exists and is accessible.",
                mp, stat_errno, strerror(stat_errno));
    }
    free(mp);
    return NULL;
  }

  /* Verify it's a directory */
  if (!S_ISDIR(st.st_mode)) {
    pdbg_logf(D_CRITICAL,
              "Mount point %s exists but is not a directory", mp);
    free(mp);
    return NULL;
  }

  return mp;
}

char *pfs_getmountpoint() {
  char *ret;
  pthread_mutex_lock(&start_mutex);
  if (started == 1)
    ret = putil_strdup(psync_current_mountpoint);
  else
    ret = NULL;
  pthread_mutex_unlock(&start_mutex);
  return ret;
}

void pfs_register_start_callback(psync_generic_callback_t callback) {
  psync_start_callback = callback;
}

char *pfs_get_path_by_folderid(psync_folderid_t folderid) {
  char *mp, *path, *ret;
  pthread_mutex_lock(&start_mutex);
  if (started == 1)
    mp = putil_strdup(psync_current_mountpoint);
  else
    mp = NULL;
  pthread_mutex_unlock(&start_mutex);
  if (!mp || folderid == 0)
    return mp;
  path =
      pfolder_path_sep(folderid, "/", NULL);
  if (path == PSYNC_INVALID_PATH) {
    free(mp);
    return NULL;
  }
  ret = putil_strcat(mp, path, NULL);
  free(mp);
  free(path);
  return ret;
}

char *pfs_get_path_by_fileid(psync_fileid_t fileid) {
  char *mp, *path, *ret;
  pthread_mutex_lock(&start_mutex);
  if (started == 1)
    mp = putil_strdup(psync_current_mountpoint);
  else
    mp = NULL;
  pthread_mutex_unlock(&start_mutex);
  if (!mp)
    return NULL;
  path = pfolder_file_path(fileid, NULL);
  if (path == PSYNC_INVALID_PATH) {
    free(mp);
    return NULL;
  }
  ret = putil_strcat(mp, path, NULL);
  free(mp);
  free(path);
  return ret;
}

static void pfs_do_stop(void) {
  if (!__sync_bool_compare_and_swap(&shutdown_in_progress, 0, 1)) {
    // prevent multiple executions
    return;
  }

  pdbg_logf(D_NOTICE, "stopping");
  pthread_mutex_lock(&start_mutex);
  if (started == 1) {

    char *mp;
    struct stat st_before, st_after;
    struct timespec ts = {0, 100000000};

    mp = psync_fuse_get_mountpoint();
    if (mp) {
      if (stat(mp, &st_before) == 0) {
#if FUSE_USE_VERSION >= 30
        struct fuse_session *se = fuse_get_session(psync_fuse);
        fuse_session_unmount(se);
#else
        fuse_unmount(mp, psync_fuse_channel);
        psync_fuse_channel = NULL;
#endif
        clock_gettime(CLOCK_REALTIME, &ts);

        // Check if the mountpoint is still accessible
        if (stat(mp, &st_after) == 0) {
          if (st_before.st_dev == st_after.st_dev) {
            pdbg_logf(D_WARNING, "FUSE filesystem may not have unmounted properly");
          }
        } else if (errno != ENOENT) {
          pdbg_logf(D_WARNING, "Unexpected error after unmount: %s",
                strerror(errno));
        }
      } else {
        pdbg_logf(D_WARNING, "Mountpoint not accessible before unmount: %s",
              strerror(errno));
      }
    } else {
      pdbg_logf(D_ERROR, "Failed to get mountpoint");
    }

    pdbg_logf(D_NOTICE, "running fuse_exit");
    fuse_exit(psync_fuse);
    started = 2;
    pdbg_logf(D_NOTICE, "fuse_exit exited, flushing cache");
    ppagecache_flush();
    pdbg_logf(D_NOTICE, "cache flushed, waiting for fuse to exit");
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += 2;

    int wait_result = pthread_cond_timedwait(&start_cond, &start_mutex, &ts);
    if (wait_result == ETIMEDOUT) {
      pdbg_logf(D_WARNING, "timed out waiting for fuse to exit");
    } else if (wait_result != 0) {
      pdbg_logf(D_ERROR, "error waiting for fuse to exit: %s",
            strerror(wait_result));
    } else {
      pdbg_logf(D_NOTICE, "waited for fuse to exit");
    }

    pfs_debug_dump_internals();
    free(mp);
  }
  pthread_mutex_unlock(&start_mutex);
}

void pfs_stop() { pfs_do_stop(); }

static void psync_signal_handler(int sig) {
  pdbg_logf(D_NOTICE, "got signal %d", sig);
  exit(1); // invoke psync_do_stop via atexit()
}

static void psync_usr2_handler(int sig) {
  /* Signal handler must be signal-safe - just set flag, don't log here */
  pdbg_reopen_log();
}

static void psync_set_signal(int sig, void (*handler)(int)) {
  struct sigaction sa;

  if (pdbg_unlikely(sigaction(sig, NULL, &sa)))
    return;

  if (sa.sa_handler == SIG_DFL) {
    memset(&sa, 0, sizeof(struct sigaction));
    sigemptyset(&(sa.sa_mask));
    sa.sa_handler = handler;
    sa.sa_flags = 0;
    sigaction(sig, &sa, NULL);
  }
}

static void psync_setup_signals() {
  psync_set_signal(SIGTERM, psync_signal_handler);
  psync_set_signal(SIGINT, psync_signal_handler);
  psync_set_signal(SIGHUP, psync_signal_handler);
  pfs_debug_register_signal_handlers();
  psync_set_signal(SIGUSR2, psync_usr2_handler);
}

static void pfs_init_once() {
#if pfs_need_per_folder_refresh_const()
  unsigned char rndbuff[16];
  char rndhex[34];
  pssl_rand_strong(rndbuff, sizeof(rndbuff));
  psync_binhex(rndhex, rndbuff, sizeof(rndbuff));
  rndhex[2 * sizeof(rndbuff)] = 0;
  pfs_fake_prefix = putil_strcat(".refresh", rndhex, NULL);
  pfs_fake_prefix_len = strlen(pfs_fake_prefix);
#endif
  pfs_task_init();
  ppagecache_init();
  atexit(pfs_do_stop);
  psync_setup_signals();
  pfs_stat_add_files();
  pfs_task_add_banned_folders();
}

static void psync_fuse_thread() {
  int fr;
  pthread_mutex_lock(&start_mutex);
  if (!initonce) {
    pfs_init_once();
    initonce = 1;
  }
  pthread_mutex_unlock(&start_mutex);
  pdbg_logf(D_NOTICE, "running fuse_loop_mt");
#if FUSE_USE_VERSION >= 30
  struct fuse_loop_config loop_config;
  loop_config.clone_fd = 1;
  loop_config.max_idle_threads = 10;
  fr = fuse_loop_mt_31(psync_fuse, &loop_config);
#else
  fr = fuse_loop_mt(psync_fuse);
#endif
  pdbg_logf(D_NOTICE, "fuse_loop_mt exited with code %d, running fuse_destroy", fr);
  pthread_mutex_lock(&start_mutex);
  fuse_destroy(psync_fuse);
  pdbg_logf(D_NOTICE, "fuse_destroy exited");
  free(psync_current_mountpoint);
  started = 0;
  pthread_cond_broadcast(&start_cond);
  pthread_mutex_unlock(&start_mutex);
}

// Returns true if FUSE 3 is installed on the user's machine.
// Returns false if FUSE version is less than 3.
static char is_fuse3_installed_on_system() {
  // Assuming that fusermount3 is only available on FUSE 3.
  FILE *pipe = popen("which fusermount3", "r");

  if (!pipe) {
    return 0;
  }

  char output[1024];
  memset(output, 0, sizeof(output));

  if (fgets(output, sizeof(output), pipe) != NULL) {
    return 0;
  }

  pclose(pipe);
  size_t outlen = strlen(output);

  return outlen > 0;
}

static int pfs_do_start() {
  char *mp;
  struct fuse_operations psync_oper;
  struct fuse_args args = FUSE_ARGS_INIT(0, NULL);

  // it seems that fuse option parser ignores the first argument
  // it is ignored as it's like in the exec() parameters, argv[0] is the program

  fuse_opt_add_arg(&args, "argv");
  fuse_opt_add_arg(&args, "-oauto_unmount");
  fuse_opt_add_arg(&args, "-ofsname=" DEFAULT_FUSE_MOUNT_POINT ".fs");

  // Add user-specified FUSE options from environment variable
  const char *fuse_opts_env = getenv("PCLOUD_FUSE_OPTS");
  if (fuse_opts_env && fuse_opts_env[0] != '\0') {
    char *fuse_opts = strdup(fuse_opts_env);
    if (fuse_opts) {
      char *saveptr = NULL;
      char *token = strtok_r(fuse_opts, ",", &saveptr);
      while (token) {
        // Trim leading/trailing whitespace
        while (*token == ' ' || *token == '\t') token++;
        char *end = token + strlen(token) - 1;
        while (end > token && (*end == ' ' || *end == '\t')) *end-- = '\0';

        if (strlen(token) > 0) {
          if (strlen(token) > 250) {
            pdbg_logf(D_WARNING, "FUSE option too long, skipping: %s", token);
          } else {
            char opt_arg[256];
            snprintf(opt_arg, sizeof(opt_arg), "-o%s", token);
            fuse_opt_add_arg(&args, opt_arg);
            pdbg_logf(D_NOTICE, "Adding FUSE option: %s", token);
          }
        }
        token = strtok_r(NULL, ",", &saveptr);
      }
      free(fuse_opts);
    }
  }

  memset(&psync_oper, 0, sizeof(psync_oper));

  psync_oper.init = pfs_init;
  psync_oper.getattr = pfs_getattr;
  psync_oper.readdir = pfs_readdir;
  psync_oper.open = pfs_open;
  psync_oper.create = pfs_creat;
  psync_oper.release = pfs_release;
  psync_oper.flush = pfs_flush;
  psync_oper.fsync = pfs_fsync;
  psync_oper.fsyncdir = pfs_fsyncdir;
  psync_oper.read = pfs_read;
  psync_oper.write = pfs_write;
  psync_oper.mkdir = pfs_mkdir;
  psync_oper.rmdir = pfs_rmdir;
  psync_oper.unlink = pfs_unlink;
  psync_oper.rename = pfs_rename;
  psync_oper.statfs = pfs_statfs;
  psync_oper.chmod = pfs_chmod;
  psync_oper.chown = pfs_chown;
  psync_oper.utimens = pfs_utimens;
#if FUSE_USE_VERSION >= 30
  psync_oper.truncate = pfs_truncate;
#else
  psync_oper.ftruncate = pfs_ftruncate;
  psync_oper.truncate = pfs_truncate;
#endif

  psync_oper.setxattr = pfs_xatr_set;
  psync_oper.getxattr = pfs_xatr_get;
  psync_oper.listxattr = pfs_xatr_list;
  psync_oper.removexattr = pfs_xatr_remove;

#if defined(FUSE_HAS_CAN_UNLINK)
  psync_oper.can_unlink = pfs_can_unlink;
  psync_oper.can_rmdir = pfs_can_rmdir;
#endif

#if defined(FUSE_HAS_SETCRTIME)
  psync_oper.setcrtime = pfs_setcrtime;
#endif

  myuid = getuid();
  mygid = getgid();
  pthread_mutex_lock(&start_mutex);
  if (started)
    goto err00;
  mp = psync_fuse_get_mountpoint();

  if (!mp) {
    pdbg_logf(D_CRITICAL,
              "CRITICAL ERROR: Cannot initialize FUSE filesystem. "
              "Mount point is unavailable. See error messages above for details.");
    goto err00;
  }

#if FUSE_USE_VERSION >= 30
  psync_fuse = fuse_new(&args, &psync_oper, sizeof(psync_oper), NULL);
  if (pdbg_unlikely(!psync_fuse)) {
    pdbg_logf(D_CRITICAL,
              "CRITICAL ERROR: fuse_new() failed. "
              "The FUSE filesystem cannot be started. errno=%d (%s)", 
              errno, strerror(errno));
    goto err0;
  }
  
  struct fuse_session *se = fuse_get_session(psync_fuse);
  if (fuse_session_mount(se, mp) != 0) {
    pdbg_logf(D_CRITICAL,
              "CRITICAL ERROR: fuse_session_mount() failed for mount point %s. "
              "The FUSE filesystem cannot be started. errno=%d (%s)", 
              mp, errno, strerror(errno));
    goto err1;
  }
#else
  struct fuse_chan *ch = fuse_mount(mp, &args);
  if (pdbg_unlikely(!ch)) {
    pdbg_logf(D_CRITICAL,
              "CRITICAL ERROR: fuse_mount() failed for mount point %s. "
              "The FUSE filesystem cannot be started. errno=%d (%s)", 
              mp, errno, strerror(errno));
    goto err0;
  }
  
  psync_fuse = fuse_new(ch, &args, &psync_oper, sizeof(psync_oper), NULL);
  if (pdbg_unlikely(!psync_fuse)) {
    pdbg_logf(D_CRITICAL,
              "CRITICAL ERROR: fuse_new() failed. "
              "The FUSE filesystem cannot be started. errno=%d (%s)", 
              errno, strerror(errno));
    fuse_unmount(mp, ch);
    goto err0;
  }
  psync_fuse_channel = ch;
#endif
  
  psync_current_mountpoint = mp;
  started = 1;
  pthread_mutex_unlock(&start_mutex);
  fuse_opt_free_args(&args);
  prun_thread("fuse", psync_fuse_thread);
  return 0;
err1:
  fuse_destroy(psync_fuse);
err0:
  free(mp);
err00:
  pthread_mutex_unlock(&start_mutex);
  fuse_opt_free_args(&args);
  return -1;
}

static void pfs_wait_start() {
  pdbg_logf(D_NOTICE, "waiting for online status");
  pstatus_wait(PSTATUS_TYPE_ONLINE, PSTATUS_ONLINE_ONLINE);
  if (psync_do_run) {
    pdbg_logf(D_NOTICE, "starting fs");
    pfs_do_start();
  }
}

static void pfs_wait_login() {
  pdbg_logf(D_NOTICE, "waiting for online status");
  pstatus_wait(PSTATUS_TYPE_ONLINE, PSTATUS_ONLINE_ONLINE);
  pdbg_logf(D_NOTICE, "waited for online status");
  psql_lock();
  waitingforlogin = 0;
  psql_unlock();
}

void pfs_pause_until_login() {
  psql_lock();
  if (waitingforlogin == 0) {
    waitingforlogin = 1;
    pdbg_logf(D_NOTICE, "stopping fs until login");
    prun_thread("fs wait login", pfs_wait_login);
  }
  psql_unlock();
}

void pfs_clean_tasks() { pfs_task_clean(); }

int pfs_start() {
  uint32_t status;
  int ret;
  pthread_mutex_lock(&start_mutex);
  if (started)
    ret = -1;
  else
    ret = 0;
  pthread_mutex_unlock(&start_mutex);
  if (ret)
    return ret;
  status = pstatus_get(PSTATUS_TYPE_AUTH);
  pdbg_logf(D_NOTICE, "auth status=%u", status);
  if (status == PSTATUS_AUTH_PROVIDED)
    return pfs_do_start();
  else {
    prun_thread("fs wait login", pfs_wait_start);
    return 0;
  }
}

int pfs_isstarted() {
  int s;
  pthread_mutex_lock(&start_mutex);
  s = started;
  pthread_mutex_unlock(&start_mutex);
  return s == 1;
}

int pfs_remount() {
  int s;
  pthread_mutex_lock(&start_mutex);
  s = started;
  pthread_mutex_unlock(&start_mutex);
  if (s) {
    pfs_stop();
    return pfs_start();
  } else
    return 0;
}
