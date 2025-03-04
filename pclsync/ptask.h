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

#ifndef _PSYNC_TASKS_H
#define _PSYNC_TASKS_H

#include "pfoldersync.h"

#define PSYNC_ASYNC_ERR_FLAG_PERM                                              \
  0x01 // the error is permanent(ish) and there is no reason to retry
#define PSYNC_ASYNC_ERR_FLAG_RETRY_AS_IS                                       \
  0x02 // same request may succeed in the future if retried as is
#define PSYNC_ASYNC_ERR_FLAG_SUCCESS                                           \
  0x04 // like no action performed because of no need - file already exists and
       // so on

#define PSYNC_ASYNC_ERROR_NET 1
#define PSYNC_ASYNC_ERROR_FILE 2
#define PSYNC_ASYNC_ERROR_DISK_FULL 3
#define PSYNC_ASYNC_ERROR_IO 4
#define PSYNC_ASYNC_ERROR_CHECKSUM 5
#define PSYNC_SERVER_ERROR_TOO_BIG 102
#define PSYNC_SERVER_ERROR_NOT_MOD 104
#define PSYNC_TASK_DOWNLOAD 0
#define PSYNC_TASK_UPLOAD 1
#define PSYNC_TASK_DWLUPL_MASK 1
#define PSYNC_TASK_FOLDER 0
#define PSYNC_TASK_FILE 2
#define PSYNC_TASK_TYPE_OFF 2
#define PSYNC_TASK_TYPE_CREATE 0
#define PSYNC_TASK_TYPE_DELETE 1
#define PSYNC_TASK_TYPE_DELREC 2
#define PSYNC_TASK_TYPE_RENAME 3
#define PSYNC_TASK_TYPE_COPY 4

#define PSYNC_CREATE_LOCAL_FOLDER                                              \
  ((PSYNC_TASK_TYPE_CREATE << PSYNC_TASK_TYPE_OFF) + PSYNC_TASK_FOLDER +       \
   PSYNC_TASK_DOWNLOAD)
#define PSYNC_DELETE_LOCAL_FOLDER                                              \
  ((PSYNC_TASK_TYPE_DELETE << PSYNC_TASK_TYPE_OFF) + PSYNC_TASK_FOLDER +       \
   PSYNC_TASK_DOWNLOAD)
#define PSYNC_DELREC_LOCAL_FOLDER                                              \
  ((PSYNC_TASK_TYPE_DELREC << PSYNC_TASK_TYPE_OFF) + PSYNC_TASK_FOLDER +       \
   PSYNC_TASK_DOWNLOAD)
#define PSYNC_RENAME_LOCAL_FOLDER                                              \
  ((PSYNC_TASK_TYPE_RENAME << PSYNC_TASK_TYPE_OFF) + PSYNC_TASK_FOLDER +       \
   PSYNC_TASK_DOWNLOAD)
#define PSYNC_COPY_LOCAL_FOLDER                                                \
  ((PSYNC_TASK_TYPE_COPY << PSYNC_TASK_TYPE_OFF) + PSYNC_TASK_FOLDER +         \
   PSYNC_TASK_DOWNLOAD)
#define PSYNC_DOWNLOAD_FILE                                                    \
  ((PSYNC_TASK_TYPE_CREATE << PSYNC_TASK_TYPE_OFF) + PSYNC_TASK_FILE +         \
   PSYNC_TASK_DOWNLOAD)
#define PSYNC_RENAME_LOCAL_FILE                                                \
  ((PSYNC_TASK_TYPE_RENAME << PSYNC_TASK_TYPE_OFF) + PSYNC_TASK_FILE +         \
   PSYNC_TASK_DOWNLOAD)
#define PSYNC_DELETE_LOCAL_FILE                                                \
  ((PSYNC_TASK_TYPE_DELETE << PSYNC_TASK_TYPE_OFF) + PSYNC_TASK_FILE +         \
   PSYNC_TASK_DOWNLOAD)

#define PSYNC_CREATE_REMOTE_FOLDER                                             \
  ((PSYNC_TASK_TYPE_CREATE << PSYNC_TASK_TYPE_OFF) + PSYNC_TASK_FOLDER +       \
   PSYNC_TASK_UPLOAD)
#define PSYNC_RENAME_REMOTE_FOLDER                                             \
  ((PSYNC_TASK_TYPE_RENAME << PSYNC_TASK_TYPE_OFF) + PSYNC_TASK_FOLDER +       \
   PSYNC_TASK_UPLOAD)
#define PSYNC_UPLOAD_FILE                                                      \
  ((PSYNC_TASK_TYPE_CREATE << PSYNC_TASK_TYPE_OFF) + PSYNC_TASK_FILE +         \
   PSYNC_TASK_UPLOAD)
#define PSYNC_RENAME_REMOTE_FILE                                               \
  ((PSYNC_TASK_TYPE_RENAME << PSYNC_TASK_TYPE_OFF) + PSYNC_TASK_FILE +         \
   PSYNC_TASK_UPLOAD)
#define PSYNC_DELETE_REMOTE_FILE                                               \
  ((PSYNC_TASK_TYPE_DELETE << PSYNC_TASK_TYPE_OFF) + PSYNC_TASK_FILE +         \
   PSYNC_TASK_UPLOAD)
#define PSYNC_DELREC_REMOTE_FOLDER                                             \
  ((PSYNC_TASK_TYPE_DELREC << PSYNC_TASK_TYPE_OFF) + PSYNC_TASK_FOLDER +       \
   PSYNC_TASK_UPLOAD)

typedef struct {
  uint64_t size;
  uint64_t hash;
  unsigned char sha1hex[40];
} psync_async_file_result_t;

typedef struct {
  uint32_t error;
  uint32_t errorflags;
  union {
    psync_async_file_result_t file;
  };
} psync_async_result_t;

typedef void (*psync_async_callback_t)(void *, psync_async_result_t *);


/* Important! The interface typically expect all passed pointers to be alive
 * until the completion callback is called.
 */
void ptask_stop_async();
int ptask_download_async(psync_fileid_t fileid, const char *localpath, psync_async_callback_t cb, void *cbext);
int ptask_download_needed_async(psync_fileid_t fileid, const char *localpath, uint64_t size, const void *sha1hex, psync_async_callback_t cb, void *cbext);

// local ops
void ptask_ldir_mk(psync_syncid_t syncid, psync_folderid_t folderid, psync_folderid_t localfolderid);
void ptask_ldir_rename(psync_syncid_t syncid, psync_folderid_t folderid, psync_folderid_t localfolderid, psync_folderid_t newlocalparentfolderid, const char *newname);
void ptask_ldir_rm(psync_syncid_t syncid, psync_folderid_t folderid, psync_folderid_t localfolderid, const char *remotepath);
void ptask_ldir_rm_r(psync_syncid_t syncid, psync_folderid_t folderid, psync_folderid_t localfolderid);
void ptask_lfile_rename(psync_syncid_t oldsyncid, psync_syncid_t newsyncid, psync_fileid_t fileid, psync_folderid_t oldlocalfolderid, psync_folderid_t newlocalfolderid, const char *newname);
void ptask_lfile_rm(psync_fileid_t fileid, const char *remotepath);
void ptask_lfile_rm_id(psync_syncid_t syncid, psync_fileid_t fileid, const char *remotepath);

// remote ops
// 
// for rename operations, "newname" should be passed here instead of reading
// it from localfile, to avoid conflict due to many pending renames
void ptask_rdir_mk(psync_syncid_t syncid, psync_folderid_t localfolderid, const char *name);
void ptask_rdir_rename(psync_syncid_t oldsyncid, psync_syncid_t newsyncid, psync_fileid_t localfileid, psync_folderid_t newlocalparentfolderid, const char *newname);
void ptask_rdir_rm(psync_syncid_t syncid, psync_folderid_t folderid);
void ptask_rfile_rename(psync_syncid_t oldsyncid, psync_syncid_t newsyncid, psync_fileid_t localfileid, psync_folderid_t newlocalparentfolderid, const char *newname);
void ptask_rfile_rm(psync_syncid_t syncid, psync_fileid_t fileid);

// file transfer
void ptask_download(psync_syncid_t syncid, psync_fileid_t fileid, psync_folderid_t localfolderid, const char *name);
void ptask_download_q(psync_syncid_t syncid, psync_fileid_t fileid, psync_folderid_t localfolderid, const char *name);
void ptask_upload(psync_syncid_t syncid, psync_fileid_t localfileid, const char *name);
void ptask_upload_q(psync_syncid_t syncid, psync_fileid_t localfileid, const char *name);

#endif
