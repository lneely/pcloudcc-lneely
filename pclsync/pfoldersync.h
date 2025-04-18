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

// pfoldersync.h provides a unified interface for folder synchronization.

#ifndef _PSYNC_FOLDERSYNC_H
#define _PSYNC_FOLDERSYNC_H

#include "pcompiler.h"
#include "plist.h"

#include <stddef.h>
#include <stdint.h>

// folders API
#define PSYNC_INVALID_FOLDERID ((psync_folderid_t) - 1)
#define PSYNC_INVALID_PATH NULL

#define PSYNC_FOLDER_FLAG_ENCRYPTED 1
#define PSYNC_FOLDER_FLAG_INVISIBLE 2
#define PSYNC_FOLDER_FLAG_PUBLIC_ROOT 4
#define PSYNC_FOLDER_FLAG_BACKUP_DEVICE_LIST 8
#define PSYNC_FOLDER_FLAG_BACKUP_DEVICE 16
#define PSYNC_FOLDER_FLAG_BACKUP_ROOT 32
#define PSYNC_FOLDER_FLAG_BACKUP 64

#define PSYNC_DOWNLOAD_ONLY 1
#define PSYNC_UPLOAD_ONLY 2
#define PSYNC_FULL 3
#define PSYNC_BACKUPS 7
#define PSYNC_STR_DOWNLOAD_ONLY "1"
#define PSYNC_STR_UPLOAD_ONLY "2"
#define PSYNC_STR_FULL "3"
#define PSYNC_STR_ALLSYNCS "1,2,3"
#define PSYNC_STR_BACKUPS "7"
#define PSYNC_SYNCTYPE_MIN 1
#define PSYNC_SYNCTYPE_MAX 7


// limitation: path length of 255, plus null terminator.
#define PSYNC_MAX_PATH_LENGTH 256

typedef uint64_t psync_folderid_t;
typedef uint64_t psync_fileid_t;
typedef uint64_t psync_fileorfolderid_t;
typedef uint32_t psync_synctype_t;
typedef uint32_t psync_syncid_t;

typedef struct {
  psync_fileid_t fileid;
  uint64_t size;
} pfile_t;

typedef struct {
  psync_folderid_t folderid;
  uint8_t cansyncup;
  uint8_t cansyncdown;
  uint8_t canshare;
  uint8_t isencrypted;
} pfolder_t;

typedef struct {
  const char *name;
  union {
    pfolder_t folder;
    pfile_t file;
  };
  uint16_t namelen;
  uint8_t isfolder;
} pentry_t;

typedef struct {
  size_t entrycnt;
  pentry_t entries[];
} pfolder_list_t;

typedef struct {
  const char *localpath;
  const char *name;
  const char *description;
} psuggested_folder_t;

typedef struct {
  size_t entrycnt;
  psuggested_folder_t entries[];
} psuggested_folders_t;

typedef struct {
  pentry_t *entries;
  char *namebuff;
  size_t nameoff;
  size_t namealloc;
  uint32_t entriescnt;
  uint32_t entriesalloc;
} folder_list;

typedef struct {
  folder_list *folderlist;
  psync_listtype_t listtype;
} flist_ltype;

typedef struct {
  char localname[PSYNC_MAX_PATH_LENGTH];
  char localpath[PSYNC_MAX_PATH_LENGTH];
  char remotename[PSYNC_MAX_PATH_LENGTH];
  char remotepath[PSYNC_MAX_PATH_LENGTH];
  psync_folderid_t folderid;
  psync_syncid_t syncid;
  psync_synctype_t synctype;
} psync_folder_t;

typedef struct {
  size_t foldercnt;
  psync_folder_t folders[];
} psync_folder_list_t;

// folder API (impl. pfolder.c)
psync_folderid_t pfolder_id(const char *path) PSYNC_NONNULL(1) PSYNC_PURE;
psync_folderid_t pfolder_id_create(const char *path) PSYNC_NONNULL(1);
char *pfolder_path(psync_folderid_t folderid, size_t *retlen);
char *pfolder_path_sep(psync_folderid_t folderid, const char *sep, size_t *retlen);
char *pfolder_file_path(psync_fileid_t fileid, size_t *retlen);
char *pfolder_lpath_lfldr(psync_folderid_t localfolderid, psync_syncid_t syncid, size_t *retlen);
char *pfolder_lpath_lfile(psync_fileid_t localfileid, size_t *retlen);
pfolder_list_t *pfolder_remote_folders(psync_folderid_t folderid, psync_listtype_t listtype);
pfolder_list_t *pfolder_local_folders(const char *path, psync_listtype_t listtype) PSYNC_NONNULL(1);
pentry_t *pfolder_stat(const char *remotepath);

// Gets a list of local syncs, based on their type. Type empty string means all.
// Accepts comma separated list of types example: 1,2,3
psync_folder_list_t *pfolder_sync_folders(char *syncTypes);
psync_folderid_t pfolder_db_wait(psync_folderid_t folderid);


/* Use the following functions to list local or remote folders.
 * For local folders fileid and folderid will be set to a value that
 * should in general uniquely identify the entry (e.g. inode number).
 * Remote paths use slashes (/) and start with one.
 * In case of success the returned folder list is to be freed with a
 * single call to free(). In case of error NULL is returned. Parameter
 * listtype should be one of PLIST_FILES, PLIST_FOLDERS or PLIST_ALL.
 *
 * Folders do not contain "." or ".." entries.
 *
 * All files/folders are listed regardless if they are to be ignored
 * based on 'ignorepatterns' setting. If needed, pass the names to
 * psync_is_name_to_ignore that returns 1 for files that are to be
 * ignored and 0 for others.
 *
 * Remote root folder has 0 folderid.
 */

// Adds a sync folder to the database. localpath is the path on the
// local machine where pcloudcc is running. remotepath is the path in
// pcloud remote storage (it must already exist). synctype may be
// PSYNC_FULL, PSYNC_DOWNLOAD_ONLY, or PSYNC_UPLOAD_ONLY.
psync_syncid_t pfolder_add_sync_path(const char *localpath, const char *remotepath, psync_synctype_t synctype);
psync_syncid_t pfolder_add_sync(const char *localpath, psync_folderid_t folderid, psync_synctype_t synctype);
int pfolder_add_sync_path_delay(const char *localpath, const char *remotepath, psync_synctype_t synctype);
pfolder_list_t *pfolder_remote_folders_path(const char *remotepath, psync_listtype_t listtype);

// "syncer" API (impl. psync.c)
void psyncer_check_delayed();
void psyncer_create(psync_syncid_t syncid);
psync_folderid_t psyncer_db_folder_create(psync_syncid_t syncid, psync_folderid_t folderid, psync_folderid_t localparentfolderid, const char *name);
void psyncer_dl_folder_add(psync_syncid_t syncid, psync_synctype_t synctype, psync_folderid_t folderid, psync_folderid_t lfoiderid);
int psyncer_dl_has_folder(psync_folderid_t folderid);
void psyncer_dl_queue_add(psync_folderid_t folderid);
void psyncer_dl_queue_clear();
void psyncer_dl_queue_del(psync_folderid_t folderid);
void psyncer_folder_dec_tasks(psync_folderid_t lfolderid);
void psyncer_folder_inc_tasks(psync_folderid_t lfolderid);
void psyncer_init();
int psyncer_str_has_prefix(const char *str1, const char *str2);
int psyncer_str_starts_with(const char *str1, const char *str2);



#endif
