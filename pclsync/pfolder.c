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
#include <stddef.h>
#include <string.h>

#include "papi.h"
#include "pcryptofolder.h"
#include "pdiff.h"
#include "pfoldersync.h"
#include "pfsfolder.h"
#include "plibs.h"
#include "plist.h"
#include "pnetlibs.h"
#include "ppathstatus.h"
#include "prun.h"
#include "psys.h"
#include "ppath.h"
#include "pfile.h"
#include "psql.h"

#define INITIAL_NAME_BUFF 2000
#define INITIAL_ENTRY_CNT 128

typedef struct _string_list {
  psync_list list;
  char *str;
  size_t len;
} string_list;

static inline int psync_crypto_is_error(const void *ptr) {
  return (uintptr_t)ptr <= PSYNC_CRYPTO_MAX_ERROR;
}

static inline int psync_crypto_to_error(const void *ptr) {
  return -((int)(uintptr_t)ptr);
}

psync_folderid_t pfolder_id(const char *path) {
  psync_folderid_t cfolderid;
  const char *sl;
  psync_sql_res *res;
  psync_uint_row row;
  size_t len;
  res = NULL;
  if (*path != '/')
    goto err;
  cfolderid = 0;
  while (1) {
    while (*path == '/')
      path++;
    if (*path == 0) {
      if (res)
        psql_free(res);
      return cfolderid;
    }
    sl = strchr(path, '/');
    if (sl)
      len = sl - path;
    else
      len = strlen(path);
    if (!res) {
      res = psql_query_rdlock(
          "SELECT id FROM folder WHERE parentfolderid=? AND name=?");
      if (pdbg_unlikely(!res)) {
        psync_error = PERROR_DATABASE_ERROR;
        return PSYNC_INVALID_FOLDERID;
      }
    } else
      psql_reset(res);

    psql_bind_uint(res, 1, cfolderid);
    psql_bind_lstr(res, 2, path, len);
    row = psql_fetch_int(res);
    if (pdbg_unlikely(!row))
      goto err;
    cfolderid = row[0];
    path += len;
  }
err:
  if (res)
    psql_free(res);
  psync_error = PERROR_REMOTE_FOLDER_NOT_FOUND;
  return PSYNC_INVALID_FOLDERID;
}

static psync_folderid_t wait_folder_id_in_db(psync_folderid_t folderid) {
  psync_sql_res *res;
  psync_uint_row row;
  int tries;
  tries = 0;
  while (++tries <= 20) {
    res = psql_query_rdlock("SELECT id FROM folder WHERE id=?");
    psql_bind_uint(res, 1, folderid);
    row = psql_fetch_int(res);
    psql_free(res);
    if (row)
      return folderid;
    psys_sleep_milliseconds(50);
  }
  return PSYNC_INVALID_FOLDERID;
}

psync_folderid_t pfolder_db_wait(psync_folderid_t folderid) {
  return wait_folder_id_in_db(folderid);
}

psync_folderid_t pfolder_id_create(const char *path) {
  psync_folderid_t cfolderid;
  const char *sl;
  psync_sql_res *res;
  psync_uint_row row;
  size_t len;
  res = NULL;
  if (*path != '/')
    goto err;
  cfolderid = 0;
  while (1) {
    while (*path == '/')
      path++;
    if (*path == 0) {
      if (res)
        psql_free(res);
      return wait_folder_id_in_db(cfolderid);
    }
    sl = strchr(path, '/');
    if (sl)
      len = sl - path;
    else
      len = strlen(path);
    if (!res) {
      res = psql_query_rdlock(
          "SELECT id FROM folder WHERE parentfolderid=? AND name=?");
      if (pdbg_unlikely(!res)) {
        psync_error = PERROR_DATABASE_ERROR;
        return PSYNC_INVALID_FOLDERID;
      }
    } else
      psql_reset(res);
    psql_bind_uint(res, 1, cfolderid);
    psql_bind_lstr(res, 2, path, len);
    row = psql_fetch_int(res);
    if (row)
      cfolderid = row[0];
    else {
      binparam params[] = {PAPI_STR("auth", psync_my_auth),
                           PAPI_NUM("folderid", cfolderid),
                           PAPI_LSTR("name", path, len)};
      psock_t *api;
      binresult *bres;
      uint64_t result;
      api = psync_apipool_get();
      if (unlikely(!api))
        goto errnet;
      bres = papi_send2(api, "createfolderifnotexists", params);
      if (bres)
        psync_apipool_release(api);
      else
        psync_apipool_release_bad(api);
      if (unlikely(!bres))
        goto errnet;
      result = papi_find_result2(bres, "result", PARAM_NUM)->num;
      if (result == 0) {
        cfolderid =
            papi_find_result2(papi_find_result2(bres, "metadata", PARAM_HASH),
                              "folderid", PARAM_NUM)
                ->num;
        if (papi_find_result2(bres, "created", PARAM_BOOL)->num)
          pdiff_wake();
        free(bres);
      } else {
        free(bres);
        psync_process_api_error(result);
        if (psync_handle_api_result(result) == PSYNC_NET_TEMPFAIL)
          goto errnet;
        else
          goto err;
      }
    }
    path += len;
  }
err:
  if (res)
    psql_free(res);
  psync_error = PERROR_REMOTE_FOLDER_NOT_FOUND;
  return PSYNC_INVALID_FOLDERID;
errnet:
  if (res)
    psql_free(res);
  psync_error = PERROR_OFFLINE;
  return PSYNC_INVALID_FOLDERID;
}

static void psync_free_string_list(psync_list *lst) {
  psync_list_for_each_element_call(lst, string_list, list, free);
}

static string_list *str_to_list_element(const char *str, size_t len) {
  string_list *le;
  le = (string_list *)malloc(sizeof(string_list) + len + 1);
  le->str = (char *)(le + 1);
  le->len = len;
  memcpy(le->str, str, len + 1);
  return le;
}

static int psync_add_path_to_list(psync_list *lst, psync_folderid_t folderid) {
  string_list *e;
  psync_sql_res *res;
  psync_variant_row row;
  const char *str;
  size_t len;
  while (1) {
    if (folderid == 0) {
      e = (string_list *)malloc(sizeof(string_list));
      e->str = (char *)e;
      e->len = 0;
      psync_list_add_head(lst, &e->list);
      return 0;
    }
    res = psql_query_rdlock(
        "SELECT parentfolderid, name FROM folder WHERE id=?");
    psql_bind_uint(res, 1, folderid);
    row = psql_fetch(res);
    if (unlikely(!row))
      break;
    folderid = psync_get_number(row[0]);
    str = psync_get_lstring(row[1], &len);
    e = str_to_list_element(str, len);
    psync_list_add_head(lst, &e->list);
    psql_free(res);
  }
  psql_free(res);
  pdbg_logf(D_ERROR, "folder %lu not found in database", (unsigned long)folderid);
  return -1;
}

static string_list *str_list_decode(psync_folderid_t folderid, string_list *e) {
  pcrypto_textdec_t dec;
  char *fn;
  dec = pcryptofolder_flddecoder_get(folderid);
  if (psync_crypto_is_error(dec)) {
    free(e);
    pdbg_logf(D_WARNING, "got error %d getting decoder for folderid %lu",
          psync_crypto_to_error(dec), (unsigned long)folderid);
    return NULL;
  }
  fn = pcryptofolder_flddecode_filename(dec, e->str);
  pcryptofolder_flddecoder_release(folderid, dec);
  free(e);
  if (pdbg_unlikely(!fn))
    return NULL;
  e = str_to_list_element(fn, strlen(fn));
  free(fn);
  return e;
}

static int psync_add_path_to_list_decode(psync_list *lst,
                                         psync_folderid_t folderid) {
  string_list *e, *c;
  psync_sql_res *res;
  psync_variant_row row;
  const char *str;
  psync_folderid_t cfolderid;
  size_t len;
  uint32_t flags;
  e = NULL;
  while (1) {
    if (folderid == 0) {
      if (e)
        psync_list_add_head(lst, &e->list);
      e = (string_list *)malloc(sizeof(string_list));
      e->str = (char *)e;
      e->len = 0;
      psync_list_add_head(lst, &e->list);
      return 0;
    }
    res = psql_query_rdlock(
        "SELECT parentfolderid, name, flags FROM folder WHERE id=?");
    psql_bind_uint(res, 1, folderid);
    row = psql_fetch(res);
    if (pdbg_unlikely(!row))
      break;
    cfolderid = folderid;
    flags = psync_get_number(row[2]);
    folderid = psync_get_number(row[0]);
    str = psync_get_lstring(row[1], &len);
    c = str_to_list_element(str, len);
    psql_free(res);
    if (e) {
      if (flags & PSYNC_FOLDER_FLAG_ENCRYPTED) {
        e = str_list_decode(cfolderid, e);
        if (pdbg_unlikely(!e))
          goto err;
      }
      psync_list_add_head(lst, &e->list);
    }
    e = c;
  }
  psql_free(res);
err:
  pdbg_logf(D_ERROR, "folder %lu not found in database", (unsigned long)folderid);
  return -1;
}

char *psync_join_string_list(const char *sep, psync_list *lst, size_t *retlen) {
  size_t slen, seplen, cnt;
  string_list *e;
  char *ret, *str;
  slen = cnt = 0;
  psync_list_for_each_element(e, lst, string_list, list) {
    slen += e->len;
    cnt++;
  }
  if (unlikely(!cnt))
    return psync_strdup("");
  seplen = strlen(sep);
  ret = str = malloc(slen + cnt * seplen + 1);
  psync_list_for_each_element(e, lst, string_list, list) {
    memcpy(str, e->str, e->len);
    str += e->len;
    memcpy(str, sep, seplen);
    str += seplen;
  }
  str -= seplen;
  *str = 0;
  if (retlen)
    *retlen = str - ret;
  return ret;
}

char *pfolder_path(psync_folderid_t folderid, size_t *retlen) {
  psync_list folderlist;
  char *ret;
  int res;
  psync_list_init(&folderlist);
  psql_rdlock();
  res = psync_add_path_to_list(&folderlist, folderid);
  psql_rdunlock();
  if (pdbg_unlikely(res)) {
    psync_free_string_list(&folderlist);
    return PSYNC_INVALID_PATH;
  }
  ret = psync_join_string_list("/", &folderlist, retlen);
  psync_free_string_list(&folderlist);
  if (!ret[0]) {
    free(ret);
    ret = psync_strdup("/");
    if (retlen)
      *retlen = 1;
  }
  return ret;
}

char *pfolder_path_sep(psync_folderid_t folderid, const char *sep,
                                     size_t *retlen) {
  psync_list folderlist;
  char *ret;
  int res;
  psync_list_init(&folderlist);
  res = psync_add_path_to_list_decode(&folderlist, folderid);
  if (pdbg_unlikely(res)) {
    psync_free_string_list(&folderlist);
    return PSYNC_INVALID_PATH;
  }
  ret = psync_join_string_list(sep, &folderlist, retlen);
  psync_free_string_list(&folderlist);
  if (!ret[0]) {
    free(ret);
    ret = psync_strdup(sep);
    if (retlen)
      *retlen = 1;
  }
  return ret;
}

char *pfolder_file_path(psync_fileid_t fileid, size_t *retlen) {
  psync_list folderlist;
  char *ret;
  psync_sql_res *res;
  psync_variant_row row;
  string_list *e;
  const char *str;
  psync_folderid_t folderid;
  size_t len;
  psync_list_init(&folderlist);
  psql_rdlock();
  res = psql_query_rdlock(
      "SELECT parentfolderid, name FROM file WHERE id=?");
  psql_bind_uint(res, 1, fileid);
  row = psql_fetch(res);
  if (pdbg_unlikely(!row)) {
    psql_free(res);
    psql_rdunlock();
    return PSYNC_INVALID_PATH;
  }
  folderid = psync_get_number(row[0]);
  str = psync_get_lstring(row[1], &len);
  e = str_to_list_element(str, len);
  psync_list_add_head(&folderlist, &e->list);
  psql_free(res);
  if (pdbg_unlikely(psync_add_path_to_list(&folderlist, folderid))) {
    psql_rdunlock();
    psync_free_string_list(&folderlist);
    return PSYNC_INVALID_PATH;
  }
  psql_rdunlock();
  ret = psync_join_string_list("/", &folderlist, retlen);
  psync_free_string_list(&folderlist);
  return ret;
}

static int psync_add_local_path_to_list_by_localfolderid(
    psync_list *lst, psync_folderid_t localfolderid, psync_syncid_t syncid) {
  string_list *e, *le;
  psync_sql_res *res;
  psync_variant_row row;
  const char *str;
  size_t len;
  res = psql_query_rdlock("SELECT localpath FROM syncfolder WHERE id=?");
  psql_bind_uint(res, 1, syncid);
  row = psql_fetch(res);
  if (unlikely(!row)) {
    pdbg_logf(D_ERROR, "could not find sync id %lu", (long unsigned)syncid);
    psql_free(res);
    return -1;
  }
  str = psync_get_lstring(row[0], &len);
  le = str_to_list_element(str, len);
  psql_free(res);
  while (1) {
    if (localfolderid == 0) {
      psync_list_add_head(lst, &le->list);
      return 0;
    }
    res = psql_query_rdlock(
        "SELECT localparentfolderid, name FROM localfolder WHERE id=?");
    psql_bind_uint(res, 1, localfolderid);
    row = psql_fetch(res);
    if (unlikely(!row))
      break;
    localfolderid = psync_get_number(row[0]);
    str = psync_get_lstring(row[1], &len);
    e = str_to_list_element(str, len);
    psync_list_add_head(lst, &e->list);
    psql_free(res);
  }
  psql_free(res);
  psync_list_add_head(lst, &le->list);
  pdbg_logf(D_ERROR, "local folder %lu not found in database",
        (unsigned long)localfolderid);
  return -1;
}

char *pfolder_lpath_lfldr(psync_folderid_t localfolderid,
                                        psync_syncid_t syncid, size_t *retlen) {
  psync_list folderlist;
  char *ret;
  int res;
  psync_list_init(&folderlist);
  psql_rdlock();
  res = psync_add_local_path_to_list_by_localfolderid(&folderlist,
                                                      localfolderid, syncid);
  psql_rdunlock();
  if (pdbg_unlikely(res)) {
    psync_free_string_list(&folderlist);
    return PSYNC_INVALID_PATH;
  }
  ret = psync_join_string_list("/", &folderlist, retlen);
  psync_free_string_list(&folderlist);
  return ret;
}

char *pfolder_lpath_lfile(psync_fileid_t localfileid,
                                      size_t *retlen) {
  psync_list folderlist;
  char *ret;
  const char *str;
  psync_sql_res *res;
  psync_variant_row row;
  string_list *e;
  psync_folderid_t localfolderid;
  size_t len;
  psync_syncid_t syncid;
  int rs;
  psync_list_init(&folderlist);
  psql_rdlock();
  res = psql_query_nolock(
      "SELECT localparentfolderid, syncid, name FROM localfile WHERE id=?");
  psql_bind_uint(res, 1, localfileid);
  if (pdbg_unlikely(!(row = psql_fetch(res)))) {
    psql_free(res);
    psql_rdunlock();
    psync_free_string_list(&folderlist);
    return PSYNC_INVALID_PATH;
  }
  localfolderid = psync_get_number(row[0]);
  syncid = psync_get_number(row[1]);
  str = psync_get_lstring(row[2], &len);
  e = str_to_list_element(str, len);
  psql_free(res);
  psync_list_add_head(&folderlist, &e->list);
  rs = psync_add_local_path_to_list_by_localfolderid(&folderlist, localfolderid,
                                                     syncid);
  psql_rdunlock();
  if (pdbg_unlikely(rs)) {
    psync_free_string_list(&folderlist);
    return PSYNC_INVALID_PATH;
  }
  ret = psync_join_string_list("/", &folderlist, retlen);
  psync_free_string_list(&folderlist);
  return ret;
}

static folder_list *folder_list_init() {
  folder_list *list;
  list = (folder_list *)malloc(sizeof(folder_list));
  list->entries =
      (pentry_t *)malloc(sizeof(pentry_t) * INITIAL_ENTRY_CNT);
  list->namebuff = (char *)malloc(INITIAL_NAME_BUFF);
  list->nameoff = 0;
  list->namealloc = INITIAL_NAME_BUFF;
  list->entriescnt = 0;
  list->entriesalloc = INITIAL_ENTRY_CNT;
  return list;
}

static void folder_list_add(folder_list *list, pentry_t *entry) {
  if (list->entriescnt >= list->entriesalloc) {
    list->entriesalloc *= 2;
    list->entries = (pentry_t *)realloc(
        list->entries, sizeof(pentry_t) * list->entriesalloc);
  }
  while (list->nameoff + entry->namelen >= list->namealloc) {
    list->namealloc *= 2;
    list->namebuff = (char *)realloc(list->namebuff, list->namealloc);
  }
  memcpy(&list->entries[list->entriescnt++], entry, sizeof(pentry_t));
  memcpy(list->namebuff + list->nameoff, entry->name, entry->namelen);
  list->nameoff += entry->namelen;
  list->namebuff[list->nameoff++] = 0;
}

static void folder_list_free(folder_list *list) {
  free(list->entries);
  free(list->namebuff);
  free(list);
}

static pfolder_list_t *folder_list_finalize(folder_list *list) {
  pfolder_list_t *ret;
  char *name;
  uint32_t i;
  pdbg_logf(D_NOTICE, "allocating %u bytes for folder list, %u of which for names",
        (unsigned)(offsetof(pfolder_list_t, entries) +
                   sizeof(pentry_t) * list->entriescnt + list->nameoff),
        (unsigned)list->nameoff);
  ret = (pfolder_list_t *)malloc(offsetof(pfolder_list_t, entries) +
                                       sizeof(pentry_t) * list->entriescnt +
                                       list->nameoff);
  name = ((char *)ret) + offsetof(pfolder_list_t, entries) +
         sizeof(pentry_t) * list->entriescnt;
  ret->entrycnt = list->entriescnt;
  memcpy(ret->entries, list->entries, sizeof(pentry_t) * list->entriescnt);
  memcpy(name, list->namebuff, list->nameoff);
  for (i = 0; i < list->entriescnt; i++) {
    ret->entries[i].name = name;
    name += list->entries[i].namelen + 1;
  }
  folder_list_free(list);
  return ret;
}

pfolder_list_t *pfolder_remote_folders(psync_folderid_t folderid,
                                         psync_listtype_t listtype) {
  folder_list *list;
  psync_sql_res *res;
  psync_variant_row row;
  size_t namelen;
  pentry_t entry;
  uint64_t perms, flags;
  list = folder_list_init();
  char *tmp;
  int parentencrypted = 0;
  if (listtype & PLIST_FOLDERS) {
    res = psql_query_rdlock("SELECT flags FROM folder WHERE id=?");
    psql_bind_uint(res, 1, folderid);
    if ((row = psql_fetch(res))) {
      parentencrypted =
          (psync_get_number(row[0]) & PSYNC_FOLDER_FLAG_ENCRYPTED) ? 1 : 0;
    } else {
      pdbg_logf(D_ERROR, "Can't find folder with id %lu", folderid);
      psql_free(res);
      return NULL;
    }
    psql_free(res);
    res = psql_query_rdlock(
        "SELECT id, permissions, name, userid, flags FROM folder WHERE "
        "parentfolderid=? ORDER BY name");
    psql_bind_uint(res, 1, folderid);
    while ((row = psql_fetch(res))) {
      entry.folder.folderid = psync_get_number(row[0]);
      perms = psync_get_number(row[1]);
      flags = psync_get_number(row[4]);
      entry.folder.cansyncup =
          ((perms & PSYNC_PERM_WRITE) == PSYNC_PERM_WRITE) &&
          ((flags &
            (PSYNC_FOLDER_FLAG_BACKUP_DEVICE_LIST |
             PSYNC_FOLDER_FLAG_BACKUP_DEVICE | PSYNC_FOLDER_FLAG_BACKUP_ROOT |
             PSYNC_FOLDER_FLAG_BACKUP)) == 0);
      entry.folder.cansyncdown =
          ((perms & PSYNC_PERM_READ) == PSYNC_PERM_READ) &&
          ((flags &
            (PSYNC_FOLDER_FLAG_BACKUP_DEVICE_LIST |
             PSYNC_FOLDER_FLAG_BACKUP_DEVICE | PSYNC_FOLDER_FLAG_BACKUP_ROOT |
             PSYNC_FOLDER_FLAG_BACKUP)) == 0);
      entry.folder.canshare = (psync_my_userid == psync_get_number(row[3]));
      entry.folder.isencrypted =
          (psync_get_number(row[4]) & PSYNC_FOLDER_FLAG_ENCRYPTED) ? 1 : 0;
      if (parentencrypted && pcryptofolder_is_unlocked()) {
        tmp = (char *)psync_get_lstring(row[2], &namelen);
        entry.name = get_decname_for_folder(folderid, tmp, namelen);
        if (!entry.name) {
          pdbg_logf(
              D_BUG,
              "Can't decrypt folder name for folderid: %lu, parent folfderid: "
              "%lu, cryptoerr: %d, encrypted name: %s. Skippping ...",
              entry.folder.folderid, folderid, psync_fsfolder_crypto_error(),
              tmp);
          continue;
        }
        entry.namelen = strlen(entry.name);
      } else {
        entry.name = psync_get_lstring(row[2], &namelen);
        entry.namelen = namelen;
      }
      entry.isfolder = 1;
      folder_list_add(list, &entry);
    }
    psql_free(res);
  }
  if (listtype & PLIST_FILES) {
    res = psql_query_rdlock(
        "SELECT id, size, name FROM file WHERE parentfolderid=? ORDER BY name");
    psql_bind_uint(res, 1, folderid);
    while ((row = psql_fetch(res))) {
      entry.file.fileid = psync_get_number(row[0]);
      entry.file.size = psync_get_number(row[1]);
      entry.name = psync_get_lstring(row[2], &namelen);
      entry.namelen = namelen;
      entry.isfolder = 0;
      folder_list_add(list, &entry);
    }
    psql_free(res);
  }
  return folder_list_finalize(list);
}

static void add_to_folderlist(void *ptr, ppath_stat *stat) {
  flist_ltype *ft = (flist_ltype *)ptr;
  pentry_t entry;
  int isfolder = pfile_stat_isfolder(&stat->stat);
  if (((ft->listtype & PLIST_FOLDERS) && isfolder) ||
      ((ft->listtype & PLIST_FILES) && !isfolder)) {
    entry.name = stat->name;
    entry.namelen = strlen(stat->name);
    if (isfolder) {
      entry.isfolder = 1;
      entry.folder.folderid = pfile_stat_inode(&stat->stat);
      entry.folder.cansyncup = pfile_stat_mode_ok(&stat->stat, 5);
      entry.folder.cansyncdown = pfile_stat_mode_ok(&stat->stat, 7);
      entry.folder.isencrypted = 0;
    } else {
      entry.isfolder = 0;
      entry.file.fileid = pfile_stat_inode(&stat->stat);
      entry.file.size = pfile_stat_size(&stat->stat);
    }
    folder_list_add(ft->folderlist, &entry);
  }
}

pfolder_list_t *pfolder_local_folders(const char *path,
                                        psync_listtype_t listtype) {
  flist_ltype ft;
  ft.folderlist = folder_list_init();
  ft.listtype = listtype;
  if (ppath_ls(path, add_to_folderlist, &ft)) {
    folder_list_free(ft.folderlist);
    return NULL;
  } else
    return folder_list_finalize(ft.folderlist);
}

pentry_t *pfolder_stat(const char *remotepath) {
  psync_folderid_t folderid;
  psync_sql_res *res;
  psync_uint_row row;
  pentry_t *ret;
  char *cremotepath;
  size_t len, olen;
  if (remotepath[0] != '/')
    return NULL;
  if (remotepath[1] == 0) {
    ret = malloc(sizeof(pentry_t));
    ret->name = "/";
    ret->namelen = 1;
    ret->isfolder = 1;
    ret->folder.folderid = 0;
    ret->folder.cansyncup = 1;
    ret->folder.cansyncdown = 1;
    ret->folder.canshare = 0;
  }
  olen = len = strlen(remotepath);
  while (remotepath[--len] != '/')
    ;
  if (len == 0)
    folderid = 0;
  else {
    cremotepath = malloc(sizeof(char) * (len + 1));
    memcpy(cremotepath, remotepath, len + 1);
    cremotepath[len] = 0;
    folderid = pfolder_id(cremotepath);
    free(cremotepath);
    if (folderid == PSYNC_INVALID_FOLDERID)
      return NULL;
  }
  len++;
  olen -= len;
  res = psql_query_rdlock("SELECT id, permissions, userid, flags FROM "
                               "folder WHERE parentfolderid=? AND name=?");
  psql_bind_uint(res, 1, folderid);
  psql_bind_lstr(res, 2, remotepath + len, olen);
  if ((row = psql_fetch_int(res))) {
    ret = (pentry_t *)malloc(sizeof(pentry_t) + olen + 1);
    ret->folder.folderid = row[0];
    ret->folder.cansyncup = ((row[1] & PSYNC_PERM_WRITE) == PSYNC_PERM_WRITE);
    ret->folder.cansyncdown = ((row[1] & PSYNC_PERM_READ) == PSYNC_PERM_READ);
    ret->folder.canshare = (psync_my_userid == row[2]);
    ret->folder.isencrypted = (row[3] & PSYNC_FOLDER_FLAG_ENCRYPTED) ? 1 : 0;
    ret->name = (char *)(ret + 1);
    ret->namelen = olen;
    ret->isfolder = 1;
    memcpy(ret + 1, remotepath + len, olen + 1);
    psql_free(res);
    return ret;
  }
  psql_free(res);
  res = psql_query_rdlock(
      "SELECT id, size FROM file WHERE parentfolderid=? AND name=?");
  psql_bind_uint(res, 1, folderid);
  psql_bind_lstr(res, 2, remotepath + len, olen);
  if ((row = psql_fetch_int(res))) {
    ret = (pentry_t *)malloc(sizeof(pentry_t) + olen + 1);
    ret->file.fileid = row[0];
    ret->file.size = row[1];
    ret->name = (char *)(ret + 1);
    ret->namelen = olen;
    ret->isfolder = 0;
    memcpy(ret + 1, remotepath + len, olen + 1);
    psql_free(res);
    return ret;
  }
  psql_free(res);
  return NULL;
}

typedef struct {
  char *localpath;
  char *remotepath;
  size_t locallen;
  size_t remotelen;
  psync_folderid_t folderid;
  psync_syncid_t syncid;
  psync_synctype_t synctype;
} psync_tmp_folder_t;

psync_folder_list_t *pfolder_sync_folders(char *syncTypes) {
  psync_sql_res *res;
  psync_variant_row row;
  psync_tmp_folder_t *folders;
  const char *cstr;
  char *str;
  psync_folder_list_t *ret;
  size_t strlens, l;
  psync_folderid_t folderid;
  uint32_t alloced, lastfolder, i;

  char sql[1024];

  folders = NULL;
  alloced = lastfolder = 0;
  strlens = 0;

  if (strlen(syncTypes) > 0) {
    psync_slprintf(sql, 1024,
                   "SELECT id, folderid, localpath, synctype FROM syncfolder "
                   "WHERE folderid IS NOT NULL AND synctype IN (%s)",
                   syncTypes);
  } else {
    psync_slprintf(sql, 1024,
                   "SELECT id, folderid, localpath, synctype FROM syncfolder "
                   "WHERE folderid IS NOT NULL");
  }

  res = psql_query_rdlock(sql);

  while ((row = psql_fetch(res))) {
    if (alloced == lastfolder) {
      alloced = (alloced + 32) * 2;
      folders = (psync_tmp_folder_t *)realloc(
          folders, sizeof(psync_tmp_folder_t) * alloced);
    }
    cstr = psync_get_lstring(row[2], &l);
    l++;
    str = (char *)malloc(l);
    memcpy(str, cstr, l);

    strlens += l;
    folders[lastfolder].localpath = str;
    folders[lastfolder].locallen = l;
    folderid = psync_get_number(row[1]);
    str = pfolder_path(folderid, &l);
    if (unlikely(!str)) {
      str = psync_strdup("/Invalid/Path");
      l = strlen(str);
    }
    l++;
    strlens += l;
    folders[lastfolder].remotepath = str;
    folders[lastfolder].remotelen = l;
    folders[lastfolder].folderid = folderid;
    folders[lastfolder].syncid = psync_get_number(row[0]);
    folders[lastfolder].synctype = psync_get_number(row[3]);
    lastfolder++;
  }
  psql_free(res);
  l = offsetof(psync_folder_list_t, folders) +
      sizeof(psync_folder_t) * lastfolder;
  ret = (psync_folder_list_t *)malloc(l + strlens);
  str = ((char *)ret) + l;
  ret->foldercnt = lastfolder;

  for (i = 0; i < lastfolder; i++) {
    l = folders[i].locallen;
    memcpy(str, folders[i].localpath, l);
    free(folders[i].localpath);
    strncpy(ret->folders[i].localpath, str,
            sizeof(ret->folders[i].localpath) - 1);
    ret->folders[i].localpath[sizeof(ret->folders[i].localpath) - 1] = '\0';

    l--;

    while (l && str[l] != '/' && str[l] != '/')
      l--;

    if ((str[l] == '/' || str[l] == '/') && str[l + 1])
      l++;

    strncpy(ret->folders[i].localname, str,
            sizeof(ret->folders[i].localname) - 1);
    ret->folders[i].localname[sizeof(ret->folders[i].localname) - 1] = '\0';
    str += folders[i].locallen;

    l = folders[i].remotelen;
    memcpy(str, folders[i].remotepath, l);
    free(folders[i].remotepath);
    strncpy(ret->folders[i].remotepath, str,
            sizeof(ret->folders[i].remotepath) - 1);
    ret->folders[i].remotepath[sizeof(ret->folders[i].remotepath) - 1] = '\0';

    if (l)
      l--;

    while (l && str[l] != '/')
      l--;

    if (str[l] == '/')
      l++;

    strncpy(ret->folders[i].remotename, str + l,
            sizeof(ret->folders[i].remotename) - 1);
    ret->folders[i].remotename[sizeof(ret->folders[i].remotename) - 1] = '\0';
    str += folders[i].remotelen;
    ret->folders[i].folderid = folders[i].folderid;
    ret->folders[i].syncid = folders[i].syncid;
    ret->folders[i].synctype = folders[i].synctype;
  }

  free(folders);

  return ret;
}

psync_syncid_t pfolder_add_sync(const char *localpath, psync_folderid_t folderid, psync_synctype_t synctype) {
  psync_sql_res *res;
  char *syncmp;
  psync_uint_row row;
  psync_str_row srow;
  uint64_t perms;
  struct stat st;
  psync_syncid_t ret;
  int unsigned mbedtls_md;

  pdbg_logf(D_NOTICE, "Add sync by folder id localpath: [%s]", localpath);

  if (pdbg_unlikely(synctype < PSYNC_SYNCTYPE_MIN ||
                   synctype > PSYNC_SYNCTYPE_MAX))
    return_isyncid(PERROR_INVALID_SYNCTYPE);
  if (pdbg_unlikely(stat(localpath, &st)) ||
      pdbg_unlikely(!pfile_stat_isfolder(&st)))
    return_isyncid(PERROR_LOCAL_FOLDER_NOT_FOUND);
  if (synctype & PSYNC_DOWNLOAD_ONLY)
    mbedtls_md = 7;
  else
    mbedtls_md = 5;
  if (pdbg_unlikely(!pfile_stat_mode_ok(&st, mbedtls_md)))
    return_isyncid(PERROR_LOCAL_FOLDER_ACC_DENIED);
  syncmp = psync_fs_getmountpoint();
  if (syncmp) {
    size_t len = strlen(syncmp);
    if (!memcmp(syncmp, localpath, len) &&
        (localpath[len] == 0 || localpath[len] == '/' ||
         localpath[len] == '\\')) {
      free(syncmp);
      return_isyncid(PERROR_LOCAL_IS_ON_PDRIVE);
    }
    free(syncmp);
  }
  res = psql_query("SELECT localpath FROM syncfolder");
  if (pdbg_unlikely(!res))
    return_isyncid(PERROR_DATABASE_ERROR);
  while ((srow = psql_fetch_str(res)))
    if (psyncer_str_has_prefix(srow[0], localpath)) {
      psql_free(res);
      return_isyncid(PERROR_PARENT_OR_SUBFOLDER_ALREADY_SYNCING);
    } else if (!strcmp(srow[0], localpath)) {
      psql_free(res);
      return_isyncid(PERROR_FOLDER_ALREADY_SYNCING);
    }
  psql_free(res);
  if (folderid) {
    res = psql_query("SELECT permissions FROM folder WHERE id=?");
    if (pdbg_unlikely(!res))
      return_isyncid(PERROR_DATABASE_ERROR);
    psql_bind_uint(res, 1, folderid);
    row = psql_fetch_int(res);
    if (pdbg_unlikely(!row)) {
      psql_free(res);
      return_isyncid(PERROR_REMOTE_FOLDER_NOT_FOUND);
    }
    perms = row[0];
    psql_free(res);
  } else
    perms = PSYNC_PERM_ALL;
  if (pdbg_unlikely((synctype & PSYNC_DOWNLOAD_ONLY &&
                    (perms & PSYNC_PERM_READ) != PSYNC_PERM_READ) ||
                   (synctype & PSYNC_UPLOAD_ONLY &&
                    (perms & PSYNC_PERM_WRITE) != PSYNC_PERM_WRITE)))
    return_isyncid(PERROR_REMOTE_FOLDER_ACC_DENIED);
  res = psql_prepare(
      "INSERT OR IGNORE INTO syncfolder (folderid, localpath, synctype, flags, "
      "inode, deviceid) VALUES (?, ?, ?, 0, ?, ?)");
  if (pdbg_unlikely(!res))
    return_isyncid(PERROR_DATABASE_ERROR);
  psql_bind_uint(res, 1, folderid);
  psql_bind_str(res, 2, localpath);
  psql_bind_uint(res, 3, synctype);
  psql_bind_uint(res, 4, pfile_stat_inode(&st));
  psql_bind_uint(res, 5, pfile_stat_device(&st));
  psql_run(res);
  if (pdbg_likely(psql_affected()))
    ret = psql_insertid();
  else
    ret = PSYNC_INVALID_SYNCID;
  psql_free(res);
  if (ret == PSYNC_INVALID_SYNCID)
    return_isyncid(PERROR_FOLDER_ALREADY_SYNCING);
  psql_sync();
  ppathstatus_reload_syncs();
  psyncer_create(ret);
  return ret;
}

psync_syncid_t pfolder_add_sync_path(const char *localpath, const char *remotepath, psync_synctype_t synctype) {
  psync_folderid_t folderid = pfolder_id(remotepath);
  if (pdbg_likely(folderid != PSYNC_INVALID_FOLDERID))
    return pfolder_add_sync(localpath, folderid, synctype);
  else
    return PSYNC_INVALID_SYNCID;
}

int pfolder_add_sync_path_delay(const char *localpath,
                                   const char *remotepath,
                                   psync_synctype_t synctype) {
  psync_sql_res *res;
  struct stat st;
  int unsigned mbedtls_md;
  if (pdbg_unlikely(synctype < PSYNC_SYNCTYPE_MIN ||
                   synctype > PSYNC_SYNCTYPE_MAX)) {
    psync_error = PERROR_INVALID_SYNCTYPE;
    return -1;
  }
  if (pdbg_unlikely(stat(localpath, &st)) ||
      pdbg_unlikely(!pfile_stat_isfolder(&st))) {
    psync_error = PERROR_LOCAL_FOLDER_NOT_FOUND;
    return -1;
  }
  if (synctype & PSYNC_DOWNLOAD_ONLY)
    mbedtls_md = 7;
  else
    mbedtls_md = 5;
  if (pdbg_unlikely(!pfile_stat_mode_ok(&st, mbedtls_md))) {
    psync_error = PERROR_LOCAL_FOLDER_ACC_DENIED;
    return -1;
  }
  res = psql_prepare("INSERT INTO syncfolderdelayed (localpath, "
                                 "remotepath, synctype) VALUES (?, ?, ?)");
  psql_bind_str(res, 1, localpath);
  psql_bind_str(res, 2, remotepath);
  psql_bind_uint(res, 3, synctype);
  psql_run_free(res);
  psql_sync();
  if (pstatus_get(PSTATUS_TYPE_ONLINE) == PSTATUS_ONLINE_ONLINE)
    prun_thread("check delayed syncs", psyncer_check_delayed);
  return 0;
}

pfolder_list_t *pfolder_remote_folders_path(const char *remotepath, psync_listtype_t listtype) {
  psync_folderid_t folderid = pfolder_id(remotepath);
  if (folderid != PSYNC_INVALID_FOLDERID)
    return pfolder_remote_folders(folderid, listtype);
  else
    return NULL;
}


