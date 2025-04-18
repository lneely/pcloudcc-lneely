/*
   Copyright (c) 2014 Anton Titov.

   Copyright (c) 2014 pCloud Ltd.  All rights reserved.

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
#include "pfs.h"
#include "pfsfolder.h"
#include "pfstasks.h"
#include "plibs.h"
#include "psys.h"
#include "pdbg.h"
#include "psql.h"


static PSYNC_THREAD int cryptoerr = 0;

static inline int psync_crypto_is_error(const void *ptr) {
  return (uintptr_t)ptr <= PSYNC_CRYPTO_MAX_ERROR;
}

static inline int psync_crypto_to_error(const void *ptr) {
  return -((int)(uintptr_t)ptr);
}

static char *get_encname_for_folder(psync_fsfolderid_t folderid,
                                    const char *path, size_t len) {
  char *name, *encname;
  pcrypto_textenc_t enc;
  enc = pcryptofolder_fldencoder_get(folderid);
  if (psync_crypto_is_error(enc)) {
    cryptoerr = psync_crypto_to_error(enc);
    return NULL;
  }
  name = psync_strndup(path, len);
  encname = pcryptofolder_fldencode_filename(enc, name);
  pcryptofolder_fldencoder_release(folderid, enc);
  free(name);
  return encname;
}

static psync_fspath_t *ret_folder_data(psync_fsfolderid_t folderid,
                                       const char *name, uint32_t permissions,
                                       uint32_t flags, uint32_t shareid) {
  psync_fspath_t *ret;
  if (flags & PSYNC_FOLDER_FLAG_ENCRYPTED &&
      strncmp(psync_fake_prefix, name, psync_fake_prefix_len)) {
    pcrypto_textenc_t enc;
    char *encname;
    size_t len;
    enc = pcryptofolder_fldencoder_get(folderid);
    if (psync_crypto_is_error(enc)) {
      cryptoerr = psync_crypto_to_error(enc);
      return NULL;
    }
    encname = pcryptofolder_fldencode_filename(enc, name);
    pcryptofolder_fldencoder_release(folderid, enc);
    len = strlen(encname);
    ret = (psync_fspath_t *)malloc(sizeof(psync_fspath_t) + len + 1);
    memcpy(ret + 1, encname, len + 1);
    free(encname);
    ret->folderid = folderid;
    ret->name = (char *)(ret + 1);
    ret->shareid = shareid;
    ret->permissions = permissions;
    ret->flags = flags;
  } else {
    ret = malloc(sizeof(psync_fspath_t));
    ret->folderid = folderid;
    ret->name = name;
    ret->shareid = shareid;
    ret->permissions = permissions;
    ret->flags = flags;
  }
  return ret;
}

char *get_decname_for_folder(psync_fsfolderid_t folderid, const char *path,
                             size_t len) {
  char *name, *decname;
  pcrypto_textdec_t dec;
  dec = pcryptofolder_flddecoder_get(folderid);
  if (psync_crypto_is_error(dec)) {
    cryptoerr = psync_crypto_to_error(dec);
    return NULL;
  }
  name = psync_strndup(path, len);
  decname = pcryptofolder_flddecode_filename(dec, name);
  pcryptofolder_flddecoder_release(folderid, dec);
  free(name);
  return decname;
}

PSYNC_NOINLINE void do_check_userid(uint64_t userid, uint64_t folderid,
                                    uint32_t *shareid) {
  psync_sql_res *res;
  psync_uint_row row;
  res = psql_query_rdlock(
      "SELECT id FROM sharedfolder WHERE userid=? AND folderid=?");
  psql_bind_uint(res, 1, userid);
  psql_bind_uint(res, 2, folderid);
  if ((row = psql_fetch_int(res)))
    *shareid = row[0];
  else
    pdbg_logf(D_WARNING,
          "came up to a folder %lu owned by userid %lu but can't find it in "
          "sharedfolder",
          (unsigned long)folderid, (unsigned long)userid);
  psql_free(res);
}

static void check_userid(uint64_t userid, uint64_t folderid,
                         uint32_t *shareid) {
  if (userid == psync_my_userid || *shareid)
    return;
  else
    do_check_userid(userid, folderid, shareid);
}

psync_fspath_t *psync_fsfolder_resolve_path(const char *path) {
  psync_fsfolderid_t cfolderid;
  const char *sl;
  psync_fstask_folder_t *folder;
  psync_fstask_mkdir_t *mk;
  psync_sql_res *res;
  psync_uint_row row;
  char *ename;
  size_t len, elen;
  uint32_t permissions, flags, shareid;
  int hasit;

  cryptoerr = 0;
  res = NULL;

  if (*path != '/')
    return NULL;

  cfolderid = 0;
  shareid = 0;
  permissions = PSYNC_PERM_ALL;
  flags = 0;

  while (1) {
    while (*path == '/')
      path++;

    if (*path == 0) {
      if (res)
        psql_free(res);
      return NULL;
    }

    sl = strchr(path, '/');

    if (sl)
      len = sl - path;
    else {
      if (res)
        psql_free(res);

      return ret_folder_data(cfolderid, path, permissions, flags, shareid);
    }

    if (!res)
      res = psql_query_rdlock("SELECT id, permissions, flags, userid FROM "
                                   "folder WHERE parentfolderid=? AND name=?");
    else
      psql_reset(res);

    psql_bind_int(res, 1, cfolderid);

    if (flags & PSYNC_FOLDER_FLAG_ENCRYPTED) {
      ename = get_encname_for_folder(cfolderid, path, len);
      if (!ename)
        break;
      elen = strlen(ename);
      psql_bind_lstr(res, 2, ename, elen);
    } else {
      psql_bind_lstr(res, 2, path, len);
      ename = (char *)path;
      elen = len;
    }
    row = psql_fetch_int(res);
    folder = psync_fstask_get_folder_tasks_rdlocked(cfolderid);
    if (folder) {
      char *name = psync_strndup(ename, elen);
      if ((mk = psync_fstask_find_mkdir(folder, name, 0))) {
        if (mk->flags & PSYNC_FOLDER_FLAG_INVISIBLE) {
          free(name);
          break;
        }
        cfolderid = mk->folderid;
        flags = mk->flags;
        hasit = 1;
      } else if (row && !psync_fstask_find_rmdir(folder, name, 0)) {
        cfolderid = row[0];
        permissions &= row[1];
        flags = row[2];
        hasit = 1;
        check_userid(row[3], row[0], &shareid);
      } else
        hasit = 0;
      free(name);
    } else {
      if (row) {
        cfolderid = row[0];
        permissions = row[1];
        flags = row[2];
        check_userid(row[3], row[0], &shareid);
        hasit = 1;
      } else
        hasit = 0;
    }
    if (ename != path)
      free(ename);
    if (!hasit)
      break;
    path += len;
  }

  if (res)
    psql_free(res);

  return NULL;
}

psync_fsfolderid_t psync_fsfolderid_by_path(const char *path,
                                            uint32_t *pflags) {
  psync_fsfolderid_t cfolderid;
  const char *sl;
  psync_fstask_folder_t *folder;
  psync_fstask_mkdir_t *mk;
  psync_sql_res *res;
  psync_uint_row row;
  char *ename;
  size_t len, elen;
  uint32_t flags;
  int hasit;
  res = NULL;
  cryptoerr = 0;
  if (*path != '/')
    return PSYNC_INVALID_FSFOLDERID;
  cfolderid = 0;
  flags = 0;
  while (1) {
    while (*path == '/')
      path++;
    if (*path == 0) {
      if (res)
        psql_free(res);
      if (pflags)
        *pflags = flags;
      return cfolderid;
    }
    sl = strchr(path, '/');
    if (sl)
      len = sl - path;
    else
      len = strlen(path);
    if (!res)
      res = psql_query_rdlock("SELECT id, flags, permissions FROM folder "
                                   "WHERE parentfolderid=? AND name=?");
    else
      psql_reset(res);
    psql_bind_int(res, 1, cfolderid);
    if (flags & PSYNC_FOLDER_FLAG_ENCRYPTED) {
      ename = get_encname_for_folder(cfolderid, path, len);
      if (!ename)
        break;
      elen = strlen(ename);
      psql_bind_lstr(res, 2, ename, elen);
    } else {
      psql_bind_lstr(res, 2, path, len);
      ename = (char *)path;
      elen = len;
    }
    row = psql_fetch_int(res);
    folder = psync_fstask_get_folder_tasks_rdlocked(cfolderid);
    if (folder) {
      char *name = psync_strndup(ename, elen);
      if ((mk = psync_fstask_find_mkdir(folder, name, 0))) {
        cfolderid = mk->folderid;
        flags = mk->flags;
        hasit = 1;
      } else if (row && !psync_fstask_find_rmdir(folder, name, 0)) {
        cfolderid = row[0];
        flags = row[1];
        hasit = 1;
      } else
        hasit = 0;
      free(name);
    } else {
      if (row) {
        cfolderid = row[0];
        flags = row[1];
        hasit = 1;
      } else
        hasit = 0;
    }
    if (ename != path)
      free(ename);
    if (!hasit)
      break;
    path += len;
  }
  if (res)
    psql_free(res);
  return PSYNC_INVALID_FSFOLDERID;
}

psync_fsfolderid_t psync_fsfolderidperm_by_path(const char *path,
                                                uint32_t *pflags,
                                                uint32_t *pPermissions) {
  psync_fsfolderid_t cfolderid;
  const char *sl;
  psync_fstask_folder_t *folder;
  psync_fstask_mkdir_t *mk;
  psync_sql_res *res;
  psync_uint_row row;
  char *ename;
  size_t len, elen;
  uint32_t flags;
  int hasit;
  res = NULL;
  cryptoerr = 0;
  if (*path != '/')
    return PSYNC_INVALID_FSFOLDERID;
  cfolderid = 0;
  flags = 0;
  *pPermissions = 0;
  while (1) {
    while (*path == '/')
      path++;
    if (*path == 0) {
      if (res)
        psql_free(res);
      if (pflags)
        *pflags = flags;
      return cfolderid;
    }
    sl = strchr(path, '/');
    if (sl)
      len = sl - path;
    else
      len = strlen(path);
    if (!res)
      res = psql_query_rdlock("SELECT id, flags, permissions FROM folder "
                                   "WHERE parentfolderid=? AND name=?");
    else
      psql_reset(res);
    psql_bind_int(res, 1, cfolderid);
    if (flags & PSYNC_FOLDER_FLAG_ENCRYPTED) {
      ename = get_encname_for_folder(cfolderid, path, len);
      if (!ename)
        break;
      elen = strlen(ename);
      psql_bind_lstr(res, 2, ename, elen);
    } else {
      psql_bind_lstr(res, 2, path, len);
      ename = (char *)path;
      elen = len;
    }
    row = psql_fetch_int(res);
    folder = psync_fstask_get_folder_tasks_rdlocked(cfolderid);
    if (folder) {
      char *name = psync_strndup(ename, elen);
      if ((mk = psync_fstask_find_mkdir(folder, name, 0))) {
        cfolderid = mk->folderid;
        flags = mk->flags;
        hasit = 1;
      } else if (row && !psync_fstask_find_rmdir(folder, name, 0)) {
        cfolderid = row[0];
        flags = row[1];
        *pPermissions = row[2];
        hasit = 1;
      } else
        hasit = 0;
      free(name);
    } else {
      if (row) {
        cfolderid = row[0];
        flags = row[1];
        *pPermissions = row[2];
        hasit = 1;
      } else
        hasit = 0;
    }
    if (ename != path)
      free(ename);
    if (!hasit)
      break;
    path += len;
  }
  if (res)
    psql_free(res);
  return PSYNC_INVALID_FSFOLDERID;
}

int psync_fsfolder_crypto_error() { return cryptoerr; }

uint32_t psync_fsfolderflags_by_id(psync_fsfolderid_t folderid,
                                   uint32_t *pperm) {
  psync_sql_res *res;
  psync_uint_row row;
  uint32_t ret = 0;
  if (pperm)
    *pperm = 0;
retry:
  if (psql_trylock()) {
    psys_sleep_milliseconds(1);
    goto retry;
  }
  res = psql_query_nolock(
      "SELECT flags, permissions FROM folder WHERE id=?");
  psql_bind_int(res, 1, folderid);
  row = psql_fetch_int(res);
  if (!row) {
    pdbg_logf(D_NOTICE, "Error reading flags by file id!");
    psql_free(res);
    psql_unlock();
    return 0;
  }
  if (pperm)
    *pperm = row[1];
  ret = row[0];
  psql_free(res);
  psql_unlock();
  return ret;
}
/*********************************************************************************************************************/
psync_fsfolderid_t psync_get_folderid(psync_fsfolderid_t parent_fid,
                                      const char *name) {
  psync_fsfolderid_t folder_id = -1;
  psync_sql_res *res;
  psync_uint_row row;

  res = psql_query_nolock(
      "SELECT id FROM folder WHERE parentfolderid=? AND name=?");
  psql_bind_uint(res, 1, parent_fid);
  psql_bind_str(res, 2, name);

  row = psql_fetch_int(res);

  if (row) {
    folder_id = row[0];

    psql_free(res);
  }

  return folder_id;
}
/*********************************************************************************************************************/
