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

#include "pfileops.h"
#include "pdiff.h"
#include "pfolder.h"
#include "plibs.h"

void pfileops_create_fldr(const binresult *meta) {
  psync_sql_res *res;
  const binresult *name;
  uint64_t userid, perms, flags;
  flags = 0;
  if ((name = papi_check_result2(meta, "encrypted", PARAM_BOOL)) && name->num)
    flags |= PSYNC_FOLDER_FLAG_ENCRYPTED;
  res = psync_sql_prep_statement(
      "INSERT OR IGNORE INTO folder (id, parentfolderid, userid, permissions, "
      "name, ctime, mtime, flags) VALUES (?, ?, ?, ?, ?, ?, ?, ?)");
  if (papi_find_result2(meta, "ismine", PARAM_BOOL)->num) {
    userid = psync_my_userid;
    perms = PSYNC_PERM_ALL;
  } else {
    userid = papi_find_result2(meta, "userid", PARAM_NUM)->num;
    perms = pfileops_get_perms(meta);
  }
  name = papi_find_result2(meta, "name", PARAM_STR);
  psync_sql_bind_uint(res, 1,
                      papi_find_result2(meta, "folderid", PARAM_NUM)->num);
  psync_sql_bind_uint(
      res, 2, papi_find_result2(meta, "parentfolderid", PARAM_NUM)->num);
  psync_sql_bind_uint(res, 3, userid);
  psync_sql_bind_uint(res, 4, perms);
  psync_sql_bind_lstring(res, 5, name->str, name->length);
  psync_sql_bind_uint(res, 6,
                      papi_find_result2(meta, "created", PARAM_NUM)->num);
  psync_sql_bind_uint(res, 7,
                      papi_find_result2(meta, "modified", PARAM_NUM)->num);
  psync_sql_bind_uint(res, 8, flags);
  psync_sql_run_free(res);
}

void pfileops_update_fldr(const binresult *meta) {
  pdiff_fldr_update(meta);
}

void pfileops_delete_fldr(const binresult *meta) {
  pdiff_fldr_delete(meta);
}

void pfileops_create_file(const binresult *meta) {
  pdiff_file_create(meta);
}

void pfileops_update_file(const binresult *meta) {
  pdiff_file_update(meta);
}

void pfileops_delete_file(const binresult *meta) {
  pdiff_file_delete(meta);
}

uint64_t pfileops_get_perms(const binresult *meta) {
  const binresult *canmanage =
      papi_check_result2(meta, "canmanage", PARAM_BOOL);
  return (papi_find_result2(meta, "canread", PARAM_BOOL)->num ? PSYNC_PERM_READ
                                                              : 0) +
         (papi_find_result2(meta, "canmodify", PARAM_BOOL)->num
              ? PSYNC_PERM_MODIFY
              : 0) +
         (papi_find_result2(meta, "candelete", PARAM_BOOL)->num
              ? PSYNC_PERM_DELETE
              : 0) +
         (papi_find_result2(meta, "cancreate", PARAM_BOOL)->num
              ? PSYNC_PERM_CREATE
              : 0) +
         (canmanage && canmanage->num ? PSYNC_PERM_MANAGE : 0);
}
