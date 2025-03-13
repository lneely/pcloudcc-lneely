/*
   Copyright (c) 2013-2015 pCloud Ltd.  All rights reserved.

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
#include "publiclinks.h"
#include "papi.h"
#include "pfsfolder.h"
#include "plibs.h"
#include "pnetlibs.h"
#include "prun.h"
#include "ptimer.h"
#include <stdio.h>
#include <string.h>

#define FOLDERID_ENTRY_SIZE 18

static void init_param_str(binparam *t, const char *name, const char *val) {
  //{PARAM_STR, strlen(name), strlen(val), (name),
  //{(uint64_t)((uintptr_t)(val))}}
  t->paramtype = PARAM_STR;
  t->paramnamelen = strlen(name);
  t->opts = strlen(val);
  t->paramname = name;
  t->str = val;
}

static void init_param_num(binparam *t, const char *name, uint64_t val) {
  //{PARAM_NUM, strlen(name), 0, (name), {(val)}}
  t->paramtype = PARAM_NUM;
  t->paramnamelen = strlen(name);
  t->opts = 0;
  t->paramname = name;
  t->num = val;
}
typedef struct _scr_params {
  int64_t linkid;
  uint64_t delay;
} scr_params;

static void modify_screenshot_public_link(void *par) {
  psock_t *api;
  binresult *bres;
  uint64_t result;
  const char *errorret;
  scr_params *linkidp = (scr_params *)par;

  uint64_t time =
      ptimer_time() + ((linkidp->delay) ? linkidp->delay : 2592000);
  time = time - time % 3600;
  binparam params[] = {PAPI_STR("auth", psync_my_auth),
                       PAPI_NUM("linkid", linkidp->linkid), PAPI_NUM("expire", time)};
  api = psync_apipool_get();
  if (unlikely(!api)) {
    pdbg_logf(D_WARNING, "Can't gat api from the pool. No pool ?\n");
    return;
  }

  bres = papi_send2(api, "changepublink", params);

  if (likely(bres))
    psync_apipool_release(api);
  else {
    psync_apipool_release_bad(api);
    pdbg_logf(D_WARNING, "Send command returned in valid result.\n");
    return;
  }

  result = papi_find_result2(bres, "result", PARAM_NUM)->num;
  if (unlikely(result)) {
    errorret = papi_find_result2(bres, "error", PARAM_STR)->str;
    pdbg_logf(
        D_WARNING,
        "command changepublink for link [%lld] returned error code %u msg [%s]",
        (long long int)linkidp->linkid, (unsigned)result, errorret);
    psync_process_api_error(result);
    psync_handle_api_result(result);
    if (result == 2261)
      pdbg_logf(D_NOTICE, "Unable to set expiration date on screen-shot link. Paid "
                      "account required.");
  }

  free(linkidp);
  free(bres);
}

int64_t do_psync_screenshot_public_link(const char *path, int hasdelay,
                                        uint64_t delay, char **link /*OUT*/,
                                        char **err /*OUT*/) {
  scr_params *params = malloc(sizeof(scr_params));
  int64_t ret =
      do_psync_file_public_link(path, &params->linkid, link, err, 0, 0, 0);
  if (hasdelay) {
    params->delay = delay;
    prun_thread1("Modify link expiration.", modify_screenshot_public_link,
                      params);
  } else
    free(params);
  return ret;
}

int64_t do_psync_file_public_link(const char *path, int64_t *plinkid,
                                  char **link /*OUT*/, char **err /*OUT*/,
                                  uint64_t expire, int maxdownloads,
                                  int maxtraffic) {
  psock_t *api;
  binresult *bres;
  uint64_t result;
  const char *rescode;
  const char *errorret;
  int64_t linkid;

  *err = 0;
  *link = 0;
  if (!expire && !maxdownloads && !maxtraffic) {
    binparam params[] = {PAPI_STR("auth", psync_my_auth), PAPI_STR("path", path)};
    api = psync_apipool_get();
    if (unlikely(!api)) {
      pdbg_logf(D_WARNING, "Can't gat api from the pool. No pool ?\n");
      *err = psync_strndup("Connection error.", 17);
      return 2;
    }

    bres = papi_send2(api, "getfilepublink", params);
  } else {
    binparam *t;
    int numparam = 2 + !!expire + !!maxdownloads + !!maxtraffic;
    int pind = 1;

    t = (binparam *)malloc(numparam * sizeof(binparam));
    init_param_str(t, "auth", psync_my_auth);
    init_param_str(t + pind++, "path", path);
    if (expire)
      init_param_num(t + pind++, "expire", expire);
    if (maxdownloads)
      init_param_num(t + pind++, "maxdownloads", maxdownloads);
    if (maxtraffic)
      init_param_num(t + pind++, "maxtraffic", maxtraffic);
    api = psync_apipool_get();
    if (unlikely(!api)) {
      pdbg_logf(D_WARNING, "Can't gat api from the pool. No pool ?\n");
      *err = psync_strndup("Connection error.", 17);
      free(t);
      return 1;
    }
    bres = papi_send(api, "getfilepublink", sizeof("getfilepublink") - 1,
                           t, pind, -1, 1);
    free(t);
  }

  if (likely(bres))
    psync_apipool_release(api);
  else {
    psync_apipool_release_bad(api);
    pdbg_logf(D_WARNING, "Send command returned in valid result.\n");
    *err = psync_strndup("Connection error.", 17);
    return 2;
  }
  result = papi_find_result2(bres, "result", PARAM_NUM)->num;
  if (unlikely(result)) {
    errorret = papi_find_result2(bres, "error", PARAM_STR)->str;
    *err = psync_strndup(errorret, strlen(errorret));
    pdbg_logf(D_WARNING, "command getfilepublink returned error code %u",
          (unsigned)result);
    psync_process_api_error(result);
    psync_handle_api_result(result);
    goto free_ret;
  }

  rescode = papi_find_result2(bres, "link", PARAM_STR)->str;
  *link = psync_strndup(rescode, strlen(rescode));
  linkid = papi_find_result2(bres, "linkid", PARAM_NUM)->num;
  if (plinkid)
    *plinkid = linkid;

free_ret:
  free(bres);
  return (int64_t)result;
}

int64_t do_psync_folder_public_link(const char *path, char **link /*OUT*/,
                                    char **err /*OUT*/, uint64_t expire,
                                    int maxdownloads, int maxtraffic) {
  psock_t *api;
  binresult *bres;
  uint64_t result;
  const char *rescode;
  const char *errorret;

  *err = 0;
  *link = 0;

  if (!expire && !maxdownloads && !maxtraffic) {
    binparam params[] = {PAPI_STR("auth", psync_my_auth), PAPI_STR("path", path)};
    api = psync_apipool_get();
    if (unlikely(!api)) {
      pdbg_logf(D_WARNING, "Can't gat api from the pool. No pool ?\n");
      *err = psync_strndup("Connection error.", 17);
      return -2;
    }
    bres = papi_send2(api, "getfolderpublink", params);
  } else {
    binparam *t;
    int numparam = 2 + !!expire + !!maxdownloads + !!maxtraffic;
    int pind = 1;

    t = (binparam *)malloc(numparam * sizeof(binparam));
    init_param_str(t, "auth", psync_my_auth);
    init_param_str(t + pind++, "path", path);
    if (expire)
      init_param_num(t + pind++, "expire", expire);
    if (maxdownloads)
      init_param_num(t + pind++, "maxdownloads", maxdownloads);
    if (maxtraffic)
      init_param_num(t + pind++, "maxtraffic", maxtraffic);
    api = psync_apipool_get();
    if (unlikely(!api)) {
      pdbg_logf(D_WARNING, "Can't gat api from the pool. No pool ?\n");
      *err = psync_strndup("Connection error.", 17);
      return -2;
    }
    bres = papi_send(api, "getfolderpublink",
                           sizeof("getfolderpublink") - 1, t, pind, -1, 1);
    free(t);
  }
  if (likely(bres))
    psync_apipool_release(api);
  else {
    psync_apipool_release_bad(api);
    pdbg_logf(D_WARNING, "Send command returned in valid result.\n");
    return -2;
  }
  result = papi_find_result2(bres, "result", PARAM_NUM)->num;
  if (unlikely(result)) {
    errorret = papi_find_result2(bres, "error", PARAM_STR)->str;
    *err = psync_strndup(errorret, strlen(errorret));
    pdbg_logf(D_WARNING, "command getfilepublink returned error code %u",
          (unsigned)result);
    psync_process_api_error(result);
    if (psync_handle_api_result(result) == PSYNC_NET_TEMPFAIL)
      return -result;
    else {
      *err = psync_strndup("Connection error.", 17);
      return -1;
    }
  }
  rescode = papi_find_result2(bres, "link", PARAM_STR)->str;
  *link = psync_strndup(rescode, strlen(rescode));
  result = papi_find_result2(bres, "linkid", PARAM_NUM)->num;

  free(bres);

  return result;
}

int64_t do_psync_folder_public_link_full(const char *path, char **link /*OUT*/,
                                         char **err /*OUT*/, uint64_t expire,
                                         int maxdownloads, int maxtraffic,
                                         const char *password) {
  psock_t *api;
  binresult *bres;
  uint64_t result;
  const char *rescode;
  const char *errorret;
  *err = 0;
  *link = 0;
  if (!expire && !maxdownloads && !maxtraffic) {
    binparam params[] = {PAPI_STR("auth", psync_my_auth), PAPI_STR("path", path)};
    api = psync_apipool_get();
    if (unlikely(!api)) {
      pdbg_logf(D_WARNING, "Can't gat api from the pool. No pool ?\n");
      *err = psync_strndup("Connection error.", 17);
      return -2;
    }
    bres = papi_send2(api, "getfolderpublink", params);
  } else {
    binparam *t;
    int numparam = 2 + !!expire + !!maxdownloads + !!maxtraffic + !!password;
    int pind = 1;

    t = (binparam *)malloc(numparam * sizeof(binparam));
    init_param_str(t, "auth", psync_my_auth);
    init_param_str(t + pind++, "path", path);
    if (password)
      init_param_str(t + pind++, "linkpassword", password);
    if (expire)
      init_param_num(t + pind++, "expire", expire);
    if (maxdownloads)
      init_param_num(t + pind++, "maxdownloads", maxdownloads);
    if (maxtraffic)
      init_param_num(t + pind++, "maxtraffic", maxtraffic);
    api = psync_apipool_get();
    if (unlikely(!api)) {
      pdbg_logf(D_WARNING, "Can't gat api from the pool. No pool ?\n");
      *err = psync_strndup("Connection error.", 17);
      return -2;
    }
    bres = papi_send(api, "getfolderpublink",
                           sizeof("getfolderpublink") - 1, t, pind, -1, 1);
    free(t);
  }

  if (likely(bres))
    psync_apipool_release(api);
  else {
    psync_apipool_release_bad(api);
    pdbg_logf(D_WARNING, "Send command returned in valid result.\n");
    return -2;
  }
  result = papi_find_result2(bres, "result", PARAM_NUM)->num;
  if (unlikely(result)) {
    errorret = papi_find_result2(bres, "error", PARAM_STR)->str;
    *err = psync_strndup(errorret, strlen(errorret));
    pdbg_logf(D_WARNING, "command getfilepublink returned error code %u",
          (unsigned)result);
    psync_process_api_error(result);
    if (psync_handle_api_result(result) == PSYNC_NET_TEMPFAIL)
      return -result;
    else {
      *err = psync_strndup("Connection error.", 17);
      return -1;
    }
  }

  rescode = papi_find_result2(bres, "link", PARAM_STR)->str;
  *link = psync_strndup(rescode, strlen(rescode));
  result = papi_find_result2(bres, "linkid", PARAM_NUM)->num;

  free(bres);

  return result;
}

int64_t do_psync_folder_updownlink_link(int canupload,
                                        unsigned long long folderid,
                                        const char *mail, char **err /*OUT*/) {
  psock_t *api;
  binresult *bres;
  uint64_t result;
  const char *errorret;
  binparam params[] = {PAPI_STR("auth", psync_my_auth),
                       PAPI_NUM("folderid", folderid), PAPI_STR("mail", mail),
                       PAPI_NUM("canupload", canupload)};
  *err = 0;
  api = psync_apipool_get();
  if (unlikely(!api)) {
    pdbg_logf(D_WARNING, "Can't get api from the pool. No pool ?\n");
    *err = psync_strndup("Connection error.", 17);
    return -2;
  }
  bres = papi_send2(api, "publink/createfolderlinkandsend", params);

  if (likely(bres))
    psync_apipool_release(api);
  else {
    psync_apipool_release_bad(api);
    pdbg_logf(D_WARNING, "Send command returned invalid result.\n");
    return -2;
  }
  result = papi_find_result2(bres, "result", PARAM_NUM)->num;
  if (unlikely(result)) {
    errorret = papi_find_result2(bres, "error", PARAM_STR)->str;
    *err = psync_strndup(errorret, strlen(errorret));
    pdbg_logf(D_WARNING,
          "command createfolderlinkwithuploadandsend returned error code %u",
          (unsigned)result);
    psync_process_api_error(result);
    if (psync_handle_api_result(result) == PSYNC_NET_TEMPFAIL)
      return -result;
    else {
      *err = psync_strndup("Connection error.", 17);
      return -1;
    }
  }

  result = 0;
  free(bres);

  return result;
}

int64_t do_ptree_public_link(const char *linkname, const char *root,
                                  char **folders, int numfolders, char **files,
                                  int numfiles, char **link /*OUT*/,
                                  char **err /*OUT*/, uint64_t expire,
                                  int maxdownloads, int maxtraffic) {
  psock_t *api;
  binresult *bres;
  uint64_t result;
  const char *rescode;
  const char *errorret;
  int64_t id = 0;
  char *ids = NULL;
  char *ids1 = NULL;
  char *ids2 = NULL;
  char *idsp = 0;
  int i, pind = 1, numparam = 2, k;
  binparam *t;
  *err = 0;
  *link = 0;

  numparam += !!root + !!numfolders + !!numfiles + !!expire + !!maxdownloads +
              !!maxtraffic;

  if (unlikely(!(!!root + !!numfolders + !!numfiles)))
    return -3;

  t = (binparam *)malloc(numparam * sizeof(binparam));

  init_param_str(t, "auth", psync_my_auth);

  init_param_str(t + pind++, "name", linkname);

  if (root) {
    ids = (char *)malloc(FOLDERID_ENTRY_SIZE);
    id = psync_fsfolderid_by_path(root, 0);
    k = sprintf(ids, "%lld", (long long)id);
    init_param_str(t + pind++, "folderid", ids);
  }

  if (numfolders) {
    ids1 = (char *)malloc(numfolders * FOLDERID_ENTRY_SIZE);
    idsp = ids1;
    for (i = 0; i < numfolders; ++i) {
      id = psync_fsfolderid_by_path(folders[i], 0);
      k = sprintf(idsp, "%lld", (long long)id);
      if (unlikely(k <= 0))
        break;
      idsp[k] = ',';
      idsp = idsp + k + 1;
    }
    if (i > 0)
      *(idsp - 1) = '\0';
    init_param_str(t + pind++, "folderids", ids1);
  }

  if (numfiles) {
    psync_sql_res *res = NULL;
    psync_uint_row row;
    psync_fspath_t *filep;

    ids2 = (char *)malloc(numfiles * FOLDERID_ENTRY_SIZE);
    idsp = ids2;
    for (i = 0; i < numfiles; ++i) {
      psync_sql_rdlock();
      filep = psync_fsfolder_resolve_path(files[i]);
      if (filep) {
        res = psync_sql_query_nolock("select id from file where parentfolderid "
                                     "= ? and name = ? limit 1");
        psync_sql_bind_uint(res, 1, filep->folderid);
        psync_sql_bind_string(res, 2, filep->name);
        row = psync_sql_fetch_rowint(res);
        id = row[0];
      } else {
        psync_sql_rdunlock();
        continue;
      }
      psync_sql_free_result(res);
      psync_sql_rdunlock();

      k = sprintf(idsp, "%lld", (long long)id);
      if (unlikely(k <= 0))
        break;
      idsp[k] = ',';
      idsp = idsp + k + 1;
    }
    if (i > 0)
      *(idsp - 1) = '\0';
    init_param_str(t + pind++, "fileids", ids2);
  }

  if (expire)
    init_param_num(t + pind++, "expire", expire);

  if (maxdownloads)
    init_param_num(t + pind++, "maxdownloads", maxdownloads);

  if (maxtraffic)
    init_param_num(t + pind++, "maxtraffic", maxtraffic);

  api = psync_apipool_get();
  if (unlikely(!api)) {
    pdbg_logf(D_WARNING, "Can't gat api from the pool. No pool ?\n");
    *err = psync_strndup("Connection error.", 17);
    return -2;
  }

  bres = papi_send(api, "gettreepublink", sizeof("gettreepublink") - 1, t,
                         pind, -1, 1);

  if (likely(bres))
    psync_apipool_release(api);
  else {
    psync_apipool_release_bad(api);
    pdbg_logf(D_WARNING, "Send command returned in valid result.\n");
    *err = psync_strndup("Connection error.", 17);
    return -2;
  }
  result = papi_find_result2(bres, "result", PARAM_NUM)->num;
  if (unlikely(result)) {
    errorret = papi_find_result2(bres, "error", PARAM_STR)->str;
    *err = psync_strndup(errorret, strlen(errorret));
    pdbg_logf(D_WARNING, "command gettreepublink returned error code %u",
          (unsigned)result);
    psync_process_api_error(result);
    if (psync_handle_api_result(result) == PSYNC_NET_TEMPFAIL)
      return -result;
    else {
      *err = psync_strndup("Connection error.", 17);
      return -1;
    }
  }

  rescode = papi_find_result2(bres, "link", PARAM_STR)->str;
  *link = psync_strndup(rescode, strlen(rescode));

  result = papi_find_result2(bres, "linkid", PARAM_NUM)->num;

  if (ids)
    free(ids);
  if (ids1)
    free(ids1);
  if (ids2)
    free(ids2);

  free(bres);
  free(t);

  return result;
}

int cache_links(char *err, size_t err_size /*OUT*/) {
  psock_t *api;
  binresult *bres;
  uint64_t result;
  const char *errorret;
  const binresult *publinks, *meta;
  binresult *link;
  int i, linkscnt;
  psync_sql_res *q;

  q = psync_sql_prep_statement("DELETE FROM links WHERE isincomming = 0 ");
  psync_sql_run_free(q);

  if (psync_my_auth[0]) {
    binparam params[] = {PAPI_STR("auth", psync_my_auth),
                         PAPI_STR("timeformat", "timestamp"),
                         PAPI_STR("iconformat", "id")};
    api = psync_apipool_get();
    if (unlikely(!api)) {
      pdbg_logf(D_WARNING, "Can't gat api from the pool. No pool ?\n");
      //*err = psync_strndup("Connection error.", 17);
      snprintf(err, err_size, "Connection error.");
      return -2;
    }
    bres = papi_send2(api, "listpublinks", params);
  } else if (psync_my_user && psync_my_pass) {

    binparam params[] = {
        PAPI_STR("username", psync_my_user), PAPI_STR("password", psync_my_pass),
        PAPI_STR("timeformat", "timestamp"), PAPI_STR("iconformat", "id")};
    api = psync_apipool_get();
    if (unlikely(!api)) {
      pdbg_logf(D_WARNING, "Can't gat api from the pool. No pool ?\n");
      //*err = psync_strndup("Connection error.", 17);
      snprintf(err, err_size, "Connection error.");
      return -2;
    }
    bres = papi_send2(api, "listpublinks", params);
  } else {
    return -1;
  }

  if (likely(bres))
    psync_apipool_release(api);
  else {
    psync_apipool_release_bad(api);
    pdbg_logf(D_WARNING, "Send command returned in valid result.\n");
    //*err = psync_strndup("Connection error.", 17);
    snprintf(err, err_size, "Connection error.");
    free(bres);
    return 0;
  }
  result = papi_find_result2(bres, "result", PARAM_NUM)->num;
  if (unlikely(result)) {
    errorret = papi_find_result2(bres, "error", PARAM_STR)->str;
    //*err = psync_strndup(errorret, strlen(errorret));
    snprintf(err, err_size, "%s", errorret);
    pdbg_logf(D_WARNING, "command listpublinks returned error code %u",
          (unsigned)result);
    psync_process_api_error(result);
    free(bres);
    if (psync_handle_api_result(result) == PSYNC_NET_TEMPFAIL)
      return -result;
    else {
      //*err = psync_strndup("Connection error.", 17);
      snprintf(err, err_size, "Connection error.");
      return 0;
    }
  }
  publinks = papi_find_result2(bres, "publinks", PARAM_ARRAY);
  linkscnt = publinks->length;
  if (!linkscnt) {
    free(bres);
    return 0;
  }
  for (i = 0; i < linkscnt; ++i) {
    link = publinks->array[i];

    q = psync_sql_prep_statement(
        "REPLACE INTO links  (id, code, comment, traffic, maxspace, downloads, "
        "created,"
        " modified, name,  isfolder, folderid, fileid, isincomming, icon, "
        "fulllink,"
        " parentfolderid, haspassword, views, type, expire, "
        "enableuploadforchosenusers, enableuploadforeveryone)"
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?, ?, ?, ?, "
        "?, ?)");
    if (!q) {
      pdbg_logf(D_WARNING, "cache links sql prep return NULL");
      return -1;
    }
    psync_sql_bind_uint(q, 1,
                        papi_find_result2(link, "linkid", PARAM_NUM)->num);
    psync_sql_bind_string(q, 2,
                          papi_find_result2(link, "code", PARAM_STR)->str);
    psync_sql_bind_uint(q, 3, 0);
    psync_sql_bind_uint(q, 4,
                        papi_find_result2(link, "traffic", PARAM_NUM)->num);
    psync_sql_bind_uint(q, 5, 0);
    psync_sql_bind_uint(q, 6,
                        papi_find_result2(link, "downloads", PARAM_NUM)->num);
    psync_sql_bind_uint(q, 7,
                        papi_find_result2(link, "created", PARAM_NUM)->num);
    psync_sql_bind_uint(q, 8,
                        papi_find_result2(link, "modified", PARAM_NUM)->num);
    meta = papi_find_result2(link, "metadata", PARAM_HASH);
    psync_sql_bind_string(q, 9,
                          papi_find_result2(meta, "name", PARAM_STR)->str);
    if (papi_find_result2(meta, "isfolder", PARAM_BOOL)->num) {
      psync_sql_bind_uint(q, 10, 1);
      psync_sql_bind_uint(q, 11,
                          papi_find_result2(meta, "folderid", PARAM_NUM)->num);
      psync_sql_bind_uint(q, 12, 0);
      if (papi_check_result2(link, "enableduploadforchosenusers", PARAM_BOOL)) {
        psync_sql_bind_uint(
            q, 20,
            papi_find_result2(link, "enableduploadforchosenusers", PARAM_BOOL)
                ->num);
      } else {
        psync_sql_bind_uint(q, 20, 0);
      }
      if (papi_check_result2(link, "enableduploadforeveryone", PARAM_BOOL)) {
        psync_sql_bind_uint(
            q, 21,
            papi_find_result2(link, "enableduploadforeveryone", PARAM_BOOL)
                ->num);
      } else {
        psync_sql_bind_uint(q, 21, 0);
      }
    } else {
      psync_sql_bind_uint(q, 10, 0);
      psync_sql_bind_uint(q, 11, 0);
      psync_sql_bind_uint(q, 12,
                          papi_find_result2(meta, "fileid", PARAM_NUM)->num);
      psync_sql_bind_uint(q, 20, 0);
      psync_sql_bind_uint(q, 21, 0);
    }
    psync_sql_bind_uint(q, 13, papi_find_result2(meta, "icon", PARAM_NUM)->num);
    psync_sql_bind_string(q, 14,
                          papi_find_result2(link, "link", PARAM_STR)->str);
    psync_sql_bind_uint(
        q, 15, papi_find_result2(meta, "parentfolderid", PARAM_NUM)->num);
    psync_sql_bind_uint(
        q, 16, papi_find_result2(link, "haspassword", PARAM_BOOL)->num);
    psync_sql_bind_uint(q, 17,
                        papi_find_result2(link, "views", PARAM_NUM)->num);
    psync_sql_bind_uint(q, 18, papi_find_result2(link, "type", PARAM_NUM)->num);
    if (papi_check_result2(link, "expires", PARAM_NUM))
      psync_sql_bind_uint(q, 19,
                          papi_find_result2(link, "expires", PARAM_NUM)->num);
    else
      psync_sql_bind_uint(q, 19, 0);

    psync_sql_run_free(q);
  }

  free(bres);
  return linkscnt;
}

int do_psync_delete_link(int64_t linkid, char **err /*OUT*/) {
  psock_t *api;
  binresult *bres;
  uint64_t result;
  const char *errorret;
  *err = 0;
  binparam params[] = {PAPI_STR("auth", psync_my_auth), PAPI_NUM("linkid", linkid)};
  api = psync_apipool_get();
  if (unlikely(!api)) {
    pdbg_logf(D_WARNING, "Can't gat api from the pool. No pool ?\n");
    *err = psync_strndup("Connection error.", 17);
    return -2;
  }
  bres = papi_send2(api, "deletepublink", params);

  if (likely(bres))
    psync_apipool_release(api);
  else {
    psync_apipool_release_bad(api);
    pdbg_logf(D_WARNING, "Send command returned in valid result.\n");
    *err = psync_strndup("Connection error.", 17);
    return -2;
  }
  result = papi_find_result2(bres, "result", PARAM_NUM)->num;
  if (unlikely(result)) {
    errorret = papi_find_result2(bres, "error", PARAM_STR)->str;
    *err = psync_strndup(errorret, strlen(errorret));
    pdbg_logf(D_WARNING, "command deletepublink returned error code %u",
          (unsigned)result);
    psync_process_api_error(result);
    if (psync_handle_api_result(result) == PSYNC_NET_TEMPFAIL)
      return -result;
    else {
      *err = psync_strndup("Connection error.", 17);
      return -1;
    }
  }
  free(bres);
  return 0;
}

int process_bres(const char *cmd, binresult *bres, psock_t *api,
                 char **err) {
  const char *errorret;
  int result;
  if (likely(bres))
    psync_apipool_release(api);
  else {
    psync_apipool_release_bad(api);
    pdbg_logf(D_WARNING, "Send command returned in valid result.\n");
    *err = psync_strndup("Connection error.", 17);
    return -2;
  }
  result = papi_find_result2(bres, "result", PARAM_NUM)->num;
  if (unlikely(result)) {
    errorret = papi_find_result2(bres, "error", PARAM_STR)->str;
    *err = psync_strndup(errorret, strlen(errorret));
    pdbg_logf(D_WARNING, "command %s returned error code %u", cmd,
          (unsigned)result);
    psync_process_api_error(result);
    if (psync_handle_api_result(result) == PSYNC_NET_TEMPFAIL)
      return -result;
    else {
      *err = psync_strndup("Connection error.", 17);
      return -1;
    }
  }

  return 0;
}

int do_psync_change_link(unsigned long long linkid, unsigned long long expire,
                         int delete_expire, const char *linkpassword,
                         int delete_password, unsigned long long maxtraffic,
                         unsigned long long maxdownloads,
                         int enableuploadforeveryone,
                         int enableuploadforchosenusers, int disableupload,
                         char **err) {
  psock_t *api;
  binresult *bres;
  uint64_t result;
  *err = 0;
  binparam *t;
  int numparam = 5; // +!!expire + !!maxdownloads + !!maxtraffic + !!password;
  int pind = 1;

  t = (binparam *)malloc(numparam * sizeof(binparam));
  init_param_str(t, "auth", psync_my_auth);
  init_param_num(t + pind++, "linkid", linkid);
  if (linkpassword)
    init_param_str(t + pind++, "linkpassword", linkpassword);
  else
    init_param_num(t + pind++, "deletepassword", delete_password);
  if (expire)
    init_param_num(t + pind++, "expire", expire);
  else
    init_param_num(t + pind++, "deleteexpire", delete_expire);

  init_param_num(t + pind++, "maxdownloads", maxdownloads);
  init_param_num(t + pind++, "maxtraffic", maxtraffic);

  if (enableuploadforeveryone)
    init_param_num(t + pind++, "enableuploadforeveryone",
                   enableuploadforeveryone);
  else if (enableuploadforchosenusers)
    init_param_num(t + pind++, "disableupload", enableuploadforchosenusers);
  else
    init_param_num(t + pind++, "disableupload", disableupload);

  api = psync_apipool_get();
  if (unlikely(!api)) {
    pdbg_logf(D_WARNING, "Can't get api from the pool. No pool ?\n");
    *err = psync_strndup("Connection error.", 17);
    return -2;
  }
  bres = papi_send(api, "changepublink", sizeof("changepublink") - 1, t,
                         pind, -1, 1);
  free(t);
  result = process_bres("deletepublink", bres, api, err);
  return result;
}

int do_change_link_expire(unsigned long long linkid, unsigned long long expire,
                          char **err) {
  psock_t *api;
  binresult *bres;
  uint64_t result;
  *err = 0;

  api = psync_apipool_get();
  if (unlikely(!api)) {
    pdbg_logf(D_WARNING, "Can't gat api from the pool. No pool ?\n");
    *err = psync_strndup("Connection error.", 17);
    return -2;
  }

  if (expire) {
    binparam params[] = {PAPI_STR("auth", psync_my_auth), PAPI_NUM("linkid", linkid),
                         PAPI_NUM("expire", expire)};
    bres = papi_send2(api, "changepublink", params);
  } else {
    binparam paramsd[] = {PAPI_STR("auth", psync_my_auth), PAPI_NUM("linkid", linkid),
                          PAPI_NUM("deleteexpire", 1)};
    bres = papi_send2(api, "changepublink", paramsd);
  }

  result = process_bres("changepublink", bres, api, err);
  free(bres);

  return result;
}

int do_change_link_password(unsigned long long linkid, const char *password,
                            char **err) {
  psock_t *api;
  binresult *bres;
  uint64_t result;
  *err = 0;

  api = psync_apipool_get();
  if (unlikely(!api)) {
    pdbg_logf(D_WARNING, "Can't gat api from the pool. No pool ?\n");
    *err = psync_strndup("Connection error.", 17);
    return -2;
  }

  if (password) {
    binparam params[] = {PAPI_STR("auth", psync_my_auth), PAPI_NUM("linkid", linkid),
                         PAPI_STR("linkpassword", password)};
    bres = papi_send2(api, "changepublink", params);
  } else {
    binparam paramsd[] = {PAPI_STR("auth", psync_my_auth), PAPI_NUM("linkid", linkid),
                          PAPI_NUM("deletepassword", 1)};
    bres = papi_send2(api, "changepublink", paramsd);
  }
  result = process_bres("changepublink", bres, api, err);
  free(bres);

  return result;
}

int do_change_link_enable_upload(unsigned long long linkid,
                                 int enableuploadforeveryone,
                                 int enableuploadforchosenusers, char **err) {
  psock_t *api;
  binresult *bres;
  uint64_t result;
  *err = 0;
  api = psync_apipool_get();
  if (unlikely(!api)) {
    pdbg_logf(D_WARNING, "Can't gat api from the pool. No pool ?\n");
    *err = psync_strndup("Connection error.", 17);
    return -2;
  }
  if (enableuploadforeveryone || enableuploadforchosenusers) {
    binparam params[] = {
        PAPI_STR("auth", psync_my_auth), PAPI_NUM("linkid", linkid),
        PAPI_NUM("enableuploadforeveryone", enableuploadforeveryone),
        PAPI_NUM("enableuploadforchosenusers", enableuploadforchosenusers)};
    bres = papi_send2(api, "changepublink", params);
  } else {
    binparam params[] = {PAPI_STR("auth", psync_my_auth), PAPI_NUM("linkid", linkid),
                         PAPI_NUM("disableupload", 1)};
    bres = papi_send2(api, "changepublink", params);
  }

  result = process_bres("changepublink", bres, api, err);
  free(bres);

  return result;
}

int64_t do_psync_upload_link(const char *path, const char *comment,
                             char **link /*OUT*/, char **err /*OUT*/,
                             uint64_t expire, int maxspace, int maxfiles) {
  psock_t *api;
  binresult *bres;
  uint64_t result;
  const char *rescode;
  const char *errorret;

  *err = 0;
  *link = 0;

  if (!expire && !maxspace && !maxfiles) {
    binparam params[] = {PAPI_STR("auth", psync_my_auth), PAPI_STR("path", path),
                         PAPI_STR("comment", comment)};
    api = psync_apipool_get();
    if (unlikely(!api)) {
      pdbg_logf(D_WARNING, "Can't gat api from the pool. No pool ?\n");
      *err = psync_strndup("Connection error.", 17);
      return -2;
    }

    bres = papi_send2(api, "createuploadlink", params);

  } else {
    binparam *t;
    int numparam = 3 + !!expire + !!maxspace + !!maxfiles;
    int pind = 1;

    t = (binparam *)malloc(numparam * sizeof(binparam));
    init_param_str(t, "auth", psync_my_auth);
    init_param_str(t + pind++, "path", path);
    init_param_str(t + pind++, "comment", comment);
    if (expire)
      init_param_num(t + pind++, "expire", expire);
    if (maxspace)
      init_param_num(t + pind++, "maxspace", maxspace);
    if (maxfiles)
      init_param_num(t + pind++, "maxfiles", maxfiles);
    api = psync_apipool_get();
    if (unlikely(!api)) {
      pdbg_logf(D_WARNING, "Can't gat api from the pool. No pool ?\n");
      *err = psync_strndup("Connection error.", 17);
      return -2;
    }
    bres = papi_send(api, "createuploadlink",
                           sizeof("createuploadlink") - 1, t, pind, -1, 1);
    free(t);
  }

  if (likely(bres))
    psync_apipool_release(api);
  else {
    psync_apipool_release_bad(api);
    pdbg_logf(D_WARNING, "Send command returned in valid result.\n");
    *err = psync_strndup("Connection error.", 17);
    return -2;
  }
  result = papi_find_result2(bres, "result", PARAM_NUM)->num;
  if (unlikely(result)) {
    errorret = papi_find_result2(bres, "error", PARAM_STR)->str;
    *err = psync_strndup(errorret, strlen(errorret));
    pdbg_logf(D_WARNING, "command createuploadlink returned error code %u",
          (unsigned)result);
    psync_process_api_error(result);
    if (psync_handle_api_result(result) == PSYNC_NET_TEMPFAIL)
      return -result;
    else {
      *err = psync_strndup("Connection error.", 17);
      return -1;
    }
  }

  rescode = papi_find_result2(bres, "link", PARAM_STR)->str;
  *link = psync_strndup(rescode, strlen(rescode));

  result = papi_find_result2(bres, "uploadlinkid", PARAM_NUM)->num;

  free(bres);

  return result;
}

int do_psync_delete_upload_link(int64_t uploadlinkid, char **err /*OUT*/) {
  psock_t *api;
  binresult *bres;
  uint64_t result;

  *err = 0;

  binparam params[] = {PAPI_STR("auth", psync_my_auth),
                       PAPI_NUM("uploadlinkid", uploadlinkid)};
  api = psync_apipool_get();
  if (unlikely(!api)) {
    pdbg_logf(D_WARNING, "Can't gat api from the pool. No pool ?\n");
    *err = psync_strndup("Connection error.", 17);
    return -2;
  }

  bres = papi_send2(api, "deleteuploadlink", params);
  result = process_bres("deletepublink", bres, api, err);
  free(bres);

  return result;
}

static int create_link(psync_list_builder_t *builder, void *element,
                       psync_variant_row row) {
  link_info_t *link;
  const char *str;
  size_t len;

  link = (link_info_t *)element;
  link->linkid = psync_get_number(row[0]);
  str = psync_get_lstring(row[1], &len);
  link->code = str;
  psync_list_add_lstring_offset(builder, offsetof(link_info_t, code), len);
  str = psync_get_lstring(row[2], &len);
  link->comment = str;
  psync_list_add_lstring_offset(builder, offsetof(link_info_t, comment), len);
  link->traffic = psync_get_number(row[3]);
  link->maxspace = psync_get_number(row[4]);
  link->downloads = psync_get_number(row[5]);
  link->created = psync_get_number(row[6]);
  link->modified = psync_get_number(row[7]);
  str = psync_get_lstring(row[8], &len);
  link->name = str;
  psync_list_add_lstring_offset(builder, offsetof(link_info_t, name), len);
  if (psync_get_number(row[9])) {
    link->isfolder = 1;
    link->itemid = psync_get_number(row[10]);

  } else {
    link->isfolder = 0;
    link->itemid = psync_get_number(row[11]);
  }
  link->isupload = psync_get_number(row[12]);
  link->icon = psync_get_number(row[13]);
  str = psync_get_lstring(row[14], &len);
  link->fulllink = str;
  link->parentfolderid = psync_get_number(row[15]);
  link->haspassword = psync_get_number(row[16]);
  link->views = psync_get_number(row[17]);
  link->type = psync_get_number(row[18]);
  if (!psync_is_null(row[19]))
    link->expire = psync_get_number(row[19]);
  else
    link->expire = 0;
  if (!psync_is_null(row[20]))
    link->enableuploadforeveryone = psync_get_number(row[20]);
  else
    link->enableuploadforeveryone = 0;
  if (!psync_is_null(row[21]))
    link->enableuploadforchosenusers = psync_get_number(row[21]);
  else
    link->enableuploadforchosenusers = 0;
  psync_list_add_lstring_offset(builder, offsetof(link_info_t, fulllink), len);
  return 0;
}

plink_info_list_t *do_psync_list_links(char **err /*OUT*/) {

  psync_list_builder_t *builder;
  psync_sql_res *res;
  *err = 0;

  builder = psync_list_builder_create(sizeof(link_info_t),
                                      offsetof(plink_info_list_t, entries));

  res = psync_sql_query_rdlock(
      "SELECT id, code, comment, traffic, maxspace, downloads, created,"
      " modified, name,  isfolder, folderid, fileid, isincomming, icon, "
      "fulllink,"
      " parentfolderid, haspassword, type, views, expire,"
      " enableuploadforeveryone, enableuploadforchosenusers FROM links");

  if (!res)
    return NULL;
  psync_list_bulder_add_sql(builder, res, create_link);

  return (plink_info_list_t *)psync_list_builder_finalize(builder);
}

plink_contents_t *do_show_link(const char *code, char **err /*OUT*/) {
  psock_t *api;
  binresult *bres;
  psync_list_builder_t *builder;
  link_cont_t *pcont;
  const binresult *contents = 0, *meta = 0, *link = 0, *br = 0;
  uint32_t concnt = 0, i = 0;
  plink_contents_t *ret = 0;
  *err = 0;

  binparam params[] = {PAPI_STR("auth", psync_my_auth),
                       PAPI_STR("timeformat", "timestamp"),
                       PAPI_STR("iconformat", "id"), PAPI_STR("code", code)};
  api = psync_apipool_get();
  if (unlikely(!api)) {
    pdbg_logf(D_WARNING, "Can't gat api from the pool. No pool ?\n");
    *err = psync_strndup("Can't gat api from the pool.", 29);
    return NULL;
  }

  bres = papi_send2(api, "showpublink", params);

  if (likely(bres))
    psync_apipool_release(api);
  else {
    psync_apipool_release_bad(api);
    pdbg_logf(D_WARNING, "Send command returned in valid result.\n");
    *err = psync_strndup("Connection error.", 17);
    return NULL;
  }

  meta = papi_check_result2(bres, "metadata", PARAM_HASH);
  if (meta) {
    contents = papi_check_result2(meta, "contents", PARAM_ARRAY);
    if (!contents) {
      free(bres);
      return 0;
    }
    concnt = contents->length;
    if (!concnt) {
      free(bres);
      return 0;
    }
    builder = psync_list_builder_create(sizeof(link_cont_t),
                                        offsetof(plink_contents_t, entries));
    for (i = 0; i < concnt; ++i) {
      link = contents->array[i];
      pcont = (link_cont_t *)psync_list_bulder_add_element(builder);
      br = papi_find_result2(link, "name", PARAM_STR);
      pcont->name = br->str;
      psync_list_add_lstring_offset(builder, offsetof(link_cont_t, name),
                                    br->length);
      pcont->created = papi_find_result2(link, "created", PARAM_NUM)->num;
      pcont->modified = papi_find_result2(link, "modified", PARAM_NUM)->num;
      if (papi_find_result2(link, "isfolder", PARAM_BOOL)->num) {
        pcont->isfolder = 1;
        pcont->itemid = papi_find_result2(link, "folderid", PARAM_NUM)->num;
      } else {
        pcont->isfolder = 0;
        pcont->itemid = papi_find_result2(link, "fileid", PARAM_NUM)->num;
      }
      pcont->icon = papi_find_result2(link, "icon", PARAM_NUM)->num;
    }
    ret = (plink_contents_t *)psync_list_builder_finalize(builder);
    free(bres);
    return ret;
  }
  free(bres);
  return 0;
}

int cache_upload_links(char **err /*OUT*/) {
  psock_t *api;
  binresult *bres;
  uint64_t result;
  const char *errorret;
  const binresult *publinks, *meta;
  binresult *link;
  const binresult *br;
  int i, linkscnt;
  psync_sql_res *q;

  *err = 0;

  q = psync_sql_prep_statement("DELETE FROM links WHERE isincomming = 1 ");
  psync_sql_run_free(q);

  if (psync_my_auth[0]) {
    binparam params[] = {PAPI_STR("auth", psync_my_auth),
                         PAPI_STR("timeformat", "timestamp"),
                         PAPI_STR("iconformat", "id")};
    api = psync_apipool_get();
    if (unlikely(!api)) {
      pdbg_logf(D_WARNING, "Can't gat api from the pool. No pool ?\n");
      *err = psync_strndup("Connection error.", 17);
      return -2;
    }
    bres = papi_send2(api, "listuploadlinks", params);
  } else if (psync_my_user && psync_my_pass) {
    binparam params[] = {
        PAPI_STR("username", psync_my_user), PAPI_STR("password", psync_my_pass),
        PAPI_STR("timeformat", "timestamp"), PAPI_STR("iconformat", "id")};
    api = psync_apipool_get();
    if (unlikely(!api)) {
      pdbg_logf(D_WARNING, "Can't gat api from the pool. No pool ?\n");
      *err = psync_strndup("Connection error.", 17);
      return -2;
    }
    bres = papi_send2(api, "listuploadlinks", params);
  } else
    return -1;
  if (likely(bres))
    psync_apipool_release(api);
  else {
    psync_apipool_release_bad(api);
    pdbg_logf(D_WARNING, "Send command returned in valid result.\n");
    *err = psync_strndup("Connection error.", 17);
    return -2;
  }
  result = papi_find_result2(bres, "result", PARAM_NUM)->num;
  if (unlikely(result)) {
    errorret = papi_find_result2(bres, "error", PARAM_STR)->str;
    *err = psync_strndup(errorret, strlen(errorret));
    pdbg_logf(D_WARNING, "command listpublinks returned error code %u",
          (unsigned)result);
    psync_process_api_error(result);
    if (psync_handle_api_result(result) == PSYNC_NET_TEMPFAIL)
      return -result;
    else {
      *err = psync_strndup("Connection error.", 17);
      return -1;
    }
  }

  publinks = papi_find_result2(bres, "uploadlinks", PARAM_ARRAY);

  linkscnt = publinks->length;
  for (i = 0; i < linkscnt; ++i) {
    link = publinks->array[i];

    q = psync_sql_prep_statement(
        "REPLACE INTO links  (id, code, comment, traffic, maxspace, downloads, "
        "created,"
        " modified, name,  isfolder, folderid, fileid, isincomming, icon, "
        "fulllink,"
        " parentfolderid, haspassword, views, type)"
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?)");
    psync_sql_bind_uint(
        q, 1, papi_find_result2(link, "uploadlinkid", PARAM_NUM)->num);
    psync_sql_bind_string(q, 2,
                          papi_find_result2(link, "code", PARAM_STR)->str);
    psync_sql_bind_string(q, 3,
                          papi_find_result2(link, "comment", PARAM_STR)->str);
    psync_sql_bind_uint(q, 4, papi_find_result2(link, "space", PARAM_NUM)->num);
    if ((br = papi_check_result2(link, "maxspace", PARAM_NUM)))
      psync_sql_bind_uint(q, 5, br->num);
    else
      psync_sql_bind_uint(q, 5, 0);
    psync_sql_bind_uint(q, 6, papi_find_result2(link, "files", PARAM_NUM)->num);
    psync_sql_bind_uint(q, 7,
                        papi_find_result2(link, "created", PARAM_NUM)->num);
    psync_sql_bind_uint(q, 8,
                        papi_find_result2(link, "modified", PARAM_NUM)->num);

    meta = papi_find_result2(link, "metadata", PARAM_HASH);
    psync_sql_bind_string(q, 9,
                          papi_find_result2(meta, "name", PARAM_STR)->str);
    if (papi_find_result2(meta, "isfolder", PARAM_BOOL)->num) {
      psync_sql_bind_uint(q, 10, 1);
      psync_sql_bind_uint(q, 11,
                          papi_find_result2(meta, "folderid", PARAM_NUM)->num);
      psync_sql_bind_uint(q, 12, 0);
    } else {
      psync_sql_bind_uint(q, 10, 0);
      psync_sql_bind_uint(q, 11, 0);
      psync_sql_bind_uint(q, 12,
                          papi_find_result2(meta, "fileid", PARAM_NUM)->num);
    }
    psync_sql_bind_uint(q, 13, papi_find_result2(meta, "icon", PARAM_NUM)->num);
    psync_sql_bind_string(q, 14,
                          papi_find_result2(link, "link", PARAM_STR)->str);
    psync_sql_bind_uint(
        q, 15, papi_find_result2(meta, "parentfolderid", PARAM_NUM)->num);
    psync_sql_bind_uint(q, 16, 0);
    psync_sql_bind_uint(q, 17, 0);
    psync_sql_bind_uint(q, 18, 0);
    psync_sql_run_free(q);
  }

  free(bres);

  return linkscnt;
}

void cache_links_all() {
  char *err /*OUT*/ = NULL;
  int ret = 0;

  ret = cache_upload_links(&err);
  if (ret >= 0)
    ret += cache_links(err, 256);

  if (ret < 0) {
    if (err) {
      pdbg_logf(D_WARNING, "Problem cacheing links errcode %d errmsg[%s]\n", ret,
            err);
      free(err);
    }
  }
  if (err)
    free(err);
}

int do_delete_all_links(int64_t folderid, int64_t fileid, char **err) {
  psync_sql_res *res;
  psync_uint_row row;
  int ret = 0;

  res = psync_sql_query_rdlock("SELECT id, folderid, fileid, isincomming FROM "
                               "links where folderid = ? or fileid = ? ");
  psync_sql_bind_int(res, 1, folderid);
  psync_sql_bind_int(res, 2, fileid);

  while ((row = psync_sql_fetch_rowint(res))) {
    if (row[3]) {
      ret = do_psync_delete_upload_link(row[0], err);
      if (ret)
        return ret;
    } else {
      ret = do_psync_delete_link(row[0], err);
      if (ret)
        return ret;
    }
  }
  return 0;
}

int do_delete_all_folder_links(psync_folderid_t folderid, char **err) {
  psync_sql_res *res;
  psync_full_result_int *rows;
  int ret = 0;
  uint32_t i;

  res = psync_sql_query_rdlock("SELECT id, folderid, fileid, isincomming FROM "
                               "links where folderid = ? ");
  psync_sql_bind_uint(res, 1, folderid);

  rows = psync_sql_fetchall_int(res);

  for (i = 0; i < rows->rows; ++i) {
    if (psync_get_result_cell(rows, i, 3)) {
      ret = do_psync_delete_upload_link(psync_get_result_cell(rows, i, 0), err);
      if (ret)
        return ret;
    } else {
      ret = do_psync_delete_link(psync_get_result_cell(rows, i, 0), err);
      if (ret)
        return ret;
    }
  }
  return 0;
}

int do_delete_all_file_links(psync_fileid_t fileid, char **err) {
  psync_sql_res *res;
  psync_full_result_int *rows;
  int ret = 0;
  uint32_t i;

  res = psync_sql_query_rdlock(
      "SELECT id, folderid, fileid, isincomming FROM links where fileid = ? ");
  psync_sql_bind_uint(res, 1, fileid);

  rows = psync_sql_fetchall_int(res);

  for (i = 0; i < rows->rows; ++i) {
    if (psync_get_result_cell(rows, i, 3)) {
      ret = do_psync_delete_upload_link(psync_get_result_cell(rows, i, 0), err);
      if (ret)
        return ret;
    } else {
      ret = do_psync_delete_link(psync_get_result_cell(rows, i, 0), err);
      if (ret)
        return ret;
    }
  }
  return 0;
}

preciever_list_t *do_list_email_with_access(unsigned long long linkid,
                                            char **err) {
  psock_t *api;
  binresult *bres;
  uint64_t result;
  const char *errorret;
  psync_list_builder_t *builder;
  reciever_info_t *pcont;
  const binresult *list = 0, *reciever = 0, *br = 0;
  preciever_list_t *ret = 0;
  int i = 0, lcnt;
  *err = 0;
  binparam params[] = {PAPI_STR("auth", psync_my_auth), PAPI_NUM("linkid", linkid)};
  api = psync_apipool_get();
  if (unlikely(!api)) {
    pdbg_logf(D_WARNING, "Can't gat api from the pool. No pool ?\n");
    *err = psync_strndup("Connection error.", 17);
    return NULL;
  }
  bres = papi_send2(api, "publink/listemailswithaccess", params);
  if (likely(bres))
    psync_apipool_release(api);
  else {
    psync_apipool_release_bad(api);
    pdbg_logf(D_WARNING, "Send command returned in valid result.\n");
    *err = psync_strndup("Connection error.", 17);
    return NULL;
  }
  result = papi_find_result2(bres, "result", PARAM_NUM)->num;
  if (unlikely(result)) {
    errorret = papi_find_result2(bres, "error", PARAM_STR)->str;
    *err = psync_strndup(errorret, strlen(errorret));
    pdbg_logf(D_WARNING, "command listemailswithaccess returned error code %u",
          (unsigned)result);
    psync_process_api_error(result);
    if (psync_handle_api_result(result) == PSYNC_NET_TEMPFAIL)
      return NULL;
    else {
      *err = psync_strndup("Connection error.", 17);
      return NULL;
    }
  }

  list = papi_find_result2(bres, "list", PARAM_ARRAY);
  lcnt = list->length;
  builder = psync_list_builder_create(sizeof(reciever_info_t),
                                      offsetof(preciever_list_t, entries));

  if (!lcnt) {
    ret = (preciever_list_t *)psync_list_builder_finalize(builder);
    free(bres);
    return ret;
  }
  for (i = 0; i < lcnt; ++i) {
    reciever = list->array[i];
    pcont = (reciever_info_t *)psync_list_bulder_add_element(builder);
    br = papi_find_result2(reciever, "email", PARAM_STR);
    if (br) {
      pcont->mail = br->str;
      psync_list_add_lstring_offset(builder, offsetof(reciever_info_t, mail),
                                    br->length);
    }
    pcont->recieverid =
        papi_find_result2(reciever, "receiverid", PARAM_NUM)->num;
  }
  ret = (preciever_list_t *)psync_list_builder_finalize(builder);

  free(bres);

  return ret;
}

int do_link_add_access(unsigned long long linkid, const char *mail,
                       char **err) {
  psock_t *api;
  binresult *bres;
  int result;

  *err = 0;
  // publink/addaccess
  binparam params[] = {PAPI_STR("auth", psync_my_auth), PAPI_NUM("linkid", linkid),
                       PAPI_STR("mail", mail)};
  api = psync_apipool_get();
  if (unlikely(!api)) {
    pdbg_logf(D_WARNING, "Can't gat api from the pool. No pool ?\n");
    *err = psync_strndup("Connection error.", 17);
    return -2;
  }

  bres = papi_send2(api, "publink/addaccess", params);
  result = process_bres("publink/addaccess", bres, api, err);
  free(bres);

  return result;
}

int do_link_remove_access(unsigned long long linkid,
                          unsigned long long receiverid, char **err) {
  psock_t *api;
  binresult *bres;
  uint64_t result;
  *err = 0;
  binparam params[] = {PAPI_STR("auth", psync_my_auth), PAPI_NUM("linkid", linkid),
                       PAPI_NUM("receiverid", receiverid)};

  api = psync_apipool_get();
  if (unlikely(!api)) {
    pdbg_logf(D_WARNING, "Can't gat api from the pool. No pool ?\n");
    *err = psync_strndup("Connection error.", 17);
    return -2;
  }

  bres = papi_send2(api, "publink/removeaccess", params);
  result = process_bres("publink/removeaccess", bres, api, err);
  free(bres);

  return result;
}

bookmarks_list_t *do_cache_bookmarks(char **err) {
  psock_t *api;
  binresult *bres;
  uint64_t result;
  const char *errorret;
  psync_list_builder_t *builder;
  bookmark_info_t *pcont;
  const binresult *list = 0, *bookmark = 0, *br = 0;
  bookmarks_list_t *ret = 0;
  int i = 0, lcnt;
  *err = 0;
  binparam params[] = {PAPI_STR("auth", psync_my_auth),
                       PAPI_STR("timeformat", "timestamp")};
  api = psync_apipool_get();
  if (unlikely(!api)) {
    pdbg_logf(D_WARNING, "Can't gat api from the pool. No pool ?\n");
    *err = psync_strndup("Connection error.", 17);
    return NULL;
  }

  bres = papi_send2(api, "publink/listpins", params);

  if (likely(bres))
    psync_apipool_release(api);
  else {
    psync_apipool_release_bad(api);
    pdbg_logf(D_WARNING, "Send command returned in valid result.\n");
    *err = psync_strndup("Connection error.", 17);
    return NULL;
  }
  result = papi_find_result2(bres, "result", PARAM_NUM)->num;
  if (unlikely(result)) {
    errorret = papi_find_result2(bres, "error", PARAM_STR)->str;
    *err = psync_strndup(errorret, strlen(errorret));
    pdbg_logf(D_WARNING, "command deletepublink returned error code %u",
          (unsigned)result);
    psync_process_api_error(result);
    if (psync_handle_api_result(result) == PSYNC_NET_TEMPFAIL)
      return NULL;
    else {
      *err = psync_strndup("Connection error.", 17);
      return NULL;
    }
  }

  list = papi_find_result2(bres, "list", PARAM_ARRAY);
  lcnt = list->length;
  builder = psync_list_builder_create(sizeof(bookmark_info_t),
                                      offsetof(bookmarks_list_t, entries));
  if (!lcnt) {
    ret = (bookmarks_list_t *)psync_list_builder_finalize(builder);
    free(bres);
    return ret;
  }

  for (i = 0; i < lcnt; ++i) {
    bookmark = list->array[i];
    pcont = (bookmark_info_t *)psync_list_bulder_add_element(builder);
    br = papi_find_result2(bookmark, "link", PARAM_STR);
    pcont->link = br->str;
    psync_list_add_lstring_offset(builder, offsetof(bookmark_info_t, link),
                                  br->length);
    br = papi_find_result2(bookmark, "name", PARAM_STR);
    pcont->name = br->str;
    psync_list_add_lstring_offset(builder, offsetof(bookmark_info_t, name),
                                  br->length);
    br = papi_find_result2(bookmark, "code", PARAM_STR);
    pcont->code = br->str;
    psync_list_add_lstring_offset(builder, offsetof(bookmark_info_t, code),
                                  br->length);
    br = papi_check_result2(bookmark, "description", PARAM_STR);
    if (br) {
      pcont->description = br->str;
      psync_list_add_lstring_offset(
          builder, offsetof(bookmark_info_t, description), br->length);
    } else {
      pcont->description = "";
    }
    pcont->created = papi_find_result2(bookmark, "ctime", PARAM_NUM)->num;
    pcont->locationid =
        papi_find_result2(bookmark, "locationid", PARAM_NUM)->num;
  }
  ret = (bookmarks_list_t *)psync_list_builder_finalize(builder);

  free(bres);

  return ret;
}

int do_remove_bookmark(const char *code, int locationid, char **err) {
  psock_t *api;
  binresult *bres;
  uint64_t result;

  *err = 0;
  binparam params[] = {PAPI_STR("auth", psync_my_auth),
                       PAPI_NUM("locationid", locationid), PAPI_STR("code", code)};
  api = psync_apipool_get();
  if (unlikely(!api)) {
    pdbg_logf(D_WARNING, "Can't gat api from the pool. No pool ?\n");
    *err = psync_strndup("Connection error.", 17);
    return -2;
  }

  bres = papi_send2(api, "publink/unpin", params);
  result = process_bres("publink/unpin", bres, api, err);
  free(bres);

  return result;
}

int do_change_bookmark(const char *code, int locationid, const char *name,
                       const char *description, char **err) {
  psock_t *api;
  binresult *bres;
  uint64_t result;

  *err = 0;
  // publink/addaccess
  binparam params[] = {PAPI_STR("auth", psync_my_auth), PAPI_STR("code", code),
                       PAPI_NUM("locationid", locationid), PAPI_STR("name", name),
                       PAPI_STR("description", description)};
  api = psync_apipool_get();
  if (unlikely(!api)) {
    pdbg_logf(D_WARNING, "Can't gat api from the pool. No pool ?\n");
    *err = psync_strndup("Connection error.", 17);
    return -2;
  }

  bres = papi_send2(api, "publink/changepin", params);
  result = process_bres("publink/changepin", bres, api, err);
  free(bres);

  return result;
}
