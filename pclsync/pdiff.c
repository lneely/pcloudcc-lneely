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
   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTsABILITY AND FITNESS
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
#include <ctype.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/debug.h>
#include <mbedtls/entropy.h>
#include <mbedtls/pkcs5.h>
#include <mbedtls/sha1.h>
#include <mbedtls/ssl.h>
#include <pthread.h>
#include <stddef.h>
#include <unistd.h>

#include "paccountevents.h"
#include "papi.h"
#include "pbusinessaccount.h"
#include "pcache.h"
#include "pcryptofolder.h"
#include "pqevent.h"
#include "pcontacts.h"
#include "pdevice.h"
#include "pdiff.h"
#include "pdownload.h"
#include "pfileops.h"
#include "pfoldersync.h"
#include "pfs.h"
#include "pfsxattr.h"
#include "plibs.h"
#include "pnetlibs.h"
#include "pnotify.h"
#include "ppathstatus.h"
#include "prun.h"
#include "psettings.h"
#include "pstatus.h"
#include "psynclib.h"
#include "pfoldersync.h"
#include "psys.h"
#include "ptask.h"
#include "ptimer.h"
#include "ptools.h"
#include "publiclinks.h"
#include "putil.h"

#define PSYNC_SQL_DOWNLOAD                                                     \
  "synctype&" NTO_STR(PSYNC_DOWNLOAD_ONLY) "=" NTO_STR(PSYNC_DOWNLOAD_ONLY)

#define create_entry()                                                         \
  binresult entry;                                                             \
  hashpair pair;                                                               \
  entry.type = PARAM_HASH;                                                     \
  entry.length = 1;                                                            \
  entry.hash = &pair;                                                          \
  pair.key = "metadata";                                                       \
  pair.value = (binresult *)meta;
#define bind_num(s)                                                            \
  psync_sql_bind_uint(res, off++, papi_find_result2(meta, s, PARAM_NUM)->num)
#define bind_bool(s)                                                           \
  psync_sql_bind_uint(res, off++, papi_find_result2(meta, s, PARAM_BOOL)->num)
#define bind_str(s)                                                            \
  do {                                                                         \
    br = papi_find_result2(meta, s, PARAM_STR);                                \
    psync_sql_bind_lstring(res, off++, br->str, br->length);                   \
  } while (0)
#define bind_opt_str(s)                                                        \
  do {                                                                         \
    br = papi_check_result2(meta, s, PARAM_STR);                               \
    if (br)                                                                    \
      psync_sql_bind_lstring(res, off++, br->str, br->length);                 \
    else                                                                       \
      psync_sql_bind_null(res, off++);                                         \
  } while (0)
#define bind_opt_num(s)                                                        \
  do {                                                                         \
    br = papi_check_result2(meta, s, PARAM_NUM);                               \
    if (br)                                                                    \
      psync_sql_bind_uint(res, off++, br->num);                                \
    else                                                                       \
      psync_sql_bind_null(res, off++);                                         \
  } while (0)
#define bind_opt_double(s)                                                     \
  do {                                                                         \
    br = papi_check_result2(meta, s, PARAM_STR);                               \
    if (br)                                                                    \
      psync_sql_bind_double(res, off++, atof(br->str));                        \
    else                                                                       \
      psync_sql_bind_null(res, off++);                                         \
  } while (0)
#define fill_str(f, s, sl)                                                     \
  do {                                                                         \
    if (s && sl) {                                                             \
      memcpy(str, s, sl);                                                      \
      f = str;                                                                 \
      str += sl;                                                               \
    } else                                                                     \
      f = "";                                                                  \
  } while (0);
#define FN(n) {process_##n, #n, sizeof(#n) - 1, 0}
#define event_list_size ARRAY_SIZE(event_list)

typedef struct {
  psync_eventtype_t eventid;
  psync_share_event_t *event_data;
  uint64_t touserid;
  uint64_t fromuserid;
  uint64_t teamid;

  char *str;
} notify_paramst;

typedef struct {
  uint64_t diffid;
  uint32_t notificationid;
  uint64_t publinkid;
  uint64_t uploadlinkid;
} subscribed_ids;

typedef struct {
  psync_folderid_t *refresh_folders;
  uint32_t refresh_last;
} refresh_folders_ptr_t;

static uint64_t used_quota = 0, current_quota = 0, free_quota = 0;
static time_t last_event = 0;
static unsigned long needdownload = 0;
static int exceptionsockwrite = INVALID_SOCKET;
static pthread_mutex_t diff_mutex = PTHREAD_MUTEX_INITIALIZER;
static int initialdownload = 0;
static paccount_cache_callback_t psync_cache_callback = NULL;
static uint32_t psync_is_business = 0;
static unsigned char adapter_hash[PSYNC_FAST_HASH256_LEN];
static psync_folderid_t *refresh_folders = NULL;
static uint32_t refresh_allocated = 0;
static uint32_t refresh_last = 0;
int unlinked = 0;
int tfa = 0;

static void psync_diff_refresh_fs_add_folder(psync_folderid_t folderid);

static void do_send_eventdata(void *param);

static void psync_notify_cache_change(psync_changetype_t event) {
  paccount_cache_callback_t callback;
  psync_changetype_t *chtype = psync_new(psync_changetype_t);
  *chtype = event;
  callback = psync_cache_callback;
  if (callback)
    prun_thread1("cache start callback", callback, chtype);
  else
    free(chtype);
}

static binresult *get_userinfo_user_digest(psock_t *sock, const char *username,
                         size_t userlen, const char *pwddig, const char *digest,
                         uint32_t diglen, const char *osversion,
                         const char *appversion, const char *deviceid,
                         const char *devicestring) {
  binparam params[] = {
      PAPI_STR("timeformat", "timestamp"),
      PAPI_LSTR("username", username, userlen),
      PAPI_LSTR("digest", digest, diglen),
      PAPI_LSTR("passworddigest", pwddig, PSYNC_SHA1_DIGEST_HEXLEN),
      PAPI_STR("osversion", osversion),
      PAPI_STR("appversion", appversion),
      PAPI_STR("deviceid", deviceid),
      PAPI_STR("device", devicestring),
      PAPI_BOOL("getauth", 1),
      PAPI_BOOL("getapiserver", 1),
      PAPI_BOOL("cryptokeyssign", 1),
      PAPI_BOOL("getlastsubscription", 1),
      PAPI_NUM("os", P_OS_ID)};
  return papi_send2(sock, "login", params);
}

static binresult *get_userinfo_user_pass(psock_t *sock, const char *username,
                       const char *password, const char *osversion,
                       const char *appversion, const char *deviceid,
                       const char *devicestring) {
  binparam empty_params[] = {PAPI_STR("MS", "sucks")};
  psync_sha1_ctx ctx;
  binresult *res, *ret;
  const binresult *dig;
  unsigned char *uc;
  size_t ul, i;
  unsigned char sha1bin[PSYNC_SHA1_DIGEST_LEN];
  char sha1hex[PSYNC_SHA1_DIGEST_HEXLEN];

  res = papi_send2(sock, "getdigest", empty_params);

  if (!res)
    return res;

  if (papi_find_result2(res, "result", PARAM_NUM)->num != 0) {
    free(res);
    return NULL;
  }

  dig = papi_find_result2(res, "digest", PARAM_STR);

  pdbg_logf(D_NOTICE, "got digest %s", dig->str);

  ul = strlen(username);
  uc = psync_new_cnt(unsigned char, ul);

  for (i = 0; i < ul; i++)
    uc[i] = tolower(username[i]);

  psync_sha1(uc, ul, sha1bin);
  free(uc);
  psync_binhex(sha1hex, sha1bin, PSYNC_SHA1_DIGEST_LEN);
  psync_sha1_init(&ctx);
  psync_sha1_update(&ctx, password, strlen(password));
  psync_sha1_update(&ctx, sha1hex, PSYNC_SHA1_DIGEST_HEXLEN);
  psync_sha1_update(&ctx, dig->str, dig->length);
  psync_sha1_final(sha1bin, &ctx);
  psync_binhex(sha1hex, sha1bin, PSYNC_SHA1_DIGEST_LEN);

  ret = get_userinfo_user_digest(sock, username, ul, sha1hex, dig->str,
                                 dig->length, osversion, appversion, deviceid,
                                 devicestring);

  free(res);
  return ret;
}

static int check_active_subscribtion(const binresult *res) {
  const binresult *sub;
  char *status;
  sub = papi_check_result2(res, "lastsubscription", PARAM_HASH);
  if (sub) {
    status = psync_strdup(papi_find_result2(sub, "status", PARAM_STR)->str);
    if (!strcmp(status, "active")) {
      free(status);
      return 1;
    }
    free(status);
  }

  return 0;
}

static int check_user_relocated(uint64_t luserid, psock_t *sock) {
  binresult *res;
  const binresult *userids;
  uint64_t result, userid;
  int cnt, i, lid, clid;
  binresult *id;
  binparam params[] = {PAPI_STR("timeformat", "timestamp"),
                       PAPI_STR("auth", psync_my_auth)};
  res = papi_send2(sock, "getolduserids", params);
  if (pdbg_unlikely(!res))
    return 0;
  result = papi_find_result2(res, "result", PARAM_NUM)->num;
  if (result) {
    pdbg_logf(D_NOTICE, "getolduserids returned error %lu %s",
          (unsigned long)result,
          papi_find_result2(res, "error", PARAM_STR)->str);
    free(res);
    return 0;
  }

  userids = papi_find_result2(res, "userids", PARAM_ARRAY);
  cnt = userids->length;
  if (!cnt) {
    free(res);
    return 0;
  }

  clid = psync_sql_cellint(
      "SELECT value FROM setting WHERE id='last_logged_location_id'", 1);

  for (i = 0; i < cnt; ++i) {
    id = userids->array[i];
    userid = papi_find_result2(id, "userid", PARAM_NUM)->num;
    lid = papi_find_result2(id, "locationid", PARAM_NUM)->num;
    if (luserid == userid && lid == clid) {
      return 1;
    }
  }
  return 0;
}

static psock_t *get_connected_socket() {
  char *auth, *user, *pass, *deviceid, *osversion, *devicestring, *binapi,
      *chrUserid;
  const char *appversion;
  psock_t *sock;
  binresult *res;
  const binresult *cres;
  psync_sql_res *q;
  uint64_t result, userid, luserid, locationid;
  int saveauth, isbusiness, cryptosetup, digest, lid, isFirstLogin;

  digest = 1;
  free(psync_my_2fa_token);
  auth = user = pass = psync_my_2fa_token = NULL;
  psync_is_business = 0;
  deviceid = psync_sql_cellstr("SELECT value FROM setting WHERE id='deviceid'");

  // generate deviceid if needed
  if (!deviceid) {
    psync_sql_res *q;
    unsigned char deviceidbin[16];
    char deviceidhex[32 + 2];
    pssl_rand_strong(deviceidbin, sizeof(deviceidbin));
    psync_binhex(deviceidhex, deviceidbin, sizeof(deviceidbin));
    deviceidhex[sizeof(deviceidbin) * 2] = 0;
    q = psync_sql_prep_statement(
        "REPLACE INTO setting (id, value) VALUES ('deviceid', ?)");
    psync_sql_bind_string(q, 1, deviceidhex);
    psync_sql_run_free(q);
    deviceid = psync_strdup(deviceidhex);
  }

  pdbg_logf(D_NOTICE, "using deviceid %s", deviceid);
  appversion = pdevice_get_software();
  devicestring = pdevice_name();

  while (1) {
    free(auth);
    free(user);
    free(pass);
    pstatus_wait(PSTATUS_TYPE_RUN, PSTATUS_RUN_RUN | PSTATUS_RUN_PAUSE);

    auth = psync_sql_cellstr("SELECT value FROM setting WHERE id='auth'");
    user = psync_sql_cellstr("SELECT value FROM setting WHERE id='user'");
    pass = psync_sql_cellstr("SELECT value FROM setting WHERE id='pass'");
    if (user && !user[0])
      user = NULL;
    if (pass && !pass[0])
      pass = NULL;
    if (auth && !auth[0])
      auth = NULL;

    chrUserid =
        psync_sql_cellstr("SELECT value FROM setting WHERE id='userid'");

    // If there is no userid row, we assume it's first login, after instalation.
    // Rise a flag so we can send a first login event later.
    if (chrUserid == NULL) {
      isFirstLogin = 1;
    } else {
      isFirstLogin = 0;
    }

    if (!auth && psync_my_auth[0])
      auth = psync_strdup(psync_my_auth);
    if (!user && psync_my_user)
      user = psync_strdup(psync_my_user);
    if (!pass && psync_my_pass)
      pass = psync_strdup(psync_my_pass);
    if (!auth && (!pass || !user)) {
      if (tfa) {
        tfa = 0;
        psys_sleep_milliseconds(1000);
        pdbg_logf(D_WARNING, "tfa sleep");
        continue;
      }
      pstatus_set(PSTATUS_TYPE_AUTH, PSTATUS_AUTH_REQUIRED);
      pstatus_wait(PSTATUS_TYPE_AUTH, PSTATUS_AUTH_PROVIDED);
      continue;
    }

    pstatus_set(PSTATUS_TYPE_AUTH, PSTATUS_AUTH_PROVIDED);
    saveauth = psync_setting_get_bool(_PS(saveauth));

    sock = papi_connect(apiserver, psync_setting_get_bool(_PS(usessl)));

    if (pdbg_unlikely(!sock)) {
      pstatus_set(PSTATUS_TYPE_ONLINE, PSTATUS_ONLINE_OFFLINE);
      psys_sleep_milliseconds(PSYNC_SLEEP_BEFORE_RECONNECT);
      continue;
    }
    osversion = pdevice_get_os();

    if (psync_my_2fa_token && psync_my_2fa_code_type && psync_my_2fa_code[0]) {
      const char *method = psync_my_2fa_code_type == 1
                               ? "tfa_login"
                               : "tfa_loginwithrecoverycode";
      binparam params[] = {PAPI_STR("timeformat", "timestamp"),
                           PAPI_STR("token", psync_my_2fa_token),
                           PAPI_STR("code", psync_my_2fa_code),
                           PAPI_BOOL("trustdevice", psync_my_2fa_trust),
                           PAPI_STR("osversion", osversion),
                           PAPI_STR("appversion", appversion),
                           PAPI_STR("deviceid", deviceid),
                           PAPI_STR("device", devicestring),
                           PAPI_BOOL("getauth", 1),
                           PAPI_BOOL("cryptokeyssign", 1),
                           PAPI_BOOL("getapiserver", 1),
                           PAPI_BOOL("getlastsubscription", 1),
                           PAPI_NUM("os", P_OS_ID)};
      res = papi_send2(sock, method, params);
    } else if (user && pass && pass[0]) {
      if (digest) {
        res = get_userinfo_user_pass(sock, user, pass, osversion, appversion,
                                     deviceid, devicestring);
      } else {
        binparam params[] = {
            PAPI_STR("timeformat", "timestamp"), PAPI_STR("username", user),
            PAPI_STR("password", pass),          PAPI_STR("osversion", osversion),
            PAPI_STR("appversion", appversion),  PAPI_STR("deviceid", deviceid),
            PAPI_STR("device", devicestring),    PAPI_BOOL("getauth", 1),
            PAPI_BOOL("cryptokeyssign", 1),      PAPI_BOOL("getapiserver", 1),
            PAPI_BOOL("getlastsubscription", 1), PAPI_NUM("os", P_OS_ID)};
        res = papi_send2(sock, "login", params);
      }
    } else {
      binparam params[] = {PAPI_STR("timeformat", "timestamp"),
                           PAPI_STR("auth", auth),
                           PAPI_STR("osversion", osversion),
                           PAPI_STR("appversion", appversion),
                           PAPI_STR("deviceid", deviceid),
                           PAPI_STR("device", devicestring),
                           PAPI_BOOL("getauth", 1),
                           PAPI_BOOL("cryptokeyssign", 1),
                           PAPI_BOOL("getapiserver", 1),
                           PAPI_BOOL("getlastsubscription", 1),
                           PAPI_NUM("os", P_OS_ID)};
      res = papi_send2(sock, "userinfo", params);
    }

    free(osversion);

    if (pdbg_unlikely(!res)) {
      psock_close(sock);
      pstatus_set(PSTATUS_TYPE_ONLINE, PSTATUS_ONLINE_OFFLINE);
      psys_sleep_milliseconds(PSYNC_SLEEP_BEFORE_RECONNECT);
      papi_conn_fail_inc();
      continue;
    }

    papi_conn_fail_reset();
    result = papi_find_result2(res, "result", PARAM_NUM)->num;

    if (unlikely(result)) {
      pdbg_logf(D_NOTICE, "userinfo returned error %lu %s", (unsigned long)result,
            papi_find_result2(res, "error", PARAM_STR)->str);
      // here we only handle statuses that need to access the result
      if (result == 2297) {
        free(psync_my_2fa_token);
        psync_my_2fa_token =
            psync_strdup(papi_find_result2(res, "token", PARAM_STR)->str);
        psync_my_2fa_has_devices =
            papi_find_result2(res, "hasdevices", PARAM_BOOL)->num;
        psync_my_2fa_type = papi_find_result2(res, "tfatype", PARAM_NUM)->num;
        psync_my_2fa_code_type = 0;
        psync_my_2fa_code[0] = 0;
        pstatus_set(PSTATUS_TYPE_AUTH, PSTATUS_AUTH_TFAREQ);
        pstatus_wait(PSTATUS_TYPE_AUTH, PSTATUS_AUTH_PROVIDED);
        psock_close(sock);
        free(res);
        continue;
      }

      if (result == 2306) {
        free(psync_my_verify_token);
        psync_my_verify_token =
            psync_strdup(papi_find_result2(res, "verifytoken", PARAM_STR)->str);
        pstatus_set(PSTATUS_TYPE_AUTH, PSTATUS_AUTH_VERIFYREQ);
        pstatus_wait(PSTATUS_TYPE_AUTH, PSTATUS_AUTH_PROVIDED);
        psock_close(sock);
        free(res);
        continue;
      }

      if (result == 2321) {
        cres = papi_check_result2(res, "location", PARAM_HASH);
        if (cres) {
          binapi =
              psync_strdup(papi_find_result2(cres, "binapi", PARAM_STR)->str);

          locationid = papi_find_result2(cres, "id", PARAM_NUM)->num;
          psync_set_apiserver(binapi, locationid);
        }

        psock_close(sock);
        free(res);
        continue;
      }

      if (result == 2330) {
        psync_set_apiserver(PSYNC_API_HOST, PSYNC_LOCATIONID_DEFAULT);
        pstatus_set(PSTATUS_TYPE_AUTH, PSTATUS_AUTH_RELOCATING);
        pstatus_wait(PSTATUS_TYPE_AUTH, PSTATUS_AUTH_PROVIDED);
        psock_close(sock);
        free(res);
        continue;
      }

      psock_close(sock);
      free(res);

      if (result == 2000 || result == 2012 || result == 2064 ||
          result == 2074 || result == 2092) {
        psync_my_2fa_code_type = 0;
        psync_my_2fa_code[0] = 0;
        if (result == 2012 || result == 2064 || result == 2074 ||
            result == 2092)
          pstatus_set(PSTATUS_TYPE_AUTH, PSTATUS_AUTH_BADCODE);
        else if (user && pass) {
          // Ugly fix, sorry :(
          if (!strcmp(user, "pass") && !strcmp(pass, "dummy")) {
            pdbg_logf(D_NOTICE,
                  "got %lu, for user=%s, not rising PSTATUS_AUTH_BADLOGIN",
                  (unsigned long)result, user);
            psys_sleep_milliseconds(1000);
            continue;
          } else {
            pstatus_set(PSTATUS_TYPE_AUTH, PSTATUS_AUTH_BADLOGIN);
            free(psync_my_pass);
            psync_my_pass = NULL;
          }
        } else {
          pstatus_set(PSTATUS_TYPE_AUTH, PSTATUS_AUTH_BADTOKEN);
          psync_set_apiserver(PSYNC_API_HOST, PSYNC_LOCATIONID_DEFAULT);
        }
        pstatus_wait(PSTATUS_TYPE_AUTH, PSTATUS_AUTH_PROVIDED);
      } else if (result == 4000)
        psys_sleep_milliseconds(5 * 60 * 1000);
      else if (result == 2205 || result == 2229) {
        psync_set_apiserver(PSYNC_API_HOST, PSYNC_LOCATIONID_DEFAULT);
        pstatus_set(PSTATUS_TYPE_AUTH, PSTATUS_AUTH_EXPIRED);
        pstatus_wait(PSTATUS_TYPE_AUTH, PSTATUS_AUTH_PROVIDED);
      } else if (result == 2237) {
        digest = 0;
        continue;
      } else
        psys_sleep_milliseconds(PSYNC_SLEEP_BEFORE_RECONNECT);
      continue;
    }

    psync_my_userid = userid = papi_find_result2(res, "userid", PARAM_NUM)->num;
    current_quota = papi_find_result2(res, "quota", PARAM_NUM)->num;
    cres = papi_check_result2(res, "freequota", PARAM_NUM);

    if (cres) {
      free_quota = cres->num;
    }

    luserid =
        psync_sql_cellint("SELECT value FROM setting WHERE id='userid'", 0);
    psync_is_business = papi_find_result2(res, "business", PARAM_BOOL)->num;
    lid = psync_setting_get_uint(_PS(location_id));
    psync_sql_start_transaction();
    psync_strlcpy(psync_my_auth, papi_find_result2(res, "auth", PARAM_STR)->str,
                  sizeof(psync_my_auth));

    if (luserid) {
      if (pdbg_unlikely(luserid != userid)) {
        if (check_user_relocated(luserid, sock)) {
          pdbg_logf(D_NOTICE, "setting PSTATUS_AUTH_RELOCATED");
          pstatus_set(PSTATUS_TYPE_AUTH, PSTATUS_AUTH_RELOCATED);
        } else {
          pdbg_logf(D_NOTICE, "user mistmatch, db userid=%lu, connected userid=%lu",
                (unsigned long)luserid, (unsigned long)userid);
          pstatus_set(PSTATUS_TYPE_AUTH, PSTATUS_AUTH_MISMATCH);
        }
        psync_sql_rollback_transaction();
        psock_close(sock);
        free(res);
        pstatus_wait(PSTATUS_TYPE_AUTH, PSTATUS_AUTH_PROVIDED);
        continue;
      }
      if (saveauth) {
        q = psync_sql_prep_statement(
            "REPLACE INTO setting (id, value) VALUES ('auth', ?)");
        psync_sql_bind_string(q, 1, psync_my_auth);
        psync_sql_run_free(q);
      }
    } else {
      used_quota = 0;
      q = psync_sql_prep_statement(
          "REPLACE INTO setting (id, value) VALUES (?, ?)");
      psync_sql_bind_string(q, 1, "userid");
      psync_sql_bind_uint(q, 2, userid);
      psync_sql_run(q);
      psync_sql_bind_string(q, 1, "last_logged_location_id");
      psync_sql_bind_uint(q, 2, lid);
      psync_sql_run(q);
      psync_sql_bind_string(q, 1, "quota");
      psync_sql_bind_uint(q, 2, current_quota);
      psync_sql_run(q);
      psync_sql_bind_string(q, 1, "freequota");
      psync_sql_bind_uint(q, 2, free_quota);
      psync_sql_run(q);
      psync_sql_bind_string(q, 1, "usedquota");
      psync_sql_bind_uint(q, 2, 0);
      psync_sql_run(q);
      result = papi_find_result2(res, "premium", PARAM_BOOL)->num;
      psync_sql_bind_string(q, 1, "premium");
      psync_sql_bind_uint(q, 2, result);
      psync_sql_run(q);
      if (result)
        result = papi_find_result2(res, "premiumexpires", PARAM_NUM)->num;
      else
        result = 0;
      psync_sql_bind_string(q, 1, "premiumexpires");
      psync_sql_bind_uint(q, 2, result);
      psync_sql_run(q);
      psync_sql_bind_string(q, 1, "emailverified");
      psync_sql_bind_uint(
          q, 2, papi_find_result2(res, "emailverified", PARAM_BOOL)->num);
      psync_sql_run(q);
      psync_sql_bind_string(q, 1, "registered");
      psync_sql_bind_uint(q, 2,
                          papi_find_result2(res, "registered", PARAM_NUM)->num);
      psync_sql_run(q);
      psync_sql_bind_string(q, 1, "username");
      psync_sql_bind_string(q, 2,
                            papi_find_result2(res, "email", PARAM_STR)->str);
      psync_sql_run(q);
      psync_sql_bind_string(q, 1, "language");
      psync_sql_bind_string(q, 2,
                            papi_find_result2(res, "language", PARAM_STR)->str);
      psync_sql_run(q);
      psync_sql_bind_string(q, 1, "plan");
      psync_sql_bind_uint(q, 2, papi_find_result2(res, "plan", PARAM_NUM)->num);
      psync_sql_run(q);
      psync_sql_bind_string(q, 1, "business");
      psync_sql_bind_uint(q, 2,
                          papi_find_result2(res, "business", PARAM_BOOL)->num);
      psync_sql_run(q);
      psync_sql_bind_string(q, 1, "premiumlifetime");
      psync_sql_bind_uint(
          q, 2, papi_find_result2(res, "premiumlifetime", PARAM_BOOL)->num);
      psync_sql_run(q);
      cres = papi_check_result2(res, "vivapcloud", PARAM_BOOL);
      if (cres) {
        psync_sql_bind_string(q, 1, "vivapcloud");
        psync_sql_bind_uint(q, 2, cres->num);
        psync_sql_run(q);
      }
      cres = papi_check_result2(res, "family", PARAM_HASH);
      if (cres) {
        psync_sql_bind_string(q, 1, "owner");
        psync_sql_bind_uint(q, 2,
                            papi_find_result2(cres, "owner", PARAM_BOOL)->num);
        psync_sql_run(q);
      }
      if (saveauth) {
        psync_sql_bind_string(q, 1, "auth");
        psync_sql_bind_string(q, 2, psync_my_auth);
        psync_sql_run(q);
      }
      psync_sql_free_result(q);
    }
    if (pstatus_get(PSTATUS_TYPE_AUTH) != PSTATUS_AUTH_PROVIDED) {
      psync_sql_rollback_transaction();
      psock_close(sock);
      free(res);
      pstatus_wait(PSTATUS_TYPE_AUTH, PSTATUS_AUTH_PROVIDED);
      continue;
    }
    pdbg_logf(D_NOTICE, "userid %lu", (unsigned long)userid);
    cres = papi_check_result2(res, "account", PARAM_HASH);
    q = psync_sql_prep_statement(
        "REPLACE INTO setting (id, value) VALUES (?, ?)");
    if (cres) {
      psync_sql_bind_string(q, 1, "business");
      psync_sql_bind_uint(q, 2, 1);
      psync_sql_run(q);
      psync_sql_bind_string(q, 1, "firstname");
      psync_sql_bind_string(
          q, 2, papi_find_result2(cres, "firstname", PARAM_STR)->str);
      psync_sql_run(q);
      psync_sql_bind_string(q, 1, "lastname");
      psync_sql_bind_string(
          q, 2, papi_find_result2(cres, "lastname", PARAM_STR)->str);
      psync_sql_run(q);
      isbusiness = 1;
    } else {
      psync_sql_bind_string(q, 1, "business");
      psync_sql_bind_uint(q, 2, 0);
      psync_sql_run(q);
      isbusiness = 0;
    }

    cres = papi_check_result2(res, "cryptov2isactive", PARAM_BOOL);
    if (cres)
      psync_set_bool_setting("cryptov2isactive", cres->num);
    else
      psync_set_bool_setting("cryptov2isactive", 0);
    cryptosetup = papi_find_result2(res, "cryptosetup", PARAM_BOOL)->num;
    psync_sql_bind_string(q, 1, "cryptosetup");
    psync_sql_bind_uint(q, 2, cryptosetup);
    psync_sql_run(q);
    if (cryptosetup) {
      char *publicsha1 = psync_sql_cellstr(
          "SELECT value FROM setting WHERE id='crypto_public_sha1'");
      char *privatesha1 = psync_sql_cellstr(
          "SELECT value FROM setting WHERE id='crypto_private_sha1'");
      if (!publicsha1 || !privatesha1 ||
          strcmp(publicsha1,
                 papi_find_result2(res, "publicsha1", PARAM_STR)->str) ||
          strcmp(privatesha1,
                 papi_find_result2(res, "privatesha1", PARAM_STR)->str))
        psync_delete_cached_crypto_keys();
      free(privatesha1);
      free(publicsha1);
    } else
      psync_delete_cached_crypto_keys();
    psync_sql_bind_string(q, 1, "cryptosubscription");
    psync_sql_bind_uint(
        q, 2, papi_find_result2(res, "cryptosubscription", PARAM_BOOL)->num);
    psync_sql_run(q);
    cres = papi_check_result2(res, "cryptoexpires", PARAM_NUM);
    psync_sql_bind_string(q, 1, "cryptoexpires");
    psync_sql_bind_uint(q, 2, cres ? cres->num : 0);
    psync_sql_run(q);
    int sub = check_active_subscribtion(res);
    psync_sql_bind_string(q, 1, "hasactivesubscription");
    psync_sql_bind_uint(q, 2, sub);
    psync_sql_run(q);
    psync_sql_free_result(q);
    psync_sql_commit_transaction();
    pthread_mutex_lock(&psync_my_auth_mutex);
    if (psync_my_pass) {
      memset(psync_my_pass, 'X', strlen(psync_my_pass));
      q = psync_sql_prep_statement(
          "UPDATE setting SET value=? WHERE id='pass'");
      psync_sql_bind_string(q, 1, psync_my_pass);
      psync_sql_run_free(q);
      free(psync_my_pass);
      psync_my_pass = NULL;
    }
    pthread_mutex_unlock(&psync_my_auth_mutex);
    if (saveauth)
      psync_sql_statement("DELETE FROM setting WHERE id='pass'");
    else
      psync_sql_statement("DELETE FROM setting WHERE id IN ('pass', 'auth')");
    cres = papi_find_result2(papi_find_result2(res, "apiserver", PARAM_HASH),
                             "binapi", PARAM_ARRAY);
    if (cres->length)
      psync_apipool_set_server(cres->array[0]->str);
    free(res);

    // If the flag is up, send a first login event to track the number of
    // sucessful installs.
    if (isFirstLogin) {
      pdbg_logf(D_NOTICE,
            "This is a first login. Send the FIRST_LOGIN event. Token:[%s], "
            "User id: [%lu]",
            psync_my_auth, (unsigned long)userid);
      time_t rawtime;
      time(&rawtime);

      char *macAddr;
      macAddr = ptools_get_mac_addr();

      eventParams params = {1, // Number of parameters we are passing below.
                            {PAPI_STR(EPARAM_MAC, macAddr)}};
      ptools_create_backend_event(apiserver, INST_EVENT_CATEG, INST_EVENT_FLOGIN,
                           INST_EVENT_CATEG, psync_my_auth, P_OS_ID, rawtime,
                           &params, (char **)res);
    } else {
      pdbg_logf(D_NOTICE, "Not a first login. Run sync event.");

      ptools_send_psyncs_event(apiserver, psync_my_auth);
    }

    if (isbusiness) {
      binparam params[] = {PAPI_STR("timeformat", "timestamp"),
                           PAPI_STR("auth", psync_my_auth)};
      res = papi_send2(sock, "account_info", params);
      if (pdbg_unlikely(!res)) {
        psock_close(sock);
        continue;
      }
      result = papi_find_result2(res, "result", PARAM_NUM)->num;
      if (likely(result == 0)) {
        cres = papi_check_result2(res, "account", PARAM_HASH);
        q = psync_sql_prep_statement(
            "REPLACE INTO setting (id, value) VALUES (?, ?)");
        psync_sql_bind_string(q, 1, "company");
        psync_sql_bind_string(
            q, 2, papi_find_result2(cres, "company", PARAM_STR)->str);
        psync_sql_run_free(q);
        cres = papi_check_result2(cres, "owner", PARAM_HASH);
        psync_set_bool_setting(
            "owner_cryptosetup",
            papi_find_result2(cres, "cryptosetup", PARAM_BOOL)->num);
      } else
        pdbg_logf(D_WARNING,
              "account_info returned %lu, continuing without business info",
              (unsigned long)result);
      free(res);
      psync_sql_sync();
    }

    free(chrUserid);
    free(auth);
    free(user);
    free(pass);
    free(psync_my_2fa_token);
    psync_my_2fa_token = NULL;
    psync_my_2fa_code_type = 0;
    psync_my_2fa_code[0] = 0;
    free(deviceid);
    free(devicestring);
    psync_sql_sync();
    return sock;
  }
}

static uint64_t extract_meta_folder_flags(const binresult *meta) {
  const binresult *res;
  uint64_t flags = 0;
  if ((res = papi_check_result2(meta, "encrypted", PARAM_BOOL)) && res->num)
    flags |= PSYNC_FOLDER_FLAG_ENCRYPTED;
  if ((res = papi_check_result2(meta, "ispublicroot", PARAM_BOOL)) && res->num)
    flags |= PSYNC_FOLDER_FLAG_PUBLIC_ROOT;
  if ((res = papi_check_result2(meta, "isbackupdevicelist", PARAM_BOOL)) &&
      res->num)
    flags |= PSYNC_FOLDER_FLAG_BACKUP_DEVICE_LIST;
  if ((res = papi_check_result2(meta, "isbackupdevice", PARAM_BOOL)) &&
      res->num)
    flags |= PSYNC_FOLDER_FLAG_BACKUP_DEVICE;
  if ((res = papi_check_result2(meta, "isbackuproot", PARAM_BOOL)) && res->num)
    flags |= PSYNC_FOLDER_FLAG_BACKUP_ROOT;
  if ((res = papi_check_result2(meta, "isbackup", PARAM_BOOL)) && res->num)
    flags |= PSYNC_FOLDER_FLAG_BACKUP;

  return flags;
}

static void process_createfolder(const binresult *entry) {
  static psync_sql_res *st = NULL, *st2 = NULL;
  psync_sql_res *res, *stmt, *stmt2;
  const binresult *meta, *name;
  uint64_t userid, perms, mtime, flags;
  psync_uint_row row;
  psync_folderid_t parentfolderid, folderid, localfolderid;
  //  char *localname;
  psync_syncid_t syncid;
  if (!entry) {
    if (st) {
      psync_sql_free_result(st);
      st = NULL;
    }
    if (st2) {
      psync_sql_free_result(st2);
      st2 = NULL;
    }
    return;
  }
  if (!st) {
    st = psync_sql_prep_statement(
        "INSERT OR IGNORE INTO folder (id, parentfolderid, userid, "
        "permissions, name, ctime, mtime, flags, subdircnt) VALUES (?, ?, ?, "
        "?, ?, ?, ?, ?, 0)");
    if (!st)
      return;
    st2 = psync_sql_prep_statement(
        "UPDATE folder SET subdircnt=subdircnt+1, mtime=? WHERE id=?");
    if (!st2)
      return;
  }
  meta = papi_find_result2(entry, "metadata", PARAM_HASH);
  flags = extract_meta_folder_flags(meta);
  if (papi_find_result2(meta, "ismine", PARAM_BOOL)->num) {
    userid = psync_my_userid;
    perms = PSYNC_PERM_ALL;
  } else {
    userid = papi_find_result2(meta, "userid", PARAM_NUM)->num;
    perms = pfileops_get_perms(meta);
  }
  name = papi_find_result2(meta, "name", PARAM_STR);
  folderid = papi_find_result2(meta, "folderid", PARAM_NUM)->num;
  parentfolderid = papi_find_result2(meta, "parentfolderid", PARAM_NUM)->num;
  mtime = papi_find_result2(meta, "modified", PARAM_NUM)->num;
  psync_sql_bind_uint(st, 1, folderid);
  psync_sql_bind_uint(st, 2, parentfolderid);
  psync_sql_bind_uint(st, 3, userid);
  psync_sql_bind_uint(st, 4, perms);
  psync_sql_bind_lstring(st, 5, name->str, name->length);
  psync_sql_bind_uint(st, 6,
                      papi_find_result2(meta, "created", PARAM_NUM)->num);
  psync_sql_bind_uint(st, 7, mtime);
  psync_sql_bind_uint(st, 8, flags);
  psync_sql_run(st);
  if (!psync_sql_affected_rows()) {
    res = psync_sql_prep_statement(
        "UPDATE folder SET parentfolderid=?, userid=?, permissions=?, name=?, "
        "ctime=?, mtime=?, flags=? WHERE id=?");
    psync_sql_bind_uint(res, 1, parentfolderid);
    psync_sql_bind_uint(res, 2, userid);
    psync_sql_bind_uint(res, 3, perms);
    psync_sql_bind_lstring(res, 4, name->str, name->length);
    psync_sql_bind_uint(res, 5,
                        papi_find_result2(meta, "created", PARAM_NUM)->num);
    psync_sql_bind_uint(res, 6, mtime);
    psync_sql_bind_uint(res, 7, flags);
    psync_sql_bind_uint(res, 8, folderid);
    psync_sql_run_free(res);
  }
  psync_sql_bind_uint(st2, 1, mtime);
  psync_sql_bind_uint(st2, 2, parentfolderid);
  psync_sql_run(st2);
  if (psyncer_dl_has_folder(parentfolderid) &&
      !psync_is_name_to_ignore(name->str)) {
    psyncer_dl_queue_add(folderid);
    res = psync_sql_query(
        "SELECT syncid, localfolderid, synctype FROM syncedfolder WHERE "
        "folderid=? AND " PSYNC_SQL_DOWNLOAD);
    psync_sql_bind_uint(res, 1, parentfolderid);
    stmt = psync_sql_prep_statement(
        "INSERT OR IGNORE INTO syncedfolder (syncid, folderid, localfolderid, "
        "synctype) VALUES (?, ?, ?, ?)");
    while ((row = psync_sql_fetch_rowint(res))) {
      syncid = row[0];
      pdbg_logf(D_NOTICE,
            "creating local folder %lu/%s for folderid %lu, parentfolderid %lu",
            (unsigned long)row[1], name->str, (unsigned long)folderid,
            (unsigned long)parentfolderid);
      localfolderid =
          psyncer_db_folder_create(syncid, folderid, row[1], name->str);
      psync_sql_bind_uint(stmt, 1, syncid);
      psync_sql_bind_uint(stmt, 2, folderid);
      psync_sql_bind_uint(stmt, 3, localfolderid);
      psync_sql_bind_uint(stmt, 4, row[2]);
      psync_sql_run(stmt);
      if (psync_sql_affected_rows() == 1) {
        ptask_ldir_mk(syncid, folderid, localfolderid);
        needdownload = 1;
      } else {
        stmt2 = psync_sql_prep_statement("UPDATE syncedfolder SET folderid=? "
                                         "WHERE syncid=? AND localfolderid=?");
        psync_sql_bind_uint(stmt2, 1, folderid);
        psync_sql_bind_uint(stmt2, 2, syncid);
        psync_sql_bind_uint(stmt2, 3, localfolderid);
        psync_sql_run_free(stmt2);
      }
    }
    psync_sql_free_result(stmt);
    psync_sql_free_result(res);
  }
}

static void group_results_by_col(psync_full_result_int *restrict r1,
                                 psync_full_result_int *restrict r2,
                                 uint32_t col) {
  VAR_ARRAY(buff, uint64_t, r1->cols);
  size_t rowsize;
  uint32_t i, j, l;
  l = 0;
  rowsize = sizeof(r1->data[0]) * r1->cols;
  pdbg_assert(r1->cols == r2->cols);
  for (i = 0; i < r1->rows; i++)
    for (j = 0; j < r2->rows; j++)
      if (psync_get_result_cell(r1, i, col) ==
          psync_get_result_cell(r2, j, col)) {
        if (i != l) {
          memcpy(buff, r1->data + i * r1->cols, rowsize);
          memcpy(r1->data + i * r1->cols, r1->data + l * r1->cols, rowsize);
          memcpy(r1->data + l * r1->cols, buff, rowsize);
        }
        if (j != l) {
          memcpy(buff, r2->data + j * r2->cols, rowsize);
          memcpy(r2->data + j * r2->cols, r2->data + l * r2->cols, rowsize);
          memcpy(r2->data + l * r2->cols, buff, rowsize);
        }
        l++;
      }
}

static void del_synced_folder_rec(psync_folderid_t folderid,
                                  psync_syncid_t syncid) {
  psync_sql_res *res;
  psync_uint_row row;
  res = psync_sql_prep_statement(
      "DELETE FROM syncedfolder WHERE folderid=? AND syncid=?");
  psync_sql_bind_uint(res, 1, folderid);
  psync_sql_bind_uint(res, 2, syncid);
  psync_sql_run_free(res);
  res = psync_sql_query("SELECT id FROM folder WHERE parentfolderid=?");
  psync_sql_bind_uint(res, 1, folderid);
  while ((row = psync_sql_fetch_rowint(res)))
    del_synced_folder_rec(row[0], syncid);
  psync_sql_free_result(res);
}

static void process_modifyfolder(const binresult *entry) {
  static psync_sql_res *st = NULL;
  psync_sql_res *res;
  psync_full_result_int *fres1, *fres2;
  const binresult *meta, *name;
  uint64_t userid, perms, mtime, flags, oldflags;
  psync_variant_row vrow;
  psync_uint_row row;
  psync_folderid_t parentfolderid, folderid, oldparentfolderid, localfolderid;
  char *oldname;
  psync_syncid_t syncid;
  uint32_t i, cnt;
  int oldsync, newsync;
  if (!entry) {
    process_createfolder(NULL);
    if (st) {
      psync_sql_free_result(st);
      st = NULL;
    }
    return;
  }
  if (!st) {
    st = psync_sql_prep_statement(
        "UPDATE folder SET parentfolderid=?, userid=?, permissions=?, name=?, "
        "ctime=?, mtime=?, flags=? WHERE id=?");
    if (!st)
      return;
  }
  meta = papi_find_result2(entry, "metadata", PARAM_HASH);
  flags = extract_meta_folder_flags(meta);
  if (papi_find_result2(meta, "ismine", PARAM_BOOL)->num) {
    userid = psync_my_userid;
    perms = PSYNC_PERM_ALL;
  } else {
    userid = papi_find_result2(meta, "userid", PARAM_NUM)->num;
    perms = pfileops_get_perms(meta);
  }
  name = papi_find_result2(meta, "name", PARAM_STR);
  folderid = papi_find_result2(meta, "folderid", PARAM_NUM)->num;
  parentfolderid = papi_find_result2(meta, "parentfolderid", PARAM_NUM)->num;
  res = psync_sql_query(
      "SELECT parentfolderid, name, flags FROM folder WHERE id=?");
  psync_sql_bind_uint(res, 1, folderid);
  vrow = psync_sql_fetch_row(res);
  if (likely(vrow)) {
    oldparentfolderid = psync_get_number(vrow[0]);
    oldname = psync_dup_string(vrow[1]);
    oldflags = psync_get_number(vrow[2]);
  } else {
    pdbg_logf(D_ERROR,
          "got modify for non-existing folder %lu (%s), processing as create",
          (unsigned long)folderid, name->str);
    psync_sql_free_result(res);
    process_createfolder(entry);
    return;
  }
  psync_sql_free_result(res);

  if ((oldflags & PSYNC_FOLDER_FLAG_BACKUP_ROOT) != 0 &&
      (flags & PSYNC_FOLDER_FLAG_BACKUP_ROOT) == 0) {
    pdbg_logf(D_NOTICE, "Stop backup root");
    psync_delete_sync_by_folderid(folderid);
    // prun_thread1("psync_async_backup_delete",
    // psync_delete_sync_by_folderid, folderid);
  }

  if ((oldflags & PSYNC_FOLDER_FLAG_BACKUP_DEVICE) != 0 &&
      (flags & PSYNC_FOLDER_FLAG_BACKUP_DEVICE) == 0) {
    pdbg_logf(D_NOTICE, "Stop backup device");
    psync_delete_backup_device(folderid);
  }

  mtime = papi_find_result2(meta, "modified", PARAM_NUM)->num;
  psync_sql_bind_uint(st, 1, parentfolderid);
  psync_sql_bind_uint(st, 2, userid);
  psync_sql_bind_uint(st, 3, perms);
  psync_sql_bind_lstring(st, 4, name->str, name->length);
  psync_sql_bind_uint(st, 5,
                      papi_find_result2(meta, "created", PARAM_NUM)->num);
  psync_sql_bind_uint(st, 6, mtime);
  psync_sql_bind_uint(st, 7, flags);
  psync_sql_bind_uint(st, 8, folderid);
  psync_sql_run(st);

  if (oldparentfolderid != parentfolderid) {
    res = psync_sql_prep_statement(
        "UPDATE folder SET subdircnt=subdircnt-1, mtime=? WHERE id=?");
    psync_sql_bind_uint(res, 1, mtime);
    psync_sql_bind_uint(res, 2, oldparentfolderid);
    psync_sql_run_free(res);
    res = psync_sql_prep_statement(
        "UPDATE folder SET subdircnt=subdircnt+1, mtime=? WHERE id=?");
    psync_sql_bind_uint(res, 1, mtime);
    psync_sql_bind_uint(res, 2, parentfolderid);
    psync_sql_run_free(res);
    ppathstatus_fldr_moved(folderid, oldparentfolderid, parentfolderid);
  }
  /* We should check if oldparentfolderid is in downloadlist, not folderid. If
   * parentfolderid is not in and folderid is in, it means that folder that is a
   * "root" of a syncid is modified, we do not care about that.
   */
  oldsync = psyncer_dl_has_folder(oldparentfolderid);
  if (oldparentfolderid == parentfolderid)
    newsync = oldsync;
  else {
    newsync = psyncer_dl_has_folder(parentfolderid);
    psync_diff_refresh_fs_add_folder(oldparentfolderid);
  }
  if ((oldsync || newsync) &&
      (oldparentfolderid != parentfolderid || strcmp(name->str, oldname))) {
    if (!oldsync)
      psyncer_dl_queue_add(folderid);
    else if (!newsync) {
      res = psync_sql_query(
          "SELECT id FROM syncfolder WHERE folderid=? AND " PSYNC_SQL_DOWNLOAD);
      psync_sql_bind_uint(res, 1, folderid);
      if (!psync_sql_fetch_rowint(res))
        psyncer_dl_queue_del(folderid);
      psync_sql_free_result(res);
    }
    res = psync_sql_query(
        "SELECT syncid, localfolderid, synctype FROM syncedfolder WHERE "
        "folderid=? AND " PSYNC_SQL_DOWNLOAD);
    psync_sql_bind_uint(res, 1, oldparentfolderid);
    fres1 = psync_sql_fetchall_int(res);
    res = psync_sql_query(
        "SELECT syncid, localfolderid, synctype FROM syncedfolder WHERE "
        "folderid=? AND " PSYNC_SQL_DOWNLOAD);
    psync_sql_bind_uint(res, 1, parentfolderid);
    fres2 = psync_sql_fetchall_int(res);
    if (psync_is_name_to_ignore(name->str))
      fres2->rows = 0;
    group_results_by_col(fres1, fres2, 0);
    cnt = fres2->rows > fres1->rows ? fres1->rows : fres2->rows;
    for (i = 0; i < cnt; i++) {
      res = psync_sql_query("SELECT localfolderid FROM syncedfolder WHERE "
                            "folderid=? AND syncid=?");
      psync_sql_bind_uint(res, 1, folderid);
      psync_sql_bind_uint(res, 2, psync_get_result_cell(fres1, i, 0));
      row = psync_sql_fetch_rowint(res);
      if (unlikely(!row)) {
        pdbg_logf(D_ERROR, "could not find local folder of folderid %lu",
              (unsigned long)folderid);
        psync_sql_free_result(res);
        continue;
      }
      localfolderid = row[0];
      psync_sql_free_result(res);
      ptask_ldir_rename(
          psync_get_result_cell(fres2, i, 0), folderid, localfolderid,
          psync_get_result_cell(fres2, i, 1), name->str);
      needdownload = 1;
      if (psync_get_result_cell(fres2, i, 0) !=
          psync_get_result_cell(fres1, i, 0)) {
        res = psync_sql_prep_statement(
            "UPDATE syncedfolder SET syncid=?, synctype=? WHERE syncid=? AND "
            "folderid=?");
        psync_sql_bind_uint(res, 1, psync_get_result_cell(fres2, i, 0));
        psync_sql_bind_uint(res, 2, psync_get_result_cell(fres2, i, 2));
        psync_sql_bind_uint(res, 3, psync_get_result_cell(fres1, i, 0));
        psync_sql_bind_uint(res, 4, folderid);
        psync_sql_run_free(res);
      }
    }
    for (/*i is already=cnt*/; i < fres1->rows; i++) {
      syncid = psync_get_result_cell(fres1, i, 0);
      res = psync_sql_query("SELECT localfolderid FROM syncedfolder WHERE "
                            "folderid=? AND syncid=?");
      psync_sql_bind_uint(res, 1, folderid);
      psync_sql_bind_uint(res, 2, syncid);
      row = psync_sql_fetch_rowint(res);
      if (unlikely(!row)) {
        pdbg_logf(D_ERROR, "could not find local folder of folderid %lu",
              (unsigned long)folderid);
        psync_sql_free_result(res);
        continue;
      }
      localfolderid = row[0];
      psync_sql_free_result(res);
      del_synced_folder_rec(folderid, syncid);
      ptask_ldir_rm_r(syncid, folderid, localfolderid);
      needdownload = 1;
    }
    for (/*i is already=cnt*/; i < fres2->rows; i++) {
      syncid = psync_get_result_cell(fres2, i, 0);
      pdbg_logf(D_NOTICE,
            "creating local folder %lu/%s for folderid %lu, parentfolderid %lu",
            (unsigned long)psync_get_result_cell(fres2, i, 1), name->str,
            (unsigned long)folderid, (unsigned long)parentfolderid);
      localfolderid = psyncer_db_folder_create(
          syncid, folderid, psync_get_result_cell(fres2, i, 1), name->str);
      ptask_ldir_mk(syncid, folderid, localfolderid);
      psyncer_dl_folder_add(
          syncid, psync_get_result_cell(fres2, i, 2), folderid, localfolderid);
      needdownload = 1;
    }
    free(fres1);
    free(fres2);
  }
  free(oldname);
}

static void process_deletefolder(const binresult *entry) {
  static psync_sql_res *st = NULL, *st2 = NULL;
  const binresult *meta;
  psync_sql_res *res, *stmt;
  char *path;
  psync_folderid_t folderid;
  psync_uint_row row;
  if (!entry) {
    if (st) {
      psync_sql_free_result(st);
      st = NULL;
    }
    if (st2) {
      psync_sql_free_result(st2);
      st2 = NULL;
    }
    return;
  }
  if (!st) {
    st = psync_sql_prep_statement("DELETE FROM folder WHERE id=?");
    if (!st)
      return;
    st2 = psync_sql_prep_statement(
        "UPDATE folder SET subdircnt=subdircnt-1, mtime=? WHERE id=?");
    if (!st2)
      return;
  }
  meta = papi_find_result2(entry, "metadata", PARAM_HASH);
  folderid = papi_find_result2(meta, "folderid", PARAM_NUM)->num;
  ppathstatus_fldr_deleted(folderid);
  if (psyncer_dl_has_folder(folderid)) {
    psyncer_dl_queue_del(folderid);
    res = psync_sql_query(
        "SELECT syncid, localfolderid FROM syncedfolder WHERE folderid=?");
    psync_sql_bind_uint(res, 1, folderid);
    while ((row = psync_sql_fetch_rowint(res))) {
      stmt = psync_sql_prep_statement(
          "DELETE FROM syncedfolder WHERE syncid=? AND folderid=?");
      psync_sql_bind_uint(stmt, 1, row[0]);
      psync_sql_bind_uint(stmt, 2, folderid);
      psync_sql_run_free(stmt);
      if (psync_sql_affected_rows() == 1) {
        path = pfolder_path(folderid, NULL);
        ptask_ldir_rm(row[0], folderid, row[1], path);
        free(path);
        needdownload = 1;
      }
    }
    psync_sql_free_result(res);
  }
  psync_sql_bind_uint(st, 1, folderid);
  psync_sql_run(st);
  if (psync_sql_affected_rows()) {
    psync_sql_bind_uint(st2, 1,
                        papi_find_result2(meta, "modified", PARAM_NUM)->num);
    psync_sql_bind_uint(
        st2, 2, papi_find_result2(meta, "parentfolderid", PARAM_NUM)->num);
    psync_sql_run(st2);
    psync_fs_folder_deleted(folderid);
  }
}

static void check_for_deletedfileid(const binresult *meta) {
  const binresult *delfileid;
  delfileid = papi_check_result2(meta, "deletedfileid", PARAM_NUM);
  if (likely(!delfileid))
    return;
  else {
    psync_sql_res *res;
    res = psync_sql_prep_statement("DELETE FROM file WHERE id=?");
    psync_sql_bind_uint(res, 1, delfileid->num);
    psync_sql_run_free(res);
    psync_fs_file_deleted(delfileid->num);
  }
}

static int bind_meta(psync_sql_res *res, const binresult *meta, int off) {
  const binresult *br;
  bind_num("created");
  bind_num("modified");
  bind_num("category");
  bind_bool("thumb");
  bind_str("icon");
  bind_opt_str("artist");
  bind_opt_str("album");
  bind_opt_str("title");
  bind_opt_str("genre");
  bind_opt_num("trackno");
  bind_opt_num("width");
  bind_opt_num("height");
  bind_opt_double("duration");
  bind_opt_double("fps");
  bind_opt_str("videocodec");
  bind_opt_str("audiocodec");
  bind_opt_num("videobitrate");
  bind_opt_num("audiobitrate");
  bind_opt_num("audiosamplerate");
  bind_opt_num("rotate");
  return off;
}

static void insert_revision(psync_fileid_t fileid, uint64_t hash,
                            uint64_t ctime, uint64_t size) {
  static psync_sql_res *st = NULL;
  if (!fileid) {
    if (st) {
      psync_sql_free_result(st);
      st = NULL;
    }
    return;
  }
  if (!st)
    st = psync_sql_prep_statement("REPLACE INTO filerevision (fileid, hash, "
                                  "ctime, size) VALUES (?, ?, ?, ?)");
  psync_sql_bind_uint(st, 1, fileid);
  psync_sql_bind_uint(st, 2, hash);
  psync_sql_bind_uint(st, 3, ctime);
  psync_sql_bind_uint(st, 4, size);
  psync_sql_run(st);
}

static void process_createfile(const binresult *entry) {
  static psync_sql_res *st = NULL;
  const binresult *meta, *name;
  psync_sql_res *res, *res2;
  psync_folderid_t parentfolderid;
  psync_fileid_t fileid;
  uint64_t size, userid, hash;
  psync_uint_row row;
  psync_str_row row2;
  int hasit;
  if (!entry) {
    if (st) {
      psync_sql_free_result(st);
      st = NULL;
    }
    insert_revision(0, 0, 0, 0);
    return;
  }
  if (!st)
    st = psync_sql_prep_statement(
        "INSERT OR IGNORE INTO file (id, parentfolderid, userid, size, hash, "
        "name, ctime, mtime, category, thumb, icon, "
        "artist, album, title, genre, trackno, width, height, duration, fps, "
        "videocodec, audiocodec, videobitrate, "
        "audiobitrate, audiosamplerate, rotate) VALUES (?, ?, ?, ?, ?, ?, ?, "
        "?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
  meta = papi_find_result2(entry, "metadata", PARAM_HASH);
  size = papi_find_result2(meta, "size", PARAM_NUM)->num;
  fileid = papi_find_result2(meta, "fileid", PARAM_NUM)->num;
  parentfolderid = papi_find_result2(meta, "parentfolderid", PARAM_NUM)->num;
  if (papi_find_result2(meta, "ismine", PARAM_BOOL)->num) {
    userid = psync_my_userid;
    used_quota += size;
  } else
    userid = papi_find_result2(meta, "userid", PARAM_NUM)->num;
  hash = papi_find_result2(meta, "hash", PARAM_NUM)->num;
  name = papi_find_result2(meta, "name", PARAM_STR);
  check_for_deletedfileid(meta);
  psync_sql_bind_uint(st, 1, fileid);
  psync_sql_bind_uint(st, 2, parentfolderid);
  psync_sql_bind_uint(st, 3, userid);
  psync_sql_bind_uint(st, 4, size);
  psync_sql_bind_uint(st, 5, hash);
  psync_sql_bind_lstring(st, 6, name->str, name->length);
  bind_meta(st, meta, 7);
  psync_sql_run(st);
  if (!psync_sql_affected_rows()) {
    int off;
    res = psync_sql_prep_statement(
        "UPDATE file SET id=?, parentfolderid=?, userid=?, size=?, hash=?, "
        "name=?, ctime=?, mtime=?, category=?, thumb=?, icon=?, "
        "artist=?, album=?, title=?, genre=?, trackno=?, width=?, height=?, "
        "duration=?, fps=?, videocodec=?, audiocodec=?, videobitrate=?, "
        "audiobitrate=?, audiosamplerate=?, rotate=? WHERE id=?");
    psync_sql_bind_uint(res, 1, fileid);
    psync_sql_bind_uint(res, 2, parentfolderid);
    psync_sql_bind_uint(res, 3, userid);
    psync_sql_bind_uint(res, 4, size);
    psync_sql_bind_uint(res, 5, hash);
    psync_sql_bind_lstring(res, 6, name->str, name->length);
    off = bind_meta(res, meta, 7);
    psync_sql_bind_uint(res, off, fileid);
    psync_sql_run_free(res);
  }
  insert_revision(fileid, hash,
                  papi_find_result2(meta, "modified", PARAM_NUM)->num, size);
  if (psyncer_dl_has_folder(parentfolderid) &&
      !psync_is_name_to_ignore(name->str)) {
    res = psync_sql_query("SELECT syncid, localfolderid FROM syncedfolder "
                          "WHERE folderid=? AND " PSYNC_SQL_DOWNLOAD);
    psync_sql_bind_uint(res, 1, parentfolderid);
    while ((row = psync_sql_fetch_rowint(res))) {
      res2 = psync_sql_query("SELECT name FROM localfile WHERE syncid=? AND "
                             "localparentfolderid=? AND hash=? AND fileid=?");
      psync_sql_bind_uint(res2, 1, row[0]);
      psync_sql_bind_uint(res2, 2, row[1]);
      psync_sql_bind_uint(res2, 3, hash);
      psync_sql_bind_uint(res2, 4, fileid);
      row2 = psync_sql_fetch_rowstr(res2);
      hasit = row2 != NULL;

      psync_sql_free_result(res2);
      if (!hasit) {
        pdbg_logf(D_NOTICE, "downloading file %s with hash %ld to local folder %lu",
              name->str, (long)hash, (unsigned long)row[1]);
        ptask_download_q(row[0], fileid, row[1], name->str);
        needdownload = 1;
      } else
        pdbg_logf(D_NOTICE,
              "file %s with hash %ld already exists in local folder %lu",
              name->str, (long)hash, (unsigned long)row[1]);
    }
    psync_sql_free_result(res);
  }
}

static void process_modifyfile(const binresult *entry) {
  static psync_sql_res *sq = NULL, *st = NULL;
  psync_sql_res *res;
  psync_full_result_int *fres1, *fres2;
  const binresult *meta, *name, *enc;
  const char *oldname;
  size_t oldnamelen;
  psync_variant_row row;
  psync_fileid_t fileid;
  psync_folderid_t parentfolderid, oldparentfolderid;
  uint64_t size, userid, hash, oldsize;
  int oldsync, newsync, lneeddownload, needrename;
  uint32_t cnt, i;
  if (!entry) {
    if (sq) {
      psync_sql_free_result(sq);
      sq = NULL;
    }
    if (st) {
      psync_sql_free_result(st);
      st = NULL;
    }
    process_createfile(NULL);
    return;
  }
  meta = papi_find_result2(entry, "metadata", PARAM_HASH);
  fileid = papi_find_result2(meta, "fileid", PARAM_NUM)->num;
  name = papi_find_result2(meta, "name", PARAM_STR);
  if (sq)
    psync_sql_reset(sq);
  else
    sq = psync_sql_query(
        "SELECT parentfolderid, userid, size, hash, name FROM file WHERE id=?");
  psync_sql_bind_uint(sq, 1, fileid);
  row = psync_sql_fetch_row(sq);
  if (!row) {
    pdbg_logf(D_ERROR,
          "got modify for non-existing file %lu (%s), processing as create",
          (unsigned long)fileid, name->str);
    process_createfile(entry);
    return;
  }
  oldsize = psync_get_number(row[2]);
  if (psync_get_number(row[1]) == psync_my_userid)
    used_quota -= oldsize;
  if (!st)
    st = psync_sql_prep_statement(
        "UPDATE file SET id=?, parentfolderid=?, userid=?, size=?, hash=?, "
        "name=?, ctime=?, mtime=?, category=?, thumb=?, icon=?, "
        "artist=?, album=?, title=?, genre=?, trackno=?, width=?, height=?, "
        "duration=?, fps=?, videocodec=?, audiocodec=?, videobitrate=?, "
        "audiobitrate=?, audiosamplerate=?, rotate=? WHERE id=?");
  size = papi_find_result2(meta, "size", PARAM_NUM)->num;
  parentfolderid = papi_find_result2(meta, "parentfolderid", PARAM_NUM)->num;
  hash = papi_find_result2(meta, "hash", PARAM_NUM)->num;
  enc = papi_check_result2(meta, "encrypted", PARAM_BOOL);
  if (enc && enc->num) {
    res = psync_sql_prep_statement(
        "DELETE FROM cryptofilekey WHERE fileid=? AND hash!=?");
    psync_sql_bind_uint(res, 1, fileid);
    psync_sql_bind_uint(res, 2, hash);
    psync_sql_run_free(res);
  }
  if (papi_find_result2(meta, "ismine", PARAM_BOOL)->num) {
    userid = psync_my_userid;
    used_quota += size;
  } else
    userid = papi_find_result2(meta, "userid", PARAM_NUM)->num;
  check_for_deletedfileid(meta);
  psync_sql_bind_uint(st, 1, fileid);
  psync_sql_bind_uint(st, 2, parentfolderid);
  psync_sql_bind_uint(st, 3, userid);
  psync_sql_bind_uint(st, 4, size);
  psync_sql_bind_uint(st, 5, hash);
  psync_sql_bind_lstring(st, 6, name->str, name->length);
  i = bind_meta(st, meta, 7);
  psync_sql_bind_uint(st, i, fileid);
  psync_sql_run(st);
  insert_revision(fileid, hash,
                  papi_find_result2(meta, "modified", PARAM_NUM)->num, size);
  oldparentfolderid = psync_get_number(row[0]);
  oldsync = psyncer_dl_has_folder(oldparentfolderid);
  if (oldparentfolderid == parentfolderid)
    newsync = oldsync;
  else {
    newsync = psyncer_dl_has_folder(parentfolderid);
    psync_diff_refresh_fs_add_folder(oldparentfolderid);
  }
  if (oldsync || newsync) {
    if (psync_is_name_to_ignore(name->str)) {
      char *path;
      pdownload_tasks_delete(fileid, 0, 1);
      path = pfolder_file_path(fileid, NULL);
      ptask_lfile_rm(fileid, path);
      free(path);
      needdownload = 1;
      return;
    }
    lneeddownload = hash != psync_get_number(row[3]) || size != oldsize;
    oldname = psync_get_lstring(row[4], &oldnamelen);
    if (lneeddownload)
      pdownload_tasks_delete(fileid, 0, 0);
    needrename = oldparentfolderid != parentfolderid ||
                 name->length != oldnamelen ||
                 memcmp(name->str, oldname, oldnamelen);
    res = psync_sql_query(
        "SELECT syncid, localfolderid, synctype FROM syncedfolder WHERE "
        "folderid=? AND " PSYNC_SQL_DOWNLOAD);
    psync_sql_bind_uint(res, 1, oldparentfolderid);
    fres1 = psync_sql_fetchall_int(res);
    res = psync_sql_query(
        "SELECT syncid, localfolderid, synctype FROM syncedfolder WHERE "
        "folderid=? AND " PSYNC_SQL_DOWNLOAD);
    psync_sql_bind_uint(res, 1, parentfolderid);
    fres2 = psync_sql_fetchall_int(res);
    group_results_by_col(fres1, fres2, 0);
    cnt = fres2->rows > fres1->rows ? fres1->rows : fres2->rows;
    //    pdbg_logf(D_NOTICE, "cnt=%u fres1->rows=%u, fres2->rows=%u,
    //    oldparentfolderid=%lu, parentfolderid=%lu", cnt, fres1->rows,
    //    fres2->rows, oldparentfolderid, parentfolderid);
    for (i = 0; i < cnt; i++) {
      if (needrename) {
        ptask_lfile_rename(psync_get_result_cell(fres1, i, 0),
                                     psync_get_result_cell(fres2, i, 0), fileid,
                                     psync_get_result_cell(fres1, i, 1),
                                     psync_get_result_cell(fres2, i, 1),
                                     name->str);
        needdownload = 1;
      }
      if (lneeddownload) {
        res = psync_sql_query(
            "SELECT 1 FROM localfile WHERE localparentfolderid=? AND fileid=? "
            "AND hash=? AND syncid=?");
        psync_sql_bind_uint(res, 1, psync_get_result_cell(fres2, i, 1));
        psync_sql_bind_uint(res, 2, fileid);
        psync_sql_bind_uint(res, 3, hash);
        psync_sql_bind_uint(res, 4, psync_get_result_cell(fres2, i, 0));
        row = psync_sql_fetch_row(res);
        psync_sql_free_result(res);
        if (row)
          pdbg_logf(D_NOTICE,
                "ignoring update for file %s, has correct hash in the database",
                name->str);
        else {
          ptask_download_q(
              psync_get_result_cell(fres2, i, 0), fileid,
              psync_get_result_cell(fres2, i, 1), name->str);
          needdownload = 1;
        }
      }
    }
    for (/*i is already=cnt*/; i < fres2->rows; i++) {
      ptask_download_q(
          psync_get_result_cell(fres2, i, 0), fileid,
          psync_get_result_cell(fres2, i, 1), name->str);
      needdownload = 1;
    }
    for (/*i is already=cnt*/; i < fres1->rows; i++) {
      char *path = pfolder_file_path(fileid, NULL);
      ptask_lfile_rm_id(psync_get_result_cell(fres1, i, 0),
                                          fileid, path);
      pdownload_tasks_delete(
          fileid, psync_get_result_cell(fres1, i, 0), 1);
      free(path);
      needdownload = 1;
    }
    free(fres1);
    free(fres2);
  }
}

static void process_deletefile(const binresult *entry) {
  static psync_sql_res *st = NULL;
  const binresult *meta;
  char *path;
  psync_fileid_t fileid;
  if (!entry) {
    if (st) {
      psync_sql_free_result(st);
      st = NULL;
    }
    return;
  }
  if (!st) {
    st = psync_sql_prep_statement("DELETE FROM file WHERE id=?");
    if (!st)
      return;
  }
  meta = papi_find_result2(entry, "metadata", PARAM_HASH);
  fileid = papi_find_result2(meta, "fileid", PARAM_NUM)->num;
  if (psyncer_dl_has_folder(
          papi_find_result2(meta, "parentfolderid", PARAM_NUM)->num)) {
    pdownload_tasks_delete(fileid, 0, 1);
    path = pfolder_file_path(fileid, NULL);
    if (likely(path)) {
      ptask_lfile_rm(fileid, path);
      free(path);
      needdownload = 1;
    }
  }
  psync_sql_bind_uint(st, 1, fileid);
  psync_sql_run(st);
  if (psync_sql_affected_rows()) {
    if (papi_find_result2(meta, "ismine", PARAM_BOOL)->num)
      used_quota -= papi_find_result2(meta, "size", PARAM_NUM)->num;
    psync_fs_file_deleted(fileid);
  }
}

static void start_download() {
  if (needdownload) {
    pdownload_wake();
    pstatus_download_recalc();
    pstatus_send_status_update();
    needdownload = 0;
  }
}

static void stop_crypto_thread() {
  pcryptofolder_lock();
  psync_delete_cached_crypto_keys();
}

static void process_modifyuserinfo(const binresult *entry) {
  const binresult *res, *cres;
  psync_sql_res *q;
  uint64_t u, crexp, crsub = 0;
  int crst = 0, crstat;

  if (!entry)
    return;
  res = papi_find_result2(entry, "userinfo", PARAM_HASH);
  q = psync_sql_prep_statement(
      "REPLACE INTO setting (id, value) VALUES (?, ?)");

  cres = papi_check_result2(res, "userid", PARAM_NUM);
  if (cres) {
    psync_sql_bind_string(q, 1, "userid");
    psync_sql_bind_uint(q, 2, cres->num);
    psync_sql_run(q);
  }

  psync_sql_bind_string(q, 1, "quota");
  current_quota = papi_find_result2(res, "quota", PARAM_NUM)->num;
  psync_sql_bind_uint(q, 2, current_quota);
  psync_sql_run(q);
  cres = papi_check_result2(res, "freequota", PARAM_NUM);
  if (cres) {
    free_quota = cres->num;
  }
  psync_sql_bind_string(q, 1, "freequota");
  psync_sql_bind_uint(q, 2, free_quota);
  psync_sql_run(q);
  u = papi_find_result2(res, "premium", PARAM_BOOL)->num;
  psync_sql_bind_string(q, 1, "premium");
  psync_sql_bind_uint(q, 2, u);
  psync_sql_run(q);
  if (u)
    u = papi_find_result2(res, "premiumexpires", PARAM_NUM)->num;
  else
    u = 0;
  psync_sql_bind_string(q, 1, "premiumexpires");
  psync_sql_bind_uint(q, 2, u);
  psync_sql_run(q);
  psync_sql_bind_string(q, 1, "emailverified");
  psync_sql_bind_uint(q, 2,
                      papi_find_result2(res, "emailverified", PARAM_BOOL)->num);
  psync_sql_run(q);
  psync_sql_bind_string(q, 1, "username");
  psync_sql_bind_string(q, 2, papi_find_result2(res, "email", PARAM_STR)->str);
  psync_sql_run(q);
  psync_sql_bind_string(q, 1, "language");
  psync_sql_bind_string(q, 2,
                        papi_find_result2(res, "language", PARAM_STR)->str);
  psync_sql_run(q);
  psync_sql_bind_string(q, 1, "plan");
  psync_sql_bind_uint(q, 2, papi_find_result2(res, "plan", PARAM_NUM)->num);
  psync_sql_run(q);
  psync_sql_bind_string(q, 1, "business");
  psync_sql_bind_uint(q, 2,
                      papi_find_result2(res, "business", PARAM_BOOL)->num);
  psync_sql_run(q);
  psync_sql_bind_string(q, 1, "premiumlifetime");
  psync_sql_bind_uint(
      q, 2, papi_find_result2(res, "premiumlifetime", PARAM_BOOL)->num);
  psync_sql_run(q);

  cres = papi_check_result2(res, "vivapcloud", PARAM_BOOL);
  if (cres) {
    psync_sql_bind_string(q, 1, "vivapcloud");
    psync_sql_bind_uint(q, 2, cres->num);
    psync_sql_run(q);
  }

  cres = papi_check_result2(res, "family", PARAM_HASH);
  if (cres) {
    psync_sql_bind_string(q, 1, "owner");
    psync_sql_bind_uint(q, 2,
                        papi_find_result2(cres, "owner", PARAM_BOOL)->num);
    psync_sql_run(q);
  }
  cres = papi_check_result2(res, "cryptov2isactive", PARAM_BOOL);
  psync_set_bool_setting("cryptov2isactive", cres ? cres->num : 0);
  u = papi_find_result2(res, "cryptosetup", PARAM_BOOL)->num;
  psync_sql_bind_string(q, 1, "cryptosetup");
  psync_sql_bind_uint(q, 2, u);
  psync_sql_run(q);
  if (!u)
    prun_thread("stop crypto moduserinfo", stop_crypto_thread);
  else
    crst = 1;
  psync_sql_bind_string(q, 1, "cryptosubscription");
  crsub = papi_find_result2(res, "cryptosubscription", PARAM_BOOL)->num;
  psync_sql_bind_uint(q, 2, crsub);
  psync_sql_run(q);
  cres = papi_check_result2(res, "cryptoexpires", PARAM_NUM);
  crexp = cres ? cres->num : 0;
  psync_sql_bind_string(q, 1, "cryptoexpires");
  psync_sql_bind_uint(q, 2, crexp);
  psync_sql_run(q);
  if (psync_is_business || crsub) {
    if (crst)
      crstat = 5;
    else
      crstat = 4;
  } else {
    if (!crst)
      crstat = 1;
    else {
      if (psys_time_seconds() > crexp)
        crstat = 3;
      else
        crstat = 2;
    }
  }
  psync_sql_bind_string(q, 1, "cryptostatus");
  psync_sql_bind_uint(q, 2, crstat);
  psync_sql_run(q);
  psync_sql_free_result(q);
  pqevent_queue_eventid(PEVENT_USERINFO_CHANGED);
}

static void send_share_notify(psync_eventtype_t eventid, const binresult *share,
                              int isba) {
  psync_share_event_t *e;
  char *str, *sharename;
  const char *message;
  char *email = "tralalal@tralala.com";
  const binresult *br;
  uint64_t ctime;
  size_t stringslen, sharenamelen, messagelen;
  size_t emaillen = 254;
  int freesharename;
  const binresult *permissions;
  uint64_t teamid = 0;
  uint64_t touserid = 0;
  uint64_t fromuserid = 0;

  if (initialdownload)
    return;
  stringslen = 0;
  ctime = 0;
  if (!(br = papi_check_result2(share, "frommail", PARAM_STR)) &&
      !(br = papi_check_result2(share, "tomail", PARAM_STR))) {
    if (!(br = papi_check_result2(share, "touserid", PARAM_NUM)) &&
        !(br = papi_check_result2(share, "fromuserid", PARAM_NUM)) &&
        !(br = papi_check_result2(share, "toteamid", PARAM_NUM))) {
      pdbg_logf(D_WARNING,
            "Neigher frommail or tomail nor buissines share found for "
            "eventtype %u",
            (unsigned)eventid);
      return;
    }
  }
  if (isba) {
    if ((br = papi_check_result2(share, "user", PARAM_BOOL)) && br->num)
      touserid = papi_find_result2(share, "touserid", PARAM_NUM)->num;

    if ((br = papi_check_result2(share, "team", PARAM_BOOL)) && br->num)
      teamid = papi_find_result2(share, "toteamid", PARAM_NUM)->num;

    if ((br = papi_check_result2(share, "fromuserid", PARAM_NUM)))
      fromuserid = br->num;

    stringslen += ++emaillen;
    stringslen += ++emaillen;
  } else {
    email = (char *)br->str;
    emaillen = br->length + 1;
    stringslen += 2 * (br->length + 1);
  }
  if ((br = papi_check_result2(share, "message", PARAM_STR))) {
    message = br->str;
    messagelen = br->length + 1;
    stringslen += br->length + 1;
  } else {
    message = NULL;
    messagelen = 0;
  }
  if ((br = papi_check_result2(share, "foldername", PARAM_STR)) ||
      (br = papi_check_result2(share, "sharename", PARAM_STR))) {
    sharename = (char *)br->str;
    sharenamelen = br->length + 1;
    stringslen += br->length + 1;
    freesharename = 0;
  } else {
    psync_sql_res *res;
    psync_variant_row row;
    const char *cstr;

    if ((br = papi_check_result2(share, "shareid", PARAM_NUM)))
      if (isba)
        res = psync_sql_query(
            "SELECT name, ctime FROM bsharedfolder WHERE id=? ");
      else
        res =
            psync_sql_query("SELECT name, ctime FROM sharedfolder WHERE id=? ");
    else if ((br = papi_check_result2(share, "sharerequestid", PARAM_NUM)))
      res = psync_sql_query("SELECT name, ctime FROM sharerequest WHERE id=? ");
    else {
      pdbg_logf(
          D_WARNING,
          "Neither sharename, shareid or sharerequestid found for eventtype %u",
          (unsigned)eventid);
      return;
    }
    psync_sql_bind_uint(res, 1, br->num);
    if ((row = psync_sql_fetch_row(res))) {
      cstr = psync_get_lstring(row[0], &sharenamelen);
      stringslen += ++sharenamelen;
      sharename = (char *)malloc(sharenamelen);
      memcpy(sharename, cstr, sharenamelen);
      freesharename = 1;
      ctime = psync_get_number(row[1]);
    } else
      sharename = NULL;
    psync_sql_free_result(res);
    if (!sharename) {
      pdbg_logf(D_WARNING,
            "Could not find sharedfolder or sharerequest in the database.");
      return;
    }
  }
  e = (psync_share_event_t *)malloc(sizeof(psync_share_event_t) +
                                          stringslen);
  str = (char *)(e + 1);
  memset(e, 0, sizeof(psync_share_event_t));
  e->folderid = papi_find_result2(share, "folderid", PARAM_NUM)->num;
  fill_str(e->sharename, sharename, sharenamelen);
  if (freesharename)
    free(sharename);

  fill_str(e->message, message, messagelen);
  if ((br = papi_check_result2(share, "userid", PARAM_NUM)))
    e->userid = br->num;
  if ((br = papi_check_result2(share, "shareid", PARAM_NUM)))
    e->shareid = br->num;
  if ((br = papi_check_result2(share, "sharerequestid", PARAM_NUM)))
    e->sharerequestid = br->num;
  if (isba) {
    if ((br = papi_check_result2(share, "shared", PARAM_NUM)))
      ctime = br->num;
  } else if ((br = papi_check_result2(share, "created", PARAM_NUM)))
    ctime = br->num;
  e->created = ctime;
  permissions = papi_check_result2(share, "permissions", PARAM_HASH);
  if (isba && permissions) {
    e->canread = papi_find_result2(permissions, "canread", PARAM_BOOL)->num;
    e->cancreate = papi_find_result2(permissions, "cancreate", PARAM_BOOL)->num;
    e->canmodify = papi_find_result2(permissions, "canmodify", PARAM_BOOL)->num;
    e->candelete = papi_find_result2(permissions, "candelete", PARAM_BOOL)->num;
    e->canmanage = papi_find_result2(permissions, "canmanage", PARAM_BOOL)->num;
  } else {
    const binresult *canread = papi_check_result2(share, "canread", PARAM_BOOL);
    if (canread) {
      e->canread = canread->num;
      e->cancreate = papi_find_result2(share, "cancreate", PARAM_BOOL)->num;
      e->canmodify = papi_find_result2(share, "canmodify", PARAM_BOOL)->num;
      e->candelete = papi_find_result2(share, "candelete", PARAM_BOOL)->num;
    } else {
      e->canread = 0;
      e->cancreate = 0;
      e->canmodify = 0;
      e->candelete = 0;
    }
  }
  if (isba) {
    notify_paramst *params = malloc(sizeof(notify_paramst));
    params->eventid = eventid;
    params->event_data = e;
    params->touserid = touserid;
    params->fromuserid = fromuserid;
    params->teamid = teamid;
    params->str = str;
    prun_thread1("Share notify", do_send_eventdata, params);
  } else {
    fill_str(e->toemail, email, emaillen);
    fill_str(e->fromemail, email, emaillen);
    pqevent_queue_event(eventid, e);
  }
}

static void do_send_eventdata(void *param) {
  notify_paramst *data = (notify_paramst *)param;
  char *email;
  size_t emaillen;
  char *str = data->str;

  get_ba_member_email(data->fromuserid, &email, &emaillen);
  fill_str(data->event_data->fromemail, email, emaillen);
  free(email);

  if (data->touserid)
    get_ba_member_email(data->touserid, &email, &emaillen);
  else
    get_ba_team_name(data->teamid, &email, &emaillen);
  fill_str(data->event_data->toemail, email, emaillen);
  free(email);

  if (email) {
    pdiff_lock();
    pqevent_queue_event(data->eventid, data->event_data);
    pdiff_unlock();
  }

  free(param);
}

static void process_requestsharein(const binresult *entry) {
  psync_sql_res *q;
  const binresult *share, *br;
  int isincomming = 1;
  uint64_t folderowneruserid = 0, owneruserid, folderid;

  if (!entry)
    return;
  share = papi_find_result2(entry, "share", PARAM_HASH);
  folderid = papi_find_result2(share, "folderid", PARAM_NUM)->num;
  psync_get_folder_ownerid(folderid, &folderowneruserid);
  psync_get_current_userid(&owneruserid);
  isincomming = (folderowneruserid == owneruserid) ? 0 : 1;

  send_share_notify(
      ((isincomming) ? PEVENT_SHARE_REQUESTIN : PEVENT_SHARE_REQUESTOUT), share,
      0);
  q = psync_sql_prep_statement(
      "REPLACE INTO sharerequest (id, folderid, ctime, etime, permissions, "
      "userid, mail, name, message, isincoming, isba) "
      "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
  psync_sql_bind_uint(
      q, 1, papi_find_result2(share, "sharerequestid", PARAM_NUM)->num);
  psync_sql_bind_uint(q, 2,
                      papi_find_result2(share, "folderid", PARAM_NUM)->num);
  psync_sql_bind_uint(q, 3,
                      papi_find_result2(share, "created", PARAM_NUM)->num);
  psync_sql_bind_uint(q, 4,
                      papi_find_result2(share, "expires", PARAM_NUM)->num);
  psync_sql_bind_uint(q, 5, pfileops_get_perms(share));
  psync_sql_bind_uint(q, 6,
                      papi_find_result2(share, "fromuserid", PARAM_NUM)->num);
  br = papi_find_result2(share, "frommail", PARAM_STR);
  psync_sql_bind_lstring(q, 7, br->str, br->length);
  if (!(br = papi_check_result2(share, "foldername", PARAM_STR)))
    br = papi_check_result2(share, "sharename", PARAM_STR);
  psync_sql_bind_lstring(q, 8, br->str, br->length);
  br = papi_check_result2(share, "message", PARAM_STR);
  if (br)
    psync_sql_bind_lstring(q, 9, br->str, br->length);
  else
    psync_sql_bind_null(q, 9);
  psync_sql_bind_uint(q, 10, isincomming);
  psync_sql_bind_uint(q, 11, !isincomming);
  psync_sql_run_free(q);
}

static void process_requestshareout(const binresult *entry) {
  psync_sql_res *q;
  const binresult *share, *br;
  int isincomming = 0;
  uint64_t folderowneruserid = 0, owneruserid, folderid;

  if (!entry)
    return;

  share = papi_find_result2(entry, "share", PARAM_HASH);
  folderid = papi_find_result2(share, "folderid", PARAM_NUM)->num;
  psync_get_folder_ownerid(folderid, &folderowneruserid);
  psync_get_current_userid(&owneruserid);
  isincomming = (folderowneruserid == owneruserid) ? 0 : 1;

  send_share_notify(
      ((isincomming) ? PEVENT_SHARE_REQUESTIN : PEVENT_SHARE_REQUESTOUT), share,
      0);
  q = psync_sql_prep_statement(
      "REPLACE INTO sharerequest (id, folderid, ctime, etime, permissions, "
      "userid, mail, name, message, isincoming, isba) "
      "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
  psync_sql_bind_uint(
      q, 1, papi_find_result2(share, "sharerequestid", PARAM_NUM)->num);
  psync_sql_bind_uint(q, 2, folderid);
  psync_sql_bind_uint(q, 3,
                      papi_find_result2(share, "created", PARAM_NUM)->num);
  psync_sql_bind_uint(q, 4,
                      papi_find_result2(share, "expires", PARAM_NUM)->num);
  psync_sql_bind_uint(q, 5, pfileops_get_perms(share));
  psync_sql_bind_uint(q, 6, folderowneruserid);
  br = papi_find_result2(share, "tomail", PARAM_STR);
  psync_sql_bind_lstring(q, 7, br->str, br->length);
  if (!(br = papi_check_result2(share, "foldername", PARAM_STR)))
    br = papi_check_result2(share, "sharename", PARAM_STR);
  psync_sql_bind_lstring(q, 8, br->str, br->length);
  br = papi_check_result2(share, "message", PARAM_STR);
  if (br)
    psync_sql_bind_lstring(q, 9, br->str, br->length);
  else
    psync_sql_bind_null(q, 9);
  psync_sql_bind_uint(q, 10, isincomming);
  psync_sql_bind_uint(q, 11, isincomming);
  psync_sql_run_free(q);
}

static void process_acceptedsharein(const binresult *entry) {
  psync_sql_res *q;
  const binresult *share, *br;
  if (!entry)
    return;
  share = papi_find_result2(entry, "share", PARAM_HASH);
  send_share_notify(PEVENT_SHARE_ACCEPTIN, share, 0);
  q = psync_sql_prep_statement("DELETE FROM sharerequest WHERE id=?");
  psync_sql_bind_uint(
      q, 1, papi_find_result2(share, "sharerequestid", PARAM_NUM)->num);
  psync_sql_run_free(q);
  q = psync_sql_prep_statement(
      "REPLACE INTO sharedfolder (id, isincoming, folderid, ctime, "
      "permissions, userid, mail, name) "
      "VALUES (?, 1, ?, ?, ?, ?, ?, ?)");
  pdbg_logf(D_WARNING, "INSERT NORMAL SHARE IN id: %lld",
        (long long)papi_find_result2(share, "shareid", PARAM_NUM)->num);
  psync_sql_bind_uint(q, 1,
                      papi_find_result2(share, "shareid", PARAM_NUM)->num);
  psync_sql_bind_uint(q, 2,
                      papi_find_result2(share, "folderid", PARAM_NUM)->num);
  psync_sql_bind_uint(q, 3,
                      papi_find_result2(share, "created", PARAM_NUM)->num);
  psync_sql_bind_uint(q, 4, pfileops_get_perms(share));
  psync_sql_bind_uint(q, 5,
                      papi_find_result2(share, "fromuserid", PARAM_NUM)->num);
  br = papi_find_result2(share, "frommail", PARAM_STR);
  psync_sql_bind_lstring(q, 6, br->str, br->length);
  if (!(br = papi_check_result2(share, "foldername", PARAM_STR)))
    br = papi_check_result2(share, "sharename", PARAM_STR);
  psync_sql_bind_lstring(q, 7, br->str, br->length);
  psync_sql_run_free(q);
}

static void process_establishbsharein(const binresult *entry) {
  psync_sql_res *q;
  const binresult *share, *br;

  if (!entry)
    return;
  share = papi_find_result2(entry, "share", PARAM_HASH);
  send_share_notify(PEVENT_SHARE_ACCEPTIN, share, 1);

  q = psync_sql_prep_statement(
      "REPLACE INTO bsharedfolder (id, isincoming, folderid, ctime, "
      "permissions, message, name, isuser, "
      "touserid, isteam, toteamid, fromuserid, folderownerid)"
      "VALUES (?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
  psync_sql_bind_int(q, 1, papi_find_result2(share, "shareid", PARAM_NUM)->num);
  psync_sql_bind_uint(q, 2,
                      papi_find_result2(share, "folderid", PARAM_NUM)->num);
  if ((br = papi_check_result2(share, "shared", PARAM_NUM)) ||
      (br = papi_check_result2(entry, "time", PARAM_NUM)))
    psync_sql_bind_uint(q, 3, br->num);
  else
    psync_sql_bind_uint(q, 3, 0);
  psync_sql_bind_uint(q, 4,
                      pfileops_get_perms(
                          papi_find_result2(share, "permissions", PARAM_HASH)));
  br = papi_check_result2(share, "message", PARAM_STR);
  if (br)
    psync_sql_bind_lstring(q, 5, br->str, br->length);
  else
    psync_sql_bind_null(q, 5);
  if (!(br = papi_check_result2(share, "foldername", PARAM_STR)))
    br = papi_check_result2(share, "sharename", PARAM_STR);
  psync_sql_bind_lstring(q, 6, br->str, br->length);
  br = papi_check_result2(share, "user", PARAM_BOOL);
  if (br)
    psync_sql_bind_int(q, 7, br->num);
  else
    psync_sql_bind_int(q, 7, 0);
  br = papi_check_result2(share, "touserid", PARAM_NUM);
  if (br)
    psync_sql_bind_int(q, 8, br->num);
  else
    psync_sql_bind_null(q, 8);
  br = papi_check_result2(share, "team", PARAM_BOOL);
  if (br)
    psync_sql_bind_int(q, 9, br->num);
  else
    psync_sql_bind_int(q, 9, 0);
  br = papi_check_result2(share, "toteamid", PARAM_NUM);
  if (br)
    psync_sql_bind_int(q, 10, br->num);
  else
    psync_sql_bind_null(q, 10);
  psync_sql_bind_int(q, 11,
                     papi_find_result2(share, "fromuserid", PARAM_NUM)->num);
  psync_sql_bind_int(q, 12,
                     papi_find_result2(share, "folderownerid", PARAM_NUM)->num);

  psync_sql_run_free(q);
}

static void process_acceptedshareout(const binresult *entry) {
  psync_sql_res *q;
  const binresult *share, *br;
  uint32_t aff = 0;
  int isincomming = 0;
  uint64_t folderowneruserid = 0, owneruserid, folderid;

  if (!entry)
    return;
  share = papi_find_result2(entry, "share", PARAM_HASH);
  q = psync_sql_prep_statement("DELETE FROM sharerequest WHERE id=?");
  psync_sql_bind_uint(
      q, 1, papi_find_result2(share, "sharerequestid", PARAM_NUM)->num);
  psync_sql_run(q);
  aff = psync_sql_affected_rows();
  psync_sql_free_result(q);
  if (aff) {

    folderid = papi_find_result2(share, "folderid", PARAM_NUM)->num;
    psync_get_folder_ownerid(folderid, &folderowneruserid);
    psync_get_current_userid(&owneruserid);
    isincomming = (folderowneruserid == owneruserid) ? 0 : 1;

    send_share_notify(
        ((isincomming) ? PEVENT_SHARE_REQUESTIN : PEVENT_SHARE_REQUESTOUT),
        share, 0);

    q = psync_sql_prep_statement(
        "REPLACE INTO sharedfolder (id, folderid, ctime, permissions, userid, "
        "mail, name, isincoming) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)");
    psync_sql_bind_uint(q, 1,
                        papi_find_result2(share, "shareid", PARAM_NUM)->num);
    psync_sql_bind_uint(q, 2,
                        papi_find_result2(share, "folderid", PARAM_NUM)->num);
    psync_sql_bind_uint(q, 3,
                        papi_find_result2(share, "created", PARAM_NUM)->num);
    psync_sql_bind_uint(q, 4, pfileops_get_perms(share));
    psync_sql_bind_uint(q, 5,
                        papi_find_result2(share, "touserid", PARAM_NUM)->num);
    br = papi_find_result2(share, "tomail", PARAM_STR);
    psync_sql_bind_lstring(q, 6, br->str, br->length);
    if (!(br = papi_check_result2(share, "foldername", PARAM_STR)))
      br = papi_check_result2(share, "sharename", PARAM_STR);
    psync_sql_bind_lstring(q, 7, br->str, br->length);
    psync_sql_bind_uint(q, 8, isincomming);
    psync_sql_run_free(q);
  }
}

static void process_establishbshareout(const binresult *entry) {
  psync_sql_res *q;
  const binresult *share, *br, *ownid, *fromuserid;
  char *email = 0;
  int isincomming = 0;
  uint64_t folderowneruserid, owneruserid;

  if (!entry)
    return;

  share = papi_find_result2(entry, "share", PARAM_HASH);
  ownid = papi_check_result2(share, "folderownerid", PARAM_NUM);
  if (ownid) {
    folderowneruserid = ownid->num;
    psync_get_current_userid(&owneruserid);
    fromuserid = papi_check_result2(share, "fromuserid", PARAM_NUM);
    if (fromuserid && fromuserid->num == owneruserid) {
      isincomming = 0;
    } else {
      isincomming = (folderowneruserid == owneruserid) ? 0 : 1;
    }
  }
  send_share_notify(
      ((isincomming) ? PEVENT_SHARE_REQUESTIN : PEVENT_SHARE_REQUESTOUT), share,
      1);

  q = psync_sql_prep_statement(
      "REPLACE INTO bsharedfolder (id, folderid, ctime, permissions, message, "
      "name, isuser, "
      "touserid, isteam, toteamid, fromuserid, folderownerid, isincoming)"
      "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
  psync_sql_bind_int(q, 1, papi_find_result2(share, "shareid", PARAM_NUM)->num);
  psync_sql_bind_uint(q, 2,
                      papi_find_result2(share, "folderid", PARAM_NUM)->num);
  if ((br = papi_check_result2(share, "shared", PARAM_NUM)) ||
      (br = papi_check_result2(entry, "time", PARAM_NUM)))
    psync_sql_bind_uint(q, 3, br->num);
  else
    psync_sql_bind_uint(q, 3, 0);
  psync_sql_bind_uint(q, 4,
                      pfileops_get_perms(
                          papi_find_result2(share, "permissions", PARAM_HASH)));
  br = papi_find_result2(share, "message", PARAM_STR);
  psync_sql_bind_lstring(q, 5, br->str, br->length);
  if (!(br = papi_check_result2(share, "foldername", PARAM_STR)))
    br = papi_check_result2(share, "sharename", PARAM_STR);
  psync_sql_bind_lstring(q, 6, br->str, br->length);
  br = papi_check_result2(share, "user", PARAM_BOOL);
  if (br)
    psync_sql_bind_int(q, 7, br->num);
  else
    psync_sql_bind_int(q, 7, 0);
  br = papi_check_result2(share, "touserid", PARAM_NUM);
  if (br)
    psync_sql_bind_int(q, 8, br->num);
  else
    psync_sql_bind_null(q, 8);
  br = papi_check_result2(share, "team", PARAM_BOOL);
  if (br)
    psync_sql_bind_int(q, 9, br->num);
  else
    psync_sql_bind_int(q, 9, 0);
  br = papi_check_result2(share, "toteamid", PARAM_NUM);
  if (br)
    psync_sql_bind_int(q, 10, br->num);
  else
    psync_sql_bind_null(q, 10);
  psync_sql_bind_int(q, 11,
                     papi_find_result2(share, "fromuserid", PARAM_NUM)->num);
  psync_sql_bind_int(q, 12,
                     papi_find_result2(share, "folderownerid", PARAM_NUM)->num);
  psync_sql_bind_int(q, 13, isincomming);

  psync_sql_run_free(q);
  if (email)
    free(email);
}

static void delete_share_request(const binresult *share) {
  psync_sql_res *q;
  q = psync_sql_prep_statement("DELETE FROM sharerequest WHERE id=?");
  psync_sql_bind_uint(
      q, 1, papi_find_result2(share, "sharerequestid", PARAM_NUM)->num);
  psync_sql_run_free(q);
}

static void process_declinedsharein(const binresult *entry) {
  const binresult *share;
  if (!entry)
    return;
  share = papi_find_result2(entry, "share", PARAM_HASH);
  send_share_notify(PEVENT_SHARE_DECLINEIN, share, 0);
  delete_share_request(share);
}

static void process_declinedshareout(const binresult *entry) {
  const binresult *share;
  if (!entry)
    return;
  share = papi_find_result2(entry, "share", PARAM_HASH);
  send_share_notify(PEVENT_SHARE_DECLINEOUT, share, 0);
  delete_share_request(share);
}

static void process_cancelledsharein(const binresult *entry) {
  const binresult *share;
  if (!entry)
    return;
  share = papi_find_result2(entry, "share", PARAM_HASH);
  send_share_notify(PEVENT_SHARE_CANCELIN, share, 0);
  delete_share_request(share);
}

static void process_cancelledshareout(const binresult *entry) {
  const binresult *share;
  if (!entry)
    return;
  share = papi_find_result2(entry, "share", PARAM_HASH);
  send_share_notify(PEVENT_SHARE_CANCELOUT, share, 0);
  delete_share_request(share);
}

static void delete_shared_folder(const binresult *share) {
  psync_sql_res *q;
  uint64_t shareid;
  q = psync_sql_prep_statement("DELETE FROM sharedfolder WHERE id=?");
  shareid = papi_find_result2(share, "shareid", PARAM_NUM)->num;
  psync_sql_bind_uint(q, 1, shareid);
  psync_sql_run_free(q);
}

static void delete_bsshared_folder(const binresult *share) {
  psync_sql_res *q;
  uint64_t shareid;
  shareid = papi_find_result2(share, "shareid", PARAM_NUM)->num;

  q = psync_sql_prep_statement("DELETE FROM bsharedfolder WHERE id=?");
  psync_sql_bind_uint(q, 1, shareid);
  psync_sql_run_free(q);
}

static void process_removedsharein(const binresult *entry) {
  const binresult *share;
  if (!entry)
    return;
  share = papi_find_result2(entry, "share", PARAM_HASH);
  send_share_notify(PEVENT_SHARE_REMOVEIN, share, 0);
  delete_shared_folder(share);
}

static void process_removebsharein(const binresult *entry) {
  const binresult *share;
  if (!entry)
    return;
  share = papi_find_result2(entry, "share", PARAM_HASH);
  send_share_notify(PEVENT_SHARE_REMOVEIN, share, 1);
  delete_bsshared_folder(share);
}

static void process_removedshareout(const binresult *entry) {
  const binresult *share;
  if (!entry)
    return;
  share = papi_find_result2(entry, "share", PARAM_HASH);
  send_share_notify(PEVENT_SHARE_REMOVEOUT, share, 0);
  delete_shared_folder(share);
}

static void process_removebshareout(const binresult *entry) {
  const binresult *share;
  if (!entry)
    return;
  share = papi_find_result2(entry, "share", PARAM_HASH);
  send_share_notify(PEVENT_SHARE_REMOVEOUT, share, 1);
  delete_bsshared_folder(share);
}

static void modify_shared_folder(const binresult *perms, uint64_t shareid) {
  psync_sql_res *q;
  q = psync_sql_prep_statement(
      "UPDATE sharedfolder SET permissions=? WHERE id=?");
  psync_sql_bind_uint(q, 1, pfileops_get_perms(perms));
  psync_sql_bind_uint(q, 2, shareid);
  psync_sql_run_free(q);
}

static void modify_bshared_folder(const binresult *perms, uint64_t shareid) {
  psync_sql_res *q;
  q = psync_sql_prep_statement(
      "UPDATE bsharedfolder SET permissions=? WHERE id=?");
  psync_sql_bind_uint(q, 1, pfileops_get_perms(perms));
  psync_sql_bind_uint(q, 2, shareid);
  psync_sql_run_free(q);
}

static void process_modifiedsharein(const binresult *entry) {
  const binresult *share;
  if (!entry)
    return;
  share = papi_find_result2(entry, "share", PARAM_HASH);
  send_share_notify(PEVENT_SHARE_MODIFYIN, share, 0);
  modify_shared_folder(share,
                       papi_find_result2(share, "shareid", PARAM_NUM)->num);
}

static void process_modifiedshareout(const binresult *entry) {
  const binresult *share;
  if (!entry)
    return;
  share = papi_find_result2(entry, "share", PARAM_HASH);
  send_share_notify(PEVENT_SHARE_MODIFYOUT, share, 0);
  modify_shared_folder(share,
                       papi_find_result2(share, "shareid", PARAM_NUM)->num);
}

static void process_modifybsharein(const binresult *entry) {
  const binresult *share;
  if (!entry)
    return;
  share = papi_find_result2(entry, "share", PARAM_HASH);
  send_share_notify(PEVENT_SHARE_MODIFYIN, share, 1);
  modify_bshared_folder(papi_find_result2(share, "permissions", PARAM_HASH),
                        papi_find_result2(share, "shareid", PARAM_NUM)->num);
}

static void process_modifybshareout(const binresult *entry) {
  const binresult *share;
  if (!entry)
    return;
  share = papi_find_result2(entry, "share", PARAM_HASH);
  send_share_notify(PEVENT_SHARE_MODIFYOUT, share, 1);
  modify_bshared_folder(papi_find_result2(share, "permissions", PARAM_HASH),
                        papi_find_result2(share, "shareid", PARAM_NUM)->num);
}

static void process_cryptopasschange(const binresult *entry) {
  psync_delete_cached_crypto_keys();
}

static void process_modifyaccountinfo(const binresult *entry) {
  const binresult *res;
  psync_userid_t ret;
  if (!entry)
    return;
  res = papi_find_result2(entry, "metadata", PARAM_HASH);
  psync_set_string_setting(
      "companyname", papi_find_result2(res, "companyname", PARAM_STR)->str);
  psync_set_uint_setting("owneruserid",
                         papi_find_result2(res, "owneruserid", PARAM_NUM)->num);
  psync_get_current_userid(&ret);
  if (psync_get_uint_setting("owneruserid") == ret) {
    psync_set_bool_value("owner", 1);
  }
  psync_set_string_setting(
      "ownerfirstname",
      papi_find_result2(res, "ownerfirstname", PARAM_STR)->str);
  psync_set_string_setting(
      "ownerlastname", papi_find_result2(res, "ownerlastname", PARAM_STR)->str);
  psync_set_string_setting(
      "owneremail", papi_find_result2(res, "owneremail", PARAM_STR)->str);
  psync_set_bool_setting(
      "owner_cryptosetup",
      papi_find_result2(res, "cryptosetup", PARAM_BOOL)->num);
}

static struct {
  void (*process)(const binresult *);
  const char *name;
  uint32_t len;
  uint8_t used;
} event_list[] = {
    FN(createfolder),     FN(modifyfolder),      FN(deletefolder),
    FN(createfile),       FN(modifyfile),        FN(deletefile),
    FN(modifyuserinfo),   FN(requestsharein),    FN(requestshareout),
    FN(acceptedsharein),  FN(acceptedshareout),  FN(declinedsharein),
    FN(declinedshareout), FN(cancelledsharein),  FN(cancelledshareout),
    FN(removedsharein),   FN(removedshareout),   FN(modifiedsharein),
    FN(modifiedshareout), FN(establishbsharein), FN(establishbshareout),
    FN(modifybsharein),   FN(modifybshareout),   FN(removebsharein),
    FN(removebshareout),  FN(cryptopasschange),  FN(modifyaccountinfo)};

static uint64_t process_entries(const binresult *entries, uint64_t newdiffid) {
  const binresult *entry, *etype;
  uint64_t oused_quota;
  uint32_t i, j;
  oused_quota = used_quota;
  needdownload = 0;
  pdiff_lock();
  if (pstatus_get(PSTATUS_TYPE_AUTH) != PSTATUS_AUTH_PROVIDED) {
    pdiff_unlock();
    return psync_sql_cellint("SELECT value FROM setting WHERE id='diffid'", 0);
  }
  psync_sql_start_transaction();
  if (entries->length >= 10000)
    psync_sql_statement("DELETE FROM setting WHERE id='lastanalyze'");
  for (i = 0; i < entries->length; i++) {
    entry = entries->array[i];
    etype = papi_find_result2(entry, "event", PARAM_STR);
    for (j = 0; j < event_list_size; j++)
      if (etype->length == event_list[j].len &&
          !memcmp(etype->str, event_list[j].name, etype->length)) {
        event_list[j].process(entry);
        event_list[j].used = 1;
      }
  }
  for (j = 0; j < event_list_size; j++)
    if (event_list[j].used)
      event_list[j].process(NULL);
  psync_set_uint_value("diffid", newdiffid);
  psync_set_uint_value("usedquota", used_quota);
  // update_ba_emails();
  // update_ba_teams();
  ppathstatus_clear_cache();
  psync_sql_commit_transaction();
  pdiff_unlock();
  if (needdownload) {
    pdownload_wake();
    pstatus_download_recalc();
    pstatus_send_status_update();
    needdownload = 0;
  }
  used_quota =
      psync_sql_cellint("SELECT value FROM setting WHERE id='usedquota'", 0);
  if (oused_quota != used_quota)
    pqevent_queue_eventid(PEVENT_USEDQUOTA_CHANGED);
  return psync_sql_cellint("SELECT value FROM setting WHERE id='diffid'", 0);
}

static void check_overquota() {
  static int lisover = 0;
  int isover = (used_quota >= current_quota);
  if (isover != lisover) {
    lisover = isover;
    if (isover) {
      pstatus_set(PSTATUS_TYPE_ACCFULL, PSTATUS_ACCFULL_OVERQUOTA);
    } else
      pstatus_set(PSTATUS_TYPE_ACCFULL, PSTATUS_ACCFULL_QUOTAOK);
  }
}

static void diff_exception_handler() {
  pdbg_logf(D_NOTICE, "got exception");
  if (likely(exceptionsockwrite != INVALID_SOCKET)) {
    ssize_t ret = write(exceptionsockwrite, "e", 1);
    if (ret == -1) {
      perror("write failed");
    } else if (ret != 1) {
      fprintf(stderr, "Partial write occurred\n");
    }
  }
}


static int setup_exeptions() {
  int pfds[2];
  if (pipe(pfds) == SOCKET_ERROR)
    return INVALID_SOCKET;
  exceptionsockwrite = pfds[1];
  ptimer_exception_handler(diff_exception_handler);
  return pfds[0];
}

static int send_diff_command(psock_t *sock, subscribed_ids ids) {
  if (pnotify_running()) {
    const char *ts = pnotify_get_thumb_size();
    if (ts) {
      if (psync_is_business) {
        binparam diffparams[] = {
            PAPI_STR(
                "subscribefor",
                "diff,notifications,publinks,uploadlinks,teams,users,contacts"),
            PAPI_STR("timeformat", "timestamp"),
            PAPI_NUM("difflimit", PSYNC_DIFF_LIMIT),
            PAPI_NUM("diffid", ids.diffid),
            PAPI_NUM("notificationid", ids.notificationid),
            PAPI_STR("notificationthumbsize", ts),
            PAPI_NUM("publinkid", ids.publinkid),
            PAPI_NUM("uploadlinkid", ids.uploadlinkid)};
        return papi_send_no_res(sock, "subscribe", diffparams) ? 0 : -1;
      } else {
        binparam diffparams[] = {
            PAPI_STR("subscribefor",
                  "diff,notifications,publinks,uploadlinks,contacts"),
            PAPI_STR("timeformat", "timestamp"),
            PAPI_NUM("difflimit", PSYNC_DIFF_LIMIT),
            PAPI_NUM("diffid", ids.diffid),
            PAPI_NUM("notificationid", ids.notificationid),
            PAPI_STR("notificationthumbsize", ts),
            PAPI_NUM("publinkid", ids.publinkid),
            PAPI_NUM("uploadlinkid", ids.uploadlinkid)};
        return papi_send_no_res(sock, "subscribe", diffparams) ? 0 : -1;
      }
    } else {
      if (psync_is_business) {
        binparam diffparams[] = {
            PAPI_STR(
                "subscribefor",
                "diff,notifications,publinks,uploadlinks,teams,users,contacts"),
            PAPI_STR("timeformat", "timestamp"),
            PAPI_NUM("difflimit", PSYNC_DIFF_LIMIT),
            PAPI_NUM("diffid", ids.diffid),
            PAPI_NUM("notificationid", ids.notificationid),
            PAPI_NUM("publinkid", ids.publinkid),
            PAPI_NUM("uploadlinkid", ids.uploadlinkid)};
        return papi_send_no_res(sock, "subscribe", diffparams) ? 0 : -1;
      } else {
        binparam diffparams[] = {
            PAPI_STR("subscribefor",
                  "diff,notifications,publinks,uploadlinks,contacts"),
            PAPI_STR("timeformat", "timestamp"),
            PAPI_NUM("difflimit", PSYNC_DIFF_LIMIT),
            PAPI_NUM("diffid", ids.diffid),
            PAPI_NUM("notificationid", ids.notificationid),
            PAPI_NUM("publinkid", ids.publinkid),
            PAPI_NUM("uploadlinkid", ids.uploadlinkid)};
        return papi_send_no_res(sock, "subscribe", diffparams) ? 0 : -1;
      }
    }
  } else {
    if (psync_is_business) {
      binparam diffparams[] = {
          PAPI_STR("subscribefor",
                "diff,publinks,uploadlinks,teams,users,contacts"),
          PAPI_STR("timeformat", "timestamp"),
          PAPI_NUM("difflimit", PSYNC_DIFF_LIMIT),
          PAPI_NUM("diffid", ids.diffid),
          PAPI_NUM("publinkid", ids.publinkid),
          PAPI_NUM("uploadlinkid", ids.uploadlinkid)};
      return papi_send_no_res(sock, "subscribe", diffparams) ? 0 : -1;
    } else {
      binparam diffparams[] = {
          PAPI_STR("subscribefor", "diff,publinks,uploadlinks,contacts"),
          PAPI_STR("timeformat", "timestamp"),
          PAPI_NUM("difflimit", PSYNC_DIFF_LIMIT),
          PAPI_NUM("diffid", ids.diffid),
          PAPI_NUM("publinkid", ids.publinkid),
          PAPI_NUM("uploadlinkid", ids.uploadlinkid)};
      return papi_send_no_res(sock, "subscribe", diffparams) ? 0 : -1;
    }
  }
}

static void handle_exception(psock_t **sock, subscribed_ids *ids,
                             char ex) {
  if (ex == 'c') {
    if (last_event >= ptimer_time() - 1)
      return;
    if (psock_select_in(&(*sock)->sock, 1, 1000) != 0) {
      pdbg_logf(D_NOTICE, "got a pdiff_wake() but no diff events in one "
                      "second, closing socket");
      psock_close(*sock);
      if (pstatus_get(PSTATUS_TYPE_AUTH) != PSTATUS_AUTH_PROVIDED)
        ids->notificationid = 0;
      pdbg_logf(D_NOTICE, "waiting for new socket");
      *sock = get_connected_socket();
      pdbg_logf(D_NOTICE, "got new socket");
      pstatus_set(PSTATUS_TYPE_ONLINE, PSTATUS_ONLINE_ONLINE);
      psyncer_check_delayed();
      ids->diffid =
          psync_sql_cellint("SELECT value FROM setting WHERE id='diffid'", 0);
      send_diff_command(*sock, *ids);
    }
    return;
  }
  pdbg_logf(D_NOTICE, "exception handler %c", ex);
  if (ex == 'r' || pstatus_get(PSTATUS_TYPE_RUN) == PSTATUS_RUN_STOP ||
      pstatus_get(PSTATUS_TYPE_AUTH) != PSTATUS_AUTH_PROVIDED ||
      psync_setting_get_bool(_PS(usessl)) != psock_is_ssl(*sock)) {
    psock_close(*sock);
    if (pstatus_get(PSTATUS_TYPE_AUTH) != PSTATUS_AUTH_PROVIDED)
      ids->notificationid = 0;
    pdbg_logf(D_NOTICE, "waiting for new socket");
    *sock = get_connected_socket();
    pdbg_logf(D_NOTICE, "got new socket");
    pstatus_set(PSTATUS_TYPE_ONLINE, PSTATUS_ONLINE_ONLINE);
    psyncer_check_delayed();
    ids->diffid =
        psync_sql_cellint("SELECT value FROM setting WHERE id='diffid'", 0);
    send_diff_command(*sock, *ids);
  } else if (ex == 'e') {
    binparam diffparams[] = {PAPI_STR("id", "ignore")};
    if (!papi_send_no_res(*sock, "nop", diffparams) ||
        psock_select_in(&(*sock)->sock, 1,
                        PSYNC_SOCK_TIMEOUT_ON_EXCEPTION * 1000) != 0) {
      const char *prefixes[] = {"API:", "HTTP"};
      pdbg_logf(D_NOTICE, "reconnecting diff");
      psock_close_bad(*sock);
      pcache_clean_oneof(prefixes, ARRAY_SIZE(prefixes));
      *sock = get_connected_socket();
      pstatus_set(PSTATUS_TYPE_ONLINE, PSTATUS_ONLINE_ONLINE);
      psyncer_check_delayed();
      send_diff_command(*sock, *ids);
    } else {
      pdbg_logf(D_NOTICE, "diff socket seems to be alive");
      (*sock)->pending = 1;
    }
  }
}

static int cmp_folderid(const void *ptr1, const void *ptr2) {
  psync_folderid_t *folderid1 = (psync_folderid_t *)ptr1;
  psync_folderid_t *folderid2 = (psync_folderid_t *)ptr2;
  if (folderid1 < folderid2)
    return -1;
  else if (folderid1 > folderid2)
    return 1;
  else
    return 0;
}

static void psync_diff_refresh_fs_add_folder(psync_folderid_t folderid) {
  if (psync_fs_need_per_folder_refresh()) {
    if (refresh_allocated == refresh_last) {
      if (refresh_allocated)
        refresh_allocated *= 2;
      else
        refresh_allocated = 8;
      refresh_folders = (psync_folderid_t *)realloc(
          refresh_folders, sizeof(psync_folderid_t) * refresh_allocated);
    }
    refresh_folders[refresh_last++] = folderid;
  }
}

static void psync_diff_refresh_thread(void *ptr) {
  refresh_folders_ptr_t *fr;
  psync_folderid_t lastfolderid;
  uint32_t i;
  psys_sleep_milliseconds(1000);
  fr = (refresh_folders_ptr_t *)ptr;
  qsort(fr->refresh_folders, fr->refresh_last, sizeof(psync_folderid_t),
        cmp_folderid);
  lastfolderid = (psync_folderid_t)-1;
  for (i = 0; i < fr->refresh_last; i++)
    if (fr->refresh_folders[i] != lastfolderid) {
      psync_fs_refresh_folder(fr->refresh_folders[i]);
      lastfolderid = fr->refresh_folders[i];
    }
  free(fr->refresh_folders);
  free(fr);
}

static void psync_diff_refresh_fs(const binresult *entries) {
  if (psync_fs_need_per_folder_refresh()) {
    const binresult *meta;
    refresh_folders_ptr_t *ptr;
    psync_folderid_t folderid, lastfolderid;
    uint32_t i;
    lastfolderid = (psync_folderid_t)-1;
    for (i = 0; i < entries->length; i++) {
      meta = papi_check_result2(entries->array[i], "metadata", PARAM_HASH);
      if (!meta)
        continue;
      meta = papi_check_result2(meta, "parentfolderid", PARAM_NUM);
      if (!meta)
        continue;
      folderid = meta->num;
      if (folderid == lastfolderid)
        continue;
      psync_diff_refresh_fs_add_folder(folderid);
      lastfolderid = folderid;
    }
    if (!refresh_last)
      return;
    ptr = psync_new(refresh_folders_ptr_t);
    ptr->refresh_folders = refresh_folders;
    ptr->refresh_last = refresh_last;
    prun_thread1("fs folder refresh", psync_diff_refresh_thread, ptr);
    refresh_folders = NULL;
    refresh_allocated = 0;
    refresh_last = 0;
  }
}

static void psync_run_analyze_if_needed() {
  if (ptimer_time() >
      psync_sql_cellint("SELECT value FROM setting WHERE id='lastanalyze'", 0) +
          24 * 3600) {
    static const char *skiptables[] = {"pagecache", "sqlite_stat1"};
    psync_sql_res *res;
    psync_uint_row row;
    psync_str_row srow;
    char **tablenames;
    char *sql;
    size_t tablecnt, i;
    pdbg_logf(D_NOTICE, "running ANALYZE on tables");
    res = psync_sql_query_rdlock(
        "SELECT COUNT(*) FROM sqlite_master WHERE type='table'");
    if ((row = psync_sql_fetch_rowint(res)))
      tablecnt = row[0];
    else
      tablecnt = 0;
    psync_sql_free_result(res);
    tablenames = psync_new_cnt(char *, tablecnt);
    res = psync_sql_query_rdlock(
        "SELECT name FROM sqlite_master WHERE type='table' LIMIT ?");
    psync_sql_bind_uint(res, 1, tablecnt);
    tablecnt = 0;
    while ((srow = psync_sql_fetch_rowstr(res))) {
      for (i = 0; i < ARRAY_SIZE(skiptables); i++)
        if (!strcmp(srow[0], skiptables[i]))
          goto skip;
      tablenames[tablecnt++] = psync_strdup(srow[0]);
    skip:;
    }
    psync_sql_free_result(res);

    while (tablecnt) {
      --tablecnt;
      pdbg_logf(D_NOTICE, "running ANALYZE on %s", tablenames[tablecnt]);
      sql = psync_strcat("ANALYZE ", tablenames[tablecnt], ";", NULL);
      free(tablenames[tablecnt]);
      psync_sql_statement(sql);
      free(sql);
      pdbg_logf(D_NOTICE, "table done");
      psys_sleep_milliseconds(5);
    }
    free(tablenames);
    res = psync_sql_prep_statement(
        "REPLACE INTO setting (id, value) VALUES (?, ?)");
    psync_sql_bind_string(res, 1, "lastanalyze");
    psync_sql_bind_uint(res, 2, ptimer_time());
    psync_sql_run_free(res);
    pdbg_logf(D_NOTICE, "done running ANALYZE on tables");
  }
}

static int psync_diff_check_quota(psock_t *sock) {
  binparam diffparams[] = {PAPI_STR("timeformat", "timestamp"),
                           PAPI_BOOL("getapiserver", 1)};
  binresult *res;
  const binresult *uq;
  uint64_t oused_quota, result;
  oused_quota = used_quota;
  res = papi_send2(sock, "userinfo", diffparams);
  if (!res)
    return -1;
  result = papi_find_result2(res, "result", PARAM_NUM)->num;
  if (unlikely(result))
    pdbg_logf(D_WARNING, "userinfo returned error %u: %s", (unsigned)result,
          papi_find_result2(res, "error", PARAM_STR)->str);
  else {
    uq = papi_check_result2(res, "usedquota", PARAM_NUM);
    if (pdbg_likely(uq))
      used_quota = uq->num;
  }
  if (used_quota != oused_quota) {
    pdbg_logf(D_WARNING, "corrected locally calculated quota from %lu to %lu",
          (unsigned long)oused_quota, (unsigned long)used_quota);
    psync_set_uint_value("usedquota", used_quota);
    pqevent_queue_eventid(PEVENT_USEDQUOTA_CHANGED);
  }
  uq = papi_find_result2(papi_find_result2(res, "apiserver", PARAM_HASH),
                         "binapi", PARAM_ARRAY);
  if (uq->length)
    psync_apipool_set_server(uq->array[0]->str);
  free(res);
  return 0;
}

static void psync_diff_adapter_hash(void *out) {
  psync_fast_hash256_ctx ctx;
  psock_ifaces_t *list;
  list = psock_list_adapters();
  pcrc32c_fast_hash256_init(&ctx);
  pcrc32c_fast_hash256_update(&ctx, list->interfaces,
                            list->interfacecnt * sizeof(psock_iface_t));
  pcrc32c_fast_hash256_final(out, &ctx);
  free(list);
}

static void psync_diff_adapter_timer(psync_timer_t timer, void *ptr) {
  unsigned char hash[PSYNC_FAST_HASH256_LEN];
  psync_diff_adapter_hash(hash);
  if (memcmp(adapter_hash, hash, PSYNC_FAST_HASH256_LEN)) {
    memcpy(adapter_hash, hash, PSYNC_FAST_HASH256_LEN);
    pdbg_logf(D_NOTICE, "network adapter list changed, sending exception");
    
    ssize_t ret = write(exceptionsockwrite, "e", 1);
    if (ret == -1) {
      pdbg_logf(D_ERROR, "Failed to write exception: %s", strerror(errno));
    } else if (ret != 1) {
      pdbg_logf(D_WARNING, "Partial write occurred when sending exception");
    }
  }
}


static void psync_diff_thread() {
  psock_t *sock;
  binresult *res = NULL;
  const binresult *entries;
  uint64_t newdiffid, result;
  int exceptionsock, socks[2];
  subscribed_ids ids = {0, 0, 0, 0};
  int sel, ret = 0;
  char ex;
  char *err = NULL;
  int should_free_res = 0;

  pstatus_set(PSTATUS_TYPE_ONLINE, PSTATUS_ONLINE_CONNECTING);
  pstatus_send_status_update();

restart:
  pstatus_set(PSTATUS_TYPE_ONLINE, PSTATUS_ONLINE_CONNECTING);
  sock = get_connected_socket();
  pdbg_logf(D_NOTICE, "connected");
  pstatus_set(PSTATUS_TYPE_ONLINE, PSTATUS_ONLINE_SCANNING);
  ids.diffid =
      psync_sql_cellint("SELECT value FROM setting WHERE id='diffid'", 0);
  if (ids.diffid == 0) {
    initialdownload = 1;
  }
  used_quota =
      psync_sql_cellint("SELECT value FROM setting WHERE id='usedquota'", 0);
  do {
    binparam diffparams[] = {PAPI_STR("timeformat", "timestamp"),
                             PAPI_NUM("limit", PSYNC_DIFF_LIMIT),
                             PAPI_NUM("diffid", ids.diffid)};
    if (!psync_do_run)
      goto cleanup;
    res = papi_send2(sock, "diff", diffparams);
    should_free_res = 1;
    if (!res) {
      psock_close(sock);
      goto restart;
    }
    result = papi_find_result2(res, "result", PARAM_NUM)->num;
    if (unlikely(result)) {
      pdbg_logf(D_ERROR, "diff returned error %u: %s", (unsigned int)result,
            papi_find_result2(res, "error", PARAM_STR)->str);
      psock_close(sock);
      psys_sleep_milliseconds(PSYNC_SLEEP_BEFORE_RECONNECT);
      goto restart;
    }
    entries = papi_find_result2(res, "entries", PARAM_ARRAY);
    if (entries->length) {
      newdiffid = papi_find_result2(res, "diffid", PARAM_NUM)->num;
      pdbg_logf(D_NOTICE, "processing diff with %u entries",
            (unsigned)entries->length);
      ids.diffid = process_entries(entries, newdiffid);
      pdbg_logf(D_NOTICE, "got diff with %u entries, new diffid %lu",
            (unsigned)entries->length, (unsigned long)ids.diffid);
    }
    result = entries->length;
    if (should_free_res) {
      free(res);
      should_free_res = 0;
      res = NULL;
    }
  } while (result);

  psync_fs_refresh_folder(0);
  pdbg_logf(D_NOTICE, "initial sync finished");
  if (psync_diff_check_quota(sock)) {
    psock_close(sock);
    psys_sleep_milliseconds(PSYNC_SLEEP_BEFORE_RECONNECT);
    goto restart;
  }
  check_overquota();
  pstatus_set(PSTATUS_TYPE_ONLINE, PSTATUS_ONLINE_ONLINE);
  initialdownload = 0;
  psync_run_analyze_if_needed();
  psyncer_check_delayed();
  exceptionsock = setup_exeptions();
  if (unlikely(exceptionsock == INVALID_SOCKET)) {
    pdbg_logf(D_ERROR, "could not create pipe");
    psock_close(sock);
    goto cleanup;
  }
  socks[0] = exceptionsock;
  socks[1] = sock->sock;
  psync_diff_adapter_hash(adapter_hash);
  ptimer_register(psync_diff_adapter_timer,
                       PSYNC_DIFF_CHECK_ADAPTER_CHANGE_SEC, NULL);
  send_diff_command(sock, ids);
  psys_sleep_milliseconds(50);
  last_event = 0;

  while (psync_do_run) {
    if (unlinked) {
      unlinked = 0;
      initialdownload = 1;
    }
    if (psync_recache_contacts) {
      if (psync_is_business) {
        cache_account_emails();
        cache_account_teams();
        cache_ba_my_teams();
      }
      cache_links_all();
      cache_contacts();
      cache_shares();
      psync_notify_cache_change(PACCOUNT_CHANGE_ALL);
      psync_recache_contacts = 0;
    }
    if (psock_pendingdata(sock))
      sel = 1;
    else
      sel = psock_select_in(socks, 2, -1);
    if (sel == 0) {
      if (!psync_do_run)
        break;
      if (read(exceptionsock, &ex, 1) != 1)
        continue;
      handle_exception(&sock, &ids, ex);
      while (psock_select_in(socks, 1, 0) == 0 &&
             read(exceptionsock, &ex, 1) == 1)
        ;
      socks[1] = sock->sock;
    } else if (sel == 1) {
      sock->pending = 1;
      res = papi_result(sock);
      should_free_res = 1;
      if (pdbg_unlikely(!res)) {
        ptimer_notify_exception();
        handle_exception(&sock, &ids, 'r');
        socks[1] = sock->sock;
        last_event = 0;
        continue;
      }
      last_event = ptimer_time();
      result = papi_find_result2(res, "result", PARAM_NUM)->num;
      if (unlikely(result)) {
        if (result == 6003 || result == 6002) { // timeout or cancel
          pdbg_logf(D_NOTICE, "got \"%s\" from the socket",
                papi_find_result2(res, "error", PARAM_STR)->str);
          send_diff_command(sock, ids);
          continue;
        }
        pdbg_logf(D_ERROR, "diff returned error %u: %s", (unsigned int)result,
              papi_find_result2(res, "error", PARAM_STR)->str);
        handle_exception(&sock, &ids, 'r');
        socks[1] = sock->sock;
        continue;
      }
      entries = papi_check_result2(res, "from", PARAM_STR);
      if (entries) {
        if (entries->length == 4 && !strcmp(entries->str, "diff")) {
          entries = papi_find_result2(res, "entries", PARAM_ARRAY);
          if (entries->length) {
            newdiffid = papi_find_result2(res, "diffid", PARAM_NUM)->num;
            ids.diffid = process_entries(entries, newdiffid);
            psync_diff_refresh_fs(entries);
            psync_diff_check_quota(sock);
            check_overquota();
            if (initialdownload)
              initialdownload = 0;
          } else
            pdbg_logf(D_NOTICE, "diff with 0 entries, did we send a nop recently?");
        } else if (entries->length == 13 &&
                   !strcmp(entries->str, "notifications")) {
          ids.notificationid =
              papi_find_result2(res, "notificationid", PARAM_NUM)->num;
          pnotify_notify(res);
          should_free_res = 0; // Don't free res in this case
        } else if (entries->length == 8 && !strcmp(entries->str, "publinks")) {
          ids.publinkid = papi_find_result2(res, "publinkid", PARAM_NUM)->num;
          ret = cache_links(err, 256);
          if (ret < 0)
            pdbg_logf(D_ERROR, "Cacheing links failed with err %s", err);
          else
            psync_notify_cache_change(PACCOUNT_CHANGE_LINKS);
        } else if (entries->length == 11 &&
                   !strcmp(entries->str, "uploadlinks")) {
          ids.uploadlinkid =
              papi_find_result2(res, "uploadlinkid", PARAM_NUM)->num;
          ret = cache_upload_links(&err);
          if (ret < 0)
            pdbg_logf(D_ERROR, "Cacheing upload links failed with err %s", err);
          else
            psync_notify_cache_change(PACCOUNT_CHANGE_LINKS);
        } else if (entries->length == 5 && !strcmp(entries->str, "teams")) {
          cache_account_teams();
          cache_ba_my_teams();
          psync_notify_cache_change(PACCOUNT_CHANGE_TEAMS);
        } else if (entries->length == 5 && !strcmp(entries->str, "users")) {
          cache_account_emails();
          psync_notify_cache_change(PACCOUNT_CHANGE_EMAILS);
        } else if (entries->length == 8 && !strcmp(entries->str, "contacts")) {
          cache_contacts();
          psync_notify_cache_change(PACCOUNT_CHANGE_CONTACTS);
        } else {
          pdbg_logf(D_NOTICE, "got no from, did we send a nop recently?");
        }
        send_diff_command(sock, ids);
      } else {
        pdbg_logf(D_NOTICE, "got no from, did we send a nop recently?");
      }
    }

    if (should_free_res) {
      free(res);
      should_free_res = 0;
      res = NULL;
    }
  }

cleanup:
  if (should_free_res && res) {
    free(res);
  }
  psock_close(sock);
  close(exceptionsock);
  close(exceptionsockwrite);
}

void do_register_account_events_callback(paccount_cache_callback_t callback) {
  psync_cache_callback = callback;
}

void pdiff_init() { 
  prun_thread("diff", psync_diff_thread); 
}

void pdiff_wake() {
  if (last_event >= ptimer_time() - 1) {
    return;
  }

  ssize_t ret = write(exceptionsockwrite, "c", 1);
  if (ret == -1) {
    pdbg_logf(D_ERROR, "Failed to write wake signal: %s", strerror(errno));
  } else if (ret != 1) {
    pdbg_logf(D_WARNING, "Partial write occurred when sending wake signal");
  }
}

void pdiff_file_create(const binresult *meta) {
  psync_sql_res *st;
  const binresult *name;
  uint64_t userid, fileid, hash, size;
  st = psync_sql_prep_statement(
      "INSERT OR IGNORE INTO file (id, parentfolderid, userid, size, hash, "
      "name, ctime, mtime, category, thumb, icon, "
      "artist, album, title, genre, trackno, width, height, duration, fps, "
      "videocodec, audiocodec, videobitrate, "
      "audiobitrate, audiosamplerate, rotate) VALUES (?, ?, ?, ?, ?, ?, ?, ?, "
      "?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
  name = papi_find_result2(meta, "name", PARAM_STR);
  check_for_deletedfileid(meta);
  if (papi_find_result2(meta, "ismine", PARAM_BOOL)->num)
    userid = psync_my_userid;
  else
    userid = papi_find_result2(meta, "userid", PARAM_NUM)->num;
  fileid = papi_find_result2(meta, "fileid", PARAM_NUM)->num;
  size = papi_find_result2(meta, "size", PARAM_NUM)->num;
  hash = papi_find_result2(meta, "hash", PARAM_NUM)->num;
  psync_sql_bind_uint(st, 1, fileid);
  psync_sql_bind_uint(
      st, 2, papi_find_result2(meta, "parentfolderid", PARAM_NUM)->num);
  psync_sql_bind_uint(st, 3, userid);
  psync_sql_bind_uint(st, 4, size);
  psync_sql_bind_uint(st, 5, hash);
  psync_sql_bind_lstring(st, 6, name->str, name->length);
  bind_meta(st, meta, 7);
  psync_sql_run_free(st);
  insert_revision(fileid, hash,
                  papi_find_result2(meta, "modified", PARAM_NUM)->num, size);
  insert_revision(0, 0, 0, 0);
}

void pdiff_file_update(const binresult *meta) {
  create_entry();
  process_modifyfile(&entry);
  process_modifyfile(NULL);
  start_download();
}

void pdiff_file_delete(const binresult *meta) {
  create_entry();
  process_deletefile(&entry);
  process_deletefile(NULL);
  start_download();
}

void pdiff_fldr_update(const binresult *meta) {
  create_entry();
  process_modifyfolder(&entry);
  process_modifyfolder(NULL);
  start_download();
}

void pdiff_fldr_delete(const binresult *meta) {
  create_entry();
  process_deletefolder(&entry);
  process_deletefolder(NULL);
  start_download();
}

void pdiff_lock() { 
  pthread_mutex_lock(&diff_mutex); 
}

void pdiff_unlock() { 
  pthread_mutex_unlock(&diff_mutex); 
}