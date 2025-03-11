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

#include "pcontacts.h"
#include "papi.h"
#include "pfileops.h"
#include "plibs.h"
#include "pnetlibs.h"

#include <stdio.h>

int do_call_contactlist(result_visitor vis, void *param) {
  psock_t *sock;
  binresult *bres;
  int i;
  const binresult *contacts;

  if (psync_my_auth[0]) {
    binparam params[] = {PAPI_STR("auth", psync_my_auth)};
    sock = psync_apipool_get();
    if (sock)
      bres = papi_send2(sock, "contactlist", params);
    else
      return -2;
  } else if (psync_my_user && psync_my_pass) {
    binparam params[] = {PAPI_STR("username", psync_my_user),
                         PAPI_STR("password", psync_my_pass)};
    sock = psync_apipool_get();
    if (sock)
      bres = papi_send2(sock, "contactlist", params);
    else
      return -2;
  } else
    return -1;
  if (likely(bres))
    psync_apipool_release(sock);
  else {
    psync_apipool_release_bad(sock);
    debug(D_WARNING, "Send command returned invalid result.\n");
    return -1;
  }

  contacts = papi_find_result2(bres, "contacts", PARAM_ARRAY);

  if (!contacts->length) {
    free(bres);
    debug(D_WARNING, "Account_users returned empty result!\n");
    return -2;
  } else {
    psync_sql_start_transaction();
    psync_sql_statement("DELETE FROM contacts");
    for (i = 0; i < contacts->length; ++i)
      vis(i, contacts->array[i], param);
    psync_sql_commit_transaction();
  }

  free(bres);
  return 0;
}

static void insert_cache_contact(int i, const binresult *user, void *_this) {
  const char *char_field = 0;
  uint64_t id = 0;
  psync_sql_res *q;

  // not checking this field...
  // char_field = papi_find_result2(user, "name", PARAM_STR)->str; // not
  id = papi_find_result2(user, "source", PARAM_NUM)->num;
  if ((id == 1) || (id == 3)) {
    q = psync_sql_prep_statement("REPLACE INTO contacts  (mail) VALUES (?)");
    char_field = papi_find_result2(user, "value", PARAM_STR)->str;
    psync_sql_bind_lstring(q, 1, char_field, strlen(char_field));
    psync_sql_run_free(q);
  }
}

void cache_contacts() { do_call_contactlist(&insert_cache_contact, NULL); }

static int create_contact(psync_list_builder_t *builder, void *element,
                          psync_variant_row row) {
  contact_info_t *contact;
  const char *str;
  size_t len;
  contact = (contact_info_t *)element;
  str = psync_get_lstring(row[0], &len);
  contact->mail = str;
  psync_list_add_lstring_offset(builder, offsetof(contact_info_t, mail), len);
  if (row[1].type != PSYNC_TNULL)
    str = psync_get_lstring(row[1], &len);
  else
    str = "";
  contact->name = str;
  psync_list_add_lstring_offset(builder, offsetof(contact_info_t, name), len);
  contact->teamid = psync_get_number(row[2]);
  contact->type = psync_get_number(row[3]);
  return 0;
}

pcontacts_list_t *do_psync_list_contacts() {
  psync_list_builder_t *builder;
  psync_sql_res *res;
  builder = psync_list_builder_create(sizeof(contact_info_t),
                                      offsetof(pcontacts_list_t, entries));
  res = psync_sql_query_rdlock(
      "select mail, ifnull(name, ' ') , 0 as teamid, 1 as type from contacts "
      "union all "
      "select  mail, (firstname||' '||lastname) as name, 0 as teamid , 2 as "
      "type from baccountemail "
      "union all "
      "select  '' as mail, name , id as teamid, 3 as type from baccountteam "
      "ORDER BY name ");
  psync_list_bulder_add_sql(builder, res, create_contact);

  return (pcontacts_list_t *)psync_list_builder_finalize(builder);
}

pcontacts_list_t *do_psync_list_myteams() {
  psync_list_builder_t *builder;
  psync_sql_res *res;
  builder = psync_list_builder_create(sizeof(contact_info_t),
                                      offsetof(pcontacts_list_t, entries));
  res = psync_sql_query_rdlock(
      "SELECT  '' AS mail, name , id AS teamid, 3 AS type FROM myteams "
      "ORDER BY name ");
  psync_list_bulder_add_sql(builder, res, create_contact);

  return (pcontacts_list_t *)psync_list_builder_finalize(builder);
}

static void process_shares_out(const binresult *shares_out, int shcnt) {
  const binresult *share;
  const binresult *br;
  psync_sql_res *q;
  int i, isincomming = 0;
  uint64_t folderowneruserid, owneruserid;

  for (i = 0; i < shcnt; ++i) {
    share = shares_out->array[i];

    folderowneruserid =
        papi_find_result2(share, "folderowneruserid", PARAM_NUM)->num;
    psync_get_current_userid(&owneruserid);
    isincomming = (folderowneruserid == owneruserid) ? 0 : 1;

    q = psync_sql_prep_statement(
        "REPLACE INTO sharedfolder (id, folderid, ctime, permissions, userid, "
        "mail, name, isincoming) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)");
    // debug(D_NOTICE, "INSERT NORMAL SHARE OUT id: %lld", (long long)
    // papi_find_result2(share, "shareid", PARAM_NUM)->num);
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

static void process_shares_in(const binresult *shares_in, int shcnt) {
  const binresult *share;
  const binresult *br;
  psync_sql_res *q;
  int i;

  for (i = 0; i < shcnt; ++i) {
    share = shares_in->array[i];

    q = psync_sql_prep_statement(
        "REPLACE INTO sharedfolder (id, isincoming, folderid, ctime, "
        "permissions, userid, mail, name) "
        "VALUES (?, 1, ?, ?, ?, ?, ?, ?)");
    // debug(D_WARNING, "INSERT NORMAL SHARE IN id: %lld", (long long)
    // papi_find_result2(share, "shareid", PARAM_NUM)->num);
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
}

static void process_shares_req_out(const binresult *shares_out, int shcnt) {
  const binresult *share;
  const binresult *br;
  psync_sql_res *q;
  int i, isincomming = 0;
  uint64_t folderowneruserid, owneruserid;

  for (i = 0; i < shcnt; ++i) {
    share = shares_out->array[i];

    folderowneruserid =
        papi_find_result2(share, "folderowneruserid", PARAM_NUM)->num;
    psync_get_current_userid(&owneruserid);
    isincomming = (folderowneruserid == owneruserid) ? 0 : 1;

    q = psync_sql_prep_statement(
        "REPLACE INTO sharerequest (id, folderid, ctime, etime, permissions, "
        "userid, mail, name, message,  isincoming, isba) "
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
}

static void process_shares_req_in(const binresult *shares_in, int shcnt) {
  const binresult *share;
  const binresult *br;
  psync_sql_res *q;
  int i, isincomming = 1;
  uint64_t folderowneruserid, owneruserid;

  for (i = 0; i < shcnt; ++i) {
    share = shares_in->array[i];
    br = papi_check_result2(share, "folderowneruserid", PARAM_NUM);
    if (br) {
      folderowneruserid = br->num;
      psync_get_current_userid(&owneruserid);
      isincomming = (folderowneruserid == owneruserid) ? 0 : 1;
    }

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
}

void cache_shares() {
  psock_t *api;
  binresult *bres;
  uint64_t result;
  const char *errorret;
  const binresult *array, *shares;
  int shcnt;
  psync_sql_res *q;

  if (psync_my_auth[0]) {
    binparam params[] = {PAPI_STR("auth", psync_my_auth),
                         PAPI_STR("timeformat", "timestamp")};
    api = psync_apipool_get();
    if (unlikely(!api)) {
      debug(D_WARNING, "Can't get api from the pool. No pool ?\n");
      return;
    }
    bres = papi_send2(api, "listshares", params);
  } else if (psync_my_user && psync_my_pass) {
    binparam params[] = {PAPI_STR("username", psync_my_user),
                         PAPI_STR("password", psync_my_pass),
                         PAPI_STR("timeformat", "timestamp")};
    api = psync_apipool_get();
    if (unlikely(!api)) {
      debug(D_WARNING, "Can't get api from the pool. No pool ?\n");
      return;
    }
    bres = papi_send2(api, "listshares", params);
  } else
    return;
  if (likely(bres))
    psync_apipool_release(api);
  else {
    psync_apipool_release_bad(api);
    debug(D_WARNING, "Send command returned in valid result.\n");
    return;
  }
  result = papi_find_result2(bres, "result", PARAM_NUM)->num;
  if (unlikely(result)) {
    errorret = papi_find_result2(bres, "error", PARAM_STR)->str;
    debug(D_WARNING, "command listshares returned error code %u message %s",
          (unsigned)result, errorret);
    psync_process_api_error(result);
    free(bres);
    return;
  }

  shares = papi_find_result2(bres, "shares", PARAM_HASH);

  psync_sql_start_transaction();

  q = psync_sql_prep_statement("DELETE FROM sharerequest ");
  psync_sql_run_free(q);

  q = psync_sql_prep_statement("DELETE FROM sharedfolder ");
  psync_sql_run_free(q);

  array = papi_find_result2(shares, "outgoing", PARAM_ARRAY);

  shcnt = array->length;
  if (shcnt) {
    process_shares_out(array, shcnt);
  }

  array = papi_find_result2(shares, "incoming", PARAM_ARRAY);

  shcnt = array->length;
  if (shcnt) {
    process_shares_in(array, shcnt);
  }

  shares = papi_find_result2(bres, "requests", PARAM_HASH);
  array = papi_find_result2(shares, "outgoing", PARAM_ARRAY);

  shcnt = array->length;
  if (shcnt) {
    process_shares_req_out(array, shcnt);
  }

  array = papi_find_result2(shares, "incoming", PARAM_ARRAY);

  shcnt = array->length;
  if (shcnt) {
    process_shares_req_in(array, shcnt);
  }

  psync_sql_commit_transaction();

  free(bres);
}
