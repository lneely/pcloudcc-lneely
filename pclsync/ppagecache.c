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

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>

#include "pcache.h"
#include "pcrc32c.h"
#include "pfile.h"
#include "pfscrypto.h"
#include "pfsupload.h"
#include "plibs.h"
#include "pmem.h"
#include "pnetlibs.h"
#include "ppagecache.h"
#include "ppath.h"
#include "prun.h"
#include "psettings.h"
#include "psql.h"
#include "pstatus.h"
#include "psys.h"
#include "ptimer.h"
#include "putil.h"

#define CACHE_PAGES (PSYNC_FS_MEMORY_CACHE / PSYNC_FS_PAGE_SIZE)
#define CACHE_HASH (CACHE_PAGES / 2)

#define PAGE_WAITER_HASH 1024

#define DB_CACHE_UPDATE_HASH (32 * 1024)

#define PAGE_TYPE_FREE 0
#define PAGE_TYPE_READ 1
#define PAGE_TYPE_CACHE 2

#define PAGE_TASK_TYPE_CREAT 0
#define PAGE_TASK_TYPE_MODIFY 1

#define QSORT_TRESH 8
#define QSORT_MTR 64
#define QSORT_REC_M (16 * 1024)

#define pagehash_by_hash_and_pageid(hash, pageid)                              \
  (((hash) + (pageid)) % CACHE_HASH)
#define waiterhash_by_hash_and_pageid(hash, pageid)                            \
  (((hash) + (pageid)) % PAGE_WAITER_HASH)
#define lock_wait(hash) pthread_mutex_lock(&wait_page_mutex)
#define unlock_wait(hash) pthread_mutex_unlock(&wait_page_mutex)

typedef struct {
  psync_list list;
  psync_list flushlist;
  char *page;
  uint64_t hash;
  uint64_t pageid;
  time_t lastuse;
  uint32_t size;
  uint32_t usecnt;
  uint32_t flushpageid;
  uint32_t crc;
  uint8_t type;
} psync_cache_page_t;

typedef struct {
  uint64_t pagecacheid;
  time_t lastuse;
  uint32_t usecnt;
} psync_cachepage_to_update;

typedef struct {
  /* list is an element of hash table for pages */
  psync_list list;
  /* list is root of a listpage elements of psync_page_waiter_t, if empty,
   * nobody waits for this page */
  psync_list waiters;
  uint64_t hash;
  uint64_t pageid;
  psync_fileid_t fileid;
} psync_page_wait_t;

typedef struct {
  /* listpage is node element of psync_page_wait_t waiters list */
  psync_list listpage;
  /* listwaiter is node element of pages that are needed for current request */
  psync_list listwaiter;
  pthread_cond_t cond;
  psync_page_wait_t *waiting_for;
  char *buff;
  uint32_t pageidx;
  uint32_t rsize;
  uint32_t size;
  uint32_t off;
  int error;
  uint8_t ready;
} psync_page_waiter_t;

typedef struct {
  psync_list list;
  uint64_t offset;
  uint64_t length;
} psync_request_range_t;

typedef struct {
  psync_list ranges;
  psync_openfile_t *of;
  psync_fileid_t fileid;
  uint64_t hash;
  int needkey;
} psync_request_t;

typedef struct {
  uint64_t hash;
  psync_tree tree;
  binresult *urls;
  uint32_t refcnt;
  uint32_t status;
} psync_urls_t;

typedef struct _psync_crypto_auth_page {
  psync_list list;
  psync_page_waiter_t *waiter;
  struct _psync_crypto_auth_page *parent;
  uint64_t firstpageid;
  uint32_t size;
  uint32_t idinparent;
  uint32_t level;
  psync_crypto_auth_sector_t auth;
} psync_crypto_auth_page;

typedef struct {
  psync_crypto_auth_page *authpage;
  psync_page_waiter_t *waiter;
  char *buff;
  uint32_t pagesize;
  uint8_t freebuff;
} psync_crypto_data_page;

typedef struct {
  unsigned char *lo;
  unsigned char *hi;
} psq_stack_t;

static psync_list cache_hash[CACHE_HASH];
static uint32_t cache_pages_in_hash = 0;
static uint32_t cache_pages_free;
static int cache_pages_reset = 1;
static psync_list free_pages;
static psync_list wait_page_hash[PAGE_WAITER_HASH];
static char *pages_base;
static uint32_t free_page_waiters = 0;
static int flush_page_running = 0;

static psync_cachepage_to_update cachepages_to_update[DB_CACHE_UPDATE_HASH];
static uint32_t cachepages_to_update_cnt = 0;
static uint32_t free_db_pages;

static pthread_mutex_t clean_cache_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t clean_cache_cond = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t cache_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t flush_cache_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t free_page_cond = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t url_cache_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t url_cache_cond = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t wait_page_mutex;
static pthread_cond_t enc_key_cond = PTHREAD_COND_INITIALIZER;

static uint32_t clean_cache_stoppers = 0;
static uint32_t clean_cache_waiters = 0;
static uint32_t clean_cache_in_progress = 0;

static int flushedbetweentimers = 0;
static int flushcacherun = 0;
static int upload_to_cache_thread_run = 0;

static uint64_t db_cache_in_pages;
static uint64_t db_cache_max_page;

static int readcache = INVALID_HANDLE_VALUE;

static psync_tree *url_cache_tree = PSYNC_TREE_EMPTY;

static int flush_pages(int nosleep);

static void flush_pages_noret() { flush_pages(0); }

static inline int psync_crypto_is_error(const void *ptr) {
  return (uintptr_t)ptr <= PSYNC_CRYPTO_MAX_ERROR;
}

static inline int psync_crypto_to_error(const void *ptr) {
  return -((int)(uintptr_t)ptr);
}

static psync_cache_page_t *psync_pagecache_get_free_page_if_available() {
  psync_cache_page_t *page;
  int runthread;
  runthread = 0;
  pthread_mutex_lock(&cache_mutex);
  if (unlikely(cache_pages_free <= CACHE_PAGES * 25 / 100 && !flushcacherun)) {
    flushcacherun = 1;
    runthread = 1;
  }
  if (likely(!psync_list_isempty(&free_pages)))
    page =
        psync_list_remove_head_element(&free_pages, psync_cache_page_t, list);
  else
    page = NULL;
  pthread_mutex_unlock(&cache_mutex);
  if (runthread)
    prun_thread("flush pages get free page ifav", flush_pages_noret);
  return page;
}

static psync_cache_page_t *
psync_pagecache_get_free_page(int runflushcacheinside) {
  psync_cache_page_t *page;
  int runthread;
  runthread = 0;
  pthread_mutex_lock(&cache_mutex);
  if (unlikely(cache_pages_free <= CACHE_PAGES * 25 / 100 && !flushcacherun)) {
    flushcacherun = 1;
    if (runflushcacheinside) {
      pthread_mutex_unlock(&cache_mutex);
      pdbg_logf(D_NOTICE, "running flush cache on this thread");
      flush_pages(2);
      pthread_mutex_lock(&cache_mutex);
    } else
      runthread = 1;
  }
  if (likely(!psync_list_isempty(&free_pages)))
    page =
        psync_list_remove_head_element(&free_pages, psync_cache_page_t, list);
  else {
    if (flush_page_running) {
      pdbg_logf(
          D_NOTICE,
          "no free pages, but somebody is flushing cache, waiting for a page");
      do {
        free_page_waiters++;
        pthread_cond_wait(&free_page_cond, &cache_mutex);
        free_page_waiters--;
      } while (flush_page_running && psync_list_isempty(&free_pages));
    }
    if (psync_list_isempty(&free_pages)) {
      pdbg_logf(D_NOTICE, "no free pages, flushing cache");
      pthread_mutex_unlock(&cache_mutex);
      flush_pages(1);
      pthread_mutex_lock(&cache_mutex);
      while (unlikely(psync_list_isempty(&free_pages))) {
        pthread_mutex_unlock(&cache_mutex);
        pdbg_logf(D_NOTICE, "no free pages after flush, sleeping");
        psys_sleep_milliseconds(200);
        flush_pages(1);
        pthread_mutex_lock(&cache_mutex);
      }
    } else
      pdbg_logf(D_NOTICE, "waited for a free page");
    page =
        psync_list_remove_head_element(&free_pages, psync_cache_page_t, list);
  }
  cache_pages_free--;
  pthread_mutex_unlock(&cache_mutex);
  if (runthread)
    prun_thread("flush pages get free page", flush_pages_noret);
  return page;
}

static int psync_api_send_read_request(psock_t *api, psync_fileid_t fileid,
                                       uint64_t hash, uint64_t offset,
                                       uint64_t length) {
  binparam params[] = {PAPI_STR("auth", psync_my_auth), PAPI_NUM("fileid", fileid),
                       PAPI_NUM("hash", hash), PAPI_NUM("offset", offset),
                       PAPI_NUM("count", length)};
  return papi_send_no_res(api, "readfile", params) == PTR_OK ? 0 : -1;
}

static int psync_api_send_read_request_thread(psock_t *api,
                                              psync_fileid_t fileid,
                                              uint64_t hash, uint64_t offset,
                                              uint64_t length) {
  binparam params[] = {PAPI_STR("auth", psync_my_auth), PAPI_NUM("fileid", fileid),
                       PAPI_NUM("hash", hash), PAPI_NUM("offset", offset),
                       PAPI_NUM("count", length)};
  return papi_send_no_res_thread(api, "readfile", params) == PTR_OK ? 0 : -1;
}

static void psync_pagecache_send_page_wait_page(psync_page_wait_t *pw,
                                                psync_cache_page_t *page) {
  psync_page_waiter_t *pwt;
  psync_list_del(&pw->list);
  psync_list_for_each_element(pwt, &pw->waiters, psync_page_waiter_t,
                              listpage) {
    page->usecnt++;
    if (pwt->off + pwt->size > page->size) {
      if (pwt->off >= page->size)
        pwt->rsize = 0;
      else
        pwt->rsize = page->size - pwt->off;
    } else
      pwt->rsize = pwt->size;
    memcpy(pwt->buff, page->page + pwt->off, pwt->rsize);
    pwt->error = 0;
    pwt->ready = 1;
    pwt->waiting_for = NULL;
    pthread_cond_broadcast(&pwt->cond);
  }
  free(pw);
}

static void psync_pagecache_return_free_page_locked(psync_cache_page_t *page) {
  psync_list_add_head(&free_pages, &page->list);
  cache_pages_free++;
}

static void psync_pagecache_return_free_page(psync_cache_page_t *page) {
  pthread_mutex_lock(&cache_mutex);
  psync_pagecache_return_free_page_locked(page);
  pthread_mutex_unlock(&cache_mutex);
}

static int psync_pagecache_read_range_from_api(psync_request_t *request,
                                               psync_request_range_t *range,
                                               psock_t *api) {
  uint64_t first_page_id, dlen;
  psync_page_wait_t *pw;
  psync_cache_page_t *page;
  binresult *res;
  unsigned long len, i, h;
  int rb;
  first_page_id = range->offset / PSYNC_FS_PAGE_SIZE;
  len = range->length / PSYNC_FS_PAGE_SIZE;
  res = papi_result_thread(api);
  if (pdbg_unlikely(!res))
    return -2;
  dlen = papi_find_result2(res, "result", PARAM_NUM)->num;
  if (unlikely(dlen)) {
    free(res);
    pdbg_logf(D_WARNING, "readfile returned error %lu", (long unsigned)dlen);
    psync_process_api_error(dlen);
    return -2;
  }
  dlen = papi_find_result2(res, "data", PARAM_DATA)->num;
  free(res);
  for (i = 0; i < len; i++) {
    page = psync_pagecache_get_free_page(0);
    rb = psync_socket_readall_download_thread(
        api, page->page, dlen < PSYNC_FS_PAGE_SIZE ? dlen : PSYNC_FS_PAGE_SIZE);
    if (pdbg_unlikely(rb <= 0)) {
      psync_pagecache_return_free_page(page);
      ptimer_notify_exception();
      return i == 0 ? -2 : -1;
    }
    dlen -= rb;
    page->hash = request->hash;
    page->pageid = first_page_id + i;
    page->lastuse = ptimer_time();
    page->size = rb;
    page->usecnt = 0;
    page->crc = pcrc32c_compute(PSYNC_CRC_INITIAL, page->page, rb);
    page->type = PAGE_TYPE_READ;
    h = waiterhash_by_hash_and_pageid(page->hash, page->pageid);
    lock_wait(page->hash);
    psync_list_for_each_element(pw, &wait_page_hash[h], psync_page_wait_t,
                                list) if (pw->hash == page->hash &&
                                          pw->pageid == page->pageid) {
      psync_pagecache_send_page_wait_page(pw, page);
      break;
    }
    unlock_wait(page->hash);
    pthread_mutex_lock(&cache_mutex);
    psync_list_add_tail(
        &cache_hash[pagehash_by_hash_and_pageid(page->hash, page->pageid)],
        &page->list);
    cache_pages_in_hash++;
    pthread_mutex_unlock(&cache_mutex);
  }
  return 0;
}

typedef struct {
  psync_list list;
  pthread_cond_t cond;
  psock_t *api;
} shared_api_waiter_t;

static pthread_mutex_t sharedapi_mutex = PTHREAD_MUTEX_INITIALIZER;
static psock_t *sharedapi = NULL;
static psync_list sharedapiwaiters = PSYNC_LIST_STATIC_INIT(sharedapiwaiters);

static void mark_api_shared(psock_t *api) {
  pthread_mutex_lock(&sharedapi_mutex);
  if (!sharedapi)
    sharedapi = api;
  pthread_mutex_unlock(&sharedapi_mutex);
}

static void signal_all_waiters() {
  shared_api_waiter_t *waiter;
  while (!psync_list_isempty(&sharedapiwaiters)) {
    waiter = psync_list_remove_head_element(&sharedapiwaiters,
                                            shared_api_waiter_t, list);
    waiter->api = (psock_t *)-1;
    pthread_cond_signal(&waiter->cond);
  }
}

static void mark_shared_api_bad(psock_t *api) {
  pthread_mutex_lock(&sharedapi_mutex);
  if (sharedapi == api) {
    sharedapi = NULL;
    signal_all_waiters();
  }
  pthread_mutex_unlock(&sharedapi_mutex);
}

static int pass_shared_api(psock_t *api) {
  shared_api_waiter_t *waiter;
  int ret;
  pthread_mutex_lock(&sharedapi_mutex);
  if (api != sharedapi)
    ret = -1;
  else if (psync_list_isempty(&sharedapiwaiters)) {
    ret = -1;
    sharedapi = NULL;
  } else {
    ret = 0;
    waiter = psync_list_remove_head_element(&sharedapiwaiters,
                                            shared_api_waiter_t, list);
    waiter->api = api;
    pthread_cond_signal(&waiter->cond);
    pdbg_logf(D_NOTICE, "passing shared api connection");
  }
  pthread_mutex_unlock(&sharedapi_mutex);
  return ret;
}

static psock_t *get_shared_api() {
  pthread_mutex_lock(&sharedapi_mutex);
  if (sharedapi)
    return sharedapi; // not supposed to unlock, it will happen in
                      // wait_shared_api
  pthread_mutex_unlock(&sharedapi_mutex);
  return NULL;
}

static void release_bad_shared_api(psock_t *api) {
  if (sharedapi == api) {
    sharedapi = NULL;
    signal_all_waiters();
  }
  pthread_mutex_unlock(&sharedapi_mutex);
}

static int wait_shared_api() {
  shared_api_waiter_t *waiter;
  psock_t *capi;
  int ret;
  capi = sharedapi;
  waiter = malloc(sizeof(shared_api_waiter_t));
  pthread_cond_init(&waiter->cond, NULL);
  waiter->api = NULL;
  psync_list_add_tail(&sharedapiwaiters, &waiter->list);
  pdbg_logf(D_NOTICE, "waiting for shared API connection");
  do {
    pthread_cond_wait(&waiter->cond, &sharedapi_mutex);
  } while (!waiter->api);
  if (waiter->api != capi) {
    pdbg_assertw(waiter->api == (psock_t *)-1);
    ret = -1;
  } else {
    pdbg_logf(D_NOTICE, "waited for shared API connection");
    ret = 0;
  }
  pthread_mutex_unlock(&sharedapi_mutex);
  pthread_cond_destroy(&waiter->cond);
  free(waiter);
  return ret;
}

static void set_urls(psync_urls_t *urls, binresult *res) {
  pthread_mutex_lock(&url_cache_mutex);
  if (res) {
    urls->status = 1;
    urls->urls = res;
    if (urls->refcnt++ > 0)
      pthread_cond_broadcast(&url_cache_cond);
  } else {
    ptree_del(&url_cache_tree, &urls->tree);
    if (urls->refcnt) {
      urls->status = 2;
      pthread_cond_broadcast(&url_cache_cond);
    } else
      free(urls);
  }
  pthread_mutex_unlock(&url_cache_mutex);
}

static void psync_pagecache_set_bad_encoder(psync_openfile_t *of) {
  psync_fs_lock_file(of);
  if (likely(of->encoder == PSYNC_CRYPTO_LOADING_SECTOR_ENCODER)) {
    of->encoder = PSYNC_CRYPTO_FAILED_SECTOR_ENCODER;
    pthread_cond_broadcast(&enc_key_cond);
  }
  pthread_mutex_unlock(&of->mutex);
}

static int send_key_request(psock_t *api, psync_request_t *request) {
  binparam params[] = {PAPI_STR("auth", psync_my_auth),
                       PAPI_NUM("fileid", request->fileid)};
  return papi_send_no_res(api, "crypto_getfilekey", params) != PTR_OK ? -1
                                                                         : 0;
}

static int get_urls(psync_request_t *request, psync_urls_t *urls) {
  binparam params[] = {
      PAPI_STR("auth", psync_my_auth), PAPI_NUM("fileid", request->fileid),
      PAPI_NUM("hash", request->hash), PAPI_STR("timeformat", "timestamp"),
      PAPI_BOOL("skipfilename", 1)};
  psock_t *api;
  binresult *ret;
  psync_request_range_t *range;
  psync_list *l1, *l2;
  const binresult *hosts;
  uint64_t totalreqlen;
  unsigned long result;
  int tries;
  pdbg_logf(D_NOTICE,
        "getting file URLs of fileid %lu, hash %lu together with requests%s",
        (unsigned long)request->fileid, (unsigned long)request->hash,
        request->needkey ? " and encryption key" : "");
  tries = 0;
  while (tries++ <= 5) {
    api = psync_apipool_get();
    if (pdbg_unlikely(!api))
      continue;
    psock_set_write_buffered(api);
    if (unlikely(papi_send_no_res(api, "getfilelink", params) != PTR_OK))
      goto err1;
    if (request->needkey && send_key_request(api, request))
      goto err1;
    totalreqlen = 0;
    psync_list_for_each_element(range, &request->ranges, psync_request_range_t,
                                list) {
      pdbg_logf(D_NOTICE, "sending request for offset %lu, size %lu to API",
            (unsigned long)range->offset, (unsigned long)range->length);
      if (unlikely(psync_api_send_read_request(api, request->fileid,
                                               request->hash, range->offset,
                                               range->length)))
        goto err1;
      totalreqlen += range->length;
    }
    mark_api_shared(api);
    ret = papi_result_thread(api);
    if (pdbg_unlikely(!ret)) {
      mark_shared_api_bad(api);
      goto err1;
    }
    result = papi_find_result2(ret, "result", PARAM_NUM)->num;
    if (unlikely(result != 0)) {
      pdbg_logf(D_WARNING, "getfilelink returned error %lu", result);
      free(ret);
      mark_shared_api_bad(api);
      psync_apipool_release_bad(api);
      psync_process_api_error(result);
      break;
    }
    hosts = papi_find_result2(ret, "hosts", PARAM_ARRAY);
    pdbg_logf(D_NOTICE, "got file URLs of fileid %lu, hash %lu",
          (unsigned long)request->fileid, (unsigned long)request->hash);
    if (pdbg_likely(hosts->length && hosts->array[0]->type == PARAM_STR) &&
        request->of->initialsize > totalreqlen)
      psync_http_connect_and_cache_host(hosts->array[0]->str);
    set_urls(urls, ret);
    if (request->needkey) {
      pcrypto_sector_encdec_t enc;
      ret = papi_result_thread(api);
      if (pdbg_unlikely(!ret))
        goto err3;
      result = papi_find_result2(ret, "result", PARAM_NUM)->num;
      if (unlikely(result != 0)) {
        pdbg_logf(D_WARNING, "crypto_getfilekey returned error %lu", result);
        psync_process_api_error(result);
        goto err4;
      }
      enc = pcryptofolder_filencoder_from_binresult(request->fileid,
                                                               ret);
      if (pdbg_unlikely(psync_crypto_is_error(enc)))
        goto err4;
      pdbg_logf(D_NOTICE, "got key for fileid %lu", (unsigned long)request->fileid);
      free(ret);
      psync_fs_lock_file(request->of);
      if (pdbg_likely(request->of->encoder ==
                     PSYNC_CRYPTO_LOADING_SECTOR_ENCODER)) {
        request->of->encoder = enc;
        pthread_cond_broadcast(&enc_key_cond);
      } else
        pcryptofolder_filencoder_release(request->fileid, request->hash,
                                                enc);
      pthread_mutex_unlock(&request->of->mutex);
      request->needkey = 0;
    }
    psync_list_for_each_safe(l1, l2, &request->ranges) {
      range = psync_list_element(l1, psync_request_range_t, list);
      if (psync_pagecache_read_range_from_api(request, range, api))
        goto err2;
      psync_list_del(l1);
      pdbg_logf(D_NOTICE, "request for offset %lu, size %lu read from API",
            (unsigned long)range->offset, (unsigned long)range->length);
      free(range);
    }
    if (pass_shared_api(api))
      psync_apipool_release(api);
    return 0;
  err1:
    psync_apipool_release_bad(api);
  }
  return -1;
err4:
  free(ret);
err3:
  if (request->needkey)
    psync_pagecache_set_bad_encoder(request->of);
err2:
  mark_shared_api_bad(api);
  psync_apipool_release_bad(api);
  return 0;
}

static psync_urls_t *get_urls_for_request(psync_request_t *req) {
  char buff[16];
  psync_tree *el, **pel;
  psync_urls_t *urls;
  binresult *res;
  int64_t d;
  pthread_mutex_lock(&url_cache_mutex);
  el = url_cache_tree;
  pel = &url_cache_tree;
  d = -1;
  while (el) {
    urls = ptree_element(el, psync_urls_t, tree);
    d = req->hash - urls->hash;
    if (d == 0)
      break;
    else if (d < 0) {
      if (el->left)
        el = el->left;
      else {
        pel = &el->left;
        break;
      }
    } else {
      if (el->right)
        el = el->right;
      else {
        pel = &el->right;
        break;
      }
    }
  }
  if (d == 0) {
    urls->refcnt++;
    while (urls->status == 0)
      pthread_cond_wait(&url_cache_cond, &url_cache_mutex);
    if (likely(urls->status == 1)) {
      pthread_mutex_unlock(&url_cache_mutex);
      return urls;
    }
    if (--urls->refcnt == 0)
      free(urls);
    pthread_mutex_unlock(&url_cache_mutex);
    return NULL;
  }
  urls = malloc(sizeof(psync_urls_t));
  urls->hash = req->hash;
  urls->refcnt = 0;
  urls->status = 0;
  *pel = &urls->tree;
  ptree_added_at(&url_cache_tree, el, &urls->tree);
  pthread_mutex_unlock(&url_cache_mutex);
  psync_get_string_id(buff, "URLS", req->hash);
  res = (binresult *)pcache_get(buff);
  if (res) {
    set_urls(urls, res);
    return urls;
  }
  if (get_urls(req, urls)) {
    set_urls(urls, NULL);
    return NULL;
  } else
    return urls;
}

static void release_urls(psync_urls_t *urls) {
  pthread_mutex_lock(&url_cache_mutex);
  if (--urls->refcnt == 0) {
    if (likely(urls->status == 1)) {
      char buff[16];
      time_t ctime, etime;
      ptree_del(&url_cache_tree, &urls->tree);
      ctime = ptimer_time();
      etime = papi_find_result2(urls->urls, "expires", PARAM_NUM)->num;
      if (etime > ctime + 3600) {
        psync_get_string_id(buff, "URLS", urls->hash);
        pcache_add(buff, urls->urls, etime - ctime - 3600, free, 2);
        urls->urls = NULL;
      }
    }
    pthread_mutex_unlock(&url_cache_mutex);
    free(urls->urls);
    free(urls);
    return;
  }
  pthread_mutex_unlock(&url_cache_mutex);
}

static void release_bad_urls(psync_urls_t *urls) {
  pthread_mutex_lock(&url_cache_mutex);
  if (urls->status == 1) {
    urls->status = 2;
    ptree_del(&url_cache_tree, &urls->tree);
  }
  if (--urls->refcnt)
    urls = NULL;
  pthread_mutex_unlock(&url_cache_mutex);
  if (urls) {
    free(urls->urls);
    free(urls);
  }
}

static uint64_t offset_round_down_to_page(uint64_t offset) {
  return offset & ~(((uint64_t)PSYNC_FS_PAGE_SIZE) - 1);
}

static uint64_t size_round_up_to_page(uint64_t size) {
  return ((size - 1) | (((uint64_t)PSYNC_FS_PAGE_SIZE) - 1)) + 1;
}

static int has_page_in_cache_by_hash(uint64_t hash, uint64_t pageid) {
  psync_cache_page_t *page;
  unsigned long h;
  h = pagehash_by_hash_and_pageid(hash, pageid);
  pthread_mutex_lock(&cache_mutex);
  psync_list_for_each_element(page, &cache_hash[h], psync_cache_page_t,
                              list) if (page->hash == hash &&
                                        page->pageid == pageid) {
    pthread_mutex_unlock(&cache_mutex);
    return 1;
  }
  pthread_mutex_unlock(&cache_mutex);
  return 0;
}

static unsigned char *has_pages_in_db(uint64_t hash, uint64_t pageid,
                                      uint32_t pagecnt, int readahead) {
  psync_sql_res *res;
  psync_uint_row row;
  unsigned char *ret;
  uint64_t fromid;
  uint32_t fcnt;
  if (unlikely(!pagecnt))
    return NULL;
  ret = malloc(sizeof(unsigned char) * pagecnt);
  memset(ret, 0, pagecnt);
  fromid = 0;
  fcnt = 0;
  res = psql_query_rdlock(
      "SELECT pageid, id FROM pagecache WHERE type=+" NTO_STR(
          PAGE_TYPE_READ) " AND hash=? AND pageid>=? AND pageid<? ORDER BY "
                          "pageid");
  psql_bind_uint(res, 1, hash);
  psql_bind_uint(res, 2, pageid);
  psql_bind_uint(res, 3, pageid + pagecnt);
  while ((row = psql_fetch_int(res))) {
    ret[row[0] - pageid] = 1;
    if (row[1] == fromid + fcnt)
      fcnt++;
    else {
      if (fcnt && readahead)
        pfile_readahead(readcache, fromid * PSYNC_FS_PAGE_SIZE,
                             fcnt * PSYNC_FS_PAGE_SIZE);
      fromid = row[1];
      fcnt = 1;
    }
  }
  psql_free(res);
  if (fcnt && readahead)
    pfile_readahead(readcache, fromid * PSYNC_FS_PAGE_SIZE,
                         fcnt * PSYNC_FS_PAGE_SIZE);
  return ret;
}

static int has_page_in_db(uint64_t hash, uint64_t pageid) {
  psync_sql_res *res;
  psync_uint_row row;
  res = psql_query_rdlock(
      "SELECT pageid FROM pagecache WHERE type=+" NTO_STR(
          PAGE_TYPE_READ) " AND hash=? AND pageid=?");
  psql_bind_uint(res, 1, hash);
  psql_bind_uint(res, 2, pageid);
  row = psql_fetch_int(res);
  psql_free(res);
  return row != NULL;
}

static long check_page_in_memory_by_hash(uint64_t hash, uint64_t pageid,
                                                char *buff, unsigned long size,
                                                unsigned long off) {
  psync_cache_page_t *page;
  unsigned long h;
  long ret;
  uint32_t crc;
  time_t tm;
  ret = -1;
  h = pagehash_by_hash_and_pageid(hash, pageid);
  pthread_mutex_lock(&cache_mutex);
  psync_list_for_each_element(page, &cache_hash[h], psync_cache_page_t,
                              list) if (page->hash == hash &&
                                        page->pageid == pageid) {
    psync_prefetch(page->page);
    tm = ptimer_time();
    if (tm > page->lastuse + 5) {
      page->usecnt++;
      page->lastuse = tm;
    }
    crc = pcrc32c_compute(PSYNC_CRC_INITIAL, page->page, page->size);
    if (unlikely(crc != page->crc)) {
      pdbg_logf(D_WARNING,
            "memory page CRC does not match %u!=%u, this is most likely memory "
            "fault or corruption, pageid %u",
            (unsigned)crc, (unsigned)page->crc, (unsigned)page->pageid);
      psync_list_del(&page->list);
      psync_pagecache_return_free_page_locked(page);
      cache_pages_in_hash--;
      break;
    }
    if (size + off > page->size) {
      if (off > page->size)
        size = 0;
      else
        size = page->size - off;
    }
    memcpy(buff, page->page + off, size);
    ret = size;
  }
  pthread_mutex_unlock(&cache_mutex);
  return ret;
}

static int switch_memory_page_to_hash(uint64_t oldhash, uint64_t newhash,
                                      uint64_t pageid) {
  psync_cache_page_t *page;
  unsigned long ho, hn;
  ho = pagehash_by_hash_and_pageid(oldhash, pageid);
  hn = pagehash_by_hash_and_pageid(newhash, pageid);
  pthread_mutex_lock(&cache_mutex);
  psync_list_for_each_element(page, &cache_hash[ho], psync_cache_page_t,
                              list) if (page->hash == oldhash &&
                                        page->pageid == pageid &&
                                        page->type == PAGE_TYPE_READ) {
    psync_list_del(&page->list);
    page->hash = newhash;
    psync_list_add_tail(&cache_hash[hn], &page->list);
    pthread_mutex_unlock(&cache_mutex);
    return 1;
  }
  pthread_mutex_unlock(&cache_mutex);
  return 0;
}

typedef struct {
  uint32_t lastuse;
  uint32_t id;
  uint16_t usecnt;
  int8_t isfirst;
  int8_t isxfirst;
} pagecache_entry;

static int pagecache_entry_cmp_lastuse(const void *p1, const void *p2) {
  const pagecache_entry *e1, *e2;
  e1 = (const pagecache_entry *)p1;
  e2 = (const pagecache_entry *)p2;
  return (int)((int64_t)e2->lastuse - (int64_t)e1->lastuse);
}

static int pagecache_entry_cmp_usecnt_lastuse2(const void *p1, const void *p2) {
  const pagecache_entry *e1, *e2;
  e1 = (const pagecache_entry *)p1;
  e2 = (const pagecache_entry *)p2;
  if (e1->usecnt >= 2 && e2->usecnt < 2)
    return -1;
  else if (e2->usecnt >= 2 && e1->usecnt < 2)
    return 1;
  else
    return (int)((int64_t)e2->lastuse - (int64_t)e1->lastuse);
}

static int pagecache_entry_cmp_usecnt_lastuse4(const void *p1, const void *p2) {
  const pagecache_entry *e1, *e2;
  e1 = (const pagecache_entry *)p1;
  e2 = (const pagecache_entry *)p2;
  if (e1->usecnt >= 4 && e2->usecnt < 4)
    return -1;
  else if (e2->usecnt >= 4 && e1->usecnt < 4)
    return 1;
  else
    return (int)((int64_t)e2->lastuse - (int64_t)e1->lastuse);
}

static int pagecache_entry_cmp_usecnt_lastuse8(const void *p1, const void *p2) {
  const pagecache_entry *e1, *e2;
  e1 = (const pagecache_entry *)p1;
  e2 = (const pagecache_entry *)p2;
  if (e1->usecnt >= 8 && e2->usecnt < 8)
    return -1;
  else if (e2->usecnt >= 8 && e1->usecnt < 8)
    return 1;
  else
    return (int)((int64_t)e2->lastuse - (int64_t)e1->lastuse);
}

static int pagecache_entry_cmp_usecnt_lastuse16(const void *p1,
                                                const void *p2) {
  const pagecache_entry *e1, *e2;
  e1 = (const pagecache_entry *)p1;
  e2 = (const pagecache_entry *)p2;
  if (e1->usecnt >= 16 && e2->usecnt < 16)
    return -1;
  else if (e2->usecnt >= 16 && e1->usecnt < 16)
    return 1;
  else
    return (int)((int64_t)e2->lastuse - (int64_t)e1->lastuse);
}

static int pagecache_entry_cmp_id(const void *p1, const void *p2) {
  return (int)((const pagecache_entry *)p1)->id -
         (int)((const pagecache_entry *)p2)->id;
}

static int pagecache_entry_cmp_first_pages(const void *p1, const void *p2) {
  const pagecache_entry *e1, *e2;
  int d;
  e1 = (const pagecache_entry *)p1;
  e2 = (const pagecache_entry *)p2;
  d = (int)e2->isfirst - (int)e1->isfirst;
  if (d)
    return d;
  else if (e1->isfirst)
    return (int)((int64_t)e2->lastuse - (int64_t)e1->lastuse);
  else {
    d = (int)e2->isxfirst - (int)e1->isxfirst;
    if (d)
      return d;
    else
      return (int)((int64_t)e2->lastuse - (int64_t)e1->lastuse);
  }
}

static int pagecache_entry_cmp_xfirst_pages(const void *p1, const void *p2) {
  const pagecache_entry *e1, *e2;
  int d;
  e1 = (const pagecache_entry *)p1;
  e2 = (const pagecache_entry *)p2;
  d = (int)e2->isxfirst - (int)e1->isxfirst;
  if (d)
    return d;
  else
    return (int)((int64_t)e2->lastuse - (int64_t)e1->lastuse);
}


static inline void sw2(unsigned char **a, unsigned char **b) {
  unsigned char *tmp = *a;
  *a = *b;
  *b = tmp;
}

static unsigned char *med5(unsigned char *a, unsigned char *b, unsigned char *c,
                           unsigned char *d, unsigned char *e,
                           int (*compar)(const void *, const void *)) {
  if (compar(b, a) < 0)
    sw2(&a, &b);
  if (compar(d, c) < 0)
    sw2(&c, &d);
  if (compar(a, c) < 0) {
    a = e;
    if (compar(b, a) < 0)
      sw2(&a, &b);
  } else {
    c = e;
    if (compar(d, c) < 0)
      sw2(&c, &d);
  }
  if (compar(a, c) < 0)
    a = b;
  else
    c = d;
  if (compar(a, c) < 0)
    return a;
  else
    return c;
}

static uint32_t pq_rnd() {
  static uint32_t a = 0x95ae3d25, b = 0xe225d755, c = 0xc63a2ae7,
                  d = 0xe4556265;
  uint32_t e = a - rot(b, 27);
  a = b ^ rot(c, 17);
  b = c + d;
  c = d + e;
  d = e + a;
  return d;
}

static unsigned char *pq_choose_part(unsigned char *base, size_t cnt, size_t size,
                              int (*compar)(const void *, const void *)) {
  if (cnt >= QSORT_REC_M) {
    cnt /= 5;
    return med5(pq_choose_part(base, cnt, size, compar),
                pq_choose_part(base + cnt * size, cnt, size, compar),
                pq_choose_part(base + cnt * size * 2, cnt, size, compar),
                pq_choose_part(base + cnt * size * 3, cnt, size, compar),
                pq_choose_part(base + cnt * size * 4, cnt, size, compar),
                compar);
  } else {
    return med5(base + (pq_rnd() % cnt) * size, base + (pq_rnd() % cnt) * size,
                base + (pq_rnd() % cnt) * size, base + (pq_rnd() % cnt) * size,
                base + (pq_rnd() % cnt) * size, compar);
  }
}

static inline void pqsswap(unsigned char *a, unsigned char *b, size_t size) {
  unsigned char tmp;
  do {
    tmp = *a;
    *a++ = *b;
    *b++ = tmp;
  } while (--size);
}

static inline void pqsswap32(unsigned char *a, unsigned char *b, size_t size) {
  uint32_t tmp;
  do {
    tmp = *(uint32_t *)a;
    *(uint32_t *)a = *(uint32_t *)b;
    *(uint32_t *)b = tmp;
    a += sizeof(uint32_t);
    b += sizeof(uint32_t);
  } while (--size);
}

static void psync_pqsort(void *base, size_t cnt, size_t sort_first, size_t size,
                  int (*compar)(const void *, const void *)) {
  psq_stack_t stack[sizeof(size_t) * 8];
  psq_stack_t *top;
  unsigned char *lo, *hi, *mid, *l, *r, *sf;
  size_t tresh, n, u32size;

  lo = NULL;
  hi = NULL;
  mid = NULL;
  l = NULL;
  r = NULL;
  sf = NULL;

  tresh = QSORT_TRESH * size;
  sf = (unsigned char *)base + sort_first * size;
  if (size % sizeof(uint32_t) == 0 && (uintptr_t)base % sizeof(uint32_t) == 0)
    u32size = size / sizeof(uint32_t);
  else
    u32size = 0;
  if (cnt > QSORT_TRESH) {
    top = stack + 1;
    lo = (unsigned char *)base;
    hi = lo + (cnt - 1) * size;
    do {
      n = (hi - lo) / size;
      if (n <= QSORT_MTR) {
        mid = lo + (n >> 1) * size;
        if (compar(mid, lo) < 0)
          pqsswap(mid, lo, size);
        if (compar(hi, mid) < 0) {
          pqsswap(mid, hi, size);
          if (compar(mid, lo) < 0)
            pqsswap(mid, lo, size);
        }
        // we already sure *hi and *lo are good, so they will be skipped without
        // checking
        l = lo;
        r = hi;
      } else {
        mid = pq_choose_part(lo, n, size, compar);
        l = lo - size;
        r = hi + size;
      }
      if (u32size) {
        do {
          do {
            l += size;
          } while (compar(l, mid) < 0);
          do {
            r -= size;
          } while (compar(mid, r) < 0);
          if (l >= r)
            break;
          pqsswap32(l, r, u32size);
          if (mid == l) {
            mid = r;
            r += size;
          } else if (mid == r) {
            mid = l;
            l -= size;
          }
        } while (1);
      } else {
        do {
          do {
            l += size;
          } while (compar(l, mid) < 0);
          do {
            r -= size;
          } while (compar(mid, r) < 0);
          if (l >= r)
            break;
          pqsswap(l, r, size);
          if (mid == l) {
            mid = r;
            r += size;
          } else if (mid == r) {
            mid = l;
            l -= size;
          }
        } while (1);
      }
      if (hi - mid <= tresh || mid >= sf) {
        if (mid - lo <= tresh) {
          top--;
          lo = top->lo;
          hi = top->hi;
        } else {
          hi = mid - size;
        }
      } else if (mid - lo <= tresh) {
        lo = mid + size;
      } else if (hi - mid < mid - lo) {
        top->lo = lo;
        top->hi = mid - size;
        top++;
        lo = mid + size;
      } else {
        top->lo = mid + size;
        top->hi = hi;
        top++;
        hi = mid - size;
      }
    } while (top != stack);
  } else if (cnt <= 1) {
    return;
  }
  lo = (unsigned char *)base;
  hi = lo + (cnt - 1) * size;
  sf += size * QSORT_TRESH;
  if (sf < hi)
    hi = sf;
  r = lo + QSORT_TRESH * size + 4;
  if (r > hi)
    r = hi;
  for (l = lo + size; l <= r; l += size)
    if (compar(l, lo) < 0)
      lo = l;
  pqsswap((unsigned char *)base, lo, size);
  l = (unsigned char *)base + size;
  hi -= size;
  while (l <= hi) {
    lo = l;
    l += size;
    while (compar(l, lo) < 0)
      lo -= size;
    lo += size;
    if (lo != l) {
      unsigned char *t = l + size;
      if (u32size) {
        while ((t -= sizeof(uint32_t)) >= l) {
          uint32_t tmp = *(uint32_t *)t;
          for (r = mid = t; (mid -= size) >= lo; r = mid)
            *(uint32_t *)r = *(uint32_t *)mid;
          *(uint32_t *)r = tmp;
        }
      } else {
        while (--t >= l) {
          unsigned char tmp = *t;
          for (r = mid = t; (mid -= size) >= lo; r = mid)
            *r = *mid;
          *r = tmp;
        }
      }
    }
  }
}

static void psync_qpartition(void *base, size_t cnt, size_t sort_first, size_t size,
                      int (*compar)(const void *, const void *)) {
  unsigned char *lo, *hi, *mid, *l, *r, *sf;
  size_t n, u32size;
  sf = (unsigned char *)base + sort_first * size;
  if (size % sizeof(uint32_t) == 0 && (uintptr_t)base % sizeof(uint32_t) == 0)
    u32size = size / sizeof(uint32_t);
  else
    u32size = 0;
  if (cnt <= 1) // otherwise cnt-1 will underflow
    return;
  lo = (unsigned char *)base;
  hi = lo + (cnt - 1) * size;
  while (1) {
    n = (hi - lo) / size;
    if (n <= QSORT_MTR) {
      mid = lo + (n >> 1) * size;
      if (compar(mid, lo) < 0)
        pqsswap(mid, lo, size);
      if (compar(hi, mid) < 0) {
        pqsswap(mid, hi, size);
        if (compar(mid, lo) < 0)
          pqsswap(mid, lo, size);
      }
      // we already sure *hi and *lo are good, so they will be skipped without
      // checking
      if (n <= 2) // when n is 2, we have 3 elements
        return;
      l = lo;
      r = hi;
    } else {
      mid = pq_choose_part(lo, n, size, compar);
      l = lo - size;
      r = hi + size;
    }
    if (u32size) {
      do {
        do {
          l += size;
        } while (compar(l, mid) < 0);
        do {
          r -= size;
        } while (compar(mid, r) < 0);
        if (l >= r)
          break;
        pqsswap32(l, r, u32size);
        if (mid == l) {
          mid = r;
          r += size;
        } else if (mid == r) {
          mid = l;
          l -= size;
        }
      } while (1);
    } else {
      do {
        do {
          l += size;
        } while (compar(l, mid) < 0);
        do {
          r -= size;
        } while (compar(mid, r) < 0);
        if (l >= r)
          break;
        pqsswap(l, r, size);
        if (mid == l) {
          mid = r;
          r += size;
        } else if (mid == r) {
          mid = l;
          l -= size;
        }
      } while (1);
    }
    if (mid < sf)
      lo = mid + size;
    else if (mid > sf)
      hi = mid - size;
    else
      return;
  }
}


/* sum should be around 90-95 percent, so after a run cache get smaller */
#define PSYNC_FS_CACHE_LRU_PERCENT 40
#define PSYNC_FS_CACHE_LRU2_PERCENT 20
#define PSYNC_FS_CACHE_LRU4_PERCENT 15
#define PSYNC_FS_CACHE_LRU8_PERCENT 10
#define PSYNC_FS_CACHE_LRU16_PERCENT 5

/* first pages percent pages are first reserved for the least recently used
 * first pages and the above percents are only applied to the remainder, so it
 * is OK if first pages percent plus all the above go above 100%
 */
#define PSYNC_FS_CACHE_LRU_FIRST_PAGES_PERCENT 15
#define PSYNC_FS_CACHE_LRU_XFIRST_PAGES_PERCENT 5
#define PSYNC_FS_FIRST_PAGES_UNDER_ID                                          \
  (PSYNC_FS_MIN_READAHEAD_START / PSYNC_FS_PAGE_SIZE)
#define PSYNC_FS_XFIRST_PAGES_UNDER_ID (1024 * 1024 / PSYNC_FS_PAGE_SIZE)

static void clean_cache() {
  psync_sql_res *res;
  uint64_t ocnt, cnt, rcnt, i, e;
  psync_uint_row row;
  pagecache_entry *entries, *oentries;
  pdbg_logf(D_NOTICE, "cleaning cache, free cache pages %u",
        (unsigned)free_db_pages);
  if (pthread_mutex_trylock(&clean_cache_mutex)) {
    pdbg_logf(D_NOTICE, "cache clean already in progress, skipping");
    return;
  }
  while (clean_cache_stoppers) {
    clean_cache_waiters++;
    pthread_cond_wait(&clean_cache_cond, &clean_cache_mutex);
    if (--clean_cache_waiters) {
      // leave the last waiter to do the job
      pthread_mutex_unlock(&clean_cache_mutex);
      return;
    }
  }
  cnt = psql_cellint("SELECT MAX(id) FROM pagecache", 0);
  if (!cnt) {
    pthread_mutex_unlock(&clean_cache_mutex);
    pdbg_logf(D_NOTICE, "no entries in pagecache, cancelling cache clean");
    return;
  }
  clean_cache_in_progress = 1;
  psql_sync();
  entries = (pagecache_entry *)malloc(cnt * sizeof(pagecache_entry));
  i = 0;
  e = 0;
  while (i < cnt) {
    res =
        psql_query_rdlock("SELECT id, pageid, lastuse, usecnt, type FROM "
                               "pagecache WHERE id>? ORDER BY id LIMIT 50000");
    psql_bind_uint(res, 1, e);
    row = psql_fetch_int(res);
    if (unlikely(!row)) {
      psql_free(res);
      break;
    }
    do {
      if (unlikely(i >= cnt))
        break;
      e = row[0];
      if (likely(row[4] == PAGE_TYPE_READ)) {
        entries[i].lastuse = row[2];
        entries[i].id = row[0];
        if (row[3] > UINT16_MAX)
          entries[i].usecnt = UINT16_MAX;
        else
          entries[i].usecnt = row[3];
        entries[i].isfirst = row[2] < PSYNC_FS_FIRST_PAGES_UNDER_ID;
        entries[i].isxfirst = row[2] < PSYNC_FS_XFIRST_PAGES_UNDER_ID;
        i++;
        if ((i & 0x3ff) == 0x3ff && psql_waiting())
          break;
      }
      row = psql_fetch_int(res);
    } while (row);
    psql_free(res);
    if (free_db_pages)
      psys_sleep_milliseconds(1);
  }
  ocnt = cnt = i;
  oentries = entries;
  pdbg_logf(D_NOTICE, "read %lu entries", (unsigned long)cnt);

  rcnt = PSYNC_FS_CACHE_LRU_FIRST_PAGES_PERCENT * ocnt / 100;
  psync_qpartition(entries, cnt, rcnt, sizeof(pagecache_entry),
                   pagecache_entry_cmp_first_pages);
  cnt -= rcnt;
  entries += rcnt;
  pdbg_logf(D_NOTICE,
        "sorted first pages, reserved %lu pages, continuing with %lu entries",
        (unsigned long)rcnt, (unsigned long)cnt);

  rcnt = PSYNC_FS_CACHE_LRU_XFIRST_PAGES_PERCENT * ocnt / 100;
  psync_qpartition(entries, cnt, rcnt, sizeof(pagecache_entry),
                   pagecache_entry_cmp_xfirst_pages);
  cnt -= rcnt;
  entries += rcnt;
  pdbg_logf(D_NOTICE,
        "sorted extended first pages, reserved %lu pages, continuing with %lu "
        "entries",
        (unsigned long)rcnt, (unsigned long)cnt);

  ocnt = cnt;
  rcnt = PSYNC_FS_CACHE_LRU_PERCENT * ocnt / 100;
  psync_qpartition(entries, cnt, rcnt, sizeof(pagecache_entry),
                   pagecache_entry_cmp_lastuse);
  cnt -= rcnt;
  entries += rcnt;
  pdbg_logf(D_NOTICE,
        "sorted entries by lastuse, reserved %lu pages, continuing with %lu "
        "oldest entries",
        (unsigned long)rcnt, (unsigned long)cnt);

  rcnt = PSYNC_FS_CACHE_LRU2_PERCENT * ocnt / 100;
  psync_qpartition(entries, cnt, rcnt, sizeof(pagecache_entry),
                   pagecache_entry_cmp_usecnt_lastuse2);
  cnt -= rcnt;
  entries += rcnt;
  pdbg_logf(D_NOTICE,
        "sorted entries by more than 2 uses and lastuse, reserved %lu pages, "
        "continuing with %lu entries",
        (unsigned long)rcnt, (unsigned long)cnt);

  rcnt = PSYNC_FS_CACHE_LRU4_PERCENT * ocnt / 100;
  psync_qpartition(entries, cnt, rcnt, sizeof(pagecache_entry),
                   pagecache_entry_cmp_usecnt_lastuse4);
  cnt -= rcnt;
  entries += rcnt;
  pdbg_logf(D_NOTICE,
        "sorted entries by more than 4 uses and lastuse, reserved %lu pages, "
        "continuing with %lu entries",
        (unsigned long)rcnt, (unsigned long)cnt);

  rcnt = PSYNC_FS_CACHE_LRU8_PERCENT * ocnt / 100;
  psync_qpartition(entries, cnt, rcnt, sizeof(pagecache_entry),
                   pagecache_entry_cmp_usecnt_lastuse8);
  cnt -= rcnt;
  entries += rcnt;
  pdbg_logf(D_NOTICE,
        "sorted entries by more than 8 uses and lastuse, reserved %lu pages, "
        "continuing with %lu entries",
        (unsigned long)rcnt, (unsigned long)cnt);

  rcnt = PSYNC_FS_CACHE_LRU16_PERCENT * ocnt / 100;
  psync_qpartition(entries, cnt, rcnt, sizeof(pagecache_entry),
                   pagecache_entry_cmp_usecnt_lastuse16);
  cnt -= rcnt;
  entries += rcnt;
  pdbg_logf(D_NOTICE,
        "sorted entries by more than 16 uses and lastuse, reserved %lu pages, "
        "deleting %lu entries",
        (unsigned long)rcnt, (unsigned long)cnt);

  psync_pqsort(entries, cnt, cnt, sizeof(pagecache_entry),
               pagecache_entry_cmp_id);
  pdbg_logf(D_NOTICE, "sorted entries to delete by id to help the SQL");

  psql_start();
  res = psql_prepare("UPDATE pagecache SET type=" NTO_STR(
      PAGE_TYPE_FREE) ", hash=NULL, pageid=NULL, crc=NULL WHERE id=?");
  for (i = 0; i < cnt; i++) {
    psql_bind_uint(res, 1, entries[i].id);
    psql_run(res);
    free_db_pages++;
    if ((i & 0x1f) == 0x1f && psql_waiting()) {
      psql_free(res);
      psql_commit();
      pdbg_logf(D_NOTICE, "got waiters for sql lock, pausing for a while");
      psys_sleep_milliseconds(5);
      psql_start();
      res = psql_prepare("UPDATE pagecache SET type=" NTO_STR(
          PAGE_TYPE_FREE) ", hash=NULL, pageid=NULL, crc=NULL WHERE id=?");
    } else if ((i & 0xfff) == 0xfff) {
      psql_free(res);
      psql_commit();
      psql_start();
      res = psql_prepare("UPDATE pagecache SET type=" NTO_STR(
          PAGE_TYPE_FREE) ", hash=NULL, pageid=NULL, crc=NULL WHERE id=?");
    }
  }
  psql_free(res);
  psql_commit();
  clean_cache_in_progress = 0;
  pthread_mutex_unlock(&clean_cache_mutex);
  free(oentries);
  pdbg_logf(D_NOTICE, "syncing database");
  psql_sync();
  pdbg_logf(D_NOTICE, "finished cleaning cache, free cache pages %u",
        (unsigned)free_db_pages);
}

static int cmp_flush_pages(const psync_list *p1, const psync_list *p2) {
  const psync_cache_page_t *page1, *page2;
  page1 = psync_list_element(p1, const psync_cache_page_t, flushlist);
  page2 = psync_list_element(p2, const psync_cache_page_t, flushlist);
  if (page1->hash < page2->hash)
    return -1;
  else if (page1->hash > page2->hash)
    return 1;
  else if (page1->pageid < page2->pageid)
    return -1;
  else if (page1->pageid > page2->pageid)
    return 1;
  else
    return 0;
}

static int cmp_discard_pages(const psync_list *p1, const psync_list *p2) {
  const psync_cache_page_t *page1, *page2;
  page1 = psync_list_element(p1, const psync_cache_page_t, flushlist);
  page2 = psync_list_element(p2, const psync_cache_page_t, flushlist);
  if (page1->lastuse < page2->lastuse)
    return -1;
  else if (page1->lastuse > page2->lastuse)
    return 1;
  else
    return 0;
}

static int check_disk_full() {
  int64_t filesize, freespace;
  uint64_t minlocal, maxpage, addspc;
  psync_sql_res *res;
  db_cache_max_page = psql_cellint("SELECT MAX(id) FROM pagecache", 0);
  filesize = pfile_size(readcache);
  if (pdbg_unlikely(filesize == -1))
    return 0;
  freespace =
      ppath_free_space(psync_setting_get_string(_PS(fscachepath)));
  minlocal = psync_setting_get_uint(_PS(minlocalfreespace));
  if (pdbg_unlikely(freespace == -1))
    return 0;
  if (db_cache_max_page * PSYNC_FS_PAGE_SIZE > filesize)
    addspc = cache_pages_in_hash * PSYNC_FS_PAGE_SIZE;
  else
    addspc = 0;
  if (minlocal + addspc <= freespace) {
    psync_set_local_full(0);
    return 0;
  }
  pdbg_logf(D_NOTICE, "local disk is full, freespace=%lu, minfreespace=%lu",
        (unsigned long)freespace, (unsigned long)minlocal);
  psync_set_local_full(1);
  if (minlocal >= freespace)
    maxpage = filesize / PSYNC_FS_PAGE_SIZE;
  else
    maxpage = (filesize + freespace - minlocal) / PSYNC_FS_PAGE_SIZE;
  res = psql_prepare("DELETE FROM pagecache WHERE id>?");
  psql_bind_uint(res, 1, maxpage);
  psql_run_free(res);
  free_db_pages = psql_cellint(
      "SELECT COUNT(*) FROM pagecache WHERE type=" NTO_STR(PAGE_TYPE_FREE), 0);
  db_cache_max_page = maxpage;
  pdbg_logf(D_NOTICE, "free_db_pages=%u, db_cache_max_page=%lu",
        (unsigned)free_db_pages, (unsigned long)db_cache_max_page);
  return 1;
}

static int flush_pages(int nosleep) {
  static time_t lastflush = 0;
  psync_list *l1, *l2;
  psync_sql_res *res;
  psync_uint_row row;
  psync_cache_page_t *page;
  psync_list pages_to_flush;
  unsigned long i, updates, pagecnt;
  time_t ctime;
  uint32_t cpih;
  int ret, diskfull;
  pthread_mutex_lock(&cache_mutex);
  flush_page_running++;
  flushcacherun = 1;
  pthread_mutex_unlock(&cache_mutex);
  flushedbetweentimers = 1;
  pthread_mutex_lock(&flush_cache_mutex);
  diskfull = check_disk_full();
  updates = 0;
  pagecnt = 0;
  ctime = ptimer_time();
  psync_list_init(&pages_to_flush);
  pthread_mutex_lock(&cache_mutex);
  if (unlikely(diskfull && free_db_pages == 0)) {
    pdbg_logf(D_NOTICE, "disk is full, discarding some pages");
    for (i = 0; i < CACHE_HASH; i++)
      psync_list_for_each_safe(l1, l2, &cache_hash[i]) {
        page = psync_list_element(l1, psync_cache_page_t, list);
        if (page->type == PAGE_TYPE_READ)
          psync_list_add_tail(&pages_to_flush, &page->flushlist);
        else if (page->type == PAGE_TYPE_CACHE) {
          psync_list_del(&page->list);
          psync_list_add_head(&free_pages, &page->list);
          cache_pages_in_hash--;
          cache_pages_free++;
        }
      }
    pthread_mutex_unlock(&cache_mutex);
    psync_list_sort(&pages_to_flush, cmp_discard_pages);
    pthread_mutex_lock(&cache_mutex);
    i = 0;
    psync_list_for_each_element(page, &pages_to_flush, psync_cache_page_t,
                                flushlist) {
      psync_list_del(&page->list);
      psync_list_add_head(&free_pages, &page->list);
      cache_pages_in_hash--;
      cache_pages_free++;
      if (++i >= CACHE_PAGES / 2)
        break;
    }
    pdbg_logf(D_NOTICE, "discarded %u pages", (unsigned)i);
    psync_list_init(&pages_to_flush);
    if (free_page_waiters)
      pthread_cond_broadcast(&free_page_cond);
  }
  if (cache_pages_in_hash) {
    pdbg_logf(D_NOTICE, "flushing cache free_db_pages=%u", (unsigned)free_db_pages);
    cache_pages_reset = 0;
    for (i = 0; i < CACHE_HASH; i++)
      psync_list_for_each_safe(l1, l2, &cache_hash[i]) {
        page = psync_list_element(l1, psync_cache_page_t, list);
        if (page->type == PAGE_TYPE_READ) {
          psync_list_add_tail(&pages_to_flush, &page->flushlist);
          pagecnt++;
        } else if (page->type == PAGE_TYPE_CACHE) {
          psync_list_del(&page->list);
          psync_list_add_head(&free_pages, &page->list);
          cache_pages_free++;
        }
      }
    cache_pages_in_hash = pagecnt;
    if (pagecnt) {
      pthread_mutex_unlock(&cache_mutex);
      pdbg_logf(D_NOTICE, "cache_pages_in_hash=%u", (unsigned)pagecnt);
      psync_list_sort(&pages_to_flush, cmp_flush_pages);
      res =
          psql_query_rdlock("SELECT id FROM pagecache WHERE type=" NTO_STR(
              PAGE_TYPE_FREE) " ORDER BY id LIMIT ?");
      psql_bind_uint(res, 1, pagecnt);
      psync_list_for_each_element(page, &pages_to_flush, psync_cache_page_t,
                                  flushlist) {
        if (unlikely(!(row = psql_fetch_int(res)))) {
          psync_list *l1, *l2;
          l1 = &page->flushlist;
          do {
            l2 = l1->next;
            psync_list_del(l1);
            l1 = l2;
          } while (l1 != &pages_to_flush);
          break;
        }
        page->flushpageid = row[0];
      }
      psql_free(res);
      i = 0;
      psync_list_for_each_element(page, &pages_to_flush, psync_cache_page_t,
                                  flushlist) {
        if (pfile_pwrite(readcache, page->page, PSYNC_FS_PAGE_SIZE,
                              (uint64_t)page->flushpageid *
                                  PSYNC_FS_PAGE_SIZE) != PSYNC_FS_PAGE_SIZE) {
          pdbg_logf(D_ERROR, "write to cache file failed");
          pthread_mutex_unlock(&flush_cache_mutex);
          return -1;
        }
        i++;
      }
      pdbg_logf(D_NOTICE, "cache data of %u pages written", (unsigned)i);
      pfile_schedulesync(readcache);
      /* if we can afford it, wait a while before calling fsync() as at least on
       * Linux this blocks reads from the same file until it returns */
      if (nosleep != 1) {
        if (nosleep == 2)
          i = 180;
        else
          i = 0;
        pthread_mutex_lock(&cache_mutex);
        while (cache_pages_free >= CACHE_PAGES * 5 / 100 && i++ < 200) {
          pthread_mutex_unlock(&cache_mutex);
          psys_sleep_milliseconds(10);
          pthread_mutex_lock(&cache_mutex);
        }
        pthread_mutex_unlock(&cache_mutex);
      }
      pdbg_logf(D_NOTICE, "syncing cache data");
      if (pfile_sync(readcache)) {
        pdbg_logf(D_ERROR, "flush of cache file failed");
        pthread_mutex_unlock(&flush_cache_mutex);
        return -1;
      }
      pdbg_logf(D_NOTICE, "cache data synced");
      pthread_mutex_lock(&cache_mutex);
    }
  }
  pthread_mutex_unlock(&cache_mutex);
  psql_start();
  pthread_mutex_lock(&cache_mutex);
  if (db_cache_max_page < db_cache_in_pages && cache_pages_in_hash &&
      !diskfull) {
    i = 0;
    res = psql_prepare(
        "INSERT INTO pagecache (type) VALUES (" NTO_STR(PAGE_TYPE_FREE) ")");
    while (db_cache_max_page + i < db_cache_in_pages && i < CACHE_PAGES &&
           i < cache_pages_in_hash) {
      psql_run(res);
      i++;
      if (i % 64 == 0) {
        pthread_mutex_unlock(&cache_mutex);
        psql_free(res);
        psql_commit();
        if (!nosleep && !free_page_waiters)
          psys_sleep_milliseconds(1);
        psql_start();
        pthread_mutex_lock(&cache_mutex);
        res = psql_prepare(
            "INSERT INTO pagecache (type) VALUES (" NTO_STR(
                PAGE_TYPE_FREE) ")");
      }
    }
    psql_free(res);
    free_db_pages += i;
    db_cache_max_page += i;
    pdbg_logf(D_NOTICE,
          "inserted %lu new free pages to database, db_cache_in_pages=%lu, "
          "db_cache_max_page=%lu",
          (unsigned long)i, (unsigned long)db_cache_in_pages,
          (unsigned long)db_cache_max_page);
    updates++;
  }
  cpih = cache_pages_in_hash;
  if (!psync_list_isempty(&pages_to_flush)) {
    pagecnt = 0;
    res = psql_prepare(
        "UPDATE OR IGNORE pagecache SET hash=?, pageid=?, type=" NTO_STR(
            PAGE_TYPE_READ) ", lastuse=?, usecnt=?, size=?, crc=? WHERE id=?");
    psync_list_for_each_element(page, &pages_to_flush, psync_cache_page_t,
                                flushlist) {
      psync_list_del(&page->list);
      psql_bind_uint(res, 1, page->hash);
      psql_bind_uint(res, 2, page->pageid);
      psql_bind_uint(res, 3, page->lastuse);
      psql_bind_uint(res, 4, page->usecnt);
      psql_bind_uint(res, 5, page->size);
      psql_bind_uint(res, 6, page->crc);
      psql_bind_uint(res, 7, page->flushpageid);
      psql_run(res);
      if (likely(psql_affected())) {
        updates++;
        pagecnt++;
        free_db_pages--;
      }
      psync_list_add_head(&free_pages, &page->list);
      cache_pages_free++;
      if (nosleep != 1 && updates % 64 == 0) {
        if (free_page_waiters)
          pthread_cond_broadcast(&free_page_cond);
        pthread_mutex_unlock(&cache_mutex);
        psql_free(res);
        psql_commit();
        if (!free_page_waiters) // it is ok if we read a stale value, because we
                                // don't hold cache_mutex any more
          psys_sleep_milliseconds(1);
        psql_start();
        pthread_mutex_lock(&cache_mutex);
        res = psql_prepare(
            "UPDATE OR IGNORE pagecache SET hash=?, pageid=?, type=" NTO_STR(
                PAGE_TYPE_READ) ", lastuse=?, usecnt=?, size=?, crc=? WHERE "
                                "id=?");
      }
    }
    psql_free(res);
    pdbg_logf(D_NOTICE,
          "flushed %u pages to cache file, free db pages %u, "
          "cache_pages_in_hash=%u",
          (unsigned)pagecnt, (unsigned)free_db_pages,
          (unsigned)cache_pages_in_hash);
    cache_pages_in_hash -= pagecnt;
  }
  if (cachepages_to_update_cnt &&
      (cpih || cachepages_to_update_cnt >= DB_CACHE_UPDATE_HASH / 4 ||
       lastflush + 300 < ctime)) {
    res = psql_prepare(
        "UPDATE pagecache SET lastuse=?, usecnt=usecnt+? WHERE id=?");
    for (i = 0; i < DB_CACHE_UPDATE_HASH; i++)
      if (cachepages_to_update[i].pagecacheid) {
        psql_bind_uint(res, 1, cachepages_to_update[i].lastuse);
        psql_bind_uint(res, 2, cachepages_to_update[i].usecnt);
        psql_bind_uint(res, 3, cachepages_to_update[i].pagecacheid);
        psql_run(res);
        memset(&cachepages_to_update[i], 0, sizeof(psync_cachepage_to_update));
        updates++;
        if (!nosleep && updates % 128 == 0) {
          pthread_mutex_unlock(&cache_mutex);
          psql_free(res);
          psql_commit();
          if (!free_page_waiters)
            psys_sleep_milliseconds(1);
          psql_start();
          pthread_mutex_lock(&cache_mutex);
          res = psql_prepare(
              "UPDATE pagecache SET lastuse=?, usecnt=usecnt+? WHERE id=?");
        }
      }
    psql_free(res);
    pdbg_logf(D_NOTICE, "flushed %u access records to database",
          (unsigned)cachepages_to_update_cnt);
    cachepages_to_update_cnt = 0;
    if (!nosleep)
      for (i = 0; i < DB_CACHE_UPDATE_HASH; i++)
        if (cachepages_to_update[i].pagecacheid)
          cachepages_to_update_cnt++;
    lastflush = ctime;
  }
  flushcacherun = 0;
  flush_page_running--;
  if (free_page_waiters) {
    pdbg_logf(D_NOTICE, "finished flushing cache, but there are still free page "
                    "waiters, broadcasting");
    pthread_cond_broadcast(&free_page_cond);
  }
  if (updates) {
    pthread_mutex_unlock(&cache_mutex);
    ret = psql_commit();
    pthread_mutex_unlock(&flush_cache_mutex);
    if (free_db_pages <= CACHE_PAGES * 2)
      prun_thread("clean cache", clean_cache);
    return ret;
  } else {
    pthread_mutex_unlock(&cache_mutex);
    psql_rollback();
    pthread_mutex_unlock(&flush_cache_mutex);
    if (free_db_pages == 0)
      prun_thread("clean cache", clean_cache);
    return 0;
  }
}

int ppagecache_flush() {
  if (flush_pages(1))
    return -EIO;
  else
    return 0;
}

static void ppagecache_flush_timer(psync_timer_t timer, void *ptr) {
  if (!flushedbetweentimers &&
      (cache_pages_in_hash || cachepages_to_update_cnt))
    prun_thread("flush pages timer", flush_pages_noret);
  flushedbetweentimers = 0;
  pthread_mutex_lock(&cache_mutex);
  if (cache_pages_free == CACHE_PAGES && !cache_pages_reset) {
    cache_pages_reset = 1;
    pdbg_logf(D_NOTICE, "resetting free pages");
    pmem_reset(pages_base, CACHE_PAGES * PSYNC_FS_PAGE_SIZE);
  }
  pthread_mutex_unlock(&cache_mutex);
}

static void mark_pagecache_used(uint64_t pagecacheid) {
  uint64_t h;
  time_t tm;
  int tries, runthread;
  h = pagecacheid % DB_CACHE_UPDATE_HASH;
  tm = ptimer_time();
  tries = 0;
  runthread = 0;
  pthread_mutex_lock(&cache_mutex);
  while (++tries <= 10) {
    if (cachepages_to_update[h].pagecacheid == 0) {
      cachepages_to_update[h].pagecacheid = pagecacheid;
      cachepages_to_update[h].lastuse = tm;
      cachepages_to_update[h].usecnt = 1;
      cachepages_to_update_cnt++;
      break;
    } else if (cachepages_to_update[h].pagecacheid == pagecacheid) {
      if (tm > cachepages_to_update[h].lastuse + 5) {
        cachepages_to_update[h].lastuse = tm;
        cachepages_to_update[h].usecnt++;
      }
      break;
    }
    if (++h >= DB_CACHE_UPDATE_HASH)
      h = 0;
  }
  if (cachepages_to_update_cnt > DB_CACHE_UPDATE_HASH / 2 && !flushcacherun) {
    flushcacherun = 1;
    runthread = 1;
  }
  pthread_mutex_unlock(&cache_mutex);
  if (runthread)
    prun_thread("flush pages mark_pagecache_used", flush_pages_noret);
}

static void mark_pagescache_used(uint64_t first_page_id, unsigned long pagecnt,
                                 unsigned char *dbread) {
  time_t tm;
  unsigned long i;
  uint64_t h;
  int tries, runthread;
  runthread = 0;
  tm = ptimer_time();
  pthread_mutex_lock(&cache_mutex);
  for (i = 0; i < pagecnt; i++)
    if (dbread[i / 8] & (1 << (i % 8))) {
      h = (first_page_id + i) % DB_CACHE_UPDATE_HASH;
      tries = 0;
      while (++tries <= 10) {
        if (cachepages_to_update[h].pagecacheid == 0) {
          cachepages_to_update[h].pagecacheid = first_page_id + i;
          cachepages_to_update[h].lastuse = tm;
          cachepages_to_update[h].usecnt = 1;
          cachepages_to_update_cnt++;
          break;
        } else if (cachepages_to_update[h].pagecacheid == first_page_id + i) {
          if (tm > cachepages_to_update[h].lastuse + 5) {
            cachepages_to_update[h].lastuse = tm;
            cachepages_to_update[h].usecnt++;
          }
          break;
        }
        if (++h >= DB_CACHE_UPDATE_HASH)
          h = 0;
      }
    }
  if (cachepages_to_update_cnt > DB_CACHE_UPDATE_HASH / 2 && !flushcacherun) {
    flushcacherun = 1;
    runthread = 1;
  }
  pthread_mutex_unlock(&cache_mutex);
  if (runthread)
    prun_thread("flush pages mark_pagescache_used", flush_pages_noret);
}

PSYNC_NOINLINE static void mark_page_free(uint64_t pagecacheid) {
  psync_sql_res *res;
  res = psql_prepare("UPDATE pagecache SET type=" NTO_STR(
      PAGE_TYPE_FREE) ", pageid=NULL, hash=NULL WHERE id=?");
  psql_bind_uint(res, 1, pagecacheid);
  psql_run_free(res);
}

static long check_page_in_database_by_hash(uint64_t hash,
                                                  uint64_t pageid, char *buff,
                                                  unsigned long size,
                                                  unsigned long off) {
  psync_sql_res *res;
  psync_uint_row row;
  size_t dsize;
  ssize_t readret;
  long ret;
  uint64_t pagecacheid;
  uint32_t crc;
  ret = -1;
  res = psql_query_rdlock(
      "SELECT id, size, crc FROM pagecache WHERE type=+" NTO_STR(
          PAGE_TYPE_READ) " AND hash=? AND pageid=?");
  psql_bind_uint(res, 1, hash);
  psql_bind_uint(res, 2, pageid);
  if ((row = psql_fetch_int(res))) {
    pagecacheid = row[0];
    dsize = row[1];
    crc = row[2];
    if (size + off > dsize) {
      if (off > dsize)
        size = 0;
      else
        size = dsize - off;
    }
    ret = size;
  }
  psql_free(res);
  if (ret != -1) {
    readret = pfile_pread(readcache, buff, size,
                               pagecacheid * PSYNC_FS_PAGE_SIZE + off);
    if (unlikely(readret != size)) {
      pdbg_logf(D_ERROR,
            "failed to read %lu bytes from cache file at offset %lu, read "
            "returned %ld, errno=%ld",
            (unsigned long)size,
            (unsigned long)(pagecacheid * PSYNC_FS_PAGE_SIZE + off),
            (long)readret, (long)errno);
      mark_page_free(pagecacheid);
      ret = -1;
    } else {
      if (unlikely(size == dsize && off == 0 &&
                   pcrc32c_compute(PSYNC_CRC_INITIAL, buff, size) != crc)) {
        pdbg_logf(D_WARNING,
              "got bad CRC when reading data from cache at offset %lu",
              (unsigned long)(pagecacheid * PSYNC_FS_PAGE_SIZE + off));
        mark_page_free(pagecacheid);
        ret = -1;
      } else
        mark_pagecache_used(pagecacheid);
    }
  }
  return ret;
}

static void check_pages_in_database_by_hash(uint64_t hash,
                                            uint64_t first_page_id,
                                            unsigned long pagecnt, char *buff,
                                            unsigned char *dbread) {
  psync_sql_res *res;
  psync_full_result_int *fres;
  uint64_t cid, cpid;
  ssize_t readret;
  uint32_t i, j, cnt;
  res = psql_query_rdlock(
      "SELECT id, pageid, size, crc FROM pagecache WHERE type=+" NTO_STR(
          PAGE_TYPE_READ) " AND hash=? AND pageid>=? AND pageid<? ORDER BY "
                          "pageid");
  psql_bind_uint(res, 1, hash);
  psql_bind_uint(res, 2, first_page_id);
  psql_bind_uint(res, 3, first_page_id + pagecnt);
  fres = psql_fetchall_int(res);
  cnt = 1;
  for (i = 0; i < fres->rows; i += cnt) {
    if (psync_get_result_cell(fres, i, 2) != PSYNC_FS_PAGE_SIZE)
      continue;
    cid = psync_get_result_cell(fres, i, 0);
    cpid = psync_get_result_cell(fres, i, 1);
    cnt = 0;
    while (i + cnt + 1 < fres->rows &&
           psync_get_result_cell(fres, i + cnt + 1, 0) == cid + cnt + 1 &&
           psync_get_result_cell(fres, i + cnt + 1, 1) == cpid + cnt + 1 &&
           psync_get_result_cell(fres, i + cnt + 1, 2) == PSYNC_FS_PAGE_SIZE)
      cnt++;
    cnt++;
    //    pdbg_logf(D_NOTICE, "reading %u consecutive pages from cache file id %lu,
    //    firstpageid %lu", (unsigned)cnt, (unsigned long)cid, (unsigned
    //    long)cpid);
    readret = pfile_pread(
        readcache, buff + (cpid - first_page_id) * PSYNC_FS_PAGE_SIZE,
        PSYNC_FS_PAGE_SIZE * cnt, cid * PSYNC_FS_PAGE_SIZE);
    if (readret != PSYNC_FS_PAGE_SIZE * cnt) {
      pdbg_logf(D_ERROR,
            "failed to read %lu bytes from cache file at offset %lu, read "
            "returned %ld, errno=%ld",
            (unsigned long)(PSYNC_FS_PAGE_SIZE * cnt),
            (unsigned long)(cid * PSYNC_FS_PAGE_SIZE), (long)readret,
            (long)errno);
      continue;
    }
    for (j = 0; j < cnt; j++)
      if (pcrc32c_compute(PSYNC_CRC_INITIAL,
                       buff + (cpid - first_page_id + j) * PSYNC_FS_PAGE_SIZE,
                       PSYNC_FS_PAGE_SIZE) ==
          psync_get_result_cell(fres, i + j, 3))
        dbread[(cpid - first_page_id + j) / 8] |=
            1 << ((cpid - first_page_id + j) % 8);
      else
        pdbg_logf(D_WARNING,
              "got bad CRC when reading data from cache at offset %lu",
              (unsigned long)((cid + j) * PSYNC_FS_PAGE_SIZE));
  }
  if (fres->rows)
    mark_pagescache_used(first_page_id, pagecnt, dbread);
  free(fres);
}

static long check_page_in_database_by_hash_and_cache(uint64_t hash,
                                                            uint64_t pageid,
                                                            char *buff,
                                                            unsigned long size,
                                                            unsigned long off) {
  psync_sql_res *res;
  psync_uint_row row;
  psync_cache_page_t *page;
  size_t dsize;
  ssize_t readret;
  long ret;
  uint64_t pagecacheid;
  uint32_t crc, ccrc;
  ret = -1;
  res = psql_query_rdlock(
      "SELECT id, size, crc FROM pagecache WHERE type=+" NTO_STR(
          PAGE_TYPE_READ) " AND hash=? AND pageid=?");
  psql_bind_uint(res, 1, hash);
  psql_bind_uint(res, 2, pageid);
  if ((row = psql_fetch_int(res))) {
    pagecacheid = row[0];
    dsize = row[1];
    crc = row[2];
    if (size + off > dsize) {
      if (off > dsize)
        size = 0;
      else
        size = dsize - off;
    }
    ret = size;
  }
  psql_free(res);
  if (ret != -1) {
    page = psync_pagecache_get_free_page(0);
    readret = pfile_pread(readcache, page->page, dsize,
                               pagecacheid * PSYNC_FS_PAGE_SIZE);
    if (unlikely(readret != dsize)) {
      pdbg_logf(D_ERROR,
            "failed to read %lu bytes from cache file at offset %lu, read "
            "returned %ld, errno=%ld",
            (unsigned long)dsize,
            (unsigned long)(pagecacheid * PSYNC_FS_PAGE_SIZE), (long)readret,
            (long)errno);
      mark_page_free(pagecacheid);
      psync_pagecache_return_free_page(page);
      ret = -1;
    } else {
      ccrc = pcrc32c_compute(PSYNC_CRC_INITIAL, page->page, dsize);
      if (unlikely(ccrc != crc)) {
        pdbg_logf(D_WARNING,
              "got bad CRC when reading data from cache at offset %lu, size "
              "%lu db CRC %u calculated CRC %u",
              (unsigned long)(pagecacheid * PSYNC_FS_PAGE_SIZE),
              (unsigned long)dsize, (unsigned)crc, (unsigned)ccrc);
        mark_page_free(pagecacheid);
        psync_pagecache_return_free_page(page);
        ret = -1;
      } else {
        mark_pagecache_used(pagecacheid);
        memcpy(buff, page->page + off, size);
        page->hash = hash;
        page->pageid = pageid;
        page->lastuse = 0;
        page->size = dsize;
        page->usecnt = 0;
        page->crc = ccrc;
        page->type = PAGE_TYPE_CACHE;
        pthread_mutex_lock(&cache_mutex);
        psync_list_add_tail(
            &cache_hash[pagehash_by_hash_and_pageid(hash, pageid)],
            &page->list);
        cache_pages_in_hash++;
        pthread_mutex_unlock(&cache_mutex);
      }
    }
  }
  return ret;
}

int ppagecache_read_mod_locked(psync_openfile_t *of, char *buf,
                                         uint64_t size, uint64_t offset) {
  psync_interval_tree_t *fi;
  uint64_t isize, ioffset;
  ssize_t br;
  int rd;
  fi = psync_interval_tree_first_interval_containing_or_after(
      of->writeintervals, offset);
  if (fi && fi->from <= offset && fi->to >= offset + size) {
    pdbg_logf(D_NOTICE, "reading %lu bytes at offset %lu only from local storage",
          (unsigned long)size, (unsigned long)offset);
    br = pfile_pread(of->datafile, buf, size, offset);
    pthread_mutex_unlock(&of->mutex);
    if (br == -1)
      return -EIO;
    else
      return br;
  }
  rd = ppagecache_read_unmod_locked(of, buf, size, offset);
  if (rd < 0)
    return rd;
  psync_fs_lock_file(of);
  fi = psync_interval_tree_first_interval_containing_or_after(
      of->writeintervals, offset);
  if (!fi || fi->from >= offset + size) {
    pthread_mutex_unlock(&of->mutex);
    if (fi)
      br = fi->from;
    else
      br = -1;
    pdbg_logf(D_NOTICE,
          "reading %lu bytes at offset %lu only from remote fileid %lu "
          "revision %lu, read returned %d, next local interval starts at %ld",
          (unsigned long)size, (unsigned long)offset,
          (unsigned long)of->remotefileid, (unsigned long)of->hash, rd,
          (long)br);
    return rd;
  }
  pdbg_logf(D_NOTICE, "reading %lu bytes at offset %lu from both network and local",
        (unsigned long)size, (unsigned long)offset);
  do {
    ioffset = fi->from;
    isize = fi->to - fi->from;
    if (ioffset < offset) {
      isize -= offset - ioffset;
      ioffset = offset;
    }
    if (ioffset + isize > offset + size)
      isize = offset + size - ioffset;
    pdbg_logf(D_NOTICE, "reading %lu bytes at offset %lu from local storage",
          (unsigned long)isize, (unsigned long)ioffset);
    br = pfile_pread(of->datafile, buf + ioffset - offset, isize, ioffset);
    if (br == -1) {
      pthread_mutex_unlock(&of->mutex);
      return -EIO;
    }
    if (rd != size && br + ioffset - offset > rd)
      rd = br + ioffset - offset;
    fi = psync_interval_tree_get_next(fi);
  } while (fi && fi->from < offset + size);
  pthread_mutex_unlock(&of->mutex);
  return rd;
}

static void psync_pagecache_free_request(psync_request_t *request) {
  psync_list_for_each_element_call(&request->ranges, psync_request_range_t,
                                   list, free);
  free(request);
}

static void psync_pagecache_send_error_page_wait(psync_page_wait_t *pw,
                                                 int err) {
  psync_page_waiter_t *pwt;
  psync_list_del(&pw->list);
  psync_list_for_each_element(pwt, &pw->waiters, psync_page_waiter_t,
                              listpage) {
    pwt->error = err;
    pwt->ready = 1;
    pthread_cond_broadcast(&pwt->cond);
  }
  free(pw);
}

static void psync_pagecache_send_range_error(psync_request_range_t *range,
                                             psync_request_t *request,
                                             int err) {
  uint64_t first_page_id;
  psync_page_wait_t *pw;
  unsigned long len, i, h;
  first_page_id = range->offset / PSYNC_FS_PAGE_SIZE;
  len = range->length / PSYNC_FS_PAGE_SIZE;
  pdbg_logf(D_NOTICE,
        "sending error %d to request for offset %lu, length %lu of fileid %lu "
        "hash %lu",
        err, (unsigned long)range->offset, (unsigned long)range->length,
        (unsigned long)request->fileid, (unsigned long)request->hash);
  for (i = 0; i < len; i++) {
    h = waiterhash_by_hash_and_pageid(request->hash, first_page_id + i);
    psync_list_for_each_element(pw, &wait_page_hash[h], psync_page_wait_t,
                                list) if (pw->hash == request->hash &&
                                          pw->pageid == first_page_id + i) {
      psync_pagecache_send_error_page_wait(pw, err);
      break;
    }
  }
}

static void psync_pagecache_send_error(psync_request_t *request, int err) {
  psync_request_range_t *range;
  lock_wait(request->hash);
  psync_list_for_each_element(range, &request->ranges, psync_request_range_t,
                              list)
      psync_pagecache_send_range_error(range, request, err);
  unlock_wait(request->ash);
  if (request->needkey)
    psync_pagecache_set_bad_encoder(request->of);
  psync_fs_dec_of_refcnt_and_readers(request->of);
  psync_pagecache_free_request(request);
}

#if IS_DEBUG
#define psync_pagecache_send_error(r, e)                                       \
  do {                                                                         \
    psync_pagecache_send_error(r, e);                                          \
    pdbg_logf(D_NOTICE, "sending request error %d", e);                            \
  } while (0)
#endif

static int psync_pagecache_read_range_from_sock(psync_request_t *request,
                                                psync_request_range_t *range,
                                                psync_http_socket *sock) {
  uint64_t first_page_id;
  psync_page_wait_t *pw;
  psync_cache_page_t *page;
  unsigned long len, i, h;
  int rb;
  first_page_id = range->offset / PSYNC_FS_PAGE_SIZE;
  len = range->length / PSYNC_FS_PAGE_SIZE;
  rb = psync_http_next_request(sock);
  if (unlikely(rb)) {
    if (rb == 410 || rb == 404 || rb == -1) {
      pdbg_logf(D_WARNING,
            "got %d from psync_http_next_request, freeing URLs and requesting "
            "retry, range from %lu",
            rb, (long unsigned)range->offset);
      return 1;
    } else {
      pdbg_logf(D_WARNING, "got %d from psync_http_next_request, returning error",
            rb);
      return -1;
    }
  }
  for (i = 0; i < len; i++) {
    page = psync_pagecache_get_free_page(0);
    rb = psync_http_request_readall(sock, page->page, PSYNC_FS_PAGE_SIZE);
    if (pdbg_unlikely(rb <= 0)) {
      psync_pagecache_return_free_page(page);
      ptimer_notify_exception();
      return -1;
    }
    page->hash = request->hash;
    page->pageid = first_page_id + i;
    page->lastuse = ptimer_time();
    page->size = rb;
    page->usecnt = 0;
    page->crc = pcrc32c_compute(PSYNC_CRC_INITIAL, page->page, rb);
    page->type = PAGE_TYPE_READ;
    h = waiterhash_by_hash_and_pageid(page->hash, page->pageid);
    lock_wait(page->hash);
    psync_list_for_each_element(pw, &wait_page_hash[h], psync_page_wait_t,
                                list) if (pw->hash == page->hash &&
                                          pw->pageid == page->pageid) {
      psync_pagecache_send_page_wait_page(pw, page);
      break;
    }
    unlock_wait(page->hash);
    pthread_mutex_lock(&cache_mutex);
    psync_list_add_tail(
        &cache_hash[pagehash_by_hash_and_pageid(page->hash, page->pageid)],
        &page->list);
    cache_pages_in_hash++;
    pthread_mutex_unlock(&cache_mutex);
  }
  return 0;
}

// X-Range-Next:
#define PSYNC_CONSTRUCT_ADD_NUMBER(x)                                          \
  do {                                                                         \
    if (off <= 24)                                                             \
      return NULL;                                                             \
    do {                                                                       \
      buff[off--] = '0' + x % 10;                                              \
      x /= 10;                                                                 \
    } while (x);                                                               \
  } while (0)
#define PSYNC_CONSTRUCT_HEADER "X-Range-Next:"
#define PSYNC_DWLTAG_HEADER "Cookie: dwltag="
char *psync_http_construct_range_next_header(psync_request_t *request,
                                             psync_urls_t *urls) {
  char buff[2048];
  const binresult *dwltag;
  uint64_t nm;
  psync_request_range_t *range;
  psync_list *l;
  size_t off;
  l = request->ranges.prev;
  off = sizeof(buff) - 1;
  buff[off--] = 0;
  buff[off--] = '\012';
  buff[off--] = '\015';
  dwltag = papi_find_result2(urls->urls, "dwltag", PARAM_STR);
  if (dwltag->length <= 40 && dwltag->length > 0) {
    off -= dwltag->length - 1;
    memcpy(buff + off, dwltag->str, dwltag->length);
    off -= sizeof(PSYNC_DWLTAG_HEADER) - 1;
    memcpy(buff + off, PSYNC_DWLTAG_HEADER, sizeof(PSYNC_DWLTAG_HEADER) - 1);
    off--;
    buff[off--] = '\012';
    buff[off--] = '\015';
  }
  while (l->prev != &request->ranges) {
    range = psync_list_element(l, psync_request_range_t, list);
    nm = range->offset + range->length - 1;
    PSYNC_CONSTRUCT_ADD_NUMBER(nm);
    buff[off--] = '-';
    nm = range->offset;
    PSYNC_CONSTRUCT_ADD_NUMBER(nm);
    buff[off--] = ' ';
    buff[off--] = ',';
    l = l->prev;
  }
  if (off < sizeof(PSYNC_CONSTRUCT_HEADER))
    return NULL;
  return psync_strdup((char *)memcpy(
      buff + off - sizeof(PSYNC_CONSTRUCT_HEADER) + 3, PSYNC_CONSTRUCT_HEADER,
      sizeof(PSYNC_CONSTRUCT_HEADER) - 1));
}

static void psync_pagecache_read_unmodified_thread(void *ptr) {
  psync_request_t *request;
  psync_http_socket *sock;
  psock_t *api;
  const char *host;
  const char *path;
  char cookie[128];
  psync_request_range_t *range;
  const binresult *hosts;
  psync_urls_t *urls;
  pcrypto_sector_encdec_t enc;
  int err, tries;
  request = (psync_request_t *)ptr;
  if (pstatus_get(PSTATUS_TYPE_ONLINE) == PSTATUS_ONLINE_OFFLINE) {
    psync_pagecache_send_error(request, -ENOTCONN);
    return;
  }
  range = psync_list_element(request->ranges.next, psync_request_range_t, list);
  pdbg_logf(D_NOTICE, "thread run, first offset %lu, size %lu",
        (unsigned long)range->offset, (unsigned long)range->length);
  tries = 0;
retry:
  if (!(urls = get_urls_for_request(request))) {
    psync_pagecache_send_error(request, -EIO);
    return;
  }
  if (unlikely(request->needkey)) {
    enc =
        pcryptofolder_filencoder_get(request->fileid, request->hash, 0);
    if (psync_crypto_to_error(enc)) {
      psync_pagecache_send_error(request, -EIO);
      return;
    }
    psync_fs_lock_file(request->of);
    if (pdbg_likely(request->of->encoder ==
                   PSYNC_CRYPTO_LOADING_SECTOR_ENCODER)) {
      request->of->encoder = enc;
      pthread_cond_broadcast(&enc_key_cond);
    } else
      pcryptofolder_filencoder_release(request->fileid, request->hash,
                                              enc);
    pthread_mutex_unlock(&request->of->mutex);
    request->needkey = 0;
  }
  if (psync_list_isempty(&request->ranges)) {
    release_urls(urls);
    psync_fs_dec_of_refcnt_and_readers(request->of);
    psync_pagecache_free_request(request);
    return;
  }
  hosts = papi_find_result2(urls->urls, "hosts", PARAM_ARRAY);
  psync_slprintf(cookie, sizeof(cookie), "Cookie: dwltag=%s\015\012",
                 papi_find_result2(urls->urls, "dwltag", PARAM_STR)->str);
  sock = psync_http_connect_multihost_from_cache(hosts, &host);
  if (!sock) {
    if ((api = psync_apipool_get_from_cache())) {
      pdbg_logf(D_NOTICE, "no cached server connections, but got cached API "
                      "connection, serving request from API");
      if (pdbg_likely(hosts->length && hosts->array[0]->type == PARAM_STR))
        psync_http_connect_and_cache_host(hosts->array[0]->str);
      psock_set_write_buffered(api);
      psync_list_for_each_element(range, &request->ranges,
                                  psync_request_range_t, list) {
        pdbg_logf(D_NOTICE, "sending request for offset %lu, size %lu to API",
              (unsigned long)range->offset, (unsigned long)range->length);
        if (psync_api_send_read_request(api, request->fileid, request->hash,
                                        range->offset, range->length))
          goto err_api1;
      }
      mark_api_shared(api);
      psync_list_for_each_element(
          range, &request->ranges, psync_request_range_t,
          list) if ((err = psync_pagecache_read_range_from_api(request, range,
                                                               api))) {
        mark_shared_api_bad(api);
        if (err == -2 && psync_list_is_head(&request->ranges, &range->list))
          goto err_api1;
        else {
          psync_apipool_release_bad(api);
          goto err0;
        }
      }
      if (pass_shared_api(api)) {
        psock_clear_write_buffered(api);
        psync_apipool_release(api);
      }
      pdbg_logf(D_NOTICE, "request from API finished");
      goto ok1;
    err_api1:
      psock_clear_write_buffered_thread(api);
      psync_apipool_release_bad(api);
      pdbg_logf(D_WARNING,
            "error reading range from API, trying from content servers");
    } else if ((api = get_shared_api())) {
      psock_set_write_buffered_thread(api);
      pdbg_logf(D_NOTICE,
            "no cached server connections, no cached API servers, but got "
            "shared API connection sending request to shared API");
      psync_list_for_each_element(range, &request->ranges,
                                  psync_request_range_t, list) {
        pdbg_logf(D_NOTICE,
              "sending request for offset %lu, size %lu to shared API",
              (unsigned long)range->offset, (unsigned long)range->length);
        if (psync_api_send_read_request_thread(api, request->fileid,
                                               request->hash, range->offset,
                                               range->length))
          goto err_api2;
      }
      psock_try_write_buffer_thread(api);
      if (wait_shared_api())
        goto err_api0;
      psync_list_for_each_element(
          range, &request->ranges, psync_request_range_t,
          list) if ((err = psync_pagecache_read_range_from_api(request, range,
                                                               api))) {
        mark_shared_api_bad(api);
        if (err == -2 && psync_list_is_head(&request->ranges, &range->list))
          goto err_api0;
        else {
          psync_apipool_release_bad(api);
          goto err0;
        }
      }
      if (pass_shared_api(api)) {
        psock_clear_write_buffered(api);
        psync_apipool_release(api);
      }
      pdbg_logf(D_NOTICE, "request from shared API finished");
      goto ok1;
    err_api2:
      psock_clear_write_buffered_thread(api);
      release_bad_shared_api(api);
    err_api0:
      pdbg_logf(D_WARNING,
            "error reading range from API, trying from content servers");
    }
  }
  if (!sock)
    sock = psync_http_connect_multihost(hosts, &host);
  if (pdbg_unlikely(!sock))
    goto err0;
  //  pdbg_logf(D_NOTICE, "connected to %s", host);
  path = papi_find_result2(urls->urls, "path", PARAM_STR)->str;
  psock_set_write_buffered(sock->sock);
  psync_list_for_each_element(range, &request->ranges, psync_request_range_t,
                              list) {
    pdbg_logf(D_NOTICE, "sending request for offset %lu, size %lu",
          (unsigned long)range->offset, (unsigned long)range->length);
    if (psync_list_is_head(&request->ranges, &range->list) &&
        !psync_list_is_tail(&request->ranges, &range->list)) {
      char *range_hdr = psync_http_construct_range_next_header(request, urls);
      pdbg_logf(D_NOTICE, "sending additional header: %s", range_hdr);
      err = psync_http_request_range_additional(
          sock, host, path, range->offset, range->offset + range->length - 1,
          range_hdr);
      free(range_hdr);
    } else
      err = psync_http_request(sock, host, path, range->offset,
                               range->offset + range->length - 1, cookie);
    if (err) {
      if (tries++ < 5) {
        psync_http_close(sock);
        goto retry;
      } else
        goto err1;
    }
  }
  psync_list_for_each_element(
      range, &request->ranges, psync_request_range_t,
      list) if ((err = psync_pagecache_read_range_from_sock(request, range,
                                                            sock))) {
    if (err == 1 && tries++ < 5) {
      psync_http_close(sock);
      release_bad_urls(urls);
      goto retry;
    } else
      goto err1;
  }
  psock_clear_write_buffered(sock->sock);
  psync_http_close(sock);
  pdbg_logf(D_NOTICE, "request from %s finished", host);
ok1:
  psync_fs_dec_of_refcnt_and_readers(request->of);
  psync_pagecache_free_request(request);
  release_urls(urls);
  return;
err1:
  psync_http_close(sock);
err0:
  psync_pagecache_send_error(request, -EIO);
  release_urls(urls);
  return;
}

static void check_or_request_page(uint64_t fileid, uint64_t hash,
                                  uint64_t pageid, psync_list *ranges) {
  if (has_page_in_cache_by_hash(hash, pageid) || has_page_in_db(hash, pageid))
    return;
  else {
    psync_page_wait_t *pw;
    psync_request_range_t *range;
    long h;
    int found;
    h = waiterhash_by_hash_and_pageid(hash, pageid);
    found = 0;
    lock_wait(hash);
    psync_list_for_each_element(pw, &wait_page_hash[h], psync_page_wait_t,
                                list) if (pw->hash == hash &&
                                          pw->pageid == pageid) {
      found = 1;
      break;
    }
    if (!found) {
      pw = malloc(sizeof(psync_page_wait_t));
      psync_list_add_tail(&wait_page_hash[h], &pw->list);
      psync_list_init(&pw->waiters);
      pw->hash = hash;
      pw->pageid = pageid;
      pw->fileid = fileid;
      if (psync_list_isempty(ranges))
        range = NULL;
      else
        range = psync_list_element(ranges->prev, psync_request_range_t, list);
      if (range && range->offset + range->length == pageid * PSYNC_FS_PAGE_SIZE)
        range->length += PSYNC_FS_PAGE_SIZE;
      else {
        range = malloc(sizeof(psync_request_range_t));
        psync_list_add_tail(ranges, &range->list);
        range->offset = pageid * PSYNC_FS_PAGE_SIZE;
        range->length = PSYNC_FS_PAGE_SIZE;
      }
    }
    unlock_wait(hash);
  }
}

static void psync_pagecache_read_unmodified_readahead(
    psync_openfile_t *of, uint64_t offset, uint64_t size, psync_list *ranges,
    psync_fileid_t fileid, uint64_t hash, uint64_t initialsize,
    psync_crypto_offsets_t *offsets) {
  uint64_t readahead, frompageoff, topageoff, first_page_id, rto;
  long i, pagecnt, h, streamid;
  psync_page_wait_t *pw;
  psync_request_range_t *range;
  time_t ctime;
  unsigned char *pages_in_db;
  int found;
  if (offset + size >= initialsize)
    return;
  readahead = 0;
  frompageoff = offset / PSYNC_FS_PAGE_SIZE;
  topageoff =
      ((offset + size + PSYNC_FS_PAGE_SIZE - 1) / PSYNC_FS_PAGE_SIZE) - 1;
  ctime = ptimer_time();
  found = 0;
  for (streamid = 0; streamid < PSYNC_FS_FILESTREAMS_CNT; streamid++)
    if (of->streams[streamid].frompage <= frompageoff &&
        of->streams[streamid].topage + 2 >= frompageoff) {
      of->streams[streamid].id = ++of->laststreamid;
      readahead = of->streams[streamid].length;
      of->streams[streamid].frompage = frompageoff;
      of->streams[streamid].topage = topageoff;
      of->streams[streamid].length += size;
      of->streams[streamid].lastuse = ctime;
      break;
    } else if (of->streams[streamid].lastuse >= ctime - 2)
      found++;
  if (streamid == PSYNC_FS_FILESTREAMS_CNT) {
    uint64_t min;
    pdbg_logf(D_NOTICE, "ran out of readahead streams");
    min = ~(uint64_t)0;
    streamid = 0;
    for (i = 0; i < PSYNC_FS_FILESTREAMS_CNT; i++)
      if (of->streams[i].id < min) {
        min = of->streams[i].id;
        streamid = i;
      }
    of->streams[streamid].id = ++of->laststreamid;
    of->streams[streamid].frompage = frompageoff;
    of->streams[streamid].topage = topageoff;
    of->streams[streamid].length = size;
    of->streams[streamid].requestedto = 0;
    of->streams[streamid].lastuse = ctime;
    if (found == 1 && of->currentspeed * 4 > readahead &&
        !psync_list_isempty(ranges)) {
      pdbg_logf(D_NOTICE,
            "found just one freshly used stream, increasing readahead to four "
            "times current speed %u",
            (unsigned int)of->currentspeed * 4);
      readahead = size_round_up_to_page(of->currentspeed * 4);
    }
  }
  if (of->runningreads >= 6 && psync_list_isempty(ranges))
    return;
  if (offset == 0 && (size < PSYNC_FS_MIN_READAHEAD_START) &&
      readahead < PSYNC_FS_MIN_READAHEAD_START - size)
    readahead = PSYNC_FS_MIN_READAHEAD_START - size;
  else if (offset == PSYNC_FS_MIN_READAHEAD_START / 2 &&
           readahead == PSYNC_FS_MIN_READAHEAD_START / 2) {
    of->streams[streamid].length += offset;
    readahead = (PSYNC_FS_MIN_READAHEAD_START / 2) * 3;
  } else if (offset != 0 && (size < PSYNC_FS_MIN_READAHEAD_RAND) &&
             readahead < PSYNC_FS_MIN_READAHEAD_RAND - size)
    readahead = PSYNC_FS_MIN_READAHEAD_RAND - size;
  if (of->currentspeed * PSYNC_FS_MAX_READAHEAD_SEC >
      PSYNC_FS_MIN_READAHEAD_START) {
    if (readahead > of->currentspeed * PSYNC_FS_MAX_READAHEAD_SEC)
      readahead =
          size_round_up_to_page(of->currentspeed * PSYNC_FS_MAX_READAHEAD_SEC);
    if (readahead > PSYNC_FS_MAX_READAHEAD_IF_SEC)
      readahead = PSYNC_FS_MAX_READAHEAD_IF_SEC;
  } else if (readahead > PSYNC_FS_MAX_READAHEAD)
    readahead = PSYNC_FS_MAX_READAHEAD;
  if (psync_list_isempty(ranges)) {
    if (readahead >= 8192 * 1024)
      readahead =
          (readahead + offset + size) / (4 * 1024 * 1024) * (4 * 1024 * 1024) -
          offset - size;
    else if (readahead >= 2048 * 1024)
      readahead = (readahead + offset + size) / (1024 * 1024) * (1024 * 1024) -
                  offset - size;
    else if (readahead >= 512 * 1024)
      readahead = (readahead + offset + size) / (256 * 1024) * (256 * 1024) -
                  offset - size;
    else if (readahead >= 128 * 1024)
      readahead = (readahead + offset + size) / (64 * 1024) * (64 * 1024) -
                  offset - size;
  }
  if (offset + size + readahead > initialsize)
    readahead = size_round_up_to_page(initialsize - offset - size);
  rto = of->streams[streamid].requestedto;
  if (of->streams[streamid].lastuse < ctime - 30)
    rto = 0;
  if (rto < offset + size + readahead)
    of->streams[streamid].requestedto = offset + size + readahead;
  //  pdbg_logf(D_NOTICE, "rto=%lu", rto);
  if (rto > offset + size) {
    if (rto > offset + size + readahead)
      return;
    first_page_id = rto / PSYNC_FS_PAGE_SIZE;
    pagecnt = (offset + size + readahead - rto) / PSYNC_FS_PAGE_SIZE;
  } else {
    first_page_id = (offset + size) / PSYNC_FS_PAGE_SIZE;
    pagecnt = readahead / PSYNC_FS_PAGE_SIZE;
  }
  if (of->encrypted) {
    uint64_t aoffset, pageid;
    long l;
    uint32_t asize, aoff;
    for (i = 0; i < pagecnt; i += PSYNC_CRYPTO_HASH_TREE_SECTORS) {
      for (l = 0; l < offsets->treelevels; l++) {
        pfscrypto_get_auth_off(first_page_id + i, l, offsets,
                                            &aoffset, &asize, &aoff);
        pageid = aoffset / PSYNC_FS_PAGE_SIZE;
        check_or_request_page(fileid, hash, pageid, ranges);
        aoff = aoffset % PSYNC_FS_PAGE_SIZE;
        if (aoff && aoff + asize > PSYNC_FS_PAGE_SIZE)
          check_or_request_page(fileid, hash, pageid + 1, ranges);
      }
    }
    // this may include some auth sectors, but should do no harm
    rto = pfscrypto_sector_id(first_page_id + pagecnt);
    first_page_id = pfscrypto_sector_id(first_page_id);
    pagecnt = rto - first_page_id;
  }
  pages_in_db = has_pages_in_db(hash, first_page_id, pagecnt, 1);
  lock_wait(hash);
  for (i = 0; i < pagecnt; i++) {
    if (pages_in_db[i])
      continue;
    if (has_page_in_cache_by_hash(hash, first_page_id + i))
      continue;
    h = waiterhash_by_hash_and_pageid(hash, first_page_id + i);
    found = 0;
    psync_list_for_each_element(pw, &wait_page_hash[h], psync_page_wait_t,
                                list) if (pw->hash == hash &&
                                          pw->pageid == first_page_id + i) {
      found = 1;
      break;
    }
    if (found)
      continue;
    //    pdbg_logf(D_NOTICE, "read-aheading page %lu", first_page_id+i);
    pw = malloc(sizeof(psync_page_wait_t));
    psync_list_add_tail(&wait_page_hash[h], &pw->list);
    psync_list_init(&pw->waiters);
    pw->hash = hash;
    pw->pageid = first_page_id + i;
    pw->fileid = fileid;
    if (psync_list_isempty(ranges))
      range = NULL;
    else
      range = psync_list_element(ranges->prev, psync_request_range_t, list);
    if (range && range->offset + range->length ==
                     (first_page_id + i) * PSYNC_FS_PAGE_SIZE)
      range->length += PSYNC_FS_PAGE_SIZE;
    else {
      range = malloc(sizeof(psync_request_range_t));
      psync_list_add_tail(ranges, &range->list);
      range->offset = (first_page_id + i) * PSYNC_FS_PAGE_SIZE;
      range->length = PSYNC_FS_PAGE_SIZE;
    }
  }
  unlock_wait(hash);
  free(pages_in_db);
  if (!psync_list_isempty(ranges))
    pdbg_logf(D_NOTICE,
          "readahead=%lu, rto=%lu, offset=%lu, size=%lu, currentspeed=%u",
          (long unsigned)readahead, (unsigned long)rto, (unsigned long)offset,
          (unsigned long)size, (unsigned)of->currentspeed);
}

static void psync_free_page_waiter(psync_page_waiter_t *pwt) {
  pthread_cond_destroy(&pwt->cond);
  free(pwt);
}

static psync_page_waiter_t *
add_page_waiter(psync_list *wait_list, psync_list *range_list, uint64_t hash,
                uint64_t pageid, uint64_t fileid, char *buff, uint32_t pageidx,
                uint32_t copyoff, uint32_t copysize) {
  psync_page_waiter_t *pwt;
  psync_page_wait_t *pw;
  psync_request_range_t *range;
  unsigned long h;
  pwt = malloc(sizeof(psync_page_waiter_t));
  pthread_cond_init(&pwt->cond, NULL);
  pwt->buff = buff;
  pwt->pageidx = pageidx;
  pwt->off = copyoff;
  pwt->size = copysize;
  pwt->error = 0;
  pwt->ready = 0;
  psync_list_add_tail(wait_list, &pwt->listwaiter);
  h = waiterhash_by_hash_and_pageid(hash, pageid);
  psync_list_for_each_element(pw, &wait_page_hash[h], psync_page_wait_t,
                              list) if (pw->hash == hash &&
                                        pw->pageid == pageid) goto found;
  pdbg_logf(D_NOTICE, "page %lu not found", (unsigned long)pageid);
  pw = malloc(sizeof(psync_page_wait_t));
  psync_list_add_tail(&wait_page_hash[h], &pw->list);
  psync_list_init(&pw->waiters);
  pw->hash = hash;
  pw->pageid = pageid;
  pw->fileid = fileid;
  if (psync_list_isempty(range_list))
    range = NULL;
  else
    range = psync_list_element(range_list->prev, psync_request_range_t, list);
  if (range && range->offset + range->length == pageid * PSYNC_FS_PAGE_SIZE)
    range->length += PSYNC_FS_PAGE_SIZE;
  else {
    range = malloc(sizeof(psync_request_range_t));
    psync_list_add_tail(range_list, &range->list);
    range->offset = pageid * PSYNC_FS_PAGE_SIZE;
    range->length = PSYNC_FS_PAGE_SIZE;
  }
found:
  psync_list_add_tail(&pw->waiters, &pwt->listpage);
  pwt->waiting_for = pw;
  return pwt;
}

static void wait_waiter(psync_page_waiter_t *pwt, uint64_t hash,
                        const char *pt) {
  lock_wait(hash);
  while (!pwt->ready) {
    pdbg_logf(D_NOTICE, "waiting for %s page #%lu to be read", pt,
          (unsigned long)pwt->waiting_for->pageid);
    pthread_cond_wait(&pwt->cond, &wait_page_mutex);
    pdbg_logf(D_NOTICE, "waited for %s page",
          pt); // not safe to use pwt->waiting_for here
  }
  unlock_wait(hash);
  if (pwt->error)
    pdbg_logf(D_WARNING, "reading of page failed with error %d", pwt->error);
}

int ppagecache_read_unmod_locked(psync_openfile_t *of, char *buf,
                                           uint64_t size, uint64_t offset) {
  unsigned char dbread[256];
  uint64_t poffset, psize, first_page_id, initialsize, hash;
  unsigned long pageoff, pagecnt, i, copysize, copyoff;
  psync_fileid_t fileid;
  long rb;
  char *pbuff;
  psync_page_waiter_t *pwt;
  psync_request_t *rq;
  psync_list waiting;
  int ret;
  initialsize = of->initialsize;
  hash = of->hash;
  fileid = of->remotefileid;
  pthread_mutex_unlock(&of->mutex);
  if (offset >= initialsize)
    return 0;
  if (offset + size > initialsize)
    size = initialsize - offset;
  poffset = offset_round_down_to_page(offset);
  pageoff = offset - poffset;
  psize = size_round_up_to_page(size + pageoff);
  pagecnt = psize / PSYNC_FS_PAGE_SIZE;
  first_page_id = poffset / PSYNC_FS_PAGE_SIZE;
  psync_list_init(&waiting);
  rq = malloc(sizeof(psync_request_t));
  psync_list_init(&rq->ranges);
  lock_wait(hash);
  if (pagecnt > 1 && pagecnt <= sizeof(dbread) * 8 && psize == size) {
    ret = 1;
    memset(dbread, 0, sizeof(dbread));
    check_pages_in_database_by_hash(hash, first_page_id, pagecnt, buf, dbread);
  } else
    ret = 0;
  for (i = 0; i < pagecnt; i++) {
    if (ret && (dbread[i / 8] & (1 << (i % 8))))
      continue;
    if (i == 0) {
      copyoff = pageoff;
      if (size > PSYNC_FS_PAGE_SIZE - copyoff)
        copysize = PSYNC_FS_PAGE_SIZE - copyoff;
      else
        copysize = size;
      pbuff = buf;
    } else if (i == pagecnt - 1) {
      copyoff = 0;
      copysize = (size + pageoff) & (PSYNC_FS_PAGE_SIZE - 1);
      if (!copysize)
        copysize = PSYNC_FS_PAGE_SIZE;
      pbuff = buf + i * PSYNC_FS_PAGE_SIZE - pageoff;
    } else {
      copyoff = 0;
      copysize = PSYNC_FS_PAGE_SIZE;
      pbuff = buf + i * PSYNC_FS_PAGE_SIZE - pageoff;
    }
    rb = check_page_in_memory_by_hash(hash, first_page_id + i, pbuff, copysize,
                                      copyoff);
    if (rb == -1 && !ret)
      rb = check_page_in_database_by_hash(hash, first_page_id + i, pbuff,
                                          copysize, copyoff);
    if (rb != -1) {
      if (rb == copysize)
        continue;
      else {
        if (i)
          size = i * PSYNC_FS_PAGE_SIZE + rb - pageoff;
        else
          size = rb;
        break;
      }
    }
    add_page_waiter(&waiting, &rq->ranges, hash, first_page_id + i, fileid,
                    pbuff, i, copyoff, copysize);
  }
  unlock_wait(hash);
  psync_pagecache_read_unmodified_readahead(of, poffset, psize, &rq->ranges,
                                            fileid, hash, initialsize, NULL);
  if (!psync_list_isempty(&rq->ranges)) {
    rq->of = of;
    rq->fileid = fileid;
    rq->hash = hash;
    rq->needkey = 0;
    psync_fs_inc_of_refcnt_and_readers(of);
    prun_thread1("read unmodified", psync_pagecache_read_unmodified_thread,
                      rq);
  } else
    free(rq);
  ret = size;
  if (!psync_list_isempty(&waiting)) {
    psync_list_for_each_element(pwt, &waiting, psync_page_waiter_t,
                                listwaiter) {
      wait_waiter(pwt, hash, "data");
      if (pwt->error)
        ret = pwt->error;
      else if (pwt->rsize < pwt->size && ret >= 0) {
        if (pwt->rsize) {
          if (pwt->pageidx)
            ret = pwt->pageidx * PSYNC_FS_PAGE_SIZE + pwt->rsize - pageoff;
          else
            ret = pwt->rsize;
        } else {
          if (pwt->pageidx) {
            if (pwt->pageidx * PSYNC_FS_PAGE_SIZE + pwt->rsize - pageoff < ret)
              ret = pwt->pageidx * PSYNC_FS_PAGE_SIZE + pwt->rsize - pageoff;
          } else
            ret = pwt->rsize;
        }
      }
    }
    psync_list_for_each_element_call(&waiting, psync_page_waiter_t, listwaiter,
                                     psync_free_page_waiter);
  }
  return ret;
}

static void free_waiters(psync_list *waiters) {
  psync_list *l1, *l2;
  psync_page_waiter_t *pwt;
  psync_page_wait_t *pw;
  psync_list_for_each_safe(l1, l2, waiters) {
    pwt = psync_list_element(l1, psync_page_waiter_t, listwaiter);
    if (!pwt->ready) {
      psync_list_del(&pwt->listpage);
      pw = pwt->waiting_for;
      if (psync_list_isempty(&pw->waiters)) {
        psync_list_del(&pw->list);
        free(pw);
      }
    }
    psync_free_page_waiter(pwt);
  }
}

static int request_auth_page(psync_crypto_auth_page *ap, psync_request_t *rq,
                             psync_list *waiting, psync_fileid_t fileid,
                             uint64_t hash, uint64_t aoffset, uint32_t asize) {
  uint64_t apageid;
  char *pbuff;
  unsigned long apoff, apsize;
  long rb;
  apageid = aoffset / PSYNC_FS_PAGE_SIZE;
  if (aoffset % PSYNC_FS_PAGE_SIZE == 0) {
    rb =
        check_page_in_memory_by_hash(hash, apageid, (char *)ap->auth, asize, 0);
    if (rb == -1)
      rb = check_page_in_database_by_hash_and_cache(hash, apageid,
                                                    (char *)ap->auth, asize, 0);
    if (rb == -1)
      ap->waiter = add_page_waiter(waiting, &rq->ranges, hash, apageid, fileid,
                                   (char *)ap->auth, 0, 0, asize);
    else if (unlikely(rb != asize)) {
      pdbg_logf(D_WARNING, "expected auth sector size to be %u, got %u",
            (unsigned)asize, (unsigned)rb);
      return -1;
    }
  } else {
    apoff = aoffset - apageid * PSYNC_FS_PAGE_SIZE;
    apsize = PSYNC_FS_PAGE_SIZE - apoff;
    if (apsize > asize)
      apsize = asize;
    rb = check_page_in_memory_by_hash(hash, apageid, (char *)ap->auth, apsize,
                                      apoff);
    if (rb == -1)
      rb = check_page_in_database_by_hash_and_cache(
          hash, apageid, (char *)ap->auth, apsize, apoff);
    if (rb == -1)
      ap->waiter = add_page_waiter(waiting, &rq->ranges, hash, apageid, fileid,
                                   (char *)ap->auth, 0, apoff, apsize);
    else if (unlikely(rb != apsize)) {
      pdbg_logf(D_WARNING, "expected auth sector size to be %u, got %u",
            (unsigned)asize, (unsigned)rb);
      return -1;
    }
    if (apsize < asize) {
      pbuff = ((char *)ap->auth) + apsize;
      apageid++;
      apsize = asize - apsize;
      pdbg_assert(apsize < PSYNC_FS_PAGE_SIZE);
      rb = check_page_in_memory_by_hash(hash, apageid, pbuff, apsize, 0);
      if (rb == -1)
        rb = check_page_in_database_by_hash_and_cache(hash, apageid, pbuff,
                                                      apsize, 0);
      if (rb == -1)
        ap->waiter = add_page_waiter(waiting, &rq->ranges, hash, apageid,
                                     fileid, pbuff, 0, 0, apsize);
      else if (unlikely(rb != apsize)) {
        pdbg_logf(D_WARNING, "expected auth sector size to be %u, got %u",
              (unsigned)asize, (unsigned)rb);
        return -1;
      }
    }
  }
  return 0;
}

int ppagecache_read_unmod_enc_locked(psync_openfile_t *of,
                                                     char *buf, uint64_t size,
                                                     uint64_t offset) {
  psync_crypto_offsets_t offsets;
  uint64_t initialsize, hash, poffset, psize, first_page_id, aoffset, apageid,
      authupto;
  unsigned long i, pageoff, pagecnt, apsize;
  long rb;
  psync_request_t *rq;
  psync_crypto_auth_page *ap;
  psync_crypto_data_page *dp;
  char *pbuff;
  psync_interval_tree_t *intv;
  psync_list auth_pages, waiting;
  psync_fileid_t fileid;
  uint32_t asize, aoff;
  int ret, needkey;
  initialsize = of->initialsize;
  hash = of->hash;
  fileid = of->remotefileid;
  intv = psync_interval_tree_first_interval_containing_or_after(
      of->authenticatedints, offset);
  if (!intv || intv->from > offset)
    authupto = 0;
  else
    authupto = intv->to;
  if (of->encoder == PSYNC_CRYPTO_UNLOADED_SECTOR_ENCODER && initialsize &&
      offset < initialsize) {
    needkey = 1;
    of->encoder = PSYNC_CRYPTO_LOADING_SECTOR_ENCODER;
  } else
    needkey = 0;
  pthread_mutex_unlock(&of->mutex);
  pdbg_assert(PSYNC_CRYPTO_SECTOR_SIZE == PSYNC_FS_PAGE_SIZE);
  pfscrypto_offset_by_size(initialsize, &offsets);
  if (offset >= initialsize)
    return 0;
  if (offset + size > initialsize)
    size = initialsize - offset;
  poffset = offset_round_down_to_page(offset);
  pageoff = offset - poffset;
  psize = size_round_up_to_page(size + pageoff);
  pagecnt = psize / PSYNC_FS_PAGE_SIZE;
  first_page_id = poffset / PSYNC_FS_PAGE_SIZE;
  rq = malloc(sizeof(psync_request_t));
  psync_list_init(&rq->ranges);
  psync_list_init(&waiting);
  psync_list_init(&auth_pages);
  dp = malloc(sizeof(psync_crypto_data_page) * pagecnt);
  memset(dp, 0, sizeof(psync_crypto_data_page) * pagecnt);
  ap = NULL;
  lock_wait(hash);
  for (i = 0; i < pagecnt; i++) {
    if (i && (first_page_id + i) / PSYNC_CRYPTO_HASH_TREE_SECTORS ==
                 (first_page_id + i - 1) / PSYNC_CRYPTO_HASH_TREE_SECTORS) {
      dp[i].authpage = ap;
      continue;
    }
    pfscrypto_get_auth_off(first_page_id + i, 0, &offsets,
                                        &aoffset, &asize, &aoff);
    ap = malloc(sizeof(psync_crypto_auth_page));
    ap->waiter = NULL;
    ap->parent = NULL;
    ap->firstpageid = (first_page_id + i) / PSYNC_CRYPTO_HASH_TREE_SECTORS *
                      PSYNC_CRYPTO_HASH_TREE_SECTORS;
    ap->size = asize;
    ap->idinparent = 0;
    ap->level = 0;
    psync_list_add_tail(&auth_pages, &ap->list);
    dp[i].authpage = ap;
    if (request_auth_page(ap, rq, &waiting, fileid, hash, aoffset, asize))
      goto err0;
    if (authupto < (first_page_id + i + 1) * PSYNC_FS_PAGE_SIZE &&
        offsets.needmasterauth) {
      psync_crypto_auth_page *lap, *cap;
      unsigned long l;
      lap = ap;
      for (l = 1; l <= offsets.treelevels; l++) {
        pfscrypto_get_auth_off(first_page_id + i, l, &offsets,
                                            &aoffset, &asize, &aoff);
        cap = malloc(sizeof(psync_crypto_auth_page));
        cap->waiter = NULL;
        cap->parent = NULL;
        cap->firstpageid = 0;
        cap->size = asize;
        cap->idinparent = 0;
        cap->level = l;
        lap->parent = cap;
        lap->idinparent = aoff;
        lap = cap;
        psync_list_add_tail(&auth_pages, &cap->list);
        if (request_auth_page(cap, rq, &waiting, fileid, hash, aoffset, asize))
          goto err0;
      }
    }
  }
  for (i = 0; i < pagecnt; i++) {
    pbuff = NULL;
    if ((first_page_id + i) * PSYNC_FS_PAGE_SIZE + PSYNC_FS_PAGE_SIZE >
        initialsize) {
      apsize = initialsize - ((first_page_id + i) * PSYNC_FS_PAGE_SIZE);
      pdbg_assert(apsize > 0 && apsize <= PSYNC_FS_PAGE_SIZE);
    } else
      apsize = PSYNC_FS_PAGE_SIZE;
    if (i == 0) {
      if (pageoff == 0 && size > apsize)
        pbuff = buf;
    } else if (i == pagecnt - 1) {
      if (i * PSYNC_FS_PAGE_SIZE + apsize <= size + pageoff)
        pbuff = buf + i * PSYNC_FS_PAGE_SIZE - pageoff;
    } else
      pbuff = buf + i * PSYNC_FS_PAGE_SIZE - pageoff;
    if (!pbuff) {
      pbuff = malloc(sizeof(char) * apsize);
      dp[i].freebuff = 1;
    }
    dp[i].buff = pbuff;
    dp[i].pagesize = apsize;
    apageid = pfscrypto_sector_id(first_page_id + i);
    rb = check_page_in_memory_by_hash(hash, apageid, pbuff, apsize, 0);
    if (rb == -1)
      rb = check_page_in_database_by_hash(hash, apageid, pbuff, apsize, 0);
    if (rb == -1)
      dp[i].waiter = add_page_waiter(&waiting, &rq->ranges, hash, apageid,
                                     fileid, pbuff, i, 0, apsize);
    else if (unlikely(rb != apsize))
      goto err0;
  }
  unlock_wait(hash);
  psync_pagecache_read_unmodified_readahead(
      of, poffset, psize, &rq->ranges, fileid, hash, initialsize, &offsets);
  if (!psync_list_isempty(&rq->ranges) || needkey) {
    rq->of = of;
    rq->fileid = fileid;
    rq->hash = hash;
    rq->needkey = needkey;
    psync_fs_inc_of_refcnt_and_readers(of);
    prun_thread1("crypto read unmodified",
                      psync_pagecache_read_unmodified_thread, rq);
  } else
    free(rq);
  ret = 0;
  if (needkey) {
    pdbg_logf(D_NOTICE, "waiting for key to download");
    psync_fs_lock_file(of);
    while (of->encoder == PSYNC_CRYPTO_LOADING_SECTOR_ENCODER)
      pthread_cond_wait(&enc_key_cond, &of->mutex);
    if (of->encoder == PSYNC_CRYPTO_FAILED_SECTOR_ENCODER) {
      pdbg_logf(D_NOTICE, "failed to download key");
      ret = -EIO;
    }
    pthread_mutex_unlock(&of->mutex);
    pdbg_logf(D_NOTICE, "waited for key to download");
  }
  for (i = 0; i < pagecnt; i++) {
    ap = dp[i].authpage;
    if (ap->waiter) {
      wait_waiter(ap->waiter, hash, "auth");
      if (!ret && ap->waiter->error)
        ret = ap->waiter->error;
    }
    if (ap->parent && !ret) {
#ifdef P_NO_CHECKSUM_CHECK
#if IS_DEBUG
      pdbg_logf(D_NOTICE,
            "NOT checking chain checksums for pages %lu-%lu tree level %d",
            (unsigned long)ap->firstpageid,
            (unsigned long)ap->firstpageid + ap->size / PSYNC_CRYPTO_AUTH_SIZE,
            (int)offsets.treelevels);
      psync_fs_lock_file(of);
      if (likely(of->hash == hash))
        psync_interval_tree_add(
            &of->authenticatedints, ap->firstpageid * PSYNC_FS_PAGE_SIZE,
            (ap->firstpageid + ap->size / PSYNC_CRYPTO_AUTH_SIZE) *
                PSYNC_FS_PAGE_SIZE);
      pthread_mutex_unlock(&of->mutex);
#else
      abort();
#endif
#else
      pcrypto_sector_auth_t sa;
      psync_crypto_auth_page *p;
      pdbg_logf(D_NOTICE,
            "checking chain checksums for pages %lu-%lu tree level %d",
            (unsigned long)ap->firstpageid,
            (unsigned long)ap->firstpageid + ap->size / PSYNC_CRYPTO_AUTH_SIZE,
            (int)offsets.treelevels);
      pcrypto_sign_sec(of->encoder, (unsigned char *)ap->auth,
                                    ap->size, sa);
      p = ap->parent;
      ap->parent = NULL;
      do {
        if (p->waiter) {
          wait_waiter(p->waiter, hash, "chain auth");
          if (!ret && p->waiter->error)
            ret = p->waiter->error;
        }
        if (!ret && memcmp(sa, p->auth[ap->idinparent],
                           sizeof(pcrypto_sector_auth_t))) {
          pdbg_logf(D_ERROR,
                "chain verification failed for sector %lu at level %u, "
                "idinparent=%u",
                (unsigned long)(first_page_id + i), (unsigned)p->level,
                (unsigned)ap->idinparent);
          ret = -EIO;
        }
        ap = p;
        pcrypto_sign_sec(of->encoder, (unsigned char *)ap->auth,
                                      ap->size, sa);
        p = ap->parent;
      } while (p);
      ap = dp[i].authpage;
      if (!ret) {
        psync_fs_lock_file(of);
        if (likely(of->hash == hash))
          psync_interval_tree_add(
              &of->authenticatedints, ap->firstpageid * PSYNC_FS_PAGE_SIZE,
              (ap->firstpageid + ap->size / PSYNC_CRYPTO_AUTH_SIZE) *
                  PSYNC_FS_PAGE_SIZE);
        pthread_mutex_unlock(&of->mutex);
      }
#endif
    }
    if (dp[i].waiter) {
      wait_waiter(dp[i].waiter, hash, "data");
      if (!ret && dp[i].waiter->error)
        ret = dp[i].waiter->error;
    }
    if (!ret) {
      apageid = first_page_id + i - ap->firstpageid;
      pdbg_assert(apageid >= 0 && apageid < PSYNC_CRYPTO_HASH_TREE_SECTORS);
      if (pcrypto_decode_sec(
              of->encoder, (unsigned char *)dp[i].buff, dp[i].pagesize,
              (unsigned char *)dp[i].buff, ap->auth[apageid],
              first_page_id + i)) {
        pdbg_logf(D_ERROR,
              "decoding of page %lu of file %s failed pagesize=%u, requested "
              "offset=%lu, requested size=%lu",
              (unsigned long)(first_page_id + i), of->currentname,
              (unsigned)dp[i].pagesize, (unsigned long)offset,
              (unsigned long)size);
        ret = -EIO;
      } else if (dp[i].freebuff) {
        uint64_t copysize;
        unsigned long copyoff;
        if (i == 0) {
          copyoff = pageoff;
          if (size > PSYNC_FS_PAGE_SIZE - copyoff)
            copysize = PSYNC_FS_PAGE_SIZE - copyoff;
          else
            copysize = size;
          pbuff = buf;
        } else {
          pdbg_assert(i == pagecnt - 1);
          copyoff = 0;
          copysize = (size + pageoff) & (PSYNC_FS_PAGE_SIZE - 1);
          if (!copysize)
            copysize = PSYNC_FS_PAGE_SIZE;
          pbuff = buf + i * PSYNC_FS_PAGE_SIZE - pageoff;
        }
        memcpy(pbuff, dp[i].buff + copyoff, copysize);
      }
    }
  }
  if (!ret)
    ret = size;
ret0:
  psync_list_for_each_element_call(&waiting, psync_page_waiter_t, listwaiter, free);
  psync_list_for_each_element_call(&auth_pages, psync_crypto_auth_page, list, free);
  for (i = 0; i < pagecnt; i++)
    if (dp[i].freebuff)
      free(dp[i].buff);
  free(dp);
  return ret;
err0:
  free_waiters(&waiting);
  unlock_wait(hash);
  psync_pagecache_free_request(rq);
  ret = -EIO;
  goto ret0;
}

int ppagecache_readv_locked(psync_openfile_t *of,
                                 psync_pagecache_read_range *ranges, int cnt) {
  uint64_t initialsize, hash, poffset, psize, first_page_id;
  unsigned long pageoff, copyoff, copysize, pagecnt, j;
  long rb;
  psync_fileid_t fileid;
  psync_request_t *rq;
  psync_page_waiter_t *pwt;
  char *pbuff;
  psync_list waiting;
  int i, ret, needkey;
  initialsize = of->initialsize;
  hash = of->hash;
  fileid = of->remotefileid;
  if (of->encrypted && of->encoder == PSYNC_CRYPTO_UNLOADED_SECTOR_ENCODER &&
      initialsize) {
    needkey = 1;
    of->encoder = PSYNC_CRYPTO_LOADING_SECTOR_ENCODER;
  } else
    needkey = 0;
  pthread_mutex_unlock(&of->mutex);
  rq = malloc(sizeof(psync_request_t));
  psync_list_init(&rq->ranges);
  psync_list_init(&waiting);
  for (i = 0; i < cnt; i++) {
    pdbg_assert(ranges[i].offset + ranges[i].size <= of->encrypted
               ? pfscrypto_crypto_size(initialsize)
               : initialsize);
    poffset = offset_round_down_to_page(ranges[i].offset);
    pageoff = ranges[i].offset - poffset;
    psize = size_round_up_to_page(ranges[i].size + pageoff);
    pagecnt = psize / PSYNC_FS_PAGE_SIZE;
    first_page_id = poffset / PSYNC_FS_PAGE_SIZE;
    for (j = 0; j < pagecnt; j++) {
      if (j == 0) {
        copyoff = pageoff;
        if (ranges[i].size > PSYNC_FS_PAGE_SIZE - copyoff)
          copysize = PSYNC_FS_PAGE_SIZE - copyoff;
        else
          copysize = ranges[i].size;
        pbuff = ranges[i].buf;
      } else if (j == pagecnt - 1) {
        copyoff = 0;
        copysize = (ranges[i].size + pageoff) & (PSYNC_FS_PAGE_SIZE - 1);
        if (!copysize)
          copysize = PSYNC_FS_PAGE_SIZE;
        pbuff = ranges[i].buf + j * PSYNC_FS_PAGE_SIZE - pageoff;
      } else {
        copyoff = 0;
        copysize = PSYNC_FS_PAGE_SIZE;
        pbuff = ranges[i].buf + j * PSYNC_FS_PAGE_SIZE - pageoff;
      }
      rb = check_page_in_memory_by_hash(hash, first_page_id + j, pbuff,
                                        copysize, copyoff);
      if (rb == -1)
        rb = check_page_in_database_by_hash(hash, first_page_id + j, pbuff,
                                            copysize, copyoff);
      if (rb != -1) {
        if (likely(rb == copysize))
          continue;
        else {
          lock_wait(hash);
          free_waiters(&waiting);
          unlock_wait(hash);
        }
      }
      lock_wait(hash);
      add_page_waiter(&waiting, &rq->ranges, hash, first_page_id + j, fileid,
                      pbuff, j, copyoff, copysize);
      unlock_wait(hash);
    }
  }
  if (psync_list_isempty(&rq->ranges) && !needkey) {
    if (psync_list_isempty(&waiting)) {
      free(rq);
      return 0;
    }
  } else {
    rq->of = of;
    rq->fileid = fileid;
    rq->hash = hash;
    rq->needkey = needkey;
    psync_fs_inc_of_refcnt_and_readers(of);
    prun_thread1("readv unmodified",
                      psync_pagecache_read_unmodified_thread, rq);
  }
  ret = 0;
  if (needkey) {
    pdbg_logf(D_NOTICE, "waiting for key to download");
    psync_fs_lock_file(of);
    while (of->encoder == PSYNC_CRYPTO_LOADING_SECTOR_ENCODER)
      pthread_cond_wait(&enc_key_cond, &of->mutex);
    if (of->encoder == PSYNC_CRYPTO_FAILED_SECTOR_ENCODER) {
      pdbg_logf(D_NOTICE, "failed to download key");
      ret = -1;
    }
    pthread_mutex_unlock(&of->mutex);
    pdbg_logf(D_NOTICE, "waited for key to download");
  }
  lock_wait(hash);
  psync_list_for_each_element(pwt, &waiting, psync_page_waiter_t, listwaiter) {
    while (!pwt->ready) {
      pdbg_logf(D_NOTICE, "waiting for page #%lu to be read",
            (unsigned long)pwt->waiting_for->pageid);
      pthread_cond_wait(&pwt->cond, &wait_page_mutex);
      pdbg_logf(D_NOTICE,
            "waited for page"); // not safe to use pwt->waiting_for here
    }
    if (pwt->error || pwt->rsize < pwt->size)
      ret = -1;
  }
  unlock_wait(hash);
  psync_list_for_each_element_call(&waiting, psync_page_waiter_t, listwaiter,
                                   psync_free_page_waiter);
  return ret;
}

static void psync_pagecache_add_page_if_not_exists(psync_cache_page_t *page,
                                                   uint64_t hash,
                                                   uint64_t pageid) {
  psync_cache_page_t *pg;
  psync_page_wait_t *pw;
  unsigned long h1, h2;
  int hasit;
  hasit = 0;
  if (has_page_in_db(hash, pageid)) {
    psync_pagecache_return_free_page(page);
    return;
  }
  h1 = pagehash_by_hash_and_pageid(hash, pageid);
  h2 = waiterhash_by_hash_and_pageid(hash, pageid);
  lock_wait(hash);
  pthread_mutex_lock(&cache_mutex);
  psync_list_for_each_element(pg, &cache_hash[h1], psync_cache_page_t,
                              list) if (pg->type == PAGE_TYPE_READ &&
                                        pg->hash == hash &&
                                        pg->pageid == pageid) {
    hasit = 1;
    break;
  }
  if (!hasit)
    psync_list_for_each_element(pw, &wait_page_hash[h2], psync_page_wait_t,
                                list) if (pw->hash == hash &&
                                          pw->pageid == pageid) {
      hasit = 1;
      break;
    }
  if (hasit)
    psync_pagecache_return_free_page_locked(page);
  else {
    psync_list_add_tail(&cache_hash[h1], &page->list);
    cache_pages_in_hash++;
  }
  pthread_mutex_unlock(&cache_mutex);
  unlock_wait(hash);
}

static void psync_check_clean_running() {
  if (unlikely(clean_cache_in_progress)) {
    if (pthread_mutex_trylock(&clean_cache_mutex)) {
      pdbg_logf(D_NOTICE, "waiting for cache clean to exit");
      pthread_mutex_lock(&clean_cache_mutex);
      pthread_mutex_unlock(&clean_cache_mutex);
      pdbg_logf(D_NOTICE, "waited for cache clean to exit");
    } else
      pthread_mutex_unlock(&clean_cache_mutex);
  }
}

static void psync_pagecache_new_upload_to_cache(uint64_t taskid, uint64_t hash,
                                                int pause) {
  char *filename;
  psync_cache_page_t *page;
  uint64_t pageid;
  ssize_t rd;
  time_t tm;
  int fd;
  char fileidhex[sizeof(psync_fsfileid_t) * 2 + 2];
  psync_binhex(fileidhex, &taskid, sizeof(psync_fsfileid_t));
  fileidhex[sizeof(psync_fsfileid_t)] = 'd';
  fileidhex[sizeof(psync_fsfileid_t) + 1] = 0;
  tm = ptimer_time();
  filename = psync_strcat(psync_setting_get_string(_PS(fscachepath)),
                          "/", fileidhex, NULL);
  fd = pfile_open(filename, O_RDONLY, 0);
  if (fd == INVALID_HANDLE_VALUE) {
    pdbg_logf(D_ERROR, "could not open cache file %s for taskid %lu, skipping",
          filename, (unsigned long)taskid);
    pfile_delete(filename);
    free(filename);
    return;
  }
  pdbg_logf(D_NOTICE, "adding file %s to cache for hash %lu (%ld) size %ld",
        filename, (unsigned long)hash, (long)hash, (long)pfile_size(fd));
  pageid = 0;
  while (1) {
    page = psync_pagecache_get_free_page(1);
    rd = pfile_read(fd, page->page, PSYNC_FS_PAGE_SIZE);
    if (rd <= 0) {
      psync_pagecache_return_free_page(page);
      break;
    }
    page->hash = hash;
    page->pageid = pageid;
    page->lastuse = tm;
    page->size = rd;
    page->usecnt = 1;
    page->crc = pcrc32c_compute(PSYNC_CRC_INITIAL, page->page, rd);
    page->type = PAGE_TYPE_READ;
    psync_pagecache_add_page_if_not_exists(page, hash, pageid);
    if (rd < PSYNC_FS_PAGE_SIZE)
      break;
    pageid++;
    if (pause && pageid % 64 == 0) {
      psync_check_clean_running();
      psys_sleep_milliseconds(10);
    }
  }
  pfile_close(fd);
  pfile_delete(filename);
  pdbg_logf(D_NOTICE, "finished adding file %s to cache for hash %lu (%ld)",
        filename, (unsigned long)hash, (long)hash);
  free(filename);
}

static void switch_pageids(uint64_t hash, uint64_t oldhash, uint64_t *pageids,
                           unsigned long pageidcnt) {
  psync_sql_res *res;
  unsigned long i;
  res = psql_prepare(
      "UPDATE OR IGNORE pagecache SET hash=?, lastuse=? WHERE hash=? AND "
      "type=? AND pageid=?");
  psql_start();
  psql_bind_uint(res, 1, hash);
  psql_bind_uint(res, 2, ptimer_time());
  psql_bind_uint(res, 3, oldhash);
  psql_bind_uint(res, 4, PAGE_TYPE_READ);
  for (i = 0; i < pageidcnt; i++) {
    psql_bind_uint(res, 5, pageids[i]);
    psql_run(res);
  }
  psql_commit();
  psql_free(res);
}

static void psync_pagecache_modify_to_cache(uint64_t taskid, uint64_t hash,
                                            uint64_t oldhash) {
  uint64_t pageids[64];
  char *filename, *indexname;
  const char *cachepath;
  psync_cache_page_t *page;
  psync_interval_tree_t *tree, *interval;
  uint64_t pageid, off, roff, rdoff, rdlen;
  int64_t fs;
  ssize_t rd;
  long pdb;
  unsigned long pageidcnt;
  time_t tm;
  int fd;
  char fileidhex[sizeof(psync_fsfileid_t) * 2 + 2];
  int ret;
  pageidcnt = 0;
  psync_binhex(fileidhex, &taskid, sizeof(psync_fsfileid_t));
  fileidhex[sizeof(psync_fsfileid_t)] = 'd';
  fileidhex[sizeof(psync_fsfileid_t) + 1] = 0;
  tm = ptimer_time();
  cachepath = psync_setting_get_string(_PS(fscachepath));
  filename =
      psync_strcat(cachepath, "/", fileidhex, NULL);
  fileidhex[sizeof(psync_fsfileid_t)] = 'i';
  indexname =
      psync_strcat(cachepath, "/", fileidhex, NULL);
  fd = pfile_open(indexname, O_RDONLY, 0);
  if (unlikely(fd == INVALID_HANDLE_VALUE)) {
    pdbg_logf(D_ERROR,
          "could not open index of cache file %s for taskid %lu, skipping",
          indexname, (unsigned long)taskid);
    pfile_delete(filename);
    pfile_delete(indexname);
    free(filename);
    free(indexname);
    return;
  }
  tree = NULL;
  if (pdbg_unlikely((fs = pfile_size(fd)) == -1 ||
                   psync_fs_load_interval_tree(fd, fs, &tree) == -1))
    goto err2;
  pfile_close(fd);
  fd = pfile_open(filename, O_RDONLY, 0);
  if (unlikely(fd == INVALID_HANDLE_VALUE)) {
    pdbg_logf(D_ERROR, "could not open cache file %s for taskid %lu, skipping",
          filename, (unsigned long)taskid);
    goto err1;
  }
  fs = pfile_size(fd);
  if (pdbg_unlikely(fs == -1))
    goto err2;
  pdbg_logf(D_NOTICE,
        "adding blocks of file %s to cache for hash %lu (%ld), old hash %lu "
        "(%ld) size %ld",
        filename, (unsigned long)hash, (long)hash, (unsigned long)oldhash,
        (long)oldhash, (long)fs);
  interval = psync_interval_tree_get_first(tree);
  for (off = 0; off < fs; off += PSYNC_FS_PAGE_SIZE) {
    pageid = off / PSYNC_FS_PAGE_SIZE;
    while (interval && interval->to <= off)
      interval = psync_interval_tree_get_next(interval);
    if (!interval ||
        interval->from >= off + PSYNC_FS_PAGE_SIZE) { // full old page
      if (unlikely(off + PSYNC_FS_PAGE_SIZE >
                   fs)) { // last page, if it is equal we are ok
        page = psync_pagecache_get_free_page(1);
        pdb = check_page_in_memory_by_hash(oldhash, pageid, page->page,
                                           fs - off, 0);
        if (pdb == -1)
          pdb = check_page_in_database_by_hash(oldhash, pageid, page->page,
                                               fs - off, 0);
        if (pdb == -1) {
          psync_pagecache_return_free_page(page);
          break;
        }
        page->hash = hash;
        page->pageid = pageid;
        page->lastuse = tm;
        page->size = pdb;
        page->usecnt = 1;
        page->crc = pcrc32c_compute(PSYNC_CRC_INITIAL, page->page, pdb);
        page->type = PAGE_TYPE_READ;
        psync_pagecache_add_page_if_not_exists(page, hash, pageid);
        break;
      }
      if (!switch_memory_page_to_hash(oldhash, hash, pageid)) {
        pageids[pageidcnt] = pageid;
        if (++pageidcnt == ARRAY_SIZE(pageids)) {
          pageidcnt = 0;
          switch_pageids(hash, oldhash, pageids, ARRAY_SIZE(pageids));
          psys_sleep_milliseconds(10);
          psync_check_clean_running();
        }
      }
    } else if (interval->from <= off &&
               (interval->to >= off + PSYNC_FS_PAGE_SIZE ||
                interval->to >= fs)) { // full new page
      page = psync_pagecache_get_free_page(1);
      if (off + PSYNC_FS_PAGE_SIZE > fs)
        rd = fs - off;
      else
        rd = PSYNC_FS_PAGE_SIZE;
      rd = pfile_pread(fd, page->page, rd, off);
      if (rd < PSYNC_FS_PAGE_SIZE && off + rd != fs) {
        psync_pagecache_return_free_page(page);
        break;
      }
      page->hash = hash;
      page->pageid = pageid;
      page->lastuse = tm;
      page->size = rd;
      page->usecnt = 1;
      page->crc = pcrc32c_compute(PSYNC_CRC_INITIAL, page->page, rd);
      page->type = PAGE_TYPE_READ;
      //      pdbg_logf(D_NOTICE, "new page %lu crc %lu size %lu", (unsigned
      //      long)pageid, (unsigned long)page->crc, (unsigned long)rd);
      psync_pagecache_add_page_if_not_exists(page, hash, pageid);
      if (pageid % 64 == 0) {
        psync_check_clean_running();
        psys_sleep_milliseconds(10);
      }
    } else { // page with both old and new fragments
      // we covered full new page and full old page cases, so this interval
      // either ends or starts inside current page
      pdbg_assert(
          (interval->to > off && interval->to <= off + PSYNC_FS_PAGE_SIZE) ||
          (interval->from >= off && interval->from < off + PSYNC_FS_PAGE_SIZE));
      page = psync_pagecache_get_free_page(1);
      pdb = check_page_in_memory_by_hash(oldhash, pageid, page->page,
                                         PSYNC_FS_PAGE_SIZE, 0);
      if (pdb == -1)
        pdb = check_page_in_database_by_hash(oldhash, pageid, page->page,
                                             PSYNC_FS_PAGE_SIZE, 0);
      if (pdb == -1) {
        psync_pagecache_return_free_page(page);
        continue;
      }
      ret = 0;
      while (1) {
        if (interval->from > off) {
          roff = interval->from - off;
          rdoff = interval->from;
        } else {
          roff = 0;
          rdoff = off;
        }
        if (interval->to < off + PSYNC_FS_PAGE_SIZE)
          rdlen = interval->to - rdoff;
        else
          rdlen = PSYNC_FS_PAGE_SIZE - roff;
        pdbg_assert(roff + rdlen <= PSYNC_FS_PAGE_SIZE);
        //          pdbg_logf(D_NOTICE, "ifrom=%lu ito=%lu roff=%lu roff=%lu
        //          rdlen=%lu", interval->from, interval->to, rdoff, roff,
        //          rdlen);
        rd = pfile_pread(fd, page->page + roff, rdlen, rdoff);
        if (rd != rdlen) {
          if (rd >= 0 && rdoff + rd >= fs) {
            if (roff + rd > pdb)
              pdb = roff + rd;
            break;
          }
          ret = -1;
          break;
        }
        if (roff + rd > pdb)
          pdb = roff + rd;
        if (interval->to > off + PSYNC_FS_PAGE_SIZE)
          break;
        interval = psync_interval_tree_get_next(interval);
        if (!interval || interval->from >= off + PSYNC_FS_PAGE_SIZE)
          break;
      }
      if (pdbg_unlikely(ret == -1)) {
        psync_pagecache_return_free_page(page);
        continue;
      }
      if (pdb + off > fs) {
        pdbg_logf(D_NOTICE, "%lu+%lu>%lu", (unsigned long)pdb, (unsigned long)off,
              (unsigned long)fs);
        pdbg_assert(fs > off);
        pdb = fs - off;
      }
      page->hash = hash;
      page->pageid = pageid;
      page->lastuse = tm;
      page->size = pdb;
      page->usecnt = 1;
      page->crc = pcrc32c_compute(PSYNC_CRC_INITIAL, page->page, pdb);
      page->type = PAGE_TYPE_READ;
      //      pdbg_logf(D_NOTICE, "combined page %lu crc %lu size %lu", (unsigned
      //      long)pageid, (unsigned long)page->crc, (unsigned long)pdb);
      psync_pagecache_add_page_if_not_exists(page, hash, pageid);
      if (pageid % 64 == 0) {
        psync_check_clean_running();
        psys_sleep_milliseconds(10);
      }
    }
  }
err2:
  if (pageidcnt)
    switch_pageids(hash, oldhash, pageids, pageidcnt);
  pfile_close(fd);
err1:
  psync_interval_tree_free(tree);
  pfile_delete(filename);
  free(filename);
  pfile_delete(indexname);
  free(indexname);
}

static void psync_pagecache_check_free_space() {
  const char *cachepath;
  uint64_t minlocal;
  int64_t freespc;
  cachepath = psync_setting_get_string(_PS(fscachepath));
  minlocal = psync_setting_get_uint(_PS(minlocalfreespace));
  freespc = ppath_free_space(cachepath);
  if (unlikely(freespc == -1)) {
    pdbg_logf(D_WARNING, "could not get free space of path %s", cachepath);
    return;
  }
  if (freespc >= minlocal)
    psync_set_local_full(0);
  else {
    pdbg_logf(D_WARNING, "local disk holding %s is full", cachepath);
    psync_set_local_full(1);
  }
}

static void psync_pagecache_upload_to_cache() {
  psync_sql_res *res;
  psync_uint_row row;
  uint64_t id, type, taskid, hash, oldhash;
  uint32_t wake;
  while (1) {
    res = psql_query("SELECT id, type, taskid, hash, oldhash FROM "
                          "pagecachetask ORDER BY id LIMIT 1");
    row = psql_fetch_int(res);
    if (!row) {
      upload_to_cache_thread_run = 0;
      psql_free(res);
      break;
    }
    id = row[0];
    type = row[1];
    taskid = row[2];
    hash = row[3];
    oldhash = row[4];
    psql_free(res);
    if (type == PAGE_TASK_TYPE_CREAT)
      psync_pagecache_new_upload_to_cache(taskid, hash, 1);
    else if (type == PAGE_TASK_TYPE_MODIFY)
      psync_pagecache_modify_to_cache(taskid, hash, oldhash);
    psql_start();
    res = psql_prepare(
        "DELETE FROM fstaskdepend WHERE dependfstaskid=?");
    psql_bind_uint(res, 1, taskid);
    psql_run_free(res);
    wake = psql_affected();
    res = psql_prepare("DELETE FROM fstask WHERE id=?");
    psql_bind_uint(res, 1, taskid);
    psql_run_free(res);
    if (IS_DEBUG) {
      if (psql_affected())
        pdbg_logf(D_NOTICE, "deleted taskid %lu from fstask",
              (unsigned long)taskid);
      else
        pdbg_logf(D_NOTICE,
              "no affected rows for deletion of taskid %lu from fstask",
              (unsigned long)taskid);
    }
    res = psql_prepare("DELETE FROM pagecachetask WHERE id=?");
    psql_bind_uint(res, 1, id);
    psql_run_free(res);
    psql_commit();
    if (wake)
      psync_fsupload_wake();
    psync_pagecache_check_free_space();
  }
}

static void psync_pagecache_add_task(uint32_t type, uint64_t taskid,
                                     uint64_t hash, uint64_t oldhash) {
  psync_sql_res *res;
  int run;
  run = 0;
  res = psql_prepare("INSERT INTO pagecachetask (type, taskid, "
                                 "hash, oldhash) VALUES (?, ?, ?, ?)");
  psql_bind_uint(res, 1, type);
  psql_bind_uint(res, 2, taskid);
  psql_bind_uint(res, 3, hash);
  psql_bind_uint(res, 4, oldhash);
  if (!upload_to_cache_thread_run) {
    upload_to_cache_thread_run = 1;
    run = 1;
  }
  psql_run_free(res);
  if (run)
    prun_thread("upload to cache", psync_pagecache_upload_to_cache);
}

void ppagecache_creat(uint64_t taskid, uint64_t hash,
                                        int onthisthread) {
  if (onthisthread)
    psync_pagecache_new_upload_to_cache(taskid, hash, 0);
  else
    psync_pagecache_add_task(PAGE_TASK_TYPE_CREAT, taskid, hash, 0);
}

void ppagecache_modify(uint64_t taskid, uint64_t hash,
                                         uint64_t oldhash) {
  psync_pagecache_add_task(PAGE_TASK_TYPE_MODIFY, taskid, hash, oldhash);
}

int ppagecache_have_all_pages(uint64_t hash, uint64_t size) {
  unsigned char *db;
  uint32_t i, pagecnt;
  pagecnt = (size + PSYNC_FS_PAGE_SIZE - 1) / PSYNC_FS_PAGE_SIZE;
  db = has_pages_in_db(hash, 0, pagecnt, 0);
  for (i = 0; i < pagecnt; i++)
    if (!db[i] && !has_page_in_cache_by_hash(hash, i))
      break;
  free(db);
  return i == pagecnt;
}

int ppagecache_copy_to_file_locked(
    psync_openfile_t *of, uint64_t hash, uint64_t size) {
  char buff[PSYNC_FS_PAGE_SIZE];
  uint64_t i, pagecnt;
  long rb;
  pagecnt = (size + PSYNC_FS_PAGE_SIZE - 1) / PSYNC_FS_PAGE_SIZE;
  for (i = 0; i < pagecnt; i++) {
    rb = check_page_in_memory_by_hash(hash, i, buff, PSYNC_FS_PAGE_SIZE, 0);
    if (rb == -1) {
      rb = check_page_in_database_by_hash(hash, i, buff, PSYNC_FS_PAGE_SIZE, 0);
      if (rb == -1)
        return -1;
    }
    pdbg_assertw(rb == PSYNC_FS_PAGE_SIZE || i * PSYNC_FS_PAGE_SIZE + rb == size);
    if (pfile_pwrite(of->datafile, buff, rb, i * PSYNC_FS_PAGE_SIZE) != rb)
      return -1;
  }
  if (pdbg_unlikely(pfile_sync(of->datafile)))
    return -1;
  else {
    pdbg_logf(D_NOTICE, "copied %lu bytes to data file of %s from cache",
          (unsigned long)size, of->currentname);
    return 0;
  }
}

int ppagecache_lock_pages() {
  if (pthread_mutex_trylock(&clean_cache_mutex))
    return -1;
  clean_cache_stoppers++;
  pthread_mutex_unlock(&clean_cache_mutex);
  return 0;
}

void ppagecache_unlock_pages() {
  pthread_mutex_lock(&clean_cache_mutex);
  if (--clean_cache_stoppers == 0 && clean_cache_waiters)
    pthread_cond_broadcast(&clean_cache_cond);
  pthread_mutex_unlock(&clean_cache_mutex);
}

void ppagecache_resize() {
  pthread_mutex_lock(&flush_cache_mutex);
  db_cache_in_pages =
      psync_setting_get_uint(_PS(fscachesize)) / PSYNC_FS_PAGE_SIZE;
  db_cache_max_page = psql_cellint("SELECT MAX(id) FROM pagecache", 0);
  if (db_cache_max_page > db_cache_in_pages) {
    psync_sql_res *res;
    struct stat st;
    res = psql_prepare("DELETE FROM pagecache WHERE id>?");
    psql_bind_uint(res, 1, db_cache_in_pages);
    psql_run_free(res);
    db_cache_max_page = db_cache_in_pages;
    if (!fstat(readcache, &st) &&
        pfile_stat_size(&st) > db_cache_in_pages * PSYNC_FS_PAGE_SIZE) {
      if (pdbg_likely(pfile_seek(readcache,
                                     db_cache_in_pages * PSYNC_FS_PAGE_SIZE,
                                     SEEK_SET) != -1)) {
        pdbg_assertw(pfile_truncate(readcache) == 0);
        pdbg_logf(D_NOTICE, "shrunk cache to %lu pages (%lu bytes)",
              (unsigned long)db_cache_in_pages,
              (unsigned long)db_cache_in_pages * PSYNC_FS_PAGE_SIZE);
      }
    }
  }
  pthread_mutex_unlock(&flush_cache_mutex);
}

static int psync_pagecache_free_page_from_read_cache() {
  struct stat st;
  uint64_t sizeinpages;
  psync_sql_res *res;
  psync_cache_page_t *page;
  psync_uint_row row;
  int ret;
  ret = -1;
  pthread_mutex_lock(&flush_cache_mutex);
  do {
    if (fstat(readcache, &st)) {
      pdbg_logf(D_NOTICE, "stat of read cache file failed");
      break;
    }
    if (pfile_stat_size(&st) < PSYNC_FS_PAGE_SIZE * 2) {
      pdbg_logf(D_NOTICE, "read cache is already zero");
      break;
    }
    sizeinpages = pfile_stat_size(&st) / PSYNC_FS_PAGE_SIZE - 1;
    if (unlikely(db_cache_max_page > sizeinpages)) {
      pdbg_logf(D_NOTICE, "there are %lu unallocated pages in db, deleting",
            (unsigned long)(db_cache_max_page - sizeinpages));
      res = psql_prepare("DELETE FROM pagecache WHERE id>?");
      psql_bind_uint(res, 1, sizeinpages);
      psql_run_free(res);
      db_cache_max_page = sizeinpages;
    } else if (pdbg_unlikely(db_cache_max_page < sizeinpages))
      sizeinpages = db_cache_max_page;
    page = psync_pagecache_get_free_page_if_available();
    if (unlikely(!page)) {
      pdbg_logf(D_NOTICE, "no free pages, skipping");
      break;
    }
    if (pfile_pread(readcache, page->page, PSYNC_FS_PAGE_SIZE,
                         sizeinpages * PSYNC_FS_PAGE_SIZE) !=
        PSYNC_FS_PAGE_SIZE) {
      psync_pagecache_return_free_page(page);
      pdbg_logf(D_NOTICE, "read from read cache failed");
      break;
    }
    res = psql_query_rdlock("SELECT type, hash, pageid, lastuse, usecnt, "
                                 "size, crc FROM pagecache WHERE id=?");
    psql_bind_uint(res, 1, sizeinpages);
    row = psql_fetch_int(res);
    if (!row || row[0] == PAGE_TYPE_FREE) {
      psql_free(res);
      psync_pagecache_return_free_page(page);
    } else {
      page->hash = row[1];
      page->pageid = row[2];
      page->lastuse = row[3];
      page->size = row[5];
      page->usecnt = row[4];
      page->crc = row[6];
      psql_free(res);
      if (unlikely(pcrc32c_compute(PSYNC_CRC_INITIAL, page->page, page->size) !=
                   page->crc)) {
        pdbg_logf(
            D_WARNING,
            "page CRC check failed, dropping page, db CRC %u calculated CRC %u",
            (unsigned)page->crc,
            (unsigned)pcrc32c_compute(PSYNC_CRC_INITIAL, page->page, page->size));
        psync_pagecache_return_free_page(page);
      } else {
        page->type = PAGE_TYPE_READ;
        psync_pagecache_add_page_if_not_exists(page, page->hash, page->pageid);
      }
    }
    db_cache_max_page = sizeinpages - 1;
    res = psql_prepare("DELETE FROM pagecache WHERE id>?");
    psql_bind_uint(res, 1, db_cache_max_page);
    psql_run_free(res);
    if (pfile_seek(readcache, sizeinpages * PSYNC_FS_PAGE_SIZE,
                        SEEK_SET) != -1 &&
        pfile_truncate(readcache) == 0)
      ret = 0;
    else
      pdbg_logf(D_NOTICE, "failed to truncate down read cache");
  } while (0);
  pthread_mutex_unlock(&flush_cache_mutex);
  return ret;
}

uint64_t ppagecache_free_read(uint64_t size) {
  uint64_t i;
  size = size_round_up_to_page(size) / PSYNC_FS_PAGE_SIZE;
  for (i = 0; i < size; i++)
    if (psync_pagecache_free_page_from_read_cache()) {
      pdbg_logf(D_WARNING, "failed to free page from read cache");
      break;
    }
  pdbg_logf(D_NOTICE, "freed %lu pages from read cache", (unsigned long)i);
  return i * PSYNC_FS_PAGE_SIZE;
}

void ppagecache_init() {
  uint64_t i;
  char *page_data, *cache_file;
  const char *cache_dir;
  psync_sql_res *res;
  psync_cache_page_t *page;
  struct stat st;
  for (i = 0; i < CACHE_HASH; i++)
    psync_list_init(&cache_hash[i]);
  for (i = 0; i < PAGE_WAITER_HASH; i++)
    psync_list_init(&wait_page_hash[i]);
  pthread_mutex_init(&wait_page_mutex, NULL);
  psync_list_init(&free_pages);
  memset(cachepages_to_update, 0, sizeof(cachepages_to_update));
  pages_base = (char *)pmem_mmap_safe(
      CACHE_PAGES * (PSYNC_FS_PAGE_SIZE + sizeof(psync_cache_page_t)));
  page_data = pages_base;
  page = (psync_cache_page_t *)(page_data + CACHE_PAGES * PSYNC_FS_PAGE_SIZE);
  cache_pages_free = CACHE_PAGES;
  for (i = 0; i < CACHE_PAGES; i++) {
    page->page = page_data;
    psync_list_add_tail(&free_pages, &page->list);
    page_data += PSYNC_FS_PAGE_SIZE;
    page++;
  }
  cache_dir = psync_setting_get_string(_PS(fscachepath));
  if (stat(cache_dir, &st)) {
    mkdir(cache_dir, PSYNC_DEFAULT_POSIX_FOLDER_MODE);
  }
  cache_file = psync_strcat(cache_dir, "/",
                            PSYNC_DEFAULT_READ_CACHE_FILE, NULL);
  if (stat(cache_file, &st))
    psql_statement("DELETE FROM pagecache");
  else {
    res = psql_prepare("DELETE FROM pagecache WHERE id>?");
    psql_bind_uint(res, 1, pfile_stat_size(&st) / PSYNC_FS_PAGE_SIZE);
    psql_run_free(res);
  }
  db_cache_in_pages =
      psync_setting_get_uint(_PS(fscachesize)) / PSYNC_FS_PAGE_SIZE;
  db_cache_max_page = psql_cellint("SELECT MAX(id) FROM pagecache", 0);
  free_db_pages = psql_cellint(
      "SELECT COUNT(*) FROM pagecache WHERE type=" NTO_STR(PAGE_TYPE_FREE), 0);
  if (db_cache_max_page < db_cache_in_pages &&
      free_db_pages < CACHE_PAGES * 2) {
    i = 0;
    psql_start();
    res = psql_prepare(
        "INSERT INTO pagecache (type) VALUES (" NTO_STR(PAGE_TYPE_FREE) ")");
    while (db_cache_max_page + i < db_cache_in_pages && i < CACHE_PAGES * 2) {
      psql_run(res);
      i++;
    }
    psql_free(res);
    psql_commit();
    free_db_pages += i;
    db_cache_max_page += i;
    pdbg_logf(D_NOTICE,
          "inserted %lu new free pages to database, db_cache_in_pages=%lu, "
          "db_cache_max_page=%lu",
          (unsigned long)i, (unsigned long)db_cache_in_pages,
          (unsigned long)db_cache_max_page);
  }
  readcache = pfile_open(cache_file, O_RDWR, O_CREAT);
  free(cache_file);
  if (pdbg_likely(pfile_seek(readcache,
                                 db_cache_max_page * PSYNC_FS_PAGE_SIZE,
                                 SEEK_SET) != -1))
    pdbg_assertw(pfile_truncate(readcache) == 0);
  if (db_cache_max_page > db_cache_in_pages)
    ppagecache_resize();
  pthread_mutex_lock(&flush_cache_mutex);
  check_disk_full();
  pthread_mutex_unlock(&flush_cache_mutex);
  psql_lock();
  if (psql_cellint("SELECT COUNT(*) FROM pagecachetask", 0)) {
    prun_thread("upload to cache", psync_pagecache_upload_to_cache);
    upload_to_cache_thread_run = 1;
  }
  psql_unlock();
  ptimer_register(ppagecache_flush_timer, PSYNC_FS_DISK_FLUSH_SEC,
                       NULL);
}

void clean_cache_del(void *delcache, ppath_stat *st) {
  int ret;
  if (!pfile_stat_isfolder(&st->stat) &&
      (delcache ||
       strcmp(st->name, PSYNC_DEFAULT_READ_CACHE_FILE))) {
    ret = pfile_delete(st->path);
    pdbg_logf(D_NOTICE, "delete of %s=%d", st->path, ret);
  }
}

void ppagecache_clean() {
  const char *cache_dir;
  cache_dir = psync_setting_get_string(_PS(fscachepath));
  if (readcache != INVALID_HANDLE_VALUE) {
    pfile_close(readcache);
    readcache = INVALID_HANDLE_VALUE;
  }
  ppath_ls(cache_dir, clean_cache_del, (void *)1);
}

void ppagecache_reopen_read() {
  char *cache_file;
  const char *cache_dir;
  struct stat st;
  cache_dir = psync_setting_get_string(_PS(fscachepath));
  if (stat(cache_dir, &st)) {
    mkdir(cache_dir, PSYNC_DEFAULT_POSIX_FOLDER_MODE);
  }
  cache_file = psync_strcat(cache_dir, "/",
                            PSYNC_DEFAULT_READ_CACHE_FILE, NULL);
  readcache = pfile_open(cache_file, O_RDWR, O_CREAT);
  free(cache_file);
}

void ppagecache_clean_read() {
  uint32_t i, cnt;
  psync_sql_res *res;
  pdbg_logf(D_NOTICE, "start");
  pthread_mutex_lock(&clean_cache_mutex);
  pthread_mutex_lock(&flush_cache_mutex);
  psql_start();
  pdbg_logf(D_NOTICE, "aquired locks");
  db_cache_in_pages =
      psync_setting_get_uint(_PS(fscachesize)) / PSYNC_FS_PAGE_SIZE;
  if (db_cache_in_pages < 2 * CACHE_PAGES)
    cnt = db_cache_in_pages;
  else
    cnt = 2 * CACHE_PAGES;
  pfile_seek(readcache, cnt * PSYNC_FS_PAGE_SIZE, SEEK_SET);
  pdbg_assertw(pfile_truncate(readcache) == 0);
  pdbg_logf(D_NOTICE, "truncated cache file");
  res = psql_prepare("DELETE FROM pagecache");
  psql_run_free(res);
  pdbg_logf(D_NOTICE, "deleted entries from pagecache");
  res = psql_prepare(
      "INSERT INTO pagecache (type) VALUES (" NTO_STR(PAGE_TYPE_FREE) ")");
  for (i = 0; i < cnt; i++)
    psql_run(res);
  psql_free(res);
  pdbg_logf(D_NOTICE,
        "re-inserted some free pages into database, commiting transaction");
  free_db_pages = cnt;
  db_cache_max_page = cnt;
  psql_commit();
  pthread_mutex_unlock(&flush_cache_mutex);
  pthread_mutex_unlock(&clean_cache_mutex);
  pdbg_logf(D_NOTICE, "end");
}

int ppagecache_move(const char *path) {
  struct stat st;
  psync_sql_res *res;
  char *rdpath, *opath;
  int newrdcache, ordcache;
  uint32_t i, cnt;
  pdbg_logf(D_NOTICE, "start");
  rdpath = psync_strcat(path, "/",
                        PSYNC_DEFAULT_READ_CACHE_FILE, NULL);
  if (!stat(rdpath, &st)) {
    free(rdpath);
    return pdbg_return_const(PERROR_CACHE_MOVE_NOT_EMPTY);
  }
  newrdcache = pfile_open(rdpath, O_RDWR, O_CREAT | O_EXCL);
  if (newrdcache == INVALID_HANDLE_VALUE) {
    free(rdpath);
    return pdbg_return_const(PERROR_CACHE_MOVE_NO_WRITE_ACCESS);
  }
  opath = psync_strdup(psync_setting_get_string(_PS(fscachepath)));
  pthread_mutex_lock(&clean_cache_mutex);
  pthread_mutex_lock(&flush_cache_mutex);
  psql_start();
  pdbg_logf(D_NOTICE, "aquired locks");
  if (psql_cellint("SELECT COUNT(*) FROM fstask", 0) != 0) {
    if (IS_DEBUG) {
      psync_variant_row row;
      pdbg_logf(D_NOTICE, "the following tasks are preventing the cache move:");
      res = psql_query_nolock(
          "SELECT id, type, status, folderid, text1 FROM fstask LIMIT 10");
      while ((row = psql_fetch(res)))
        pdbg_logf(D_NOTICE, "%u %u %u %u %s", (unsigned)psync_get_number(row[0]),
              (unsigned)psync_get_number(row[1]),
              (unsigned)psync_get_number(row[2]),
              (unsigned)psync_get_number(row[3]), psync_get_string(row[4]));
    }
    psql_rollback();
    pthread_mutex_unlock(&flush_cache_mutex);
    pthread_mutex_unlock(&clean_cache_mutex);
    pfile_close(newrdcache);
    pfile_delete(rdpath);
    free(opath);
    free(rdpath);
    return pdbg_return_const(PERROR_CACHE_MOVE_DRIVE_HAS_TASKS);
  }
  ordcache = readcache;
  readcache = newrdcache;
  psync_setting_set_string(_PS(fscachepath), path);
  db_cache_in_pages =
      psync_setting_get_uint(_PS(fscachesize)) / PSYNC_FS_PAGE_SIZE;
  if (db_cache_in_pages < 2 * CACHE_PAGES)
    cnt = db_cache_in_pages;
  else
    cnt = 2 * CACHE_PAGES;
  pfile_seek(readcache, cnt * PSYNC_FS_PAGE_SIZE, SEEK_SET);
  pdbg_assertw(pfile_truncate(readcache) == 0);
  pdbg_logf(D_NOTICE, "truncated cache file");
  res = psql_prepare("DELETE FROM pagecache");
  psql_run_free(res);
  pdbg_logf(D_NOTICE, "deleted entries from pagecache");
  res = psql_prepare(
      "INSERT INTO pagecache (type) VALUES (" NTO_STR(PAGE_TYPE_FREE) ")");
  for (i = 0; i < cnt; i++)
    psql_run(res);
  psql_free(res);
  pdbg_logf(D_NOTICE,
        "re-inserted some free pages into database, commiting transaction");
  free_db_pages = cnt;
  db_cache_max_page = cnt;
  psql_commit();
  pthread_mutex_unlock(&flush_cache_mutex);
  pthread_mutex_unlock(&clean_cache_mutex);
  pdbg_logf(D_NOTICE, "released locks");
  pfile_close(ordcache);
  ppath_ls(opath, clean_cache_del, (void *)1);
  free(opath);
  free(rdpath);
  pdbg_logf(D_NOTICE, "end");
  return 0;
}
