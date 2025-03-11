/*
  Copyright (c) 2014 Anton Titov.

  Copyright (c) 2014 pCloud Ltd.  All rights reserved.

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


#include <mbedtls/ctr_drbg.h>
#include <mbedtls/debug.h>
#include <mbedtls/entropy.h>
#include <mbedtls/pkcs5.h>
#include <mbedtls/ssl.h>
#include <pthread.h>

#include "pcache.h"
#include "plibs.h"
#include "plist.h"
#include "psynclib.h"
#include "psys.h"
#include "ptimer.h"
#include <string.h>

// required by psync_cache_get
extern PSYNC_THREAD const char *psync_thread_name; 

#define CACHE_HASH_SIZE 2048
#define CACHE_NUM_LOCKS 8

#define hash_to_bucket(h) ((h) % CACHE_HASH_SIZE)
#define hash_to_lock(h) ((((h) * CACHE_NUM_LOCKS) / CACHE_HASH_SIZE) % CACHE_NUM_LOCKS)

typedef struct {
  psync_list list;
  void *value;
  pcache_free_cb free;
  psync_timer_t timer;
  uint32_t hash;
  char key[];
} cache_entry_t;

static psync_list cache_hash[CACHE_HASH_SIZE];
static pthread_mutex_t cachelocks[CACHE_NUM_LOCKS];
static uint32_t hash_seed;

static uint32_t compute_hash(const char *key, size_t *len) {
  const char *k;
  uint32_t c, hash;
  k = key;
  hash = hash_seed;
  while ((c = (uint32_t)*k++))
    hash = c + (hash << 5) + hash;
  hash += hash << 3;
  hash ^= hash >> 11;
  if(len) {
    *len = k - key - 1;
  }
  return hash;
}

static void cache_timer(psync_timer_t timer, void *ptr) {
  cache_entry_t *he = (cache_entry_t *)ptr;
  pthread_mutex_lock(&cachelocks[hash_to_lock(he->hash)]);
  psync_list_del(&he->list);
  pthread_mutex_unlock(&cachelocks[hash_to_lock(he->hash)]);
  he->free(he->value);
  free(he);
  ptimer_stop(timer);
}

void pcache_init() {
  pthread_mutexattr_t mattr;
  unsigned long i;
  for (i = 0; i < CACHE_HASH_SIZE; i++)
    psync_list_init(&cache_hash[i]);
  for (i = 0; i < CACHE_NUM_LOCKS; i++) {
    pthread_mutexattr_init(&mattr);
    pthread_mutexattr_settype(&mattr, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&cachelocks[i], &mattr);
    pthread_mutexattr_destroy(&mattr);
  }
  // do not use psync_ssl_rand_* here as it is not yet initialized
  hash_seed = psys_time_seconds() * 0xc2b2ae35U;
}

void *pcache_get(const char *key) {
  cache_entry_t *he;
  void *val;
  psync_list *lst;
  uint32_t h;
  if (IS_DEBUG && !strcmp(psync_thread_name, "timer"))
    debug(D_ERROR,
          "trying get key %s from the timer thread, this may (and eventually "
          "will) lead to a deadlock, "
          "please start a worker thread to do the job or don't use cache (if "
          "you are looking up sql "
          "query/statement, you can use _nocache version)",
          key);

  h = compute_hash(key, NULL);
  //  debug(D_NOTICE, "get %s %lu", key, h);
  lst = &cache_hash[hash_to_bucket(h)];
  pthread_mutex_lock(&cachelocks[hash_to_lock(h)]);
  psync_list_for_each_element(
      he, lst, cache_entry_t, list) if (he->hash == h && !strcmp(key, he->key)) {
    if (ptimer_stop(he->timer))
      continue;
    psync_list_del(&he->list);
    pthread_mutex_unlock(&cachelocks[hash_to_lock(h)]);
    val = he->value;
    free(he);
    return val;
  }
  pthread_mutex_unlock(&cachelocks[hash_to_lock(h)]);
  return NULL;
}

int pcache_has(const char *key) {
  cache_entry_t *he;
  psync_list *lst;
  uint32_t h;
  int ret;
  h = compute_hash(key, NULL);
  ret = 0;
  lst = &cache_hash[hash_to_bucket(h)];
  pthread_mutex_lock(&cachelocks[hash_to_lock(h)]);
  psync_list_for_each_element(
      he, lst, cache_entry_t, list) if (he->hash == h && !strcmp(key, he->key)) {
    ret = 1;
    break;
  }
  pthread_mutex_unlock(&cachelocks[hash_to_lock(h)]);
  return ret;
}

void pcache_add(const char *key, void *ptr, time_t freeafter,
                     pcache_free_cb freefunc, uint32_t maxkeys) {
  cache_entry_t *he, *he2;
  psync_list *lst;
  size_t l;
  uint32_t h;
  h = compute_hash(key, &l);
  l++;
  he = (cache_entry_t *)malloc(offsetof(cache_entry_t, key) + l);
  he->value = ptr;
  he->free = freefunc;
  he->hash = h;
  memcpy(he->key, key, l);
  lst = &cache_hash[hash_to_bucket(h)];
  pthread_mutex_lock(&cachelocks[hash_to_lock(h)]);
  if (maxkeys) {
    l = 0;
    psync_list_for_each_element(he2, lst, cache_entry_t,
                                list) if (unlikely(he2->hash == h &&
                                                   !strcmp(key, he2->key) &&
                                                   ++l == maxkeys)) {
      pthread_mutex_unlock(&cachelocks[hash_to_lock(h)]);
      free(he);
      freefunc(ptr);
      //        debug(D_NOTICE, "not adding key %s to cache as there already %u
      //        elements present", key, (unsigned int)maxkeys);
      return;
    }
  }
  /* adding to head should be better than to the tail: more recent objects are
   * likely to be in processor cache, more recent connections are likely to be
   * "faster" (e.g. further from idle slowstart reset)
   */
  psync_list_add_head(lst, &he->list);
  he->timer = ptimer_register(cache_timer, freeafter, he);
  pthread_mutex_unlock(&cachelocks[hash_to_lock(h)]);
}

void pcache_del(const char *key) {
  cache_entry_t *he;
  psync_list *lst;
  uint32_t h;
  if (IS_DEBUG && !strcmp(psync_thread_name, "timer"))
    debug(D_ERROR,
          "trying get key %s from the timer thread, this may (and eventually "
          "will) lead to a deadlock, "
          "please start a worker thread to do the job or don't use cache (if "
          "you are looking up sql "
          "query/statement, you can use _nocache version)",
          key);

  h = compute_hash(key, NULL);
  lst = &cache_hash[hash_to_bucket(h)];
restart:
  pthread_mutex_lock(&cachelocks[hash_to_lock(h)]);
  psync_list_for_each_element(
      he, lst, cache_entry_t, list) if (he->hash == h && !strcmp(key, he->key)) {
    if (ptimer_stop(he->timer))
      continue;
    psync_list_del(&he->list);
    pthread_mutex_unlock(&cachelocks[hash_to_lock(h)]);
    he->free(he->value);
    free(he);
    goto restart;
  }
  pthread_mutex_unlock(&cachelocks[hash_to_lock(h)]);
}

void pcache_clean() {
  psync_list *l1, *l2;
  cache_entry_t *he;
  unsigned long h;
  for (h = 0; h < CACHE_HASH_SIZE; h++) {
    pthread_mutex_lock(&cachelocks[hash_to_lock(h)]);
    psync_list_for_each_safe(l1, l2, &cache_hash[h]) {
      he = psync_list_element(l1, cache_entry_t, list);
      if (!ptimer_stop(he->timer)) {
        psync_list_del(l1);
        he->free(he->value);
        free(he);
      }
    }
    pthread_mutex_unlock(&cachelocks[hash_to_lock(h)]);
  }
}

void pcache_clean_oneof(const char **prefixes, size_t cnt) {
  psync_list *l1, *l2;
  cache_entry_t *he;
  unsigned long h;
  size_t i;
  VAR_ARRAY(lens, size_t, cnt);
  for (i = 0; i < cnt; i++)
    lens[i] = strlen(prefixes[i]);
  for (h = 0; h < CACHE_HASH_SIZE; h++) {
    pthread_mutex_lock(&cachelocks[hash_to_lock(h)]);
    psync_list_for_each_safe(l1, l2, &cache_hash[h]) {
      he = psync_list_element(l1, cache_entry_t, list);
      for (i = 0; i < cnt; i++)
        if (!strncmp(he->key, prefixes[i], lens[i]))
          break;
      if (i == cnt)
        continue;
      if (!ptimer_stop(he->timer)) {
        psync_list_del(l1);
        he->free(he->value);
        free(he);
      }
    }
    pthread_mutex_unlock(&cachelocks[hash_to_lock(h)]);
  }
}
