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

#ifndef _PSYNC_LIBS_H
#define _PSYNC_LIBS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <pthread.h>

#include "pcompiler.h"
#include "pstatus.h"
#include "pdbg.h"

#include <stdint.h>
#include <string.h>

// required for pcloud api; 7=>linux
#define P_OS_ID 7 

#define PSYNC_TNUMBER 1
#define PSYNC_TSTRING 2
#define PSYNC_TREAL 3
#define PSYNC_TNULL 4
#define PSYNC_TBOOL 5

#define psync_is_null(v) ((v).type == PSYNC_TNULL)
#define psync_get_number(v)                                                    \
  (likely((v).type == PSYNC_TNUMBER)                                           \
       ? (v).num                                                               \
       : psync_err_number_expected(__FILE__, __FUNCTION__, __LINE__, &(v)))
#define psync_get_snumber(v)                                                   \
  (likely((v).type == PSYNC_TNUMBER)                                           \
       ? (int64_t)((v).num)                                                    \
       : (int64_t)psync_err_number_expected(__FILE__, __FUNCTION__, __LINE__,  \
                                            &(v)))
#define psync_get_number_or_null(v)                                            \
  (((v).type == PSYNC_TNUMBER)                                                 \
       ? (v).num                                                               \
       : (likely((v).type == PSYNC_TNULL)                                      \
              ? 0                                                              \
              : psync_err_number_expected(__FILE__, __FUNCTION__, __LINE__,    \
                                          &(v))))
#define psync_get_snumber_or_null(v)                                           \
  (((v).type == PSYNC_TNUMBER)                                                 \
       ? (int64_t)(v).num                                                      \
       : (likely((v).type == PSYNC_TNULL)                                      \
              ? 0                                                              \
              : (int64_t)psync_err_number_expected(__FILE__, __FUNCTION__,     \
                                                   __LINE__, &(v))))
#define psync_get_string(v)                                                    \
  (likely((v).type == PSYNC_TSTRING)                                           \
       ? (v).str                                                               \
       : psync_err_string_expected(__FILE__, __FUNCTION__, __LINE__, &(v)))
#define psync_get_string_or_null(v)                                            \
  (((v).type == PSYNC_TSTRING)                                                 \
       ? (v).str                                                               \
       : (likely((v).type == PSYNC_TNULL)                                      \
              ? NULL                                                           \
              : psync_err_string_expected(__FILE__, __FUNCTION__, __LINE__,    \
                                          &(v))))
#define psync_dup_string(v)                                                    \
  (likely((v).type == PSYNC_TSTRING)                                           \
       ? psync_strndup((v).str, (v).length)                                    \
       : psync_strdup(psync_err_string_expected(__FILE__, __FUNCTION__,        \
                                                __LINE__, &(v))))
#define psync_get_lstring(v, l)                                                \
  psync_lstring_expected(__FILE__, __FUNCTION__, __LINE__, &(v), l)
#define psync_get_lstring_or_null(v, l)                                        \
  ((v).type == PSYNC_TNULL                                                     \
       ? NULL                                                                  \
       : psync_lstring_expected(__FILE__, __FUNCTION__, __LINE__, &(v), l))
#define psync_get_real(v)                                                      \
  (likely((v).type == PSYNC_TREAL)                                             \
       ? (v).real                                                              \
       : psync_err_real_expected(__FILE__, __FUNCTION__, __LINE__, &(v)))

#if D_WARNING <= DEBUG_LEVEL
#if defined(PTHREAD_ERRORCHECK_MUTEX_INITIALIZER_NP)
#undef PTHREAD_MUTEX_INITIALIZER
#define PTHREAD_MUTEX_INITIALIZER PTHREAD_ERRORCHECK_MUTEX_INITIALIZER_NP
#endif
#define pthread_mutex_lock(mutex)                                              \
  do {                                                                         \
    int __mutex_result = pthread_mutex_lock(mutex);                            \
    if (unlikely(__mutex_result)) {                                            \
      pdbg_logf(D_CRITICAL, "pthread_mutex_lock returned %d", __mutex_result);     \
      abort();                                                                 \
    }                                                                          \
  } while (0)
#define pthread_mutex_unlock(mutex)                                            \
  do {                                                                         \
    int __mutex_result = pthread_mutex_unlock(mutex);                          \
    if (unlikely(__mutex_result)) {                                            \
      pdbg_logf(D_CRITICAL, "pthread_mutex_unlock returned %d", __mutex_result);   \
      abort();                                                                 \
    }                                                                          \
  } while (0)
#endif

#define psync_binhex(dst, src, cnt)                                            \
  do {                                                                         \
    size_t it__;                                                               \
    size_t cnt__ = (cnt);                                                      \
    const uint8_t *src__ = (const uint8_t *)(src);                             \
    uint16_t *dst__ = (uint16_t *)(dst);                                       \
    for (it__ = 0; it__ < cnt__; it__++)                                       \
      dst__[it__] = __hex_lookup[src__[it__]];                                 \
  } while (0)

#define psync_get_result_cell(res, row, col)                                   \
  (res)->data[(row) * (res)->cols + (col)]

typedef void (*psync_run_after_t)(void *);

extern int psync_do_run;
extern int psync_recache_contacts;
extern pstatus_t psync_status;
extern char psync_my_auth[64], psync_my_2fa_code[32], *psync_my_user,
    *psync_my_pass, *psync_my_2fa_token, *psync_my_verify_token;
extern int psync_my_2fa_code_type, psync_my_2fa_trust, psync_my_2fa_has_devices,
    psync_my_2fa_type;
extern uint64_t psync_my_userid;
extern pthread_mutex_t psync_my_auth_mutex;
extern PSYNC_THREAD uint32_t psync_error;
extern uint16_t const *__hex_lookup;

int psync_rename_conflicted_file(const char *path);

void psync_run_after_sec(psync_run_after_t run, void *ptr, uint32_t seconds);
void psync_free_after_sec(void *ptr, uint32_t seconds);

int psync_match_pattern(const char *name, const char *pattern, size_t plen);

void psync_pqsort(void *base, size_t cnt, size_t sort_first, size_t size, int (*compar)(const void *, const void *));
void psync_qpartition(void *base, size_t cnt, size_t sort_first, size_t size, int (*compar)(const void *, const void *));

/* needs 12 characters of buffer space on top of the length of the prefix */
static inline void psync_get_string_id(char *dst, const char *prefix, uint64_t id) {
  size_t plen;
  plen = strlen(prefix);
  dst = (char *)memcpy(dst, prefix, plen) + plen;
  do {
    *dst++ = base64_table[id % 64];
    id /= 64;
  } while (id);
  *dst = 0;
}

/* needs 24 characters of buffer space on top of the length of the prefix */
static inline void psync_get_string_id2(char *dst, const char *prefix, uint64_t id1, uint64_t id2) {
  size_t plen;
  plen = strlen(prefix);
  dst = (char *)memcpy(dst, prefix, plen) + plen;
  do {
    *dst++ = base64_table[id1 % 64];
    id1 /= 64;
  } while (id1);
  *dst++ = '.';
  do {
    *dst++ = base64_table[id2 % 64];
    id2 /= 64;
  } while (id2);
  *dst = 0;
}

#ifdef __cplusplus 
}
#endif

#endif
