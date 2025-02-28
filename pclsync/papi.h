/*
  Copyright (c) 2013 Anton Titov.

  Copyright (c) 2013 pCloud Ltd.  All rights reserved.

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
  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL pCloud Ltd BE
  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
  BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
  WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
  OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
  EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#ifndef _PSYNC_API_H
#define _PSYNC_API_H

#include "pcompiler.h"
#include "psock.h"
#include <stdint.h>

#define PARAM_STR 0
#define PARAM_NUM 1
#define PARAM_BOOL 2

#define PARAM_ARRAY 3
#define PARAM_HASH 4
#define PARAM_DATA 5

#define PARAM_END 255

#define PTR_OK ((binresult *)1)

#define ASYNC_RES_NEEDMORE 0
#define ASYNC_RES_READY 1

typedef struct {
  uint16_t paramtype;
  uint16_t paramnamelen;
  uint32_t opts;
  const char *paramname;
  union {
    uint64_t num;
    const char *str;
  };
} binparam;

struct _binresult;

typedef struct _hashpair {
  const char *key;
  struct _binresult *value;
} hashpair;

typedef struct _binresult {
  uint32_t type;
  uint32_t length;
  union {
    uint64_t num;
    const char str[8];
    struct _binresult **array;
    struct _hashpair *hash;
  };
} binresult;

typedef struct {
  binresult *result;
  uint32_t state;
  uint32_t bytesread;
  uint32_t bytestoread;
  uint32_t respsize;
  unsigned char *data;
} async_result_reader;

#define PAPI_STR(name, val)                                                       \
  {                                                                            \
    PARAM_STR, strlen(name), strlen(val), (name), {                            \
      (uint64_t)((uintptr_t)(val))                                             \
    }                                                                          \
  }
#define PAPI_LSTR(name, val, len)                                                 \
  {                                                                            \
    PARAM_STR, strlen(name), (len), (name), { (uint64_t)((uintptr_t)(val)) }   \
  }
#define PAPI_NUM(name, val)                                                       \
  {                                                                            \
    PARAM_NUM, strlen(name), 0, (name), { (val) }                              \
  }
#define PAPI_BOOL(name, val)                                                      \
  {                                                                            \
    PARAM_BOOL, strlen(name), 0, (name), { (val) ? 1 : 0 }                     \
  }

#define papi_send2(sock, cmd, params)                                        \
  papi_send(sock, cmd, strlen(cmd), params,                              \
                  sizeof(params) / sizeof(binparam), -1, 1)
#define papi_send_no_res(sock, cmd, params)                                 \
  papi_send(sock, cmd, strlen(cmd), params,                              \
                  sizeof(params) / sizeof(binparam), -1, 0)

#define papi_send_thread(sock, cmd, params)                                 \
  papi_send(sock, cmd, strlen(cmd), params,                              \
                  sizeof(params) / sizeof(binparam), -1, 1 | 2)
#define papi_send_no_res_thread(sock, cmd, params)                          \
  papi_send(sock, cmd, strlen(cmd), params,                              \
                  sizeof(params) / sizeof(binparam), -1, 2)

#define papi_prepare_alloc(cmd, params, datalen, alloclen, retlen)     \
  papi_prepare(cmd, strlen(cmd), params,                                 \
                     sizeof(params) / sizeof(binparam), datalen, alloclen,     \
                     retlen)

#define papi_find_result2(res, name, type)                                     \
  papi_find_result(res, name, type, __FILE__, __FUNCTION__, __LINE__)
#define papi_check_result2(res, name, type)                                    \
  papi_check_result(res, name, type, __FILE__, __FUNCTION__, __LINE__)
#define papi_get_result2(res, name)                                            \
  papi_get_result(res, name, __FILE__, __FUNCTION__, __LINE__)
#define papi_dump2(res)                                                 \
  papi_dump(res, __FILE__, __FUNCTION__, __LINE__)

psock_t *papi_connect(const char *hostname, int usessl);
void papi_conn_fail_inc();
void papi_conn_fail_reset();
binresult *papi_result(psock_t *sock) PSYNC_NONNULL(1);
binresult *papi_result_thread(psock_t *sock) PSYNC_NONNULL(1);
void papi_rdr_alloc(async_result_reader *reader) PSYNC_NONNULL(1);
void papi_rdr_free(async_result_reader *reader) PSYNC_NONNULL(1);
int papi_result_async(psock_t *sock, async_result_reader *reader) PSYNC_NONNULL(1, 2);
unsigned char *papi_prepare(const char *command, size_t cmdlen, const binparam *params, size_t paramcnt, int64_t datalen, size_t additionalalloc, size_t *retlen);
binresult *papi_send(psock_t *sock, const char *command, size_t cmdlen, const binparam *params, size_t paramcnt, int64_t datalen, int readres) PSYNC_NONNULL(1, 2);
const binresult *papi_find_result(const binresult *res, const char *name, uint32_t type, const char *file, const char *function, int unsigned line) PSYNC_NONNULL(2) PSYNC_PURE;
const binresult *papi_check_result(const binresult *res, const char *name, uint32_t type, const char *file, const char *function, int unsigned line) PSYNC_NONNULL(2) PSYNC_PURE;
const binresult *papi_get_result(const binresult *res, const char *name, const char *file, const char *function, int unsigned line) PSYNC_NONNULL(2) PSYNC_PURE;
void papi_dump(const binresult *res, const char *file, const char *function, int unsigned line);

#endif
