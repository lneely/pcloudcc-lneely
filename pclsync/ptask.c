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

#include <errno.h>
#include <pthread.h>
#include <stddef.h>

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/debug.h>
#include <mbedtls/entropy.h>
#include <mbedtls/pkcs5.h>
#include <mbedtls/ssl.h>
#include <pthread.h>

#include "papi.h"
#include "pdeflate.h"
#include "pdownload.h"
#include "pfile.h"
#include "plibs.h"
#include "pnetlibs.h"
#include "ppathstatus.h"
#include "prun.h"
#include "psettings.h"
#include "pssl.h"
#include "pstatus.h"
#include "psys.h"
#include "ptask.h"
#include "ptree.h"
#include "pupload.h"

#define get_len(t) (sizeof(t) - offsetof(t, request))

#define TASK_TYPE_EXIT 0
#define TASK_TYPE_FILE_DWL 1
#define TASK_TYPE_FILE_DWL_NM 2

#define STREAM_FLAG_ACTIVE 1

#define STREAM_HEADER_LEN 6 // 4 bytes stream id, 2 bytes length

#define CHECK_LEN(l)                                                           \
  do {                                                                         \
    if (unlikely(len != l)) {                                                  \
      pdbg_logf(D_BUG,                                                             \
            "wrong size for packet of type %u, expected size %u but got %u",   \
            (unsigned)type, (unsigned)l, (unsigned)len);                       \
      return 2;                                                                \
    }                                                                          \
  } while (0)

typedef struct {
  uint32_t type;
  uint32_t len;
} hdr_t;

typedef struct {
  psync_fileid_t fileid;
  const char *localpath;
  psync_async_callback_t cb;
  void *cbext;
} download_req_t;

typedef struct {
  hdr_t head;
  download_req_t request;
} download_task_t;

typedef struct {
  psync_fileid_t fileid;
  const char *localpath;
  uint64_t size;
  char sha1hex[PSYNC_SHA1_DIGEST_HEXLEN];
  psync_async_callback_t cb;
  void *cbext;
} download_needed_req_t;

typedef struct {
  hdr_t head;
  download_needed_req_t request;
} download_needed_task_t;

typedef struct {
  uint32_t error;
  uint32_t errorflags;
  uint64_t size;
  uint64_t hash;
  uint64_t mtime;
  uint64_t oldhash;
  uint64_t oldmtime;
  unsigned char sha1hex[PSYNC_SHA1_DIGEST_HEXLEN];
} download_rsp_t;

typedef struct _async_params_t {
  psync_deflate_t *enc;
  psync_deflate_t *dec;
  psock_t *api;
  psync_tree *streams;
  uint64_t datapendingsince;
  int (*process_buf)(struct _async_params_t *);
  char *curreadbuff;
  int privsock;
  uint32_t curreadbuffrem;
  uint32_t curreadbufflen;
  uint32_t currentstreamid;
  uint32_t laststreamid;
  uint32_t pendingrequests;
  char buffer[64 * 1024];
} async_params_t;

typedef struct _stream_t {
  psync_tree tree;
  uint32_t streamid;
  uint32_t flags;
  psync_async_callback_t cb;
  void (*free)(struct _stream_t *, uint32_t);
  void *cbext;
  int (*process_data)(struct _stream_t *, async_params_t *, const char *,
                      uint32_t);
} stream_t;

typedef struct {
  const char *localpath;
  uint64_t fileid;
  uint64_t size;
  uint64_t hash;
  unsigned char osize;
  unsigned char sha1hex[PSYNC_SHA1_DIGEST_HEXLEN];
  unsigned char osha1hex[PSYNC_SHA1_DIGEST_HEXLEN];
  psync_sha1_ctx sha1ctx;
  uint64_t remsize;
  int fd;
} download_context_t;

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static int running = 0;
static int sockd = INVALID_SOCKET;

static int data_pending_send(async_params_t *prms);
static int handle_command_data(async_params_t *prms, char *data, uint32_t type, uint32_t len);
static int sock_readall(int sock, void *buff, size_t len);
static int sock_writeall(int sock, const void *buff, size_t len);
static int stream_process_header(async_params_t *prms);
static stream_t *stream_create(async_params_t *prms, size_t addsize);
static void stream_destroy(stream_t *s);
static void stream_setup_header(async_params_t *prms);

static int data_send(async_params_t *prms, const void *data, int len) {
  int wr;
  while (len) {
    wr = pdeflate_write(prms->enc, data, len, PSYNC_DEFLATE_NOFLUSH);
    if (wr > 0) {
      len -= wr;
      data = (const char *)data + wr;
    } else if (wr != PSYNC_DEFLATE_FULL) {
      pdbg_logf(D_ERROR, "write to deflate compressor of %d bytes returned %d", len,
            wr);
      return -1;
    }
    if (data_pending_send(prms))
      return -1;
  }
  if (!prms->pendingrequests)
    prms->datapendingsince = psys_time_milliseconds();
  prms->pendingrequests++;
  return 0;
}

static int data_pending_flush(async_params_t *prms) {
  int ret;
  ret = pdeflate_write(prms->enc, "", 0, PSYNC_DEFLATE_FLUSH);
  if (ret != 0) {
    pdbg_logf(D_WARNING, "psync_deflate_write returned %d when flushing", ret);
    return -1;
  }
  prms->pendingrequests = 0;
  return data_pending_send(prms);
}

static int data_pending_send(async_params_t *prms) {
  char buff[4096];
  int ret;
  while (1) {
    ret = pdeflate_read(prms->enc, buff, sizeof(buff));
    if (ret == PSYNC_DEFLATE_NODATA || ret == PSYNC_DEFLATE_EOF)
      return 0;
    if (ret > 0) {
      if (psock_writeall(prms->api, buff, ret) != ret) {
        pdbg_logf(D_WARNING, "write of %d bytes to socket failed", ret);
        return -1;
      } else
        pdbg_logf(D_NOTICE, "sent %d bytes of compressed data to socket", ret);
    } else {
      pdbg_logf(D_ERROR, "read from deflate compressor returned %d", ret);
      return -1;
    }
  }
}

static void download_free(stream_t *s, uint32_t error) {
  download_context_t *fda;
  fda = (download_context_t *)(s + 1);
  if (fda->fd != INVALID_HANDLE_VALUE) {
    pfile_close(fda->fd);
    if (error)
      pfile_delete(fda->localpath);
  }
}

static int download_send_error(stream_t *s, async_params_t *prms,
                                    download_context_t *fda, uint32_t error,
                                    uint32_t errorflags) {
  psync_async_result_t r;
  if (error)
    pdbg_logf(D_NOTICE, "got error %u(%u) for file %s", (unsigned)error,
          (unsigned)errorflags, fda->localpath);
  else
    pdbg_logf(D_NOTICE, "download of %s finished", fda->localpath);
  r.error = error;
  r.errorflags = errorflags;
  r.file.size = fda->size;
  r.file.hash = fda->hash;
  memcpy(r.file.sha1hex, fda->sha1hex, PSYNC_SHA1_DIGEST_HEXLEN);
  s->cb(s->cbext, &r);

  pdbg_logf(D_NOTICE, "closing stream %u", (unsigned)s->streamid);
  ptree_del(&prms->streams, &s->tree);
  if (s->free)
    s->free(s, error);
  free(s);
  return 0;
}

static int download_checksum(download_context_t *fda) {
  unsigned char sha1b[PSYNC_SHA1_DIGEST_LEN], sha1h[PSYNC_SHA1_DIGEST_HEXLEN];
  psync_sha1_final(sha1b, &fda->sha1ctx);
  psync_binhex(sha1h, sha1b, PSYNC_SHA1_DIGEST_LEN);
  if (memcmp(sha1h, fda->sha1hex, PSYNC_SHA1_DIGEST_HEXLEN)) {
    pdbg_logf(D_WARNING,
          "checksum verification for file %s failed, expected %40s got %40s",
          fda->localpath, (char *)fda->sha1hex, (char *)sha1h);
    return -1;
  } else
    return 0;
}

static int download_process_data(stream_t *s, async_params_t *prms,
                                      const char *buff, uint32_t datalen) {
  download_context_t *fda;
  ssize_t wr;
  int err;
  fda = (download_context_t *)(s + 1);
  if (datalen > fda->remsize) {
    pdbg_logf(D_ERROR,
          "got packed of size %u for stream %u file %s when the remaining data "
          "is %lu",
          (unsigned)datalen, (unsigned)s->streamid, fda->localpath,
          (unsigned long)fda->remsize);
    download_send_error(s, prms, fda, PSYNC_ASYNC_ERROR_NET,
                             PSYNC_ASYNC_ERR_FLAG_RETRY_AS_IS);
    return -1;
  }
  fda->remsize -= datalen;
  psync_account_downloaded_bytes(datalen);
  psync_sha1_update(&fda->sha1ctx, buff, datalen);
  while (datalen) {
    wr = pfile_write(fda->fd, buff, datalen);
    if (wr == -1) {
      err = (int)errno;
      pdbg_logf(D_WARNING, "writing to file %s failed, errno %d", fda->localpath,
            err);
      return download_send_error(
          s, prms, fda,
          err == ENOSPC ? PSYNC_ASYNC_ERROR_DISK_FULL : PSYNC_ASYNC_ERROR_IO,
          0);
    }
    datalen -= wr;
    buff += wr;
  }
  if (fda->remsize == 0) {
    if (download_checksum(fda))
      return download_send_error(s, prms, fda, PSYNC_ASYNC_ERROR_CHECKSUM,
                                      0);
    else
      return download_send_error(s, prms, fda, 0, 0);
  } else
    return 0;
}

static int download_process_headers(stream_t *s,
                                         async_params_t *prms,
                                         const char *buff, uint32_t datalen) {
  download_rsp_t r;
  download_context_t *fda;
  psync_sql_res *res;
  if (unlikely(datalen < sizeof(download_rsp_t))) {
    pdbg_logf(D_ERROR,
          "got packet of size %u while expecting at least %u, disconnecting",
          (unsigned)datalen, (unsigned)sizeof(download_rsp_t));
    return -1;
  }
  memcpy(&r, buff, sizeof(download_rsp_t));
  fda = (download_context_t *)(s + 1);
  fda->size = r.size;
  fda->hash = r.hash;
  memcpy(fda->sha1hex, r.sha1hex, PSYNC_SHA1_DIGEST_HEXLEN);
  if (r.error)
    return download_send_error(s, prms, fda, r.error + 100, r.errorflags);
  pdbg_logf(D_NOTICE,
        "got headers for file %s size %" PRIu64 " hash %" PRIu64
        " sha1 %.40s",
        fda->localpath, fda->size, fda->hash, fda->sha1hex);
  psync_sql_start_transaction();
  res = psync_sql_prep_statement(
      "REPLACE INTO hashchecksum (hash, size, checksum) VALUES (?, ?, ?)");
  psync_sql_bind_uint(res, 1, r.hash);
  psync_sql_bind_uint(res, 2, r.size);
  psync_sql_bind_lstring(res, 3, (const char *)r.sha1hex,
                         PSYNC_SHA1_DIGEST_HEXLEN);
  if (r.oldmtime) {
    psync_sql_run(res);
    psync_sql_bind_uint(res, 1, r.oldhash);
    psync_sql_bind_uint(res, 2, fda->osize);
    psync_sql_bind_lstring(res, 3, (const char *)fda->osha1hex,
                           PSYNC_SHA1_DIGEST_HEXLEN);
    psync_sql_run_free(res);
  } else
    psync_sql_run_free(res);
  res = psync_sql_prep_statement("REPLACE INTO filerevision (fileid, hash, "
                                 "ctime, size) VALUES (?, ?, ?, ?)");
  psync_sql_bind_uint(res, 1, fda->fileid);
  psync_sql_bind_uint(res, 2, r.hash);
  psync_sql_bind_uint(res, 3, r.mtime);
  psync_sql_bind_uint(res, 4, r.size);
  if (r.oldmtime) {
    psync_sql_run(res);
    psync_sql_bind_uint(res, 1, fda->fileid);
    psync_sql_bind_uint(res, 2, r.oldhash);
    psync_sql_bind_uint(res, 3, r.oldmtime);
    psync_sql_bind_uint(res, 4, fda->osize);
    psync_sql_run_free(res);
  } else
    psync_sql_run_free(res);
  psync_sql_commit_transaction();
  fda->fd = pfile_open(fda->localpath, O_WRONLY, O_CREAT | O_TRUNC);
  if (fda->fd == INVALID_HANDLE_VALUE) {
    pdbg_logf(D_WARNING, "could not open file %s, errno %d", fda->localpath,
          (int)errno);
    return download_send_error(s, prms, fda, PSYNC_ASYNC_ERROR_FILE, 0);
  }
  fda->remsize = fda->size;
  if (!fda->remsize)
    return download_send_error(s, prms, fda, 0, 0);
  s->process_data = download_process_data;
  psync_sha1_init(&fda->sha1ctx);
  if (datalen > sizeof(download_rsp_t))
    return download_process_data(
        s, prms, buff + sizeof(download_rsp_t),
        datalen - sizeof(download_rsp_t));
  else
    return 0;
}

static int handle_command(async_params_t *prms) {
  char buff[4096];
  hdr_t hdr;
  int ret;
  unsigned char r;
  if (sock_readall(prms->privsock, &hdr, sizeof(hdr))) {
    pdbg_logf(D_WARNING, "could not read header from socket pair");
    return -1;
  }
  if (hdr.len > sizeof(buff)) {
    pdbg_logf(D_WARNING,
          "too large length of packet %u provided, maximum supported is %u",
          (unsigned)hdr.len, (unsigned)sizeof(buff));
    return -1;
  }
  if (sock_readall(prms->privsock, buff, hdr.len)) {
    pdbg_logf(D_WARNING, "could not read %u bytes of data from socket pair",
          (unsigned)hdr.len);
    return -1;
  }
  ret = handle_command_data(prms, buff, hdr.type, hdr.len);
  if (ret < 0) {
    r = 255;
    ret = -1;
  } else {
    r = (unsigned char)ret;
    ret = 0;
  }
  if (sock_writeall(prms->privsock, &r, sizeof(r))) {
    pdbg_logf(D_WARNING, "failed to write response to socket pair");
    return -1;
  }
  return ret;
}

static int handle_download(async_params_t *prms,
                                download_req_t *dwl) {
  char buff[256];
  stream_t *s;
  download_context_t *fda;
  int len;
  s = stream_create(prms, sizeof(download_context_t));
  fda = (download_context_t *)(s + 1);
  fda->fileid = dwl->fileid;
  s->free = download_free;
  s->cb = dwl->cb;
  s->cbext = dwl->cbext;
  s->process_data = download_process_headers;
  fda->localpath = dwl->localpath;
  fda->fd = INVALID_HANDLE_VALUE;
  len = psync_slprintf(buff, sizeof(buff),
                       "act=dwl,strm=%" PRIu64 ",fileid=%" PRIu64 "\n",
                       (uint64_t)s->streamid, (uint64_t)dwl->fileid);
  if (data_send(prms, buff, len)) {
    pdbg_logf(D_WARNING, "failed to send request for fileid %lu",
          (unsigned long)dwl->fileid);
    return -1;
  }
  s->flags |= STREAM_FLAG_ACTIVE;
  pdbg_logf(D_NOTICE, "requested data of fileid %lu to be saved in %s",
        (unsigned long)dwl->fileid, dwl->localpath);
  return 0;
}

static int handle_download_nm(async_params_t *prms,
                                   download_needed_req_t *dwl) {
  char buff[256];
  stream_t *s;
  download_context_t *fda;
  int len;
  s = stream_create(prms, sizeof(download_context_t));
  fda = (download_context_t *)(s + 1);
  fda->fileid = dwl->fileid;
  s->free = download_free;
  s->cb = dwl->cb;
  s->cbext = dwl->cbext;
  s->process_data = download_process_headers;
  fda->osize = dwl->size;
  memcpy(fda->osha1hex, dwl->sha1hex, PSYNC_SHA1_DIGEST_HEXLEN);
  fda->localpath = dwl->localpath;
  fda->fd = INVALID_HANDLE_VALUE;
  len = psync_slprintf(
      buff, sizeof(buff),
      "act=dwlnm,strm=%" PRIu64 ",fileid=%" PRIu64 ",sha1=%.40s\n",
      (uint64_t)s->streamid, (uint64_t)dwl->fileid, dwl->sha1hex);
  if (data_send(prms, buff, len)) {
    pdbg_logf(D_WARNING, "failed to send request for fileid %lu",
          (unsigned long)dwl->fileid);
    return -1;
  }
  s->flags |= STREAM_FLAG_ACTIVE;
  pdbg_logf(D_NOTICE, "requested data of fileid %lu to be saved in %s",
        (unsigned long)dwl->fileid, dwl->localpath);
  return 0;
}

static int handle_command_data(async_params_t *prms, char *data, uint32_t type, uint32_t len) {
  switch (type) {
  case TASK_TYPE_EXIT:
    CHECK_LEN(0);
    pdbg_logf(D_NOTICE, "exiting");
    return -1;
  case TASK_TYPE_FILE_DWL:
    CHECK_LEN(sizeof(download_req_t));
    return handle_download(prms, (download_req_t *)data);
  case TASK_TYPE_FILE_DWL_NM:
    CHECK_LEN(sizeof(download_needed_req_t));
    return handle_download_nm(prms,
                                   (download_needed_req_t *)data);
  default:
    pdbg_logf(D_BUG, "got packet of unknown type %u", (unsigned)type);
    return 1;
  }
}

static int handle_decompressed_data(async_params_t *prms) {
  int rd;
  while (1) {
    rd = pdeflate_read(prms->dec, prms->curreadbuff, prms->curreadbuffrem);
    if (rd > 0) {
      prms->curreadbuff += rd;
      prms->curreadbuffrem -= rd;
      if (!prms->curreadbuffrem && prms->process_buf(prms))
        return -1;
    } else if (rd == PSYNC_DEFLATE_NODATA)
      return 0;
    else {
      pdbg_logf(D_ERROR, "psync_deflate_read returned %d", rd);
      return -1;
    }
  }
}

static int handle_incoming_data(async_params_t *prms) {
  char buff[4096];
  char *ptr;
  int rdsock, wrdecomp;
  while (1) {
    rdsock = psock_read_noblock(prms->api, buff, sizeof(buff));
    if (rdsock == PSYNC_SOCKET_WOULDBLOCK)
      return 0;
    else if (rdsock <= 0) {
      pdbg_logf(D_WARNING, "read from socket returned %d", rdsock);
      return -1;
    }
    ptr = buff;
    while (rdsock) {
      wrdecomp =
          pdeflate_write(prms->dec, ptr, rdsock, PSYNC_DEFLATE_FLUSH);
      if (wrdecomp == PSYNC_DEFLATE_ERROR) {
        pdbg_logf(D_ERROR, "psync_deflate_write returned PSYNC_DEFLATE_ERROR");
        return -1;
      } else if (wrdecomp != PSYNC_DEFLATE_FULL) {
        pdbg_assert(wrdecomp > 0);
        rdsock -= wrdecomp;
        ptr += wrdecomp;
      }
      if (handle_decompressed_data(prms))
        return -1;
    }
  }
}

static void proc_async_transfer(void *ptr) {
  async_params_t *prms = (async_params_t *)ptr;
  int sel[2];
  int ret;
  sel[0] = prms->api->sock;
  sel[1] = prms->privsock;
  stream_setup_header(prms);
  while (1) {
    if (prms->pendingrequests) {
      if ((prms->pendingrequests >= PSYNC_ASYNC_MAX_GROUPED_REQUESTS ||
           prms->datapendingsince + PSYNC_ASYNC_GROUP_REQUESTS_FOR <
               psys_time_milliseconds()) &&
          data_pending_flush(prms))
        break;
      ret = psock_select_in(sel, 2, PSYNC_ASYNC_GROUP_REQUESTS_FOR / 4);
      if (ret == -1)
        continue;
    } else {
      if (psock_pendingdata(prms->api))
        ret = 0;
      else
        ret = psock_select_in(sel, 2, PSYNC_ASYNC_THREAD_TIMEOUT);
    }
    if (ret == 0) {
      if (handle_incoming_data(prms))
        break;
    } else if (ret == 1) {
      if (handle_command(prms))
        break;
    } else {
      pdbg_logf(D_NOTICE, "psync_select_in returned %d, exiting, errno %d", ret,
            (int)errno);
      break;
    }
  }
  // close prms->privsock before locking as there might be somebody who keeps
  // the mutex locked while waiting for us to reply
  close(prms->privsock);
  pthread_mutex_lock(&mutex);
  close(sockd);
  sockd = INVALID_SOCKET;
  running--;
  pthread_mutex_unlock(&mutex);
  psync_apipool_release_bad(prms->api);
  pdeflate_destroy(prms->enc);
  pdeflate_destroy(prms->dec);
  ptree_for_each_element_call_safe(prms->streams, stream_t, tree,
                                        stream_destroy);
  free(prms);
}

static int proc_start_async_transfer() {
  /* If some form of protocol version negotiation is to be performed, here is
   * the place to pass any needed parameters. The assumption will be that server
   * supports everything and clients inform the server what they support.
   */
  binparam params[] = {PAPI_STR("auth", psync_my_auth), PAPI_STR("checksum", "sha1")};
  async_params_t *tparams;
  psync_deflate_t *enc, *dec;
  binresult *res;
  psock_t *api;
  int pair[2];
  int tries;
  tries = 0;
  while (1) {
    api = psync_apipool_get();
    if (!api) {
      pdbg_logf(D_NOTICE, "could not connect to API, failing");
      goto err0;
    }
    res = papi_send2(api, "asynctransfer", params);
    if (likely(res))
      break;
    psync_apipool_release_bad(api);
    if (++tries >= 5) {
      pdbg_logf(D_NOTICE, "failing after %d tries to send asynctransfer call",
            tries);
      goto err0;
    }
  }
  if (papi_find_result2(res, "result", PARAM_NUM)->num) {
    pdbg_logf(D_WARNING, "asynctransfer returned error %d: %s",
          (int)papi_find_result2(res, "result", PARAM_NUM)->num,
          papi_find_result2(res, "error", PARAM_STR)->str);
    psync_process_api_error(papi_find_result2(res, "result", PARAM_NUM)->num);
    free(res);
    psync_apipool_release(api);
    goto err0;
  }
  free(res);
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair)) {
    pdbg_logf(D_NOTICE, "socketpair() failed");
    goto err1;
  }
  enc = pdeflate_init(PSYNC_DEFLATE_COMP_FAST);
  if (!enc) {
    pdbg_logf(D_NOTICE, "pdeflate_init() failed");
    goto err2;
  }
  dec = pdeflate_init(PSYNC_DEFLATE_DECOMPRESS);
  if (!dec) {
    pdbg_logf(D_NOTICE, "pdeflate_init() failed");
    goto err3;
  }
  tparams = psync_new(async_params_t);
  memset(tparams, 0, sizeof(async_params_t));
  tparams->enc = enc;
  tparams->dec = dec;
  tparams->api = api;
  tparams->privsock = pair[1];
  sockd = pair[0];
  prun_thread1("async transfer", proc_async_transfer, tparams);
  running++;
  return 0;
err3:
  pdeflate_destroy(enc);
err2:
  close(pair[0]);
  close(pair[1]);
err1:
  psync_apipool_release_bad(api);
err0:
  return -1;
}

static int sock_readall(int sock, void *buff, size_t len) {
  ssize_t rd;
  while (len) {
    if (psock_wait_read_timeout(sock))
      return -1;
    rd = read(sock, buff, len);
    if (rd > 0) {
      len -= rd;
      buff = (char *)buff + rd;
    } else if (rd == PSYNC_SOCKET_ERROR &&
               (errno == EINTR || errno == EAGAIN ||
                errno == EWOULDBLOCK))
      continue;
    else {
      pdbg_logf(D_WARNING, "read from socket of %lu bytes returned %ld, errno %d",
            (unsigned long)len, (long)rd, (int)errno);
      return -1;
    }
  }
  return 0;
}

static int sock_writeall(int sock, const void *buff, size_t len) {
  ssize_t wr;
  while (len) {
    if (psock_wait_write_timeout(sock))
      return -1;
    wr = write(sock, buff, len);
    if (wr > 0) {
      len -= wr;
      buff = (const char *)buff + wr;
    } else if (wr == PSYNC_SOCKET_ERROR &&
               (errno == EINTR || errno == EAGAIN ||
                errno == EWOULDBLOCK))
      continue;
    else {
      pdbg_logf(D_WARNING, "write to socket of %lu bytes returned %ld, errno %d",
            (unsigned long)len, (long)wr, (int)errno);
      return -1;
    }
  }
  return 0;
}

static stream_t *stream_create(async_params_t *prms, size_t addsize) {
  psync_tree *parent;
  stream_t *ret;
  ret = (stream_t *)malloc(sizeof(stream_t) + addsize);
  ret->streamid = ++prms->laststreamid;
  ret->flags = 0;
  ret->free = NULL;
  parent = ptree_get_last(prms->streams);
  if (parent)
    parent->right = &ret->tree;
  else
    prms->streams = &ret->tree;
  ptree_added_at(&prms->streams, parent, &ret->tree);
  return ret;
}

static void stream_destroy(stream_t *s) {
  pdbg_logf(D_NOTICE, "freeing unfinished stream %u", (unsigned)s->streamid);
  if (s->flags & STREAM_FLAG_ACTIVE) {
    psync_async_result_t ar;
    memset(&ar, 0, sizeof(ar));
    ar.error = PSYNC_ASYNC_ERROR_NET;
    ar.errorflags = PSYNC_ASYNC_ERR_FLAG_RETRY_AS_IS;
    s->cb(s->cbext, &ar);
  }
  if (s->free)
    s->free(s, PSYNC_ASYNC_ERROR_NET);
  free(s);
}

static int stream_process_data(async_params_t *prms) {
  psync_tree *tr;
  stream_t *s;
  int ret;
  tr = prms->streams;
  while (tr) {
    s = ptree_element(tr, stream_t, tree);
    if (prms->currentstreamid < s->streamid)
      tr = tr->left;
    else if (prms->currentstreamid > s->streamid)
      tr = tr->right;
    else {
      ret = s->process_data(s, prms, prms->buffer, prms->curreadbufflen);
      break;
    }
  }
  if (!tr) {
    pdbg_logf(D_NOTICE, "throwing out %u bytes of data for unknown streamid %u",
          (unsigned)prms->curreadbufflen, (unsigned)prms->currentstreamid);
    ret = 0;
  }
  stream_setup_header(prms);
  return ret;
}

static int stream_process_header(async_params_t *prms) {
  uint32_t len;
  memcpy(&prms->currentstreamid, prms->buffer, 4);
  len = 0;
  memcpy(&len, prms->buffer + 4, 2);
  prms->curreadbuff = prms->buffer;
  prms->curreadbufflen = prms->curreadbuffrem = len + 1;
  prms->process_buf = stream_process_data;
  return 0;
}

static void stream_setup_header(async_params_t *prms) {
  prms->curreadbuff = prms->buffer;
  prms->curreadbuffrem = STREAM_HEADER_LEN;
  prms->process_buf = stream_process_header;
}

static int task_send_async_locked(const void *task, size_t len) {
  unsigned char ch;
  if (sock_writeall(sockd, task, len)) {
    pdbg_logf(D_WARNING, "failed to write %lu bytes of task to socket",
          (unsigned long)len);
    return -1;
  }
  if (sock_readall(sockd, &ch, 1)) {
    pdbg_logf(D_WARNING, "failed to read response from socket");
    return -1;
  }
  if (ch == 0)
    return 0;
  else {
    pdbg_logf(D_WARNING, "got error %d from async thread", (int)ch);
    return -1;
  }
}

static int task_send_async(const void *task, size_t len) {
  int ret;
  pthread_mutex_lock(&mutex);
  if (running)
    ret = task_send_async_locked(task, len);
  else {
    ret = proc_start_async_transfer();
    if (!ret)
      ret = task_send_async_locked(task, len);
  }
  pthread_mutex_unlock(&mutex);
  return ret;
}

void ptask_ldir_mk(psync_syncid_t syncid,
                                    psync_folderid_t folderid,
                                    psync_folderid_t localfolderid) {
  psync_sql_res *res;
  res = psync_sql_prep_statement("INSERT INTO task (type, syncid, itemid, "
                                 "localitemid) VALUES (?, ?, ?, ?)");
  psync_sql_bind_uint(res, 1, PSYNC_CREATE_LOCAL_FOLDER);
  psync_sql_bind_uint(res, 2, syncid);
  psync_sql_bind_uint(res, 3, folderid);
  psync_sql_bind_uint(res, 4, localfolderid);
  psync_sql_run_free(res);
}

void ptask_ldir_rm(psync_syncid_t syncid, psync_folderid_t folderid, psync_folderid_t localfolderid, const char *remotepath) {
  psync_sql_res *res;
  res = psync_sql_prep_statement("INSERT INTO task (type, syncid, itemid, "
                                 "localitemid, name) VALUES (?, ?, ?, ?, ?)");
  psync_sql_bind_uint(res, 1, PSYNC_DELETE_LOCAL_FOLDER);
  psync_sql_bind_uint(res, 2, syncid);
  psync_sql_bind_uint(res, 3, folderid);
  psync_sql_bind_uint(res, 4, localfolderid);
  psync_sql_bind_string(res, 5, remotepath);
  psync_sql_run_free(res);
}

void ptask_ldir_rm_r(psync_syncid_t syncid, psync_folderid_t folderid, psync_folderid_t localfolderid) {
  psync_sql_res *res;
  res = psync_sql_prep_statement("INSERT INTO task (type, syncid, itemid, "
                                 "localitemid) VALUES (?, ?, ?, ?)");
  psync_sql_bind_uint(res, 1, PSYNC_DELREC_LOCAL_FOLDER);
  psync_sql_bind_uint(res, 2, syncid);
  psync_sql_bind_uint(res, 3, folderid);
  psync_sql_bind_uint(res, 4, localfolderid);
  psync_sql_run_free(res);
}

void ptask_ldir_rename(psync_syncid_t syncid, psync_folderid_t folderid, psync_folderid_t localfolderid, psync_folderid_t newlocalparentfolderid, const char *newname) {
  psync_sql_res *res;
  res = psync_sql_prep_statement(
      "INSERT INTO task (type, syncid, itemid, localitemid, newitemid, name) "
      "VALUES (?, ?, ?, ?, ?, ?)");
  psync_sql_bind_uint(res, 1, PSYNC_RENAME_LOCAL_FOLDER);
  psync_sql_bind_uint(res, 2, syncid);
  psync_sql_bind_uint(res, 3, folderid);
  psync_sql_bind_uint(res, 4, localfolderid);
  psync_sql_bind_uint(res, 5, newlocalparentfolderid);
  psync_sql_bind_string(res, 6, newname);
  psync_sql_run_free(res);
}

void ptask_download_q(psync_syncid_t syncid, psync_fileid_t fileid, psync_folderid_t localfolderid, const char *name) {
  psync_sql_res *res;
  res = psync_sql_prep_statement("INSERT INTO task (type, syncid, itemid, "
                                 "localitemid, name) VALUES (?, ?, ?, ?, ?)");
  psync_sql_bind_uint(res, 1, PSYNC_DOWNLOAD_FILE);
  psync_sql_bind_uint(res, 2, syncid);
  psync_sql_bind_uint(res, 3, fileid);
  psync_sql_bind_uint(res, 4, localfolderid);
  psync_sql_bind_string(res, 5, name);
  ppath_syncfldr_task_added_locked(syncid, localfolderid);
  psync_sql_run_free(res);
}

void ptask_download(psync_syncid_t syncid, psync_fileid_t fileid, psync_folderid_t localfolderid, const char *name) {
  ptask_download_q(syncid, fileid, localfolderid, name);
  pdownload_wake();
  pstatus_download_recalc();
  pstatus_send_status_update();
}

void ptask_lfile_rename(psync_syncid_t oldsyncid, psync_syncid_t newsyncid, psync_fileid_t fileid, psync_folderid_t oldlocalfolderid, psync_folderid_t newlocalfolderid, const char *newname) {
  psync_sql_res *res;
  res = psync_sql_prep_statement(
      "INSERT INTO task (type, syncid, newsyncid, itemid, localitemid, "
      "newitemid, name) VALUES (?, ?, ?, ?, ?, ?, ?)");
  psync_sql_bind_uint(res, 1, PSYNC_RENAME_LOCAL_FILE);
  psync_sql_bind_uint(res, 2, oldsyncid);
  psync_sql_bind_uint(res, 3, newsyncid);
  psync_sql_bind_uint(res, 4, fileid);
  psync_sql_bind_uint(res, 5, oldlocalfolderid);
  psync_sql_bind_uint(res, 6, newlocalfolderid);
  psync_sql_bind_string(res, 7, newname);
  psync_sql_run_free(res);
}

void ptask_lfile_rm(psync_fileid_t fileid, const char *remotepath) {
  psync_sql_res *res;
  res = psync_sql_prep_statement(
      "INSERT INTO task (type, itemid, localitemid, name) VALUES (?, ?, 0, ?)");
  psync_sql_bind_uint(res, 1, PSYNC_DELETE_LOCAL_FILE);
  psync_sql_bind_uint(res, 2, fileid);
  psync_sql_bind_string(res, 3, remotepath);
  psync_sql_run_free(res);
}

void ptask_lfile_rm_id(psync_syncid_t syncid, psync_fileid_t fileid, const char *remotepath) {
  psync_sql_res *res;
  res = psync_sql_prep_statement("INSERT INTO task (type, syncid, itemid, "
                                 "localitemid, name) VALUES (?, ?, ?, 0, ?)");
  psync_sql_bind_uint(res, 1, PSYNC_DELETE_LOCAL_FILE);
  psync_sql_bind_uint(res, 2, syncid);
  psync_sql_bind_uint(res, 3, fileid);
  psync_sql_bind_string(res, 4, remotepath);
  psync_sql_run_free(res);
}

void ptask_rdir_mk(psync_syncid_t syncid, psync_folderid_t localfolderid, const char *name) {
  psync_sql_res *res;
  res = psync_sql_prep_statement("INSERT INTO task (type, syncid, itemid, "
                                 "localitemid, name) VALUES (?, ?, ?, ?, ?)");
  psync_sql_bind_uint(res, 1, PSYNC_CREATE_REMOTE_FOLDER);
  psync_sql_bind_uint(res, 2, syncid);
  psync_sql_bind_uint(res, 3, 0);
  psync_sql_bind_uint(res, 4, localfolderid);
  psync_sql_bind_string(res, 5, name);
  psync_sql_run_free(res);
}

void ptask_upload_q(psync_syncid_t syncid, psync_fileid_t localfileid, const char *name) {
  psync_sql_res *res;
  res = psync_sql_prep_statement("INSERT INTO task (type, syncid, itemid, "
                                 "localitemid, name) VALUES (?, ?, ?, ?, ?)");
  psync_sql_bind_uint(res, 1, PSYNC_UPLOAD_FILE);
  psync_sql_bind_uint(res, 2, syncid);
  psync_sql_bind_uint(res, 3, 0);
  psync_sql_bind_uint(res, 4, localfileid);
  psync_sql_bind_string(res, 5, name);
  psync_sql_run_free(res);
}

void ptask_upload(psync_syncid_t syncid, psync_fileid_t localfileid, const char *name) {
  psync_sql_res *res;
  res = psync_sql_prep_statement("INSERT INTO task (type, syncid, itemid, "
                                 "localitemid, name) VALUES (?, ?, ?, ?, ?)");
  psync_sql_bind_uint(res, 1, PSYNC_UPLOAD_FILE);
  psync_sql_bind_uint(res, 2, syncid);
  psync_sql_bind_uint(res, 3, 0);
  psync_sql_bind_uint(res, 4, localfileid);
  psync_sql_bind_string(res, 5, name);
  psync_sql_run_free(res);
  pupload_wake();
  pstatus_upload_recalc_async();
}

void ptask_rfile_rename(psync_syncid_t oldsyncid, psync_syncid_t newsyncid, psync_fileid_t localfileid, psync_folderid_t newlocalparentfolderid, const char *newname) {
  psync_sql_res *res;
  res = psync_sql_prep_statement(
      "INSERT INTO task (type, syncid, newsyncid, localitemid, newitemid, "
      "name, itemid) VALUES (?, ?, ?, ?, ?, ?, 0)");
  psync_sql_bind_uint(res, 1, PSYNC_RENAME_REMOTE_FILE);
  psync_sql_bind_uint(res, 2, oldsyncid);
  psync_sql_bind_uint(res, 3, newsyncid);
  psync_sql_bind_uint(res, 4, localfileid);
  psync_sql_bind_uint(res, 5, newlocalparentfolderid);
  psync_sql_bind_string(res, 6, newname);
  psync_sql_run_free(res);
}

void ptask_rdir_rename(psync_syncid_t oldsyncid, psync_syncid_t newsyncid, psync_fileid_t localfileid, psync_folderid_t newlocalparentfolderid, const char *newname) {
  psync_sql_res *res;
  res = psync_sql_prep_statement(
      "INSERT INTO task (type, syncid, newsyncid, localitemid, newitemid, "
      "name, itemid) VALUES (?, ?, ?, ?, ?, ?, 0)");
  psync_sql_bind_uint(res, 1, PSYNC_RENAME_REMOTE_FOLDER);
  psync_sql_bind_uint(res, 2, oldsyncid);
  psync_sql_bind_uint(res, 3, newsyncid);
  psync_sql_bind_uint(res, 4, localfileid);
  psync_sql_bind_uint(res, 5, newlocalparentfolderid);
  psync_sql_bind_string(res, 6, newname);
  psync_sql_run_free(res);
}

void ptask_rfile_rm(psync_syncid_t syncid, psync_fileid_t fileid) {
  psync_sql_res *res;
  res = psync_sql_prep_statement("INSERT INTO task (type, syncid, itemid, "
                                 "localitemid) VALUES (?, ?, ?, 0)");
  psync_sql_bind_uint(res, 1, PSYNC_DELETE_REMOTE_FILE);
  psync_sql_bind_uint(res, 2, syncid);
  psync_sql_bind_uint(res, 3, fileid);
  psync_sql_run_free(res);
}

void ptask_rdir_rm(psync_syncid_t syncid, psync_folderid_t folderid) {
  psync_sql_res *res;
  res = psync_sql_prep_statement("INSERT INTO task (type, syncid, itemid, "
                                 "localitemid) VALUES (?, ?, ?, 0)");
  psync_sql_bind_uint(res, 1, PSYNC_DELETE_REMOTE_FILE);
  psync_sql_bind_uint(res, 2, syncid);
  psync_sql_bind_uint(res, 3, folderid);
  psync_sql_run_free(res);
}

void ptask_stop_async() {
  hdr_t task;
  task.type = TASK_TYPE_EXIT;
  task.len = 0;
  pthread_mutex_lock(&mutex);
  if (running)
    task_send_async_locked(&task, sizeof(task));
  pthread_mutex_unlock(&mutex);
}

int ptask_download_async(psync_fileid_t fileid, const char *localpath,
                              psync_async_callback_t cb, void *cbext) {
  download_task_t task;
  task.head.type = TASK_TYPE_FILE_DWL;
  task.head.len = get_len(download_task_t);
  task.request.fileid = fileid;
  task.request.localpath = localpath;
  task.request.cb = cb;
  task.request.cbext = cbext;
  return task_send_async(&task, sizeof(task));
}

int ptask_download_needed_async(psync_fileid_t fileid,
                                         const char *localpath, uint64_t size,
                                         const void *sha1hex,
                                         psync_async_callback_t cb,
                                         void *cbext) {
  download_needed_task_t task;
  task.head.type = TASK_TYPE_FILE_DWL_NM;
  task.head.len = get_len(download_needed_task_t);
  task.request.fileid = fileid;
  task.request.localpath = localpath;
  task.request.size = size;
  memcpy(task.request.sha1hex, sha1hex, PSYNC_SHA1_DIGEST_HEXLEN);
  task.request.cb = cb;
  task.request.cbext = cbext;
  return task_send_async(&task, sizeof(task));
}

void ptask_cfldr_save_fldrkey(void *ptr) {
  insert_folder_key_task *t;
  psync_sql_res *res;
  t = (insert_folder_key_task *)ptr;
  res = psync_sql_prep_statement(
      "REPLACE INTO cryptofolderkey (folderid, enckey) VALUES (?, ?)");
  psync_sql_bind_uint(res, 1, t->id);
  psync_sql_bind_blob(res, 2, (const char *)t->key->data, t->key->datalen);
  psync_sql_run_free(res);
  free(t->key);
  free(t);
}

void ptask_cfldr_save_filekey(void *ptr) {
  insert_file_key_task *t;
  psync_sql_res *res;
  t = (insert_file_key_task *)ptr;
  res = psync_sql_prep_statement(
      "REPLACE INTO cryptofilekey (fileid, hash, enckey) VALUES (?, ?, ?)");
  psync_sql_bind_uint(res, 1, t->id);
  psync_sql_bind_uint(res, 2, t->hash);
  psync_sql_bind_blob(res, 3, (const char *)t->key->data, t->key->datalen);
  psync_sql_run_free(res);
  free(t->key);
  free(t);
}