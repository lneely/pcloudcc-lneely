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

#include <ctype.h>
#include <errno.h>
#include <pthread.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <mbedtls/asn1.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/debug.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/md.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/pkcs5.h>
#include <mbedtls/rsa.h>
#include <mbedtls/sha256.h>
#include <mbedtls/ssl.h>

#include "pcache.h"
#include "pcompiler.h"
#include "plibs.h"
#include "prand.h"
#include "psettings.h"
#include "pssl.h"
#include "psslcerts.h"
#include "psynclib.h"
#include "putil.h"


static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

static void ssl_pdbg_logf(int loglevel, int errnum, const char *msg) {
    char ebuf[100];
    mbedtls_strerror(errnum, ebuf, sizeof(ebuf));
    pdbg_logf(loglevel, "%s: %s (-0x%04x)", msg, ebuf, (unsigned int)-errnum);
}

static void free_encrypted(psync_encrypted_data_t e) {
  putil_wipe(e->data, e->datalen);
  free(e);
}

void prsa_free_binary(psync_binary_rsa_key_t bin) {
  free_encrypted(bin);
}

void psymkey_free(psync_symmetric_key_t key) {
  putil_wipe(key->key, key->keylen);
  free(key);
}

psync_encrypted_symmetric_key_t
psymkey_alloc_encrypted(size_t len) {
  psync_encrypted_symmetric_key_t ret;
  ret = malloc(offsetof(psync_encrypted_data_struct_t, data) + len);
  ret->datalen = len;
  return ret;
}

psync_encrypted_symmetric_key_t
psymkey_copy_encrypted(psync_encrypted_symmetric_key_t src) {
  psync_encrypted_symmetric_key_t ret;
  ret = malloc(offsetof(psync_encrypted_data_struct_t, data) +
                     src->datalen);
  ret->datalen = src->datalen;
  memcpy(ret->data, src->data, src->datalen);
  return ret;
}

psync_symmetric_key_t prsa_decrypt_symm_key_lock(
    psync_rsa_privatekey_t *rsa,
    const psync_encrypted_symmetric_key_t *enckey) {
  psync_symmetric_key_t sym_key;

  pdbg_logf(D_NOTICE, "Get RSA decrypt key lock.");
  pthread_mutex_lock(&mutex);

  sym_key = psymkey_decrypt(*rsa, *enckey);

  pthread_mutex_unlock(&mutex);
  pdbg_logf(D_NOTICE, "RSA decrypt key Lock released.");

  return sym_key;
}

static const int ciphersuites[] = {
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    MBEDTLS_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    MBEDTLS_TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
    MBEDTLS_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
    MBEDTLS_TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    MBEDTLS_TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
    MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
    MBEDTLS_TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,
    0};

typedef struct {
  mbedtls_ctr_drbg_context rnd;
  pthread_mutex_t mutex;
} rng_ctx;

typedef struct {
  mbedtls_net_context srv;
  mbedtls_ssl_context ssl;
  mbedtls_ssl_config cfg;
  int sock;
  int isbroken;
  char cachekey[];
} ssl_connection_t;

static rng_ctx rng;
static mbedtls_entropy_context entropy;
static mbedtls_x509_crt ca_chain;

PSYNC_THREAD int psync_ssl_errno;

static pssl_debug_callback_t debug_cb = NULL;
static void *debug_ctx = NULL;

void pssl_log_threshold(int threshold) {
  mbedtls_debug_set_threshold(threshold);
}

void pssl_debug_cb(pssl_debug_callback_t cb, void *ctx) {
  debug_cb = cb;
  debug_ctx = ctx;
}

int rng_get(void *p_rng, unsigned char *output, size_t output_len) {
  rng_ctx *rng;
  int ret;
  rng = (rng_ctx *)p_rng;
  pthread_mutex_lock(&rng->mutex);
  ret = mbedtls_ctr_drbg_random(&rng->rnd, output, output_len);
  pthread_mutex_unlock(&rng->mutex);
  return ret;
}

int pssl_init() {
  unsigned char seed[PSYNC_LHASH_DIGEST_LEN];
  unsigned long i;
  int result;

  if (pthread_mutex_init(&rng.mutex, NULL))
    return pdbg_return(-1);

  mbedtls_entropy_init(&entropy);
  prand_seed(seed, seed, sizeof(seed), 0);
  mbedtls_entropy_update_manual(&entropy, seed, sizeof(seed));

  mbedtls_ctr_drbg_init(&rng.rnd);
  if ((result = mbedtls_ctr_drbg_seed(&rng.rnd, mbedtls_entropy_func,
                                      &entropy, NULL, 0))) {
    pdbg_logf(D_ERROR, "mbedtls_ctr_drbg_seed failed with return code %d", result);
    return pdbg_return(-1);
  }
  

  mbedtls_x509_crt_init(&ca_chain);
  for (i = 0; i < ARRAY_SIZE(psync_ssl_trusted_certs); i++) {
    result = mbedtls_x509_crt_parse(&ca_chain,
                                    (unsigned char *)psync_ssl_trusted_certs[i],
                                    1 + strlen(psync_ssl_trusted_certs[i]));
    if (result) {
      pdbg_logf(D_ERROR, "failed to load certificate %lu, got result %d",
            (unsigned long)i, result);
    }
  }

  return 0;
}

static ssl_connection_t *conn_alloc(const char *hostname) {
  ssl_connection_t *conn;
  size_t len;
  len = strlen(hostname) + 1;
  conn = (ssl_connection_t *)malloc(offsetof(ssl_connection_t, cachekey) +
                                          len + 4);
  conn->isbroken = 0;
  memcpy(conn->cachekey, "SSLS", 4);
  memcpy(conn->cachekey + 4, hostname, len);
  return conn;
}

static void set_error(ssl_connection_t *conn, int err) {
  if (err == MBEDTLS_ERR_SSL_WANT_READ)
    psync_ssl_errno = PSYNC_SSL_ERR_WANT_READ;
  else if (err == MBEDTLS_ERR_SSL_WANT_WRITE)
    psync_ssl_errno = PSYNC_SSL_ERR_WANT_WRITE;
  else {
    psync_ssl_errno = PSYNC_SSL_ERR_UNKNOWN;
    conn->isbroken = 1;
    if (err == MBEDTLS_ERR_NET_RECV_FAILED)
      pdbg_logf(D_NOTICE, "got MBEDTLS_ERR_NET_RECV_FAILED");
    else if (err == MBEDTLS_ERR_NET_SEND_FAILED)
      pdbg_logf(D_NOTICE, "got MBEDTLS_ERR_NET_SEND_FAILED");
    else
      pdbg_logf(D_NOTICE, "got error %d", err);
  }
}

static int mbed_read(void *ptr, unsigned char *buf, size_t len) {
  ssl_connection_t *conn;
  ssize_t ret;
  int err;
  conn = (ssl_connection_t *)ptr;
  ret = read(conn->sock, buf, len);
  if (ret == -1) {
    err = errno;
    if (err == EWOULDBLOCK || err == EAGAIN || err == EINTR)
      return MBEDTLS_ERR_SSL_WANT_READ;
    else
      return MBEDTLS_ERR_NET_RECV_FAILED;
  } else
    return (int)ret;
}

static int mbed_write(void *ptr, const unsigned char *buf, size_t len) {
  ssl_connection_t *conn;
  ssize_t ret;
  int err;
  conn = (ssl_connection_t *)ptr;
  ret = write(conn->sock, buf, len);
  if (ret == -1) {
    err = errno;
    if (err == EWOULDBLOCK || err == EAGAIN || err == EINTR)
      return MBEDTLS_ERR_SSL_WANT_WRITE;
    else
      return MBEDTLS_ERR_NET_SEND_FAILED;
  } else
    return (int)ret;
}

static void free_session(void *ptr) {
  mbedtls_ssl_session_free((mbedtls_ssl_session *)ptr);
  free(ptr);
}

static void save_session(ssl_connection_t *conn) {
  mbedtls_ssl_session *sess;
  sess = malloc(sizeof(mbedtls_ssl_session));
  // mbedtls_ssl_get_session seems to copy all elements, instead of referencing
  // them, therefore it is thread safe to add session upon connect
  memset(sess, 0, sizeof(mbedtls_ssl_session));
  if (mbedtls_ssl_get_session(&conn->ssl, sess))
    free(sess);
  else
    pcache_add(conn->cachekey, sess, PSYNC_SSL_SESSION_CACHE_TIMEOUT,
                    free_session, PSYNC_MAX_SSL_SESSIONS_PER_DOMAIN);
}

static int check_peer_pubkey(ssl_connection_t *conn) {
  const mbedtls_x509_crt *cert;
  unsigned char buff[1024], sigbin[32];
  char sighex[66];
  int i;

  // TODO: returning null, why?
  cert = mbedtls_ssl_get_peer_cert(&conn->ssl);
  if (!cert) {
    pdbg_logf(D_WARNING, "ssl_get_peer_cert returned NULL");
    return -1;
  }
  if (mbedtls_pk_get_type(&cert->pk) != MBEDTLS_PK_RSA) {
    pdbg_logf(D_WARNING, "public key is not RSA");
    return -1;
  }
  i = mbedtls_pk_write_pubkey_der((mbedtls_pk_context *)&cert->pk, buff,
                                  sizeof(buff));
  if (i <= 0) {
    pdbg_logf(D_WARNING, "pk_write_pubkey_der returned error %d", i);
    return -1;
  }
  mbedtls_sha256(buff + sizeof(buff) - i, i, sigbin, 0);
  psync_binhex(sighex, sigbin, 32);
  sighex[64] = 0;
  for (i = 0; i < ARRAY_SIZE(psync_ssl_trusted_pk_sha256); i++)
    if (!strcmp(sighex, psync_ssl_trusted_pk_sha256[i]))
      return 0;
  pdbg_logf(D_ERROR,
        "got sha256hex of public key %s that does not match any approved "
        "fingerprint",
        sighex);
  return -1;
}

int pssl_connect(int sock, void **sslconn,
                      const char *hostname) {
  ssl_connection_t *conn;
  mbedtls_ssl_session *sess;
  int ret;

  conn = conn_alloc(hostname);
  mbedtls_ssl_init(&conn->ssl);
  mbedtls_ssl_config_init(&conn->cfg);
  mbedtls_net_init(&conn->srv);
  conn->sock = sock;

  if ((ret = mbedtls_ssl_config_defaults(&conn->cfg, MBEDTLS_SSL_IS_CLIENT,
                                         MBEDTLS_SSL_TRANSPORT_STREAM,
                                         MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
    pdbg_logf(D_ERROR,
          "failed to set ssl cfg defaults: ! mbedtls_ssl_config_defaults "
          "returned %d\n\n",
          ret);
    goto err0;
  }

  mbedtls_ssl_conf_max_version(&conn->cfg, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);
  mbedtls_ssl_conf_min_version(&conn->cfg, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);      

  mbedtls_ssl_conf_endpoint(&conn->cfg, MBEDTLS_SSL_IS_CLIENT);
  mbedtls_ssl_conf_dbg(&conn->cfg, debug_cb, debug_ctx);
  mbedtls_ssl_conf_authmode(&conn->cfg, MBEDTLS_SSL_VERIFY_REQUIRED);
  mbedtls_ssl_conf_ca_chain(&conn->cfg, &ca_chain, NULL);
  mbedtls_ssl_conf_ciphersuites(&conn->cfg, ciphersuites);
  mbedtls_ssl_conf_rng(&conn->cfg, rng_get, &rng);

  mbedtls_ssl_set_bio(&conn->ssl, &conn->srv, mbed_write, mbed_read, NULL);
  mbedtls_ssl_set_hostname(&conn->ssl, hostname);

  mbedtls_ssl_setup(&conn->ssl, &conn->cfg); // attach config to ssl

  if ((sess = (mbedtls_ssl_session *)pcache_get(conn->cachekey))) {
    pdbg_logf(D_NOTICE, "reusing cached session for %s", hostname);
    if (mbedtls_ssl_set_session(&conn->ssl, sess)) {
      pdbg_logf(D_WARNING, "ssl_set_session failed");
    }
    mbedtls_ssl_session_free(sess);
    free(sess);
  }

  ret = mbedtls_ssl_handshake(&conn->ssl);
  if (ret == 0) {
    if ((check_peer_pubkey(conn))) {
      goto err1;
    }
    *sslconn = conn;

    save_session(conn);
    return PSYNC_SSL_SUCCESS;
  }

  set_error(conn, ret);
  if (pdbg_likely(ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE)) {
    *sslconn = conn;
    return PSYNC_SSL_NEED_FINISH;
  }
err1:
  mbedtls_ssl_free(&conn->ssl);
err0:
  free(conn);
  return pdbg_return_const(PSYNC_SSL_FAIL);
}

int pssl_connect_finish(void *sslconn, const char *hostname) {
  ssl_connection_t *conn;
  int ret;

  conn = (ssl_connection_t *)sslconn;
  ret = mbedtls_ssl_handshake(&conn->ssl);
  if (ret == 0) {
    if ((check_peer_pubkey(conn))) {
      goto fail;
    }
    save_session(conn);
    return PSYNC_SSL_SUCCESS;
  } else {
    pdbg_logf(D_ERROR, "handshake failed, return code was %d", ret);
  }
  set_error(conn, ret);
  if (pdbg_likely(ret == MBEDTLS_ERR_SSL_WANT_READ ||
                 ret == MBEDTLS_ERR_SSL_WANT_WRITE))
    return PSYNC_SSL_NEED_FINISH;
fail:
  mbedtls_ssl_free(&conn->ssl);
  free(conn);
  return pdbg_return_const(PSYNC_SSL_FAIL);
}

int pssl_shutdown(void *sslconn) {
  ssl_connection_t *conn;
  int ret;
  conn = (ssl_connection_t *)sslconn;
  if (conn->isbroken)
    goto noshutdown;
  ret = mbedtls_ssl_close_notify(&conn->ssl);
  if (ret == 0)
    goto noshutdown;
  set_error(conn, ret);
  if (pdbg_likely(ret == MBEDTLS_ERR_SSL_WANT_READ ||
                 ret == MBEDTLS_ERR_SSL_WANT_WRITE))
    return PSYNC_SSL_NEED_FINISH;
noshutdown:
  mbedtls_ssl_free(&conn->ssl);
  free(conn);
  return PSYNC_SSL_SUCCESS;
}

void pssl_free(void *sslconn) {
  ssl_connection_t *conn;
  conn = (ssl_connection_t *)sslconn;
  mbedtls_ssl_free(&conn->ssl);
  free(conn);
}

int pssl_pendingdata(void *sslconn) {
  return mbedtls_ssl_get_bytes_avail(&((ssl_connection_t *)sslconn)->ssl);
}

int pssl_read(void *sslconn, void *buf, int num) {
  ssl_connection_t *conn;
  int res;
  conn = (ssl_connection_t *)sslconn;
  res = mbedtls_ssl_read(&conn->ssl, (unsigned char *)buf, num);
  if (res >= 0)
    return res;
  set_error(conn, res);
  return PSYNC_SSL_FAIL;
}

int pssl_write(void *sslconn, const void *buf, int num) {
  ssl_connection_t *conn;
  int res;
  conn = (ssl_connection_t *)sslconn;
  res = mbedtls_ssl_write(&conn->ssl, (const unsigned char *)buf, num);
  if (res >= 0)
    return res;
  set_error(conn, res);
  return PSYNC_SSL_FAIL;
}

void pssl_rand_strong(unsigned char *buf, int num) {
  // FIXME: causing segfault
  if (unlikely(rng_get(&rng, buf, num))) {
    pdbg_logf(D_CRITICAL, "could not generate %d random bytes, exiting", num);
    abort();
  }
}

psync_rsa_t pssl_gen_rsa(int bits) {
  mbedtls_rsa_context *ctx;
  ctx = malloc(sizeof(mbedtls_rsa_context));
  mbedtls_rsa_init(ctx);
  mbedtls_rsa_set_padding(ctx, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA1);

  if (mbedtls_rsa_gen_key(ctx, rng_get, &rng, bits,
                          65537)) {
    mbedtls_rsa_free(ctx);
    free(ctx);
    return PSYNC_INVALID_RSA;
  } else
    return ctx;
}

void pssl_free_rsa(psync_rsa_t rsa) {
  mbedtls_rsa_free(rsa);
  free(rsa);
}

psync_rsa_publickey_t prsa_get_public(psync_rsa_t rsa) {
  psync_binary_rsa_key_t bin;
  psync_rsa_publickey_t ret;
  bin = prsa_public_to_binary(rsa);
  if (bin == PSYNC_INVALID_BIN_RSA)
    return PSYNC_INVALID_RSA;
  ret = prsa_binary_to_public(bin);
  prsa_free_binary(bin);
  return ret;
}

void prsa_free_public(psync_rsa_publickey_t key) {
  pssl_free_rsa(key);
}

psync_rsa_privatekey_t prsa_get_private(psync_rsa_t rsa) {
  mbedtls_rsa_context *ctx;
  ctx = malloc(sizeof(mbedtls_rsa_context));
  mbedtls_rsa_init(ctx);
  mbedtls_rsa_set_padding(ctx, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA1);

  if (unlikely(mbedtls_rsa_copy(ctx, rsa))) {
    mbedtls_rsa_free(ctx);
    free(ctx);
    return PSYNC_INVALID_RSA;
  } else
    return ctx;
}

void prsa_free_private(psync_rsa_privatekey_t key) {
  pssl_free_rsa(key);
}

psync_binary_rsa_key_t
prsa_public_to_binary(psync_rsa_publickey_t rsa) {
  unsigned char buff[4096], *p;
  mbedtls_pk_context ctx;
  psync_binary_rsa_key_t ret;
  int len;
  mbedtls_pk_init(&ctx);
  if (mbedtls_pk_setup(&ctx, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA)) ||
      mbedtls_rsa_copy(mbedtls_pk_rsa(ctx), rsa))
    return PSYNC_INVALID_BIN_RSA;
  p = buff + sizeof(buff);
  len = mbedtls_pk_write_pubkey(&p, buff, &ctx);
  mbedtls_pk_free(&ctx);
  if (len <= 0)
    return PSYNC_INVALID_BIN_RSA;
  ret =
      malloc(offsetof(psync_encrypted_data_struct_t, data) + len);
  ret->datalen = len;
  memcpy(ret->data, buff + sizeof(buff) - len, len);
  return ret;
}

psync_binary_rsa_key_t
prsa_private_to_binary(psync_rsa_privatekey_t rsa) {
  unsigned char buff[4096];
  mbedtls_pk_context ctx;
  psync_binary_rsa_key_t ret;
  int len;
  mbedtls_pk_init(&ctx);
  if (mbedtls_pk_setup(&ctx, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA)) ||
      mbedtls_rsa_copy(mbedtls_pk_rsa(ctx), rsa))
    return PSYNC_INVALID_BIN_RSA;
  len = mbedtls_pk_write_key_der(&ctx, buff, sizeof(buff));
  mbedtls_pk_free(&ctx);
  if (len <= 0)
    return PSYNC_INVALID_BIN_RSA;
  ret =
      malloc(offsetof(psync_encrypted_data_struct_t, data) + len);
  ret->datalen = len;
  memcpy(ret->data, buff + sizeof(buff) - len, len);
  putil_wipe(buff + sizeof(buff) - len, len);
  return ret;
}

psync_rsa_publickey_t prsa_load_public(const unsigned char *keydata,
                                                size_t keylen) {
  mbedtls_pk_context ctx;
  mbedtls_rsa_context *rsa;
  int ret;

  mbedtls_pk_init(&ctx);

  if (unlikely(ret = mbedtls_pk_parse_public_key(&ctx, keydata, keylen))) {
    pdbg_logf(D_WARNING, "pk_parse_public_key failed with code %d (-0x%04x); resorting to " "mbedtls 1.x RSA fallback", ret, -ret);
    return PSYNC_INVALID_RSA;
  }
  rsa = malloc(sizeof(mbedtls_rsa_context));
  mbedtls_rsa_init(rsa);
  mbedtls_rsa_set_padding(rsa, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA1);
  ret = mbedtls_rsa_copy(rsa, mbedtls_pk_rsa(ctx));
  mbedtls_pk_free(&ctx);
  if (unlikely(ret)) {
    pdbg_logf(D_WARNING, "rsa_copy failed with code %d", ret);
    mbedtls_rsa_free(rsa);
    free(rsa);
    return PSYNC_INVALID_RSA;
  } else {
    mbedtls_rsa_set_padding(rsa, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA1);
    return rsa;
  }
}

// mbedtls 3.x: mbedtls_pk_parse_key rejects keys with trailing garbage. This
// function gets the actual key length from the ASN.1 header, trims any bytes
// that exceed that length, and writes the trimmed key and length to keydata
// and keylen.
static void trim_der_key(unsigned char *keydata, size_t *keylen) {
    size_t len, header_size, correct_len;
    unsigned char *p = (unsigned char *)keydata;
    const unsigned char *end;
    int ret;
    unsigned char *trimmed;
    
    end = keydata + *keylen;
    ret = mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
    if (ret != 0) {
        return;
    }
    header_size = p - keydata;
    correct_len = header_size + len;
    trimmed = malloc(correct_len);
    if (!trimmed) return;
    memcpy(trimmed, keydata, correct_len);
    memcpy(keydata, trimmed, correct_len);
    free(trimmed);
    *keylen = correct_len;
}

psync_rsa_privatekey_t prsa_load_private(const unsigned char *keydata, size_t keylen) {
  mbedtls_pk_context ctx;
  mbedtls_rsa_context *rsa;
  int ret;

  trim_der_key((unsigned char *)keydata, &keylen);
  
  mbedtls_pk_init(&ctx);
  ret = mbedtls_pk_parse_key(&ctx, keydata, keylen, NULL, 0, rng_get, &rng);
  if(unlikely(ret)) {
    ssl_pdbg_logf(D_WARNING, ret, "pk_parse_key failed");
    return PSYNC_INVALID_RSA;
  }
  rsa = malloc(sizeof(mbedtls_rsa_context));
  mbedtls_rsa_init(rsa);
  mbedtls_rsa_set_padding(rsa, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA1);
  ret = mbedtls_rsa_copy(rsa, mbedtls_pk_rsa(ctx));
  mbedtls_pk_free(&ctx);
  if (unlikely(ret)) {
    pdbg_logf(D_WARNING, "rsa_copy failed with code %d", ret);
    mbedtls_rsa_free(rsa);
    free(rsa);
    return PSYNC_INVALID_RSA;
  } else {
    mbedtls_rsa_set_padding(rsa, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA1);
    return rsa;
  }
}

psync_rsa_publickey_t
prsa_binary_to_public(psync_binary_rsa_key_t bin) {
  return prsa_load_public(bin->data, bin->datalen);
}

psync_rsa_privatekey_t
prsa_binary_to_private(psync_binary_rsa_key_t bin) {
  return prsa_load_private(bin->data, bin->datalen);
}

psync_symmetric_key_t
psymkey_generate(const char *password, size_t keylen,
                                      const unsigned char *salt, size_t saltlen,
                                      size_t iterations) {
  psync_symmetric_key_t key = (psync_symmetric_key_t)malloc(
      keylen + offsetof(psync_symmetric_key_struct_t, key));
  mbedtls_md_context_t ctx;
  mbedtls_md_init(&ctx);
  const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA512);
  mbedtls_md_setup(&ctx, md_info, 1);
  key->keylen = keylen;
  mbedtls_pkcs5_pbkdf2_hmac(&ctx, (const unsigned char *)password,
                           strlen(password), salt, saltlen, iterations,
                           keylen, key->key);
  mbedtls_md_free(&ctx);
  return key;
}

char *psymkey_derive(const char *username,
                                                const char *passphrase) {
  unsigned char *usercopy;
  unsigned char usersha512[PSYNC_SHA512_DIGEST_LEN], passwordbin[32];
  mbedtls_md_context_t ctx;
  size_t userlen, i;
  userlen = strlen(username);
  usercopy = malloc(sizeof(unsigned char) * userlen);
  for (i = 0; i < userlen; i++)
    if ((unsigned char)username[i] <= 127)
      usercopy[i] = tolower((unsigned char)username[i]);
    else
      usercopy[i] = '*';
  psync_sha512(usercopy, userlen, usersha512);
  free(usercopy);
  mbedtls_md_init(&ctx);
  const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA512);
  mbedtls_md_setup(&ctx, md_info, 1);
  mbedtls_pkcs5_pbkdf2_hmac(&ctx, (const unsigned char *)passphrase, strlen(passphrase), usersha512,
    PSYNC_SHA512_DIGEST_LEN, 5000, sizeof(passwordbin), passwordbin);
  mbedtls_md_free(&ctx);
  usercopy = psync_base64_encode(passwordbin, sizeof(passwordbin), &userlen);
  return (char *)usercopy;
}

psync_encrypted_symmetric_key_t
prsa_encrypt_data(psync_rsa_publickey_t rsa, const unsigned char *data,
                           size_t datalen) {
  psync_encrypted_symmetric_key_t ret;
  int code;
  size_t rsalen = mbedtls_rsa_get_len(rsa);

  ret = (psync_encrypted_symmetric_key_t)malloc(
      offsetof(psync_encrypted_data_struct_t, data) + rsalen);
  if ((code = mbedtls_rsa_rsaes_oaep_encrypt(
           rsa, rng_get, &rng,
           NULL, 0, datalen, data, ret->data))) {
    free(ret);
    pdbg_logf(
        D_WARNING,
        "rsa_rsaes_oaep_encrypt failed with error=%d, datalen=%lu, rsasize=%d",
        code, (unsigned long)datalen, (int)rsalen);
    return PSYNC_INVALID_ENC_SYM_KEY;
  }
  ret->datalen = rsalen;
  pdbg_logf(D_NOTICE, "datalen=%lu", (unsigned long)ret->datalen);
  return ret;
}

psync_symmetric_key_t prsa_decrypt_data(psync_rsa_privatekey_t rsa,
                                                 const unsigned char *data,
                                                 size_t datalen) {
  unsigned char buff[2048];
  psync_symmetric_key_t ret;
  size_t len;
  if (mbedtls_rsa_rsaes_oaep_decrypt(rsa, rng_get,
                                     &rng,
                                     NULL, 0, &len, data, buff, sizeof(buff)))
    return PSYNC_INVALID_SYM_KEY;
  ret = (psync_symmetric_key_t)malloc(
      offsetof(psync_symmetric_key_struct_t, key) + len);
  ret->keylen = len;
  memcpy(ret->key, buff, len);
  putil_wipe(buff, len);
  return ret;
}

psync_encrypted_symmetric_key_t
psymkey_encrypt(psync_rsa_publickey_t rsa,
                                    const psync_symmetric_key_t key) {
  return prsa_encrypt_data(rsa, key->key, key->keylen);
}

psync_symmetric_key_t psymkey_decrypt(
    psync_rsa_privatekey_t rsa, const psync_encrypted_symmetric_key_t enckey) {
  return prsa_decrypt_data(rsa, enckey->data, enckey->datalen);
}

psync_aes256_encoder
paes_create_encoder(psync_symmetric_key_t key) {
  mbedtls_aes_context *aes;
  pdbg_assert(key->keylen >= PSYNC_AES256_KEY_SIZE);
  aes = malloc(sizeof(mbedtls_aes_context));
  mbedtls_aes_setkey_enc(aes, key->key, 256);
  return aes;
}

void paes_free_encoder(psync_aes256_encoder aes) {
  putil_wipe(aes, sizeof(mbedtls_aes_context));
  free(aes);
}

psync_aes256_encoder
paes_create_decoder(psync_symmetric_key_t key) {
  mbedtls_aes_context *aes;
  pdbg_assert(key->keylen >= PSYNC_AES256_KEY_SIZE);
  aes = malloc(sizeof(mbedtls_aes_context));
  mbedtls_aes_setkey_dec(aes, key->key, 256);
  return aes;
}

void paes_free_decoder(psync_aes256_encoder aes) {
  putil_wipe(aes, sizeof(mbedtls_aes_context));
  free(aes);
}

psync_rsa_signature_t
prsa_sign_sha256_hash(psync_rsa_privatekey_t rsa,
                               const unsigned char *data) {
  psync_rsa_signature_t ret;
  int padding, hash_id;
  size_t rsalen = mbedtls_rsa_get_len(rsa);

  ret = (psync_rsa_signature_t)malloc(
      offsetof(psync_symmetric_key_struct_t, key) + rsalen);
  if (!ret)
    return (psync_rsa_signature_t)(void *)PERROR_NO_MEMORY;
  ret->datalen = rsalen;
  /* Save current padding settings (assume PKCS_V21 with SHA1 as default) */
  padding = MBEDTLS_RSA_PKCS_V21;
  hash_id = MBEDTLS_MD_SHA1;
  mbedtls_rsa_set_padding(rsa, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256);
  if (mbedtls_rsa_rsassa_pss_sign(rsa, rng_get, &rng,
                                  MBEDTLS_MD_SHA256,
                                  PSYNC_SHA256_DIGEST_LEN, data, ret->data)) {
    free(ret);
    mbedtls_rsa_set_padding(rsa, padding, hash_id);
    return (psync_rsa_signature_t)(void *)PSYNC_CRYPTO_NOT_STARTED;
  }
  mbedtls_rsa_set_padding(rsa, padding, hash_id);
  return ret;
}
