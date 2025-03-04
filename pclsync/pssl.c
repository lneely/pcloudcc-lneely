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
#include <mbedtls/bignum.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/debug.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/md.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/pk.h>
#include <mbedtls/pkcs5.h>
#include <mbedtls/sha256.h>
#include <mbedtls/ssl.h>
#include <pthread.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "pcache.h"
#include "pcompiler.h"
#include "plibs.h"
#include "pmemlock.h"
#include "pmemlock.h"
#include "prand.h"
#include "psettings.h"
#include "pssl.h"
#include "psslcerts.h"
#include "psynclib.h"
#include "psynclib.h"

// Lock used to serialize access to RSA decrypt key function
typedef struct {
  mbedtls_ctr_drbg_context rnd;
  pthread_mutex_t mutex;
} pssl_drbg_context_t;

static pthread_mutex_t rsa_decr_mutex = PTHREAD_MUTEX_INITIALIZER;
static pssl_drbg_context_t psync_mbed_rng;
static mbedtls_entropy_context psync_mbed_entropy;
static mbedtls_x509_crt psync_mbed_trusted_certs_x509;
PSYNC_THREAD int psync_ssl_errno;
static psync_ssl_debug_callback_t debug_cb = NULL;
static void *debug_ctx = NULL;
static const int psync_mbed_ciphersuite[] = {
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

static int check_peer_pubkey(pssl_connection_t *conn) {
  const mbedtls_x509_crt *cert;
  unsigned char buff[1024], sigbin[32];
  char sighex[66];
  int i;

  cert = mbedtls_ssl_get_peer_cert(&conn->ssl);
  if (!cert) {
    debug(D_WARNING, "ssl_get_peer_cert returned NULL");
    return -1;
  }
  if (mbedtls_pk_get_type(&cert->pk) != MBEDTLS_PK_RSA) {
    debug(D_WARNING, "public key is not RSA");
    return -1;
  }
  i = mbedtls_pk_write_pubkey_der((mbedtls_pk_context *)&cert->pk, buff,
                                  sizeof(buff));
  if (i <= 0) {
    debug(D_WARNING, "pk_write_pubkey_der returned error %d", i);
    return -1;
  }
  mbedtls_sha256(buff + sizeof(buff) - i, i, sigbin, 0);
  psync_binhex(sighex, sigbin, 32);
  sighex[64] = 0;
  for (i = 0; i < ARRAY_SIZE(psync_ssl_trusted_pk_sha256); i++)
    if (!strcmp(sighex, psync_ssl_trusted_pk_sha256[i]))
      return 0;
  debug(D_ERROR,
        "got sha256hex of public key %s that does not match any approved "
        "fingerprint",
        sighex);
  return -1;
}

static pssl_connection_t *conn_alloc(const char *hostname) {
  pssl_connection_t *conn;
  size_t len;
  len = strlen(hostname) + 1;
  conn = (pssl_connection_t *)psync_malloc(offsetof(pssl_connection_t, cachekey) +
                                          len + 4);
  conn->isbroken = 0;
  memcpy(conn->cachekey, "SSLS", 4);
  memcpy(conn->cachekey + 4, hostname, len);
  return conn;
}

static int drbg_random_safe(void *p_rng, unsigned char *output, size_t output_len) {
  pssl_drbg_context_t *rng;
  int ret;
  rng = (pssl_drbg_context_t *)p_rng;
  pthread_mutex_lock(&rng->mutex);
  ret = mbedtls_ctr_drbg_random(&rng->rnd, output, output_len);
  pthread_mutex_unlock(&rng->mutex);
  return ret;
}

static void encdata_free(pssl_enc_data_t *e) {
  pssl_cleanup(e->data, e->datalen);
  pmemlock_free(e);
}

static void free_session(void *ptr) {
  mbedtls_ssl_session_free((mbedtls_ssl_session *)ptr);
  psync_free(ptr);
}

static int mbed_read(void *ptr, unsigned char *buf, size_t len) {
  pssl_connection_t *conn;
  ssize_t ret;
  int err;
  conn = (pssl_connection_t *)ptr;
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
  pssl_connection_t *conn;
  ssize_t ret;
  int err;
  conn = (pssl_connection_t *)ptr;
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

static void save_session(pssl_connection_t *conn) {
  mbedtls_ssl_session *sess;
  sess = psync_new(mbedtls_ssl_session);
  // mbedtls_ssl_get_session seems to copy all elements, instead of referencing
  // them, therefore it is thread safe to add session upon connect
  memset(sess, 0, sizeof(mbedtls_ssl_session));
  if (mbedtls_ssl_get_session(&conn->ssl, sess))
    psync_free(sess);
  else
    pcache_add(conn->cachekey, sess, PSYNC_SSL_SESSION_CACHE_TIMEOUT,
                    free_session, PSYNC_MAX_SSL_SESSIONS_PER_DOMAIN);
}

static void set_errno(pssl_connection_t *conn, int err) {
  if (err == MBEDTLS_ERR_SSL_WANT_READ)
    psync_ssl_errno = PSSL_ERR_WANT_READ;
  else if (err == MBEDTLS_ERR_SSL_WANT_WRITE)
    psync_ssl_errno = PSSL_ERR_WANT_WRITE;
  else {
    psync_ssl_errno = PSSL_ERR_UNKNOWN;
    conn->isbroken = 1;
    if (err == MBEDTLS_ERR_NET_RECV_FAILED)
      debug(D_NOTICE, "got MBEDTLS_ERR_NET_RECV_FAILED");
    else if (err == MBEDTLS_ERR_NET_SEND_FAILED)
      debug(D_NOTICE, "got MBEDTLS_ERR_NET_SEND_FAILED");
    else
      debug(D_NOTICE, "got error %d", err);
  }
}

void paes_2blk_encode(pssl_decoder_t enc, const unsigned char *src, unsigned char *dst) {
  mbedtls_aes_crypt_ecb(enc, MBEDTLS_AES_ENCRYPT, src, dst);
  mbedtls_aes_crypt_ecb(enc, MBEDTLS_AES_ENCRYPT, src + PAES_BLOCK_SIZE,
                        dst + PAES_BLOCK_SIZE);
}

void paes_2blk_decode(pssl_decoder_t enc, const unsigned char *src, unsigned char *dst) {
  mbedtls_aes_crypt_ecb(enc, MBEDTLS_AES_DECRYPT, src, dst);
  mbedtls_aes_crypt_ecb(enc, MBEDTLS_AES_DECRYPT, src + PAES_BLOCK_SIZE,
                        dst + PAES_BLOCK_SIZE);
}

void paes_4blk_xor_decode(pssl_decoder_t enc, const unsigned char *src, unsigned char *dst, unsigned char *bxor) {
  unsigned long i;
  mbedtls_aes_crypt_ecb(enc, MBEDTLS_AES_DECRYPT, src, dst);
  mbedtls_aes_crypt_ecb(enc, MBEDTLS_AES_DECRYPT, src + PAES_BLOCK_SIZE,
                        dst + PAES_BLOCK_SIZE);
  mbedtls_aes_crypt_ecb(enc, MBEDTLS_AES_DECRYPT,
                        src + PAES_BLOCK_SIZE * 2,
                        dst + PAES_BLOCK_SIZE * 2);
  mbedtls_aes_crypt_ecb(enc, MBEDTLS_AES_DECRYPT,
                        src + PAES_BLOCK_SIZE * 3,
                        dst + PAES_BLOCK_SIZE * 3);
  for (i = 0; i < PAES_BLOCK_SIZE * 4 / sizeof(unsigned long); i++)
    ((unsigned long *)dst)[i] ^= ((unsigned long *)bxor)[i];
}

void paes_blk_encode(pssl_encoder_t enc, const unsigned char *src, unsigned char *dst) {
  mbedtls_aes_crypt_ecb(enc, MBEDTLS_AES_ENCRYPT, src, dst);
}

void paes_blk_decode(pssl_decoder_t enc, const unsigned char *src, unsigned char *dst) {
  mbedtls_aes_crypt_ecb(enc, MBEDTLS_AES_DECRYPT, src, dst);
}

pssl_encoder_t paes_decoder_create(pssl_symkey_t *key) {
  mbedtls_aes_context *aes;
  assert(key->keylen >= PAES_KEY_SIZE);
  aes = psync_new(mbedtls_aes_context);
  mbedtls_aes_setkey_dec(aes, key->key, 256);
  return aes;
}

void paes_decoder_free(pssl_encoder_t aes) {
  pssl_cleanup(aes, sizeof(mbedtls_aes_context));
  psync_free(aes);
}

pssl_encoder_t paes_encoder_create(pssl_symkey_t *key) {
  mbedtls_aes_context *aes;
  assert(key->keylen >= PAES_KEY_SIZE);
  aes = psync_new(mbedtls_aes_context);
  mbedtls_aes_setkey_enc(aes, key->key, 256);
  return aes;
}

void paes_encoder_free(pssl_encoder_t aes) {
  pssl_cleanup(aes, sizeof(mbedtls_aes_context));
  psync_free(aes);
}

void prsa_binary_free(pssl_rsabinkey_t bin) {
  encdata_free(bin);
}

pssl_rsabinkey_t prsa_binary_private(pssl_rsaprivkey_t rsa) {
  unsigned char buff[4096];
  mbedtls_pk_context ctx;
  pssl_rsabinkey_t ret;
  int len;
  mbedtls_pk_init(&ctx);
  if (mbedtls_pk_setup(&ctx, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA)) ||
      mbedtls_rsa_copy(mbedtls_pk_rsa(ctx), rsa))
    return PRSA_INVALID_BIN_KEY;
  len = mbedtls_pk_write_key_der(&ctx, buff, sizeof(buff));
  mbedtls_pk_free(&ctx);
  if (len <= 0)
    return PRSA_INVALID_BIN_KEY;
  ret =
      pmemlock_malloc(offsetof(pssl_enc_data_t, data) + len);
  ret->datalen = len;
  memcpy(ret->data, buff + sizeof(buff) - len, len);
  pssl_cleanup(buff + sizeof(buff) - len, len);
  return ret;
}

pssl_rsabinkey_t prsa_binary_public(pssl_rsapubkey_t rsa) {
  unsigned char buff[4096], *p;
  mbedtls_pk_context ctx;
  pssl_rsabinkey_t ret;
  int len;
  mbedtls_pk_init(&ctx);
  if (mbedtls_pk_setup(&ctx, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA)) ||
      mbedtls_rsa_copy(mbedtls_pk_rsa(ctx), rsa))
    return PRSA_INVALID_BIN_KEY;
  p = buff + sizeof(buff);
  len = mbedtls_pk_write_pubkey(&p, buff, &ctx);
  mbedtls_pk_free(&ctx);
  if (len <= 0)
    return PRSA_INVALID_BIN_KEY;
  ret =
      pmemlock_malloc(offsetof(pssl_enc_data_t, data) + len);
  ret->datalen = len;
  memcpy(ret->data, buff + sizeof(buff) - len, len);
  return ret;
}

void prsa_free(pssl_context_t rsa) {
  mbedtls_rsa_free(rsa);
  psync_free(rsa);
}

void prsa_free_private(pssl_rsaprivkey_t key) {
  prsa_free(key);
}

void prsa_free_public(pssl_rsapubkey_t key) {
  prsa_free(key);
}

pssl_context_t prsa_generate(int bits) {
  mbedtls_rsa_context *ctx;
  ctx = psync_new(mbedtls_rsa_context);
  mbedtls_rsa_init(ctx);
  mbedtls_rsa_set_padding(ctx, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA1);
  if (mbedtls_rsa_gen_key(ctx, drbg_random_safe, &psync_mbed_rng, bits,
                          65537)) {
    mbedtls_rsa_free(ctx);
    psync_free(ctx);
    return PRSA_INVALID;
  } else
    return ctx;
}

pssl_rsaprivkey_t prsa_get_private(pssl_context_t rsa) {
  mbedtls_rsa_context *ctx;
  ctx = psync_new(mbedtls_rsa_context);
  mbedtls_rsa_init(ctx);
  mbedtls_rsa_set_padding(ctx, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA1);
  if (unlikely(mbedtls_rsa_copy(ctx, rsa))) {
    mbedtls_rsa_free(ctx);
    psync_free(ctx);
    return PRSA_INVALID;
  } else
    return ctx;
}

pssl_rsapubkey_t prsa_get_public(pssl_context_t rsa) {
  pssl_rsabinkey_t bin;
  pssl_rsapubkey_t ret;
  bin = prsa_binary_public(rsa);
  if (bin == PRSA_INVALID_BIN_KEY)
    return PRSA_INVALID;
  ret = prsa_load_public(bin->data, bin->datalen);  
  prsa_binary_free(bin);
  return ret;
}

pssl_rsaprivkey_t prsa_load_private(const unsigned char *keydata, size_t keylen) {
  mbedtls_pk_context pkctx;
  mbedtls_rsa_context *rsactx;
  int ret;
  mbedtls_pk_init(&pkctx);

  ret = mbedtls_pk_parse_key(&pkctx, keydata, keylen, NULL, 0, mbedtls_ctr_drbg_random, &psync_mbed_rng.rnd);
  if (unlikely(ret)) {
      char ebuf[100];
      mbedtls_strerror(ret, ebuf, sizeof(ebuf));
      debug(D_WARNING, "failed to parse private key: %s (-0x%04x)", ebuf, (unsigned int) -ret);
      return PRSA_INVALID;
  }

  rsactx = psync_new(mbedtls_rsa_context);
  mbedtls_rsa_init(rsactx);
  mbedtls_rsa_set_padding(rsactx, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA1);
  ret = mbedtls_rsa_copy(rsactx, mbedtls_pk_rsa(pkctx));
  mbedtls_pk_free(&pkctx);
  if (unlikely(ret)) {
    debug(D_WARNING, "rsa_copy failed with code %d", ret);
    mbedtls_rsa_free(rsactx);
    psync_free(rsactx);
    return PRSA_INVALID;
  } else {
    return rsactx;
  }
}

pssl_rsapubkey_t prsa_load_public(const unsigned char *keydata, size_t keylen) {
  mbedtls_pk_context ctx;
  mbedtls_rsa_context *rsa;
  int ret;

  mbedtls_pk_init(&ctx);
  ret = mbedtls_pk_parse_public_key(&ctx, keydata, keylen);
  if (unlikely(ret)) {
    debug(D_ERROR, "failed to parse public key with code %d", ret);
    return PRSA_INVALID;
  }

  rsa = psync_new(mbedtls_rsa_context);
  mbedtls_rsa_init(rsa);
  mbedtls_rsa_set_padding(rsa, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA1);
  ret = mbedtls_rsa_copy(rsa, mbedtls_pk_rsa(ctx));
  mbedtls_pk_free(&ctx);
  if (unlikely(ret)) {
    debug(D_WARNING, "rsa_copy failed with code %d", ret);
    mbedtls_rsa_free(rsa);
    psync_free(rsa);
    return PRSA_INVALID;
  } else {
    mbedtls_rsa_set_padding(rsa, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA1);
    return rsa;
  }
}

pssl_signature_t prsa_signature(pssl_rsaprivkey_t rsa, const unsigned char *data) {
  pssl_signature_t ret;
  int padding, hash_id;
  size_t rsalen;

  rsalen = mbedtls_rsa_get_len(rsa);
  ret = (pssl_signature_t)psync_malloc(
      offsetof(pssl_symkey_t, key) + rsalen);
  if (!ret)
    return (pssl_signature_t)(void *)PERROR_NO_MEMORY;
  ret->datalen = rsalen;
  padding = mbedtls_rsa_get_padding_mode(rsa);
  hash_id = mbedtls_rsa_get_md_alg(rsa);
  mbedtls_rsa_set_padding(rsa, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256);
  if (mbedtls_rsa_rsassa_pss_sign(rsa, drbg_random_safe, &psync_mbed_rng,
                                  MBEDTLS_MD_SHA256,
                                  PSSL_SHA256_DIGEST_LEN, data, ret->data)) {
    free(ret);
    mbedtls_rsa_set_padding(rsa, padding, hash_id);
    return (pssl_signature_t)(void *)PSYNC_CRYPTO_NOT_STARTED;
  }
  mbedtls_rsa_set_padding(rsa, padding, hash_id);
  return ret;
}

int pssl_bytes_left(pssl_connection_t *sslconn) {
  return mbedtls_ssl_get_bytes_avail(&((pssl_connection_t *)sslconn)->ssl);
}

void pssl_cleanup(void *ptr, size_t len) {
  volatile unsigned char *p = ptr;
  while (len--)
    *p++ = 0;
}

int pssl_close(pssl_connection_t *sslconn) {
  pssl_connection_t *conn;
  int ret;
  conn = (pssl_connection_t *)sslconn;
  if (conn->isbroken)
    goto noshutdown;
  ret = mbedtls_ssl_close_notify(&conn->ssl);
  if (ret == 0)
    goto noshutdown;
  set_errno(conn, ret);
  if (likely_log(ret == MBEDTLS_ERR_SSL_WANT_READ ||
                 ret == MBEDTLS_ERR_SSL_WANT_WRITE))
    return PSSL_NEED_FINISH;
noshutdown:
  mbedtls_ssl_free(&conn->ssl);
  psync_free(conn);
  return PSSL_SUCCESS;
}

void pssl_debug_cb(psync_ssl_debug_callback_t cb, void *ctx) {
  debug_cb = cb;
  debug_ctx = ctx;
}

int pssl_finish(pssl_connection_t *sslconn, const char *hostname) {
  pssl_connection_t *conn;
  int ret;

  conn = (pssl_connection_t *)sslconn;
  ret = mbedtls_ssl_handshake(&conn->ssl);
  if (ret == 0) {
    if ((check_peer_pubkey(conn))) {
      goto fail;
    }
    save_session(conn);
    return PSSL_SUCCESS;
  } else {
    debug(D_ERROR, "handshake failed, return code was %d", ret);
  }
  set_errno(conn, ret);
  if (likely_log(ret == MBEDTLS_ERR_SSL_WANT_READ ||
                 ret == MBEDTLS_ERR_SSL_WANT_WRITE))
    return PSSL_NEED_FINISH;
fail:
  mbedtls_ssl_free(&conn->ssl);
  psync_free(conn);
  return PRINT_RETURN_CONST(PSSL_FAIL);
}

void pssl_free(pssl_connection_t *sslconn) {
  pssl_connection_t *conn;
  conn = (pssl_connection_t *)sslconn;
  mbedtls_ssl_free(&conn->ssl);
  psync_free(conn);
}

int pssl_init() {
  unsigned char seed[PSYNC_LHASH_DIGEST_LEN];
  unsigned long i;
  int result;

  if (pthread_mutex_init(&psync_mbed_rng.mutex, NULL))
    return PRINT_RETURN(-1);

  mbedtls_entropy_init(&psync_mbed_entropy);
  prand_seed(seed, seed, sizeof(seed), 0);
  mbedtls_entropy_update_manual(&psync_mbed_entropy, seed, sizeof(seed));

  mbedtls_ctr_drbg_init(&psync_mbed_rng.rnd);
  if ((result = mbedtls_ctr_drbg_seed(&psync_mbed_rng.rnd, mbedtls_entropy_func,
                                      &psync_mbed_entropy, NULL, 0))) {
    debug(D_ERROR, "mbedtls_ctr_drbg_seed failed with return code %d", result);
    return PRINT_RETURN(-1);
  }

  mbedtls_x509_crt_init(&psync_mbed_trusted_certs_x509);
  for (i = 0; i < ARRAY_SIZE(psync_ssl_trusted_certs); i++) {
    result = mbedtls_x509_crt_parse(&psync_mbed_trusted_certs_x509,
                                    (unsigned char *)psync_ssl_trusted_certs[i],
                                    1 + strlen(psync_ssl_trusted_certs[i]));
    if (result) {
      debug(D_ERROR, "failed to load certificate %lu, got result %d",
            (unsigned long)i, result);
    }
  }

  return 0;
}

void pssl_log_level(int threshold) {
  mbedtls_debug_set_threshold(threshold);
}

int pssl_open(int sock, pssl_connection_t **sslconn, const char *hostname) {
  pssl_connection_t *conn;
  mbedtls_ssl_session *sess;
  int ret;

  debug(D_NOTICE, "Starting SSL connection to %s", hostname);

  conn = conn_alloc(hostname);
  mbedtls_ssl_init(&conn->ssl);
  mbedtls_ssl_config_init(&conn->cfg);
  
  mbedtls_net_init(&conn->srv);
  conn->sock = sock;
  
  debug(D_NOTICE, "Initialized SSL structures");

  if ((ret = mbedtls_ssl_config_defaults(&conn->cfg, MBEDTLS_SSL_IS_CLIENT,
                                         MBEDTLS_SSL_TRANSPORT_STREAM,
                                         MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
    debug(D_ERROR,
          "Failed to set SSL config defaults: mbedtls_ssl_config_defaults returned %d", ret);
    goto err0;
  }

  debug(D_NOTICE, "Set SSL config defaults successfully");

  // force tls 1.2
  mbedtls_ssl_conf_max_tls_version(&conn->cfg, MBEDTLS_SSL_VERSION_TLS1_2);
  mbedtls_ssl_conf_min_tls_version(&conn->cfg, MBEDTLS_SSL_VERSION_TLS1_2);                              
  debug(D_NOTICE, "Set TLS version to 1.2 only");

  mbedtls_ssl_conf_endpoint(&conn->cfg, MBEDTLS_SSL_IS_CLIENT);
  mbedtls_ssl_conf_dbg(&conn->cfg, debug_cb, debug_ctx);
  mbedtls_ssl_conf_authmode(&conn->cfg, MBEDTLS_SSL_VERIFY_REQUIRED);
  mbedtls_ssl_conf_ca_chain(&conn->cfg, &psync_mbed_trusted_certs_x509, NULL);
  mbedtls_ssl_conf_ciphersuites(&conn->cfg, psync_mbed_ciphersuite);
  mbedtls_ssl_conf_rng(&conn->cfg, drbg_random_safe, &psync_mbed_rng);

  debug(D_NOTICE, "Configured SSL parameters");

  mbedtls_ssl_set_bio(&conn->ssl, &conn->srv, mbed_write, mbed_read, NULL);
  mbedtls_ssl_set_hostname(&conn->ssl, hostname);

  debug(D_NOTICE, "Set SSL bio and hostname");

  if (mbedtls_ssl_setup(&conn->ssl, &conn->cfg) != 0) {
    debug(D_ERROR, "Failed to setup SSL");
    goto err0;
  }

  debug(D_NOTICE, "SSL setup complete");

  if ((sess = (mbedtls_ssl_session *)pcache_get(conn->cachekey))) {
    debug(D_NOTICE, "Reusing cached session for %s", hostname);
    if (mbedtls_ssl_set_session(&conn->ssl, sess)) {
      debug(D_WARNING, "ssl_set_session failed");
    }
    mbedtls_ssl_session_free(sess);
    psync_free(sess);
  } else {
    debug(D_NOTICE, "No cached session found for %s", hostname);
  }

  debug(D_NOTICE, "Starting SSL handshake");
  ret = mbedtls_ssl_handshake(&conn->ssl);
  if (ret == 0) {
    debug(D_NOTICE, "SSL handshake completed successfully");
    if ((check_peer_pubkey(conn))) {
      debug(D_ERROR, "Peer public key check failed");
      goto err1;
    }
    *sslconn = conn;

    save_session(conn);
    debug(D_NOTICE, "SSL connection established successfully");
    return PSSL_SUCCESS;
  }

  set_errno(conn, ret);
  if (likely_log(ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE)) {
    *sslconn = conn;
    return PSSL_NEED_FINISH;
  }
  debug(D_ERROR, "SSL handshake failed with error code %d", ret);

err1:
  mbedtls_ssl_free(&conn->ssl);
err0:
  psync_free(conn);
  return PRINT_RETURN_CONST(PSSL_FAIL);
}

void pssl_random(unsigned char *buf, int num) {
  if (unlikely(drbg_random_safe(&psync_mbed_rng, buf, num))) {
    debug(D_CRITICAL, "could not generate %d random bytes, exiting", num);
    abort();
  }
}

int pssl_read(pssl_connection_t *sslconn, void *buf, int num) {
  pssl_connection_t *conn;
  int res;
  conn = (pssl_connection_t *)sslconn;
  res = mbedtls_ssl_read(&conn->ssl, (unsigned char *)buf, num);
  if (res >= 0)
    return res;
  set_errno(conn, res);
  return PSSL_FAIL;
}

int pssl_write(pssl_connection_t *sslconn, const void *buf, int num) {
  pssl_connection_t *conn;
  int res;
  conn = (pssl_connection_t *)sslconn;
  res = mbedtls_ssl_write(&conn->ssl, (const unsigned char *)buf, num);
  if (res >= 0)
    return res;
  set_errno(conn, res);
  return PSSL_FAIL;
}

pssl_enc_symkey_t psymkey_alloc(size_t len) {
  pssl_enc_symkey_t ret;
  ret = psync_malloc(offsetof(pssl_enc_data_t, data) + len);
  ret->datalen = len;
  return ret;
}

pssl_enc_symkey_t psymkey_copy(pssl_enc_symkey_t src) {
  pssl_enc_symkey_t ret;
  ret = psync_malloc(offsetof(pssl_enc_data_t, data) +
                     src->datalen);
  ret->datalen = src->datalen;
  memcpy(ret->data, src->data, src->datalen);
  return ret;
}

pssl_symkey_t *psymkey_decrypt(pssl_rsaprivkey_t rsa, const unsigned char *data, size_t datalen) {
  unsigned char buff[2048];
  pssl_symkey_t *ret;
  size_t len;
  if (mbedtls_rsa_rsaes_oaep_decrypt(rsa, drbg_random_safe,
                                     &psync_mbed_rng, NULL,
                                     0, &len, data, buff, sizeof(buff)))
    return PSYMKEY_INVALID;
  ret = (pssl_symkey_t *)pmemlock_malloc(
      offsetof(pssl_symkey_t, key) + len);
  ret->keylen = len;
  memcpy(ret->key, buff, len);
  pssl_cleanup(buff, len);
  return ret;
}

pssl_symkey_t *psymkey_decrypt_lock(pssl_rsaprivkey_t *rsa, const pssl_enc_symkey_t *enckey) {
  pssl_symkey_t *sym_key;

  debug(D_NOTICE, "Get RSA decrypt key lock.");
  pthread_mutex_lock(&rsa_decr_mutex);

  sym_key = psymkey_decrypt(*rsa, (*enckey)->data, (*enckey)->datalen);

  pthread_mutex_unlock(&rsa_decr_mutex);
  debug(D_NOTICE, "RSA decrypt key Lock released.");

  return sym_key;
}

char *psymkey_derive_passphrase(const char *username, const char *passphrase) {
  unsigned char *usercopy;
  unsigned char usersha512[PSSL_SHA512_DIGEST_LEN], passwordbin[32];
  mbedtls_md_context_t ctx;
  size_t userlen, i;
  userlen = strlen(username);
  usercopy = psync_new_cnt(unsigned char, userlen);
  for (i = 0; i < userlen; i++)
    if ((unsigned char)username[i] <= 127)
      usercopy[i] = tolower((unsigned char)username[i]);
    else
      usercopy[i] = '*';
  psync_sha512(usercopy, userlen, usersha512);
  psync_free(usercopy);
  mbedtls_md_init(&ctx);
  mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA512), 0);

  const mbedtls_md_info_t *md_info = mbedtls_md_info_from_ctx(&ctx);
  mbedtls_md_type_t md_type = mbedtls_md_get_type(md_info);
  mbedtls_pkcs5_pbkdf2_hmac_ext(md_type, (const unsigned char *)passphrase, strlen(passphrase), usersha512, 
    PSSL_SHA512_DIGEST_LEN, 5000, sizeof(passwordbin), passwordbin);
  mbedtls_md_free(&ctx);
  usercopy = psync_base64_encode(passwordbin, sizeof(passwordbin), &userlen);
  return (char *)usercopy;
}

pssl_enc_symkey_t psymkey_encrypt(pssl_rsapubkey_t rsa, const unsigned char *data, size_t datalen) {
  pssl_enc_symkey_t ret;
  int code;
  size_t rsalen;

  rsalen = mbedtls_rsa_get_len(rsa);
  ret = (pssl_enc_symkey_t)psync_malloc(
      offsetof(pssl_enc_data_t, data) + rsalen);
  if ((code = mbedtls_rsa_rsaes_oaep_encrypt(
           rsa, drbg_random_safe, &psync_mbed_rng,
           NULL, 0, datalen, data, ret->data))) {
    psync_free(ret);
    debug(
        D_WARNING,
        "rsa_rsaes_oaep_encrypt failed with error=%d, datalen=%lu, rsasize=%d",
        code, (unsigned long)datalen, (int)rsalen);
    return PSYMKEY_INVALID_ENC;
  }
  ret->datalen = rsalen;
  debug(D_NOTICE, "datalen=%lu", (unsigned long)ret->datalen);
  return ret;
}

void psymkey_free(pssl_symkey_t *key) {
  pssl_cleanup(key->key, key->keylen);
  pmemlock_free(key);
}

pssl_symkey_t *psymkey_generate(const char *password, size_t keylen, const unsigned char *salt, size_t saltlen, size_t iterations) {
  pssl_symkey_t *key = (pssl_symkey_t *)pmemlock_malloc(
      keylen + offsetof(pssl_symkey_t, key));
  mbedtls_md_context_t ctx;
  mbedtls_md_init(&ctx);
  mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA512), 0);
  key->keylen = keylen;
  const mbedtls_md_info_t *md_info = mbedtls_md_info_from_ctx(&ctx);
  mbedtls_md_type_t md_type = mbedtls_md_get_type(md_info);
  mbedtls_pkcs5_pbkdf2_hmac_ext(md_type, (const unsigned char *)password,
                               strlen(password), salt, saltlen, iterations, keylen,
                               key->key);
  mbedtls_md_free(&ctx);
  return key;
}

