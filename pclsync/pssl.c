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
#include <ctype.h>
#include <mbedtls/bignum.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/debug.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/md.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/pkcs5.h>
#include <mbedtls/sha256.h>
#include <mbedtls/ssl.h>
#include <pthread.h>
#include <stddef.h>
#include <stdio.h>

#include "pfile.h"
#include "pcompiler.h"

#include "pcache.h"
#include "plibs.h"
#include "pmemlock.h"
#include "prand.h"
#include "psettings.h"
#include "psslcerts.h"
#include "psynclib.h"

#include "plibs.h"
#include "pmemlock.h"
#include "pssl.h"
#include "psynclib.h"
#include <stddef.h>
#include <string.h>

// HACK: This function is duplicated from mbedtls/library/pkparse.c, because
// it is needed to properly parse the RSA keys returned by the pcloud server
// for some reason... see the fallback code in psync_ssl_rsa_load_public.
static int pk_get_rsapubkey(unsigned char **p, const unsigned char *end,
                            mbedtls_rsa_context *rsa) {
  int ret;
  size_t len;
  mbedtls_mpi N, E;

  debug(D_NOTICE, "Entering pk_get_rsapubkey");

  if ((ret = mbedtls_asn1_get_tag(
           p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) !=
      0) {
    debug(D_WARNING, "mbedtls_asn1_get_tag failed with code %d", ret);
    return (MBEDTLS_ERR_PK_INVALID_PUBKEY + ret);
  }

  debug(D_NOTICE, "ASN.1 tag parsed successfully, len: %zu", len);

  if (*p + len != end) {
    debug(D_WARNING, "Length mismatch in ASN.1 structure");
    return (MBEDTLS_ERR_PK_INVALID_PUBKEY + MBEDTLS_ERR_ASN1_LENGTH_MISMATCH);
  }

  mbedtls_mpi_init(&N);
  mbedtls_mpi_init(&E);
  if ((ret = mbedtls_asn1_get_mpi(p, end, &N)) != 0 ||
      (ret = mbedtls_asn1_get_mpi(p, end, &E)) != 0) {
    debug(D_WARNING, "Failed to parse MPI N or E, ret: %d", ret);
    mbedtls_mpi_free(&N);
    mbedtls_mpi_free(&E);
    ret = (MBEDTLS_ERR_PK_INVALID_PUBKEY + ret);
    goto cleanup;
  }

  debug(D_NOTICE, "Successfully parsed MPIs N and E");

  if (*p != end) {
    debug(D_WARNING, "Extra data after parsing N and E");
    ret = (MBEDTLS_ERR_PK_INVALID_PUBKEY + MBEDTLS_ERR_ASN1_LENGTH_MISMATCH);
    goto cleanup;
  }

  // set N and E in the rsa context
  ret = mbedtls_rsa_import(rsa, &N, NULL, NULL, NULL, &E);
  if (ret != 0) {
    debug(D_WARNING, "mbedtls_rsa_import failed with code %d", ret);
    mbedtls_mpi_free(&N);
    mbedtls_mpi_free(&E);
    goto cleanup;
  }

  debug(D_NOTICE, "Successfully imported N and E into RSA context");

  ret = mbedtls_rsa_check_pubkey(rsa);
  if (ret != 0) {
    debug(D_WARNING, "mbedtls_rsa_check_pubkey failed with code %d", ret);
    ret = (MBEDTLS_ERR_PK_INVALID_PUBKEY);
    goto cleanup;
  }

  debug(D_NOTICE, "Public key check passed successfully");

cleanup:
  mbedtls_mpi_free(&N);
  mbedtls_mpi_free(&E);
  debug(D_NOTICE, "Exiting pk_get_rsapubkey with ret: %d", ret);
  return ret;
}


static pthread_mutex_t rsa_decr_mutex = PTHREAD_MUTEX_INITIALIZER;

static void psync_ssl_free_psync_encrypted_data_t(psync_encrypted_data_t e) {
  psync_ssl_memclean(e->data, e->datalen);
  pmemlock_free(e);
}

void psync_ssl_rsa_free_binary(psync_binary_rsa_key_t bin) {
  psync_ssl_free_psync_encrypted_data_t(bin);
}

void psync_ssl_free_symmetric_key(psync_symmetric_key_t key) {
  psync_ssl_memclean(key->key, key->keylen);
  pmemlock_free(key);
}

psync_encrypted_symmetric_key_t
psync_ssl_alloc_encrypted_symmetric_key(size_t len) {
  psync_encrypted_symmetric_key_t ret;
  ret = psync_malloc(offsetof(psync_encrypted_data_struct_t, data) + len);
  ret->datalen = len;
  return ret;
}

psync_encrypted_symmetric_key_t
psync_ssl_copy_encrypted_symmetric_key(psync_encrypted_symmetric_key_t src) {
  psync_encrypted_symmetric_key_t ret;
  ret = psync_malloc(offsetof(psync_encrypted_data_struct_t, data) +
                     src->datalen);
  ret->datalen = src->datalen;
  memcpy(ret->data, src->data, src->datalen);
  return ret;
}

psync_symmetric_key_t psync_ssl_rsa_decrypt_symm_key_lock(
    psync_rsa_privatekey_t *rsa,
    const psync_encrypted_symmetric_key_t *enckey) {
  psync_symmetric_key_t sym_key;

  debug(D_NOTICE, "Get RSA decrypt key lock.");
  pthread_mutex_lock(&rsa_decr_mutex);

  sym_key = psync_ssl_rsa_decrypt_symmetric_key(*rsa, *enckey);

  pthread_mutex_unlock(&rsa_decr_mutex);
  debug(D_NOTICE, "RSA decrypt key Lock released.");

  return sym_key;
}

#if defined(PSYNC_AES_HW_MSC)
#include <intrin.h>
#include <wmmintrin.h>
#endif

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

typedef struct {
  mbedtls_ctr_drbg_context rnd;
  pthread_mutex_t mutex;
} ctr_drbg_context_locked;

typedef struct {
  mbedtls_net_context srv;
  mbedtls_ssl_context ssl;
  mbedtls_ssl_config cfg;
  int sock;
  int isbroken;
  char cachekey[];
} ssl_connection_t;

static ctr_drbg_context_locked psync_mbed_rng;
static mbedtls_entropy_context psync_mbed_entropy;
static mbedtls_x509_crt psync_mbed_trusted_certs_x509;

PSYNC_THREAD int psync_ssl_errno;

#if defined(PSYNC_AES_HW)
int psync_ssl_hw_aes;
#endif

static psync_ssl_debug_callback_t debug_cb = NULL;
static void *debug_ctx = NULL;

void psync_ssl_set_log_threshold(int threshold) {
  mbedtls_debug_set_threshold(threshold);
}

void psync_ssl_set_debug_callback(psync_ssl_debug_callback_t cb, void *ctx) {
  debug_cb = cb;
  debug_ctx = ctx;
}

int ctr_drbg_random_locked(void *p_rng, unsigned char *output,
                           size_t output_len) {
  ctr_drbg_context_locked *rng;
  int ret;
  rng = (ctr_drbg_context_locked *)p_rng;
  pthread_mutex_lock(&rng->mutex);
  ret = mbedtls_ctr_drbg_random(&rng->rnd, output, output_len);
  pthread_mutex_unlock(&rng->mutex);
  return ret;
}

#if defined(PSYNC_AES_HW_GCC)
static int psync_ssl_detect_aes_hw() {
  uint32_t eax, ecx;
  eax = 1;
  __asm__("cpuid" : "=c"(ecx) : "a"(eax) : "%ebx", "%edx");
  ecx = (ecx >> 25) & 1;
  if (ecx)
    debug(D_NOTICE, "hardware AES support detected");
  else
    debug(D_NOTICE, "hardware AES support not detected");
  return ecx;
}
#elif defined(PSYNC_AES_HW_MSC)
static int psync_ssl_detect_aes_hw() {
  int info[4];
  int ret;
  __cpuid(info, 1);
  ret = (info[2] >> 25) & 1;
  if (ret)
    debug(D_NOTICE, "hardware AES support detected");
  else
    debug(D_NOTICE, "hardware AES support not detected");
  return ret;
}
#endif

int psync_ssl_init() {
  unsigned char seed[PSYNC_LHASH_DIGEST_LEN];
  unsigned long i;
  int result;

#if defined(PSYNC_AES_HW)
  psync_ssl_hw_aes = psync_ssl_detect_aes_hw();
#else
  debug(D_NOTICE, "hardware AES is not supported for this compiler");
#endif
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

void psync_ssl_memclean(void *ptr, size_t len) {
  volatile unsigned char *p = ptr;
  while (len--)
    *p++ = 0;
}

static ssl_connection_t *psync_ssl_alloc_conn(const char *hostname) {
  ssl_connection_t *conn;
  size_t len;
  len = strlen(hostname) + 1;
  conn = (ssl_connection_t *)psync_malloc(offsetof(ssl_connection_t, cachekey) +
                                          len + 4);
  conn->isbroken = 0;
  memcpy(conn->cachekey, "SSLS", 4);
  memcpy(conn->cachekey + 4, hostname, len);
  return conn;
}

static void psync_set_ssl_error(ssl_connection_t *conn, int err) {
  if (err == MBEDTLS_ERR_SSL_WANT_READ)
    psync_ssl_errno = PSYNC_SSL_ERR_WANT_READ;
  else if (err == MBEDTLS_ERR_SSL_WANT_WRITE)
    psync_ssl_errno = PSYNC_SSL_ERR_WANT_WRITE;
  else {
    psync_ssl_errno = PSYNC_SSL_ERR_UNKNOWN;
    conn->isbroken = 1;
    if (err == MBEDTLS_ERR_NET_RECV_FAILED)
      debug(D_NOTICE, "got MBEDTLS_ERR_NET_RECV_FAILED");
    else if (err == MBEDTLS_ERR_NET_SEND_FAILED)
      debug(D_NOTICE, "got MBEDTLS_ERR_NET_SEND_FAILED");
    else
      debug(D_NOTICE, "got error %d", err);
  }
}

static int psync_mbed_read(void *ptr, unsigned char *buf, size_t len) {
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

static int psync_mbed_write(void *ptr, const unsigned char *buf, size_t len) {
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

static void psync_ssl_free_session(void *ptr) {
  mbedtls_ssl_session_free((mbedtls_ssl_session *)ptr);
  psync_free(ptr);
}

static void psync_ssl_save_session(ssl_connection_t *conn) {
  mbedtls_ssl_session *sess;
  sess = psync_new(mbedtls_ssl_session);
  // mbedtls_ssl_get_session seems to copy all elements, instead of referencing
  // them, therefore it is thread safe to add session upon connect
  memset(sess, 0, sizeof(mbedtls_ssl_session));
  if (mbedtls_ssl_get_session(&conn->ssl, sess))
    psync_free(sess);
  else
    psync_cache_add(conn->cachekey, sess, PSYNC_SSL_SESSION_CACHE_TIMEOUT,
                    psync_ssl_free_session, PSYNC_MAX_SSL_SESSIONS_PER_DOMAIN);
}

static int psync_ssl_check_peer_public_key(ssl_connection_t *conn) {
  const mbedtls_x509_crt *cert;
  unsigned char buff[1024], sigbin[32];
  char sighex[66];
  int i;

  // TODO: returning null, why?
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

int psync_ssl_connect(int sock, void **sslconn, const char *hostname) {
  ssl_connection_t *conn;
  mbedtls_ssl_session *sess;
  int ret;

  debug(D_NOTICE, "Starting SSL connection to %s", hostname);

  conn = psync_ssl_alloc_conn(hostname);
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
  mbedtls_ssl_conf_rng(&conn->cfg, ctr_drbg_random_locked, &psync_mbed_rng);

  debug(D_NOTICE, "Configured SSL parameters");

  mbedtls_ssl_set_bio(&conn->ssl, &conn->srv, psync_mbed_write, psync_mbed_read, NULL);
  mbedtls_ssl_set_hostname(&conn->ssl, hostname);

  debug(D_NOTICE, "Set SSL bio and hostname");

  if (mbedtls_ssl_setup(&conn->ssl, &conn->cfg) != 0) {
    debug(D_ERROR, "Failed to setup SSL");
    goto err0;
  }

  debug(D_NOTICE, "SSL setup complete");

  if ((sess = (mbedtls_ssl_session *)psync_cache_get(conn->cachekey))) {
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
    if ((psync_ssl_check_peer_public_key(conn))) {
      debug(D_ERROR, "Peer public key check failed");
      goto err1;
    }
    *sslconn = conn;

    psync_ssl_save_session(conn);
    debug(D_NOTICE, "SSL connection established successfully");
    return PSYNC_SSL_SUCCESS;
  }

  psync_set_ssl_error(conn, ret);
  if (likely_log(ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE)) {
    *sslconn = conn;
    return PSYNC_SSL_NEED_FINISH;
  }
  debug(D_ERROR, "SSL handshake failed with error code %d", ret);

err1:
  mbedtls_ssl_free(&conn->ssl);
err0:
  psync_free(conn);
  return PRINT_RETURN_CONST(PSYNC_SSL_FAIL);
}

int psync_ssl_connect_finish(void *sslconn, const char *hostname) {
  ssl_connection_t *conn;
  int ret;

  conn = (ssl_connection_t *)sslconn;
  ret = mbedtls_ssl_handshake(&conn->ssl);
  if (ret == 0) {
    if ((psync_ssl_check_peer_public_key(conn))) {
      goto fail;
    }
    psync_ssl_save_session(conn);
    return PSYNC_SSL_SUCCESS;
  } else {
    debug(D_ERROR, "handshake failed, return code was %d", ret);
  }
  psync_set_ssl_error(conn, ret);
  if (likely_log(ret == MBEDTLS_ERR_SSL_WANT_READ ||
                 ret == MBEDTLS_ERR_SSL_WANT_WRITE))
    return PSYNC_SSL_NEED_FINISH;
fail:
  mbedtls_ssl_free(&conn->ssl);
  psync_free(conn);
  return PRINT_RETURN_CONST(PSYNC_SSL_FAIL);
}


int psync_ssl_shutdown(void *sslconn) {
  ssl_connection_t *conn;
  int ret;
  conn = (ssl_connection_t *)sslconn;
  if (conn->isbroken)
    goto noshutdown;
  ret = mbedtls_ssl_close_notify(&conn->ssl);
  if (ret == 0)
    goto noshutdown;
  psync_set_ssl_error(conn, ret);
  if (likely_log(ret == MBEDTLS_ERR_SSL_WANT_READ ||
                 ret == MBEDTLS_ERR_SSL_WANT_WRITE))
    return PSYNC_SSL_NEED_FINISH;
noshutdown:
  mbedtls_ssl_free(&conn->ssl);
  psync_free(conn);
  return PSYNC_SSL_SUCCESS;
}

void psync_ssl_free(void *sslconn) {
  ssl_connection_t *conn;
  conn = (ssl_connection_t *)sslconn;
  mbedtls_ssl_free(&conn->ssl);
  psync_free(conn);
}

int psync_ssl_pendingdata(void *sslconn) {
  return mbedtls_ssl_get_bytes_avail(&((ssl_connection_t *)sslconn)->ssl);
}

int psync_ssl_read(void *sslconn, void *buf, int num) {
  ssl_connection_t *conn;
  int res;
  conn = (ssl_connection_t *)sslconn;
  res = mbedtls_ssl_read(&conn->ssl, (unsigned char *)buf, num);
  if (res >= 0)
    return res;
  psync_set_ssl_error(conn, res);
  return PSYNC_SSL_FAIL;
}

int psync_ssl_write(void *sslconn, const void *buf, int num) {
  ssl_connection_t *conn;
  int res;
  conn = (ssl_connection_t *)sslconn;
  res = mbedtls_ssl_write(&conn->ssl, (const unsigned char *)buf, num);
  if (res >= 0)
    return res;
  psync_set_ssl_error(conn, res);
  return PSYNC_SSL_FAIL;
}

void psync_ssl_rand_strong(unsigned char *buf, int num) {
  // FIXME: causing segfault
  if (unlikely(ctr_drbg_random_locked(&psync_mbed_rng, buf, num))) {
    debug(D_CRITICAL, "could not generate %d random bytes, exiting", num);
    abort();
  }
}

void psync_ssl_rand_weak(unsigned char *buf, int num) {
  psync_ssl_rand_strong(buf, num);
}

psync_rsa_t psync_ssl_gen_rsa(int bits) {
  mbedtls_rsa_context *ctx;
  ctx = psync_new(mbedtls_rsa_context);
  mbedtls_rsa_init(ctx);
  mbedtls_rsa_set_padding(ctx, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA1);
  if (mbedtls_rsa_gen_key(ctx, ctr_drbg_random_locked, &psync_mbed_rng, bits,
                          65537)) {
    mbedtls_rsa_free(ctx);
    psync_free(ctx);
    return PSYNC_INVALID_RSA;
  } else
    return ctx;
}

void psync_ssl_free_rsa(psync_rsa_t rsa) {
  mbedtls_rsa_free(rsa);
  psync_free(rsa);
}

psync_rsa_publickey_t psync_ssl_rsa_get_public(psync_rsa_t rsa) {
  psync_binary_rsa_key_t bin;
  psync_rsa_publickey_t ret;
  bin = psync_ssl_rsa_public_to_binary(rsa);
  if (bin == PSYNC_INVALID_BIN_RSA)
    return PSYNC_INVALID_RSA;
  ret = psync_ssl_rsa_binary_to_public(bin);
  psync_ssl_rsa_free_binary(bin);
  return ret;
}

void psync_ssl_rsa_free_public(psync_rsa_publickey_t key) {
  psync_ssl_free_rsa(key);
}

psync_rsa_privatekey_t psync_ssl_rsa_get_private(psync_rsa_t rsa) {
  mbedtls_rsa_context *ctx;
  ctx = psync_new(mbedtls_rsa_context);
  mbedtls_rsa_init(ctx);
  mbedtls_rsa_set_padding(ctx, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA1);
  if (unlikely(mbedtls_rsa_copy(ctx, rsa))) {
    mbedtls_rsa_free(ctx);
    psync_free(ctx);
    return PSYNC_INVALID_RSA;
  } else
    return ctx;
}

void psync_ssl_rsa_free_private(psync_rsa_privatekey_t key) {
  psync_ssl_free_rsa(key);
}

psync_binary_rsa_key_t
psync_ssl_rsa_public_to_binary(psync_rsa_publickey_t rsa) {
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
      pmemlock_malloc(offsetof(psync_encrypted_data_struct_t, data) + len);
  ret->datalen = len;
  memcpy(ret->data, buff + sizeof(buff) - len, len);
  return ret;
}

psync_binary_rsa_key_t
psync_ssl_rsa_private_to_binary(psync_rsa_privatekey_t rsa) {
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
      pmemlock_malloc(offsetof(psync_encrypted_data_struct_t, data) + len);
  ret->datalen = len;
  memcpy(ret->data, buff + sizeof(buff) - len, len);
  psync_ssl_memclean(buff + sizeof(buff) - len, len);
  return ret;
}

psync_rsa_publickey_t psync_ssl_rsa_load_public(const unsigned char *keydata,
                                                size_t keylen) {
  mbedtls_pk_context ctx;
  mbedtls_rsa_context *rsa;
  int ret;

  debug(D_NOTICE, "Public key data (first 16 bytes): %02x %02x %02x %02x ...",
        keydata[0], keydata[1], keydata[2], keydata[3]);

  mbedtls_pk_init(&ctx);

  if (unlikely(ret = mbedtls_pk_parse_public_key(&ctx, keydata, keylen))) {
    debug(D_WARNING,
          "pk_parse_public_key failed with code %d (-0x%04x); resorting to "
          "mbedtls 1.x RSA fallback",
          ret, -ret);

    if (ret != 0) {
      mbedtls_pk_setup(&ctx, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
      unsigned char *p = (unsigned char *)keydata;
      ret = pk_get_rsapubkey(&p, p + keylen, mbedtls_pk_rsa(ctx));
      if (ret != 0)
        mbedtls_pk_free(&ctx);
    }

    if (ret != 0) {
      char error_buf[100];
      mbedtls_strerror(ret, error_buf, sizeof(error_buf));
      debug(D_WARNING, "Error details: %s", error_buf);
      return PSYNC_INVALID_RSA;
    }
  }

  if (mbedtls_pk_get_type(&ctx) != MBEDTLS_PK_RSA) {
    debug(D_WARNING, "Parsed key is not RSA");
    mbedtls_pk_free(&ctx);
    return PSYNC_INVALID_RSA;
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
    return PSYNC_INVALID_RSA;
  } else {
    mbedtls_rsa_set_padding(rsa, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA1);
    return rsa;
  }
}

psync_rsa_privatekey_t psync_ssl_rsa_load_private(const unsigned char *keydata,
                                                  size_t keylen) {
  mbedtls_pk_context ctx;
  mbedtls_rsa_context *rsa;
  int ret;
  mbedtls_pk_init(&ctx);
  if (unlikely(ret = mbedtls_pk_parse_key(&ctx, keydata, keylen, NULL, 0, mbedtls_ctr_drbg_random, &psync_mbed_rng.rnd))) {
      debug(D_WARNING, "pk_parse_key failed with code %d", ret);
      return PSYNC_INVALID_RSA;
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
    return PSYNC_INVALID_RSA;
  } else {
    mbedtls_rsa_set_padding(rsa, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA1);
    return rsa;
  }
}

psync_rsa_publickey_t
psync_ssl_rsa_binary_to_public(psync_binary_rsa_key_t bin) {
  return psync_ssl_rsa_load_public(bin->data, bin->datalen);
}

psync_rsa_privatekey_t
psync_ssl_rsa_binary_to_private(psync_binary_rsa_key_t bin) {
  return psync_ssl_rsa_load_private(bin->data, bin->datalen);
}

psync_symmetric_key_t
psync_ssl_gen_symmetric_key_from_pass(const char *password, size_t keylen,
                                      const unsigned char *salt, size_t saltlen,
                                      size_t iterations) {
  psync_symmetric_key_t key = (psync_symmetric_key_t)pmemlock_malloc(
      keylen + offsetof(psync_symmetric_key_struct_t, key));
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

char *psync_ssl_derive_password_from_passphrase(const char *username,
                                                const char *passphrase) {
  unsigned char *usercopy;
  unsigned char usersha512[PSYNC_SHA512_DIGEST_LEN], passwordbin[32];
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
    PSYNC_SHA512_DIGEST_LEN, 5000, sizeof(passwordbin), passwordbin);
  mbedtls_md_free(&ctx);
  usercopy = psync_base64_encode(passwordbin, sizeof(passwordbin), &userlen);
  return (char *)usercopy;
}

psync_encrypted_symmetric_key_t
psync_ssl_rsa_encrypt_data(psync_rsa_publickey_t rsa, const unsigned char *data,
                           size_t datalen) {
  psync_encrypted_symmetric_key_t ret;
  int code;
  size_t rsalen;

  rsalen = mbedtls_rsa_get_len(rsa);
  ret = (psync_encrypted_symmetric_key_t)psync_malloc(
      offsetof(psync_encrypted_data_struct_t, data) + rsalen);
  if ((code = mbedtls_rsa_rsaes_oaep_encrypt(
           rsa, ctr_drbg_random_locked, &psync_mbed_rng,
           NULL, 0, datalen, data, ret->data))) {
    psync_free(ret);
    debug(
        D_WARNING,
        "rsa_rsaes_oaep_encrypt failed with error=%d, datalen=%lu, rsasize=%d",
        code, (unsigned long)datalen, (int)rsalen);
    return PSYNC_INVALID_ENC_SYM_KEY;
  }
  ret->datalen = rsalen;
  debug(D_NOTICE, "datalen=%lu", (unsigned long)ret->datalen);
  return ret;
}

psync_symmetric_key_t psync_ssl_rsa_decrypt_data(psync_rsa_privatekey_t rsa,
                                                 const unsigned char *data,
                                                 size_t datalen) {
  unsigned char buff[2048];
  psync_symmetric_key_t ret;
  size_t len;
  if (mbedtls_rsa_rsaes_oaep_decrypt(rsa, ctr_drbg_random_locked,
                                     &psync_mbed_rng, NULL,
                                     0, &len, data, buff, sizeof(buff)))
    return PSYNC_INVALID_SYM_KEY;
  ret = (psync_symmetric_key_t)pmemlock_malloc(
      offsetof(psync_symmetric_key_struct_t, key) + len);
  ret->keylen = len;
  memcpy(ret->key, buff, len);
  psync_ssl_memclean(buff, len);
  return ret;
}

psync_encrypted_symmetric_key_t
psync_ssl_rsa_encrypt_symmetric_key(psync_rsa_publickey_t rsa,
                                    const psync_symmetric_key_t key) {
  return psync_ssl_rsa_encrypt_data(rsa, key->key, key->keylen);
}

psync_symmetric_key_t psync_ssl_rsa_decrypt_symmetric_key(
    psync_rsa_privatekey_t rsa, const psync_encrypted_symmetric_key_t enckey) {
  return psync_ssl_rsa_decrypt_data(rsa, enckey->data, enckey->datalen);
}

psync_aes256_encoder
psync_ssl_aes256_create_encoder(psync_symmetric_key_t key) {
  mbedtls_aes_context *aes;
  assert(key->keylen >= PSYNC_AES256_KEY_SIZE);
  aes = psync_new(mbedtls_aes_context);
  mbedtls_aes_setkey_enc(aes, key->key, 256);
  return aes;
}

void psync_ssl_aes256_free_encoder(psync_aes256_encoder aes) {
  psync_ssl_memclean(aes, sizeof(mbedtls_aes_context));
  psync_free(aes);
}

psync_aes256_encoder
psync_ssl_aes256_create_decoder(psync_symmetric_key_t key) {
  mbedtls_aes_context *aes;
  assert(key->keylen >= PSYNC_AES256_KEY_SIZE);
  aes = psync_new(mbedtls_aes_context);
  mbedtls_aes_setkey_dec(aes, key->key, 256);
  return aes;
}

void psync_ssl_aes256_free_decoder(psync_aes256_encoder aes) {
  psync_ssl_memclean(aes, sizeof(mbedtls_aes_context));
  psync_free(aes);
}

psync_rsa_signature_t
psync_ssl_rsa_sign_sha256_hash(psync_rsa_privatekey_t rsa,
                               const unsigned char *data) {
  psync_rsa_signature_t ret;
  int padding, hash_id;
  size_t rsalen;

  rsalen = mbedtls_rsa_get_len(rsa);
  ret = (psync_rsa_signature_t)psync_malloc(
      offsetof(psync_symmetric_key_struct_t, key) + rsalen);
  if (!ret)
    return (psync_rsa_signature_t)(void *)PERROR_NO_MEMORY;
  ret->datalen = rsalen;
  padding = mbedtls_rsa_get_padding_mode(rsa);
  hash_id = mbedtls_rsa_get_md_alg(rsa);
  mbedtls_rsa_set_padding(rsa, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256);
  if (mbedtls_rsa_rsassa_pss_sign(rsa, ctr_drbg_random_locked, &psync_mbed_rng,
                                  MBEDTLS_MD_SHA256,
                                  PSYNC_SHA256_DIGEST_LEN, data, ret->data)) {
    free(ret);
    mbedtls_rsa_set_padding(rsa, padding, hash_id);
    return (psync_rsa_signature_t)(void *)PSYNC_CRYPTO_NOT_STARTED;
  }
  mbedtls_rsa_set_padding(rsa, padding, hash_id);
  return ret;
}

#if defined(PSYNC_AES_HW_GCC)

#define SSE2FUNC __attribute__((__target__("sse2")))

#define AESDEC ".byte 0x66,0x0F,0x38,0xDE,"
#define AESDECLAST ".byte 0x66,0x0F,0x38,0xDF,"
#define AESENC ".byte 0x66,0x0F,0x38,0xDC,"
#define AESENCLAST ".byte 0x66,0x0F,0x38,0xDD,"

#define xmm0_xmm1 "0xC8"
#define xmm0_xmm2 "0xD0"
#define xmm0_xmm3 "0xD8"
#define xmm0_xmm4 "0xE0"
#define xmm0_xmm5 "0xE8"
// #define xmm1_xmm0   "0xC1" // unused, may be important later
#define xmm1_xmm2 "0xD1"
#define xmm1_xmm3 "0xD9"
#define xmm1_xmm4 "0xE1"
#define xmm1_xmm5 "0xE9"

SSE2FUNC void psync_aes256_encode_block_hw(psync_aes256_encoder enc,
                                           const unsigned char *src,
                                           unsigned char *dst) {
  mbedtls_aes_crypt_ecb(enc, MBEDTLS_AES_ENCRYPT, src, dst);
}

SSE2FUNC void psync_aes256_decode_block_hw(psync_aes256_decoder enc,
                                           const unsigned char *src,
                                           unsigned char *dst) {
  mbedtls_aes_crypt_ecb(enc, MBEDTLS_AES_DECRYPT, src, dst);
}

SSE2FUNC void psync_aes256_encode_2blocks_consec_hw(psync_aes256_encoder enc,
                                                    const unsigned char *src,
                                                    unsigned char *dst) {
  mbedtls_aes_crypt_ecb(enc, MBEDTLS_AES_ENCRYPT, src, dst);
  mbedtls_aes_crypt_ecb(enc, MBEDTLS_AES_ENCRYPT, src + 16, dst + 16);
}

SSE2FUNC void psync_aes256_decode_2blocks_consec_hw(psync_aes256_decoder enc,
                                                    const unsigned char *src,
                                                    unsigned char *dst) {
    mbedtls_aes_crypt_ecb(enc, MBEDTLS_AES_DECRYPT, src, dst);
    mbedtls_aes_crypt_ecb(enc, MBEDTLS_AES_DECRYPT, src + 16, dst + 16);
}

SSE2FUNC void psync_aes256_decode_4blocks_consec_xor_hw(
    psync_aes256_decoder enc, const unsigned char *src, unsigned char *dst,
    unsigned char *bxor) {
  unsigned char temp[16];
  for (int i = 0; i < 4; i++) {
    mbedtls_aes_crypt_ecb(enc, MBEDTLS_AES_DECRYPT, src + i * 16, temp);
    for (int j = 0; j < 16; j++) {
      dst[i * 16 + j] = temp[j] ^ bxor[i * 16 + j];
    }
  }
}

#elif defined(PSYNC_AES_HW_MSC)

void psync_aes256_encode_block_hw(psync_aes256_encoder enc,
                                  const unsigned char *src,
                                  unsigned char *dst) {
  __m128i r0, r1;
  unsigned char *key;
  unsigned cnt;
  key = (unsigned char *)enc->rk;
  r0 = _mm_loadu_si128((__m128i *)key);
  r1 = _mm_load_si128((__m128i *)src);
  cnt = enc->nr - 1;
  key += 16;
  r1 = _mm_xor_si128(r0, r1);
  r0 = _mm_loadu_si128((__m128i *)key);
  do {
    key += 16;
    r1 = _mm_aesenc_si128(r1, r0);
    r0 = _mm_loadu_si128((__m128i *)key);
  } while (--cnt);
  r1 = _mm_aesenclast_si128(r1, r0);
  _mm_store_si128((__m128i *)dst, r1);
}

void psync_aes256_decode_block_hw(psync_aes256_encoder enc,
                                  const unsigned char *src,
                                  unsigned char *dst) {
  __m128i r0, r1;
  unsigned char *key;
  unsigned cnt;
  key = (unsigned char *)enc->rk;
  r0 = _mm_loadu_si128((__m128i *)key);
  r1 = _mm_load_si128((__m128i *)src);
  cnt = enc->nr - 1;
  key += 16;
  r1 = _mm_xor_si128(r0, r1);
  r0 = _mm_loadu_si128((__m128i *)key);
  do {
    key += 16;
    r1 = _mm_aesdec_si128(r1, r0);
    r0 = _mm_loadu_si128((__m128i *)key);
  } while (--cnt);
  r1 = _mm_aesdeclast_si128(r1, r0);
  _mm_store_si128((__m128i *)dst, r1);
}

void psync_aes256_encode_2blocks_consec_hw(psync_aes256_encoder enc,
                                           const unsigned char *src,
                                           unsigned char *dst) {
  __m128i r0, r1, r2;
  unsigned char *key;
  unsigned cnt;
  key = (unsigned char *)enc->rk;
  r0 = _mm_loadu_si128((__m128i *)key);
  r1 = _mm_load_si128((__m128i *)src);
  r2 = _mm_load_si128((__m128i *)(src + 16));
  cnt = enc->nr - 1;
  key += 16;
  r1 = _mm_xor_si128(r0, r1);
  r2 = _mm_xor_si128(r0, r2);
  r0 = _mm_loadu_si128((__m128i *)key);
  do {
    key += 16;
    r1 = _mm_aesenc_si128(r1, r0);
    r2 = _mm_aesenc_si128(r2, r0);
    r0 = _mm_loadu_si128((__m128i *)key);
  } while (--cnt);
  r1 = _mm_aesenclast_si128(r1, r0);
  r2 = _mm_aesenclast_si128(r2, r0);
  _mm_store_si128((__m128i *)dst, r1);
  _mm_store_si128((__m128i *)(dst + 16), r2);
}

void psync_aes256_decode_2blocks_consec_hw(psync_aes256_decoder enc,
                                           const unsigned char *src,
                                           unsigned char *dst) {
  __m128i r0, r1, r2;
  unsigned char *key;
  unsigned cnt;
  key = (unsigned char *)enc->rk;
  r0 = _mm_loadu_si128((__m128i *)key);
  r1 = _mm_load_si128((__m128i *)src);
  r2 = _mm_load_si128((__m128i *)(src + 16));
  cnt = enc->nr - 1;
  key += 16;
  r1 = _mm_xor_si128(r0, r1);
  r2 = _mm_xor_si128(r0, r2);
  r0 = _mm_loadu_si128((__m128i *)key);
  do {
    key += 16;
    r1 = _mm_aesdec_si128(r1, r0);
    r2 = _mm_aesdec_si128(r2, r0);
    r0 = _mm_loadu_si128((__m128i *)key);
  } while (--cnt);
  r1 = _mm_aesdeclast_si128(r1, r0);
  r2 = _mm_aesdeclast_si128(r2, r0);
  _mm_store_si128((__m128i *)dst, r1);
  _mm_store_si128((__m128i *)(dst + 16), r2);
}

void psync_aes256_decode_4blocks_consec_xor_hw(psync_aes256_decoder enc,
                                               const unsigned char *src,
                                               unsigned char *dst,
                                               unsigned char *bxor) {
  __m128i r0, r1, r2, r3, r4;
  unsigned char *key;
  unsigned cnt;
  key = (unsigned char *)enc->rk;
  r0 = _mm_loadu_si128((__m128i *)key);
  r1 = _mm_load_si128((__m128i *)src);
  r2 = _mm_load_si128((__m128i *)(src + 16));
  r3 = _mm_load_si128((__m128i *)(src + 32));
  r4 = _mm_load_si128((__m128i *)(src + 48));
  cnt = enc->nr - 1;
  key += 16;
  r1 = _mm_xor_si128(r0, r1);
  r2 = _mm_xor_si128(r0, r2);
  r3 = _mm_xor_si128(r0, r3);
  r4 = _mm_xor_si128(r0, r4);
  r0 = _mm_loadu_si128((__m128i *)key);
  do {
    key += 16;
    r1 = _mm_aesdec_si128(r1, r0);
    r2 = _mm_aesdec_si128(r2, r0);
    r3 = _mm_aesdec_si128(r3, r0);
    r4 = _mm_aesdec_si128(r4, r0);
    r0 = _mm_loadu_si128((__m128i *)key);
  } while (--cnt);
  r1 = _mm_aesdeclast_si128(r1, r0);
  r2 = _mm_aesdeclast_si128(r2, r0);
  r3 = _mm_aesdeclast_si128(r3, r0);
  r4 = _mm_aesdeclast_si128(r4, r0);
  r0 = _mm_load_si128((__m128i *)bxor);
  r1 = _mm_xor_si128(r0, r1);
  r0 = _mm_load_si128((__m128i *)(bxor + 16));
  _mm_store_si128((__m128i *)dst, r1);
  r2 = _mm_xor_si128(r0, r2);
  r0 = _mm_load_si128((__m128i *)(bxor + 32));
  _mm_store_si128((__m128i *)(dst + 16), r2);
  r3 = _mm_xor_si128(r0, r3);
  r0 = _mm_load_si128((__m128i *)(bxor + 48));
  _mm_store_si128((__m128i *)(dst + 32), r3);
  r4 = _mm_xor_si128(r0, r4);
  _mm_store_si128((__m128i *)(dst + 48), r4);
}

#endif

#if defined(PSYNC_AES_HW)

void psync_aes256_decode_4blocks_consec_xor_sw(psync_aes256_decoder enc,
                                               const unsigned char *src,
                                               unsigned char *dst,
                                               unsigned char *bxor) {
  unsigned long i;
  mbedtls_aes_crypt_ecb(enc, MBEDTLS_AES_DECRYPT, src, dst);
  mbedtls_aes_crypt_ecb(enc, MBEDTLS_AES_DECRYPT, src + PSYNC_AES256_BLOCK_SIZE,
                        dst + PSYNC_AES256_BLOCK_SIZE);
  mbedtls_aes_crypt_ecb(enc, MBEDTLS_AES_DECRYPT,
                        src + PSYNC_AES256_BLOCK_SIZE * 2,
                        dst + PSYNC_AES256_BLOCK_SIZE * 2);
  mbedtls_aes_crypt_ecb(enc, MBEDTLS_AES_DECRYPT,
                        src + PSYNC_AES256_BLOCK_SIZE * 3,
                        dst + PSYNC_AES256_BLOCK_SIZE * 3);
  for (i = 0; i < PSYNC_AES256_BLOCK_SIZE * 4 / sizeof(unsigned long); i++)
    ((unsigned long *)dst)[i] ^= ((unsigned long *)bxor)[i];
}

#endif
