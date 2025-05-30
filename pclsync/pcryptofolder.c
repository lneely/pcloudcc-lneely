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

#include <pthread.h>
#include <string.h>

#include "papi.h"
#include "pcache.h"
#include "pcryptofolder.h"
#include "pcrypto.h"
#include "pfileops.h"
#include "pfoldersync.h"
#include "pfs.h"
#include "plibs.h"
#include "pnetlibs.h"
#include "psettings.h"
#include "pssl.h"
#include "prun.h"
#include "psys.h"
#include "ptask.h"
#include "psql.h"


#define PSYNC_CRYPTO_API_ERR_INTERNAL -511

static PSYNC_THREAD int crypto_api_errno;
static PSYNC_THREAD char crypto_api_err[128];

static const char *crypto_errors[] = {"Success.",
                                      "Encryption is not started.",
                                      "Unexpected RSA encryption error.",
                                      "Folder not found.",
                                      "Invalid key.",
                                      "Can not connect to server.",
                                      "Folder is not encrypted."};

static uint32_t crypto_started_l = 0;
static psync_rsa_publickey_t crypto_pubkey = PSYNC_INVALID_RSA;
static psync_rsa_privatekey_t crypto_privkey = PSYNC_INVALID_RSA;
static pthread_rwlock_t crypto_lock = PTHREAD_RWLOCK_INITIALIZER;
static uint32_t crypto_started_un = 0;

typedef struct {
  uint32_t type;
  uint32_t flags;
  unsigned char salt[PSYNC_CRYPTO_PBKDF2_SALT_LEN];
  unsigned char key[];
} priv_key_ver1;

typedef struct {
  uint32_t type;
  uint32_t flags;
  unsigned char key[];
} pub_key_ver1;

typedef struct {
  uint32_t type;
  uint32_t flags;
  unsigned char aeskey[PSYNC_AES256_KEY_SIZE];
  unsigned char hmackey[PSYNC_CRYPTO_HMAC_SHA512_KEY_LEN];
} sym_key_ver1;

static void sha1hex(const void *data, size_t len, char *out);

void pcryptofolder_cache_clean() {
  const char *prefixes[] = {"DKEY", "FKEY", "FLDE", "FLDD", "SEEN"};
  pcache_clean_oneof(prefixes, ARRAY_SIZE(prefixes));
}

static inline int is_err(const void *ptr) {
  return (uintptr_t)ptr <= PSYNC_CRYPTO_MAX_ERROR;
}

static inline int to_err(const void *ptr) {
  return -((int)(uintptr_t)ptr);
}

static void save_to_db(
    const unsigned char *rsapriv, size_t rsaprivlen,
    const unsigned char *rsapub, size_t rsapublen, const unsigned char *salt,
    size_t saltlen, size_t iterations, time_t expires, const char *publicsha1,
    const char *privatesha1, uint32_t flags) {
  psync_sql_res *res;
  res = psql_prepare(
      "REPLACE INTO setting (id, value) VALUES (?, ?)");
  psql_start();
  psql_bind_str(res, 1, "cryptosetup");
  psql_bind_uint(res, 2, 1);
  psql_run(res);
  if (expires) {
    psql_bind_str(res, 1, "cryptoexpires");
    psql_bind_uint(res, 2, expires);
    psql_run(res);
  }
  psql_bind_str(res, 1, "crypto_private_key");
  psql_bind_blob(res, 2, (const char *)rsapriv, rsaprivlen);
  psql_run(res);
  psql_bind_str(res, 1, "crypto_public_key");
  psql_bind_blob(res, 2, (const char *)rsapub, rsapublen);
  psql_run(res);
  psql_bind_str(res, 1, "crypto_private_salt");
  psql_bind_blob(res, 2, (const char *)salt, saltlen);
  psql_run(res);
  psql_bind_str(res, 1, "crypto_private_iter");
  psql_bind_uint(res, 2, iterations);
  psql_run(res);
  psql_bind_str(res, 1, "crypto_public_sha1");
  psql_bind_str(res, 2, publicsha1);
  psql_run(res);
  psql_bind_str(res, 1, "crypto_private_sha1");
  psql_bind_str(res, 2, privatesha1);
  psql_run(res);
  psql_bind_str(res, 1, "crypto_private_flags");
  psql_bind_uint(res, 2, flags);
  psql_run_free(res);
  psql_commit();
}

static int setup_do_upload(const unsigned char *rsapriv,
                                              size_t rsaprivlen,
                                              const unsigned char *rsapub,
                                              size_t rsapublen,
                                              const char *hint,
                                              time_t *cryptoexpires) {
  binparam params[] = {PAPI_STR("auth", psync_my_auth),
                       PAPI_LSTR("privatekey", rsapriv, rsaprivlen),
                       PAPI_LSTR("publickey", rsapub, rsapublen),
                       PAPI_STR("hint", hint), PAPI_STR("timeformat", "timestamp")};
  psock_t *api;
  binresult *res;
  uint64_t result;
  int tries;
  tries = 0;
  pdbg_logf(D_NOTICE, "uploading keys");
  while (1) {
    api = psync_apipool_get();
    if (!api)
      return pdbg_return_const(PSYNC_CRYPTO_SETUP_CANT_CONNECT);
    res = papi_send2(api, "crypto_setuserkeys", params);
    if (pdbg_unlikely(!res)) {
      psync_apipool_release_bad(api);
      if (++tries > 5)
        return pdbg_return_const(PSYNC_CRYPTO_SETUP_CANT_CONNECT);
    } else {
      psync_apipool_release(api);
      break;
    }
  }
  result = papi_find_result2(res, "result", PARAM_NUM)->num;
  if (!result)
    *cryptoexpires = papi_find_result2(res, "cryptoexpires", PARAM_NUM)->num;
  free(res);
  if (result != 0)
    pdbg_logf(D_WARNING, "crypto_setuserkeys returned %u", (unsigned)result);
  if (result == 0)
    return PSYNC_CRYPTO_SETUP_SUCCESS;
  psync_process_api_error(result);
  switch (result) {
  case 1000:
    return pdbg_return_const(PSYNC_CRYPTO_SETUP_NOT_LOGGED_IN);
  case 2000:
    return pdbg_return_const(PSYNC_CRYPTO_SETUP_CANT_CONNECT);
  case 2110:
    return pdbg_return_const(PSYNC_CRYPTO_SETUP_ALREADY_SETUP);
  }
  return pdbg_return_const(PSYNC_CRYPTO_SETUP_UNKNOWN_ERROR);
}

static void load_str_to(const psync_variant *v, unsigned char **ptr,
                        size_t *len) {
  const char *str;
  size_t l;
  str = psync_get_lstring(*v, &l);
  *ptr = (unsigned char *)malloc(l);
  memcpy(*ptr, str, l);
  *len = l;
}

static int download_keys(unsigned char **rsapriv, size_t *rsaprivlen, unsigned char **rsapub, size_t *rsapublen, unsigned char **salt, size_t *saltlen, size_t *iterations, char *publicsha1, char *privatesha1, uint32_t *flags) {
  binparam params[] = {PAPI_STR("auth", psync_my_auth)};
  psock_t *api;
  binresult *res;
  const binresult *data;
  unsigned char *rsaprivstruct, *rsapubstruct;
  uint64_t result;
  size_t rsaprivstructlen, rsapubstructlen;
  int tries;
  tries = 0;
  pdbg_logf(D_NOTICE, "dowloading keys");
  while (1) {
    api = psync_apipool_get();
    if (!api)
      return pdbg_return_const(PSYNC_CRYPTO_START_CANT_CONNECT);
    res = papi_send2(api, "crypto_getuserkeys", params);
    if (pdbg_unlikely(!res)) {
      psync_apipool_release_bad(api);
      if (++tries > 5)
        return pdbg_return_const(PSYNC_CRYPTO_START_CANT_CONNECT);
    } else {
      psync_apipool_release(api);
      break;
    }
  }
  result = papi_find_result2(res, "result", PARAM_NUM)->num;
  if (result) {
    free(res);
    psync_process_api_error(result);
    switch (result) {
    case 2111:
      return pdbg_return_const(PSYNC_CRYPTO_START_NOT_SETUP);
    case 2000:
      return pdbg_return_const(PSYNC_CRYPTO_START_CANT_CONNECT);
    case 1000:
      return pdbg_return_const(PSYNC_CRYPTO_START_NOT_LOGGED_IN);
    }
    return pdbg_return_const(PSYNC_CRYPTO_START_UNKNOWN_ERROR);
  }
  data = papi_find_result2(res, "privatekey", PARAM_STR);
  rsaprivstruct = psync_base64_decode((const unsigned char *)data->str,
                                      data->length, &rsaprivstructlen);
  data = papi_find_result2(res, "publickey", PARAM_STR);
  rsapubstruct = psync_base64_decode((const unsigned char *)data->str,
                                     data->length, &rsapubstructlen);
  free(res);
  sha1hex(rsaprivstruct, rsaprivstructlen, privatesha1);
  sha1hex(rsapubstruct, rsapubstructlen, publicsha1);
  pdbg_logf(D_NOTICE, "rsapubstruct=%s", rsapubstruct);
  switch (*((uint32_t *)rsapubstruct)) {
  case PSYNC_CRYPTO_PUB_TYPE_RSA4096:
    if (offsetof(pub_key_ver1, key) >= rsapubstructlen)
      goto def1;
    *rsapublen = rsapubstructlen - offsetof(pub_key_ver1, key);
    *rsapub = (unsigned char *)malloc(*rsapublen);
    memcpy(*rsapub, rsapubstruct + offsetof(pub_key_ver1, key), *rsapublen);
    break;
  default:
  def1:
    putil_wipe(rsaprivstruct, rsaprivstructlen);
    free(rsaprivstruct);
    free(rsapubstruct);
    return pdbg_return_const(PSYNC_CRYPTO_START_UNKNOWN_KEY_FORMAT);
  }
  switch (*((uint32_t *)rsaprivstruct)) {
  case PSYNC_CRYPTO_TYPE_RSA4096_64BYTESALT_20000IT:
    if (offsetof(priv_key_ver1, key) >= rsaprivstructlen)
      goto def2;
    *rsaprivlen = rsaprivstructlen - offsetof(priv_key_ver1, key);
    *rsapriv = (unsigned char *)malloc(*rsaprivlen);
    memcpy(*rsapriv, rsaprivstruct + offsetof(priv_key_ver1, key), *rsaprivlen);
    *saltlen = PSYNC_CRYPTO_PBKDF2_SALT_LEN;
    *salt = (unsigned char *)malloc(PSYNC_CRYPTO_PBKDF2_SALT_LEN);
    memcpy(*salt, rsaprivstruct + offsetof(priv_key_ver1, salt),
           PSYNC_CRYPTO_PBKDF2_SALT_LEN);
    *iterations = PSYNC_CRYPTO_PASS_TO_KEY_ITERATIONS;
    *flags = ((priv_key_ver1 *)rsaprivstruct)->flags;
    break;
  default:
  def2:
    free(*rsapub);
    putil_wipe(rsaprivstruct, rsaprivstructlen);  
    free(rsaprivstruct);
    free(rsapubstruct);
    return pdbg_return_const(PSYNC_CRYPTO_START_UNKNOWN_KEY_FORMAT);
  }
  putil_wipe(rsaprivstruct, rsaprivstructlen);  
  free(rsaprivstruct);
  free(rsapubstruct);
  return PSYNC_CRYPTO_START_SUCCESS;
}

static binresult *psync_get_keys_bin_auth(const char *auth) {
  binparam params[] = {PAPI_STR("auth", auth)};
  psock_t *api;
  binresult *res;
  api = psync_apipool_get();
  if (!api)
    return NULL;
  res = papi_send2(api, "crypto_getuserkeys", params);
  if (pdbg_unlikely(!res)) {
    psync_apipool_release_bad(api);
  } else {
    psync_apipool_release(api);
  }
  return res;
}

static int
setup_upload(const unsigned char *rsapriv, size_t rsaprivlen,
                                const unsigned char *rsapub, size_t rsapublen,
                                const unsigned char *salt, const char *hint,
                                time_t *cryptoexpires, char *publicsha1,
                                char *privatesha1) {
  priv_key_ver1 *priv;
  pub_key_ver1 *pub;
  unsigned char *b64priv, *b64pub;
  size_t b64privlen, b64publen;
  int ret;
  *cryptoexpires = 0;
  priv =
      (priv_key_ver1 *)malloc(offsetof(priv_key_ver1, key) + rsaprivlen);
  priv->type = PSYNC_CRYPTO_TYPE_RSA4096_64BYTESALT_20000IT;
  priv->flags = 0;
  memcpy(priv->salt, salt, PSYNC_CRYPTO_PBKDF2_SALT_LEN);
  memcpy(priv->key, rsapriv, rsaprivlen);
  pub = (pub_key_ver1 *)malloc(offsetof(pub_key_ver1, key) + rsapublen);
  pub->type = PSYNC_CRYPTO_PUB_TYPE_RSA4096;
  pub->flags = 0;
  memcpy(pub->key, rsapub, rsapublen);
  sha1hex(priv, offsetof(priv_key_ver1, key) + rsaprivlen,
                     privatesha1);
  sha1hex(pub, offsetof(pub_key_ver1, key) + rsapublen, publicsha1);
  b64priv = psync_base64_encode((unsigned char *)priv,
                                offsetof(priv_key_ver1, key) + rsaprivlen,
                                &b64privlen);
  b64pub =
      psync_base64_encode((unsigned char *)pub,
                          offsetof(pub_key_ver1, key) + rsapublen, &b64publen);
  free(priv);
  free(pub);
  ret = setup_do_upload(b64priv, b64privlen, b64pub,
                                           b64publen, hint, cryptoexpires);
  free(b64priv);
  free(b64pub);
  return ret;
}

int pcryptofolder_issetup() {
  return psql_cellint("SELECT value FROM setting WHERE id='cryptosetup'", 0);
}


/*
 * generate 64 byte (512 bit) salt for PBKDF2
 * generate AES key and IV with PBKDF2
 * create RSA key and encrypt private part using CTR mode
 * upload to server salt, encrypted private and public
 *
 */
int pcryptofolder_setup(const char *password, const char *hint) {
  unsigned char salt[PSYNC_CRYPTO_PBKDF2_SALT_LEN];
  char publicsha1[PSYNC_SHA1_DIGEST_HEXLEN + 2],
      privatesha1[PSYNC_SHA1_DIGEST_HEXLEN + 2];
  psync_symmetric_key_t aeskey;
  pcrypto_ctr_encdec_t enc;
  psync_rsa_t rsa;
  psync_rsa_privatekey_t rsaprivate;
  psync_rsa_publickey_t rsapublic;
  psync_binary_rsa_key_t rsaprivatebin, rsapublicbin;
  time_t cryptoexpires;
  int ret;
  pdbg_logf(D_NOTICE, "generating salt");
  pssl_rand_strong(salt, PSYNC_CRYPTO_PBKDF2_SALT_LEN);
  pdbg_logf(D_NOTICE, "generating AES key from password and setting up encoder");
  aeskey = psymkey_generate(
      password, PSYNC_AES256_KEY_SIZE + PSYNC_AES256_BLOCK_SIZE, salt,
      PSYNC_CRYPTO_PBKDF2_SALT_LEN, PSYNC_CRYPTO_PASS_TO_KEY_ITERATIONS);
  enc = pcrypto_ctr_encdec_create(aeskey);
  psymkey_free(aeskey);
  if (unlikely(enc == PSYNC_CRYPTO_INVALID_ENCODER)) {
    pdbg_logf(D_WARNING, "psync_crypto_aes256_ctr_encoder_decoder_create failed");
    return PSYNC_CRYPTO_SETUP_KEYGEN_FAILED;
  }
  pdbg_logf(D_NOTICE, "generating %d bit RSA key", (int)PSYNC_CRYPTO_RSA_SIZE);
  rsa = pssl_gen_rsa(PSYNC_CRYPTO_RSA_SIZE);
  if (unlikely(rsa == PSYNC_INVALID_RSA)) {
    pdbg_logf(D_WARNING, "RSA key generation failed");
    pcrypto_ctr_encdec_free(enc);
    return PSYNC_CRYPTO_SETUP_KEYGEN_FAILED;
  } else
    pdbg_logf(D_NOTICE, "RSA key generated");
  rsaprivate = prsa_get_private(rsa);
  rsapublic = prsa_get_public(rsa);
  pssl_free_rsa(rsa);
  if (unlikely(rsaprivate == PSYNC_INVALID_RSA ||
               rsapublic == PSYNC_INVALID_RSA)) {
    pdbg_logf(D_WARNING,
          "psync_ssl_rsa_get_private or psync_ssl_rsa_get_public failed");
    if (rsaprivate != PSYNC_INVALID_RSA)
      prsa_free_private(rsaprivate);
    if (rsapublic != PSYNC_INVALID_RSA)
      prsa_free_public(rsapublic);
    pcrypto_ctr_encdec_free(enc);
    return PSYNC_CRYPTO_SETUP_KEYGEN_FAILED;
  }
  rsaprivatebin = prsa_private_to_binary(rsaprivate);
  rsapublicbin = prsa_public_to_binary(rsapublic);
  prsa_free_private(rsaprivate);
  prsa_free_public(rsapublic);
  if (unlikely(rsaprivatebin == PSYNC_INVALID_BIN_RSA ||
               rsapublic == PSYNC_INVALID_BIN_RSA)) {
    pdbg_logf(D_WARNING, "psync_ssl_rsa_private_to_binary or "
                     "psync_ssl_rsa_public_to_binary failed");
    if (rsaprivatebin != PSYNC_INVALID_BIN_RSA)
      prsa_free_binary(rsaprivatebin);
    if (rsapublicbin != PSYNC_INVALID_BIN_RSA)
      prsa_free_binary(rsapublicbin);
    pcrypto_ctr_encdec_free(enc);
    return PSYNC_CRYPTO_SETUP_KEYGEN_FAILED;
  }
  pdbg_logf(D_NOTICE, "encoding private key");
  pcrypto_ctr_encdec_decode(enc, rsaprivatebin->data,
                                                rsaprivatebin->datalen, 0);
  pcrypto_ctr_encdec_free(enc);
  pdbg_logf(D_NOTICE, "encoded private key, uploading keys");
  ret = setup_upload(
      rsaprivatebin->data, rsaprivatebin->datalen, rsapublicbin->data,
      rsapublicbin->datalen, salt, hint, &cryptoexpires, publicsha1,
      privatesha1);
  if (unlikely(ret != PSYNC_CRYPTO_SETUP_SUCCESS)) {
    pdbg_logf(D_WARNING, "keys upload failed with error %d", ret);
    prsa_free_binary(rsaprivatebin);
    prsa_free_binary(rsapublicbin);
    return ret;
  }
  pdbg_logf(D_NOTICE, "keys uploaded");
  save_to_db(
      rsaprivatebin->data, rsaprivatebin->datalen, rsapublicbin->data,
      rsapublicbin->datalen, salt, PSYNC_CRYPTO_PBKDF2_SALT_LEN,
      PSYNC_CRYPTO_PASS_TO_KEY_ITERATIONS, cryptoexpires, publicsha1,
      privatesha1, 0);
  prsa_free_binary(rsaprivatebin);
  prsa_free_binary(rsapublicbin);
  return PSYNC_CRYPTO_SETUP_SUCCESS;
}

int pcryptofolder_get_hint(char **hint) {
  binparam params[] = {PAPI_STR("auth", psync_my_auth)};
  psock_t *api;
  binresult *res;
  uint64_t result;
  int tries;
  tries = 0;
  pdbg_logf(D_NOTICE, "dowloading hint");
  while (1) {
    api = psync_apipool_get();
    if (!api)
      return pdbg_return_const(PSYNC_CRYPTO_HINT_CANT_CONNECT);
    res = papi_send2(api, "crypto_getuserhint", params);
    if (pdbg_unlikely(!res)) {
      psync_apipool_release_bad(api);
      if (++tries > 5)
        return pdbg_return_const(PSYNC_CRYPTO_HINT_CANT_CONNECT);
    } else {
      psync_apipool_release(api);
      break;
    }
  }
  result = papi_find_result2(res, "result", PARAM_NUM)->num;
  if (result) {
    free(res);
    psync_process_api_error(result);
    switch (result) {
    case 2122:
      return pdbg_return_const(PSYNC_CRYPTO_HINT_NOT_PROVIDED);
    case 2000:
      return pdbg_return_const(PSYNC_CRYPTO_HINT_CANT_CONNECT);
    case 1000:
      return pdbg_return_const(PSYNC_CRYPTO_HINT_NOT_LOGGED_IN);
    }
    return pdbg_return_const(PSYNC_CRYPTO_HINT_UNKNOWN_ERROR);
  }
  *hint = psync_strdup(papi_find_result2(res, "hint", PARAM_STR)->str);
  free(res);
  return PSYNC_CRYPTO_HINT_SUCCESS;
}

static int crypto_keys_match() {
  psync_symmetric_key_t key, deckey;
  psync_encrypted_symmetric_key_t enckey;
  int res;
  pdbg_logf(D_NOTICE, "trying encrypt/decrypt operation with loaded keys");
  key = (psync_symmetric_key_t)malloc(
      offsetof(psync_symmetric_key_struct_t, key) + 64);
  key->keylen = 64;
  pssl_rand_strong(key->key, key->keylen);
  enckey = psymkey_encrypt(crypto_pubkey, key);
  if (enckey == PSYNC_INVALID_ENC_SYM_KEY) {
    free(key);
    return 0;
  }

  deckey = prsa_decrypt_symm_key_lock(&crypto_privkey, &enckey);

  free(enckey);
  if (deckey == PSYNC_INVALID_SYM_KEY) {
    free(key);
    return 0;
  }
  res = key->keylen == deckey->keylen &&
        !memcmp(key->key, deckey->key, key->keylen);
  psymkey_free(deckey);
  free(key);
  if (res)
    pdbg_logf(D_NOTICE, "encrypt/decrypt operation succeeded");
  return res;
}

int pcryptofolder_unlock(const char *password) {
  char publicsha1[PSYNC_SHA1_DIGEST_HEXLEN + 2],
      privatesha1[PSYNC_SHA1_DIGEST_HEXLEN + 2];
  psync_sql_res *res;
  psync_variant_row row;
  const char *id;
  unsigned char *rsapriv, *rsaprivdec, *rsapub, *salt;
  size_t iterations, rsaprivlen, rsapublen, saltlen;
  psync_symmetric_key_t aeskey;
  pcrypto_ctr_encdec_t enc;
  uint32_t rowcnt, flags;
  int ret;
  flags = 0;
  rsaprivlen = 0;
  rsapublen = 0;
  saltlen = 0;

  /*
   * Read locks of crypto_lock are taken both before and after taking sql_lock.
   * While read locks are concurrent and can not lead to deadlock it is possible
   * to have some thread to hold sql_lock and wait for read lock. This will
   * normally deadlock with us holding writelock and waiting for sql_lock.
   * Therefore we use sql_trylock here.
   */
  while (1) {
    pthread_rwlock_wrlock(&crypto_lock);
    if (crypto_started_l) {
      pthread_rwlock_unlock(&crypto_lock);
      return pdbg_return_const(PSYNC_CRYPTO_START_ALREADY_STARTED);
    }
    rowcnt = 0;
    rsapriv = rsapub = salt = NULL;
    iterations = 0;
    if (psql_trylock()) {
      pthread_rwlock_unlock(&crypto_lock);
      psys_sleep_milliseconds(1);
      continue;
    }
    break;
  }
  res = psql_query_nolock(
      "SELECT id, value FROM setting WHERE id IN ('crypto_private_key', "
      "'crypto_public_key', 'crypto_private_salt', 'crypto_private_iter')");
  while ((row = psql_fetch(res))) {
    id = psync_get_string(row[0]);
    rowcnt++;
    if (!strcmp(id, "crypto_private_key"))
      load_str_to(&row[1], &rsapriv, &rsaprivlen);
    else if (!strcmp(id, "crypto_public_key"))
      load_str_to(&row[1], &rsapub, &rsapublen);
    else if (!strcmp(id, "crypto_private_salt"))
      load_str_to(&row[1], &salt, &saltlen);
    else {
      pdbg_assert(!strcmp(id, "crypto_private_iter"));
      iterations = atoi(psync_get_string(row[1]));
    }
  }
  psql_free(res);
  psql_unlock();
  if (rowcnt < 4) {
    if (unlikely(rowcnt != 0)) {
      pdbg_logf(D_BUG,
            "only some of records found in the database, should not happen");
      putil_wipe(rsapriv, rsaprivlen);  
      free(rsapriv);
      free(rsapub);
      free(salt);
    }
    ret = download_keys(
        &rsapriv, &rsaprivlen, &rsapub, &rsapublen, &salt, &saltlen,
        &iterations, publicsha1, privatesha1, &flags);
    if (ret != PSYNC_CRYPTO_START_SUCCESS) {
      pthread_rwlock_unlock(&crypto_lock);
      pdbg_logf(D_WARNING, "downloading key failed, error %d", ret);
      return ret;
    } else
      pdbg_logf(D_NOTICE, "dowloaded keys");
  } else {
    pdbg_logf(D_NOTICE, "got keys from the database");
    pdbg_assert(rowcnt == 4);
  }

  pdbg_logf(D_NOTICE, "trying to load public key");
  crypto_pubkey = prsa_load_public(rsapub, rsapublen);
  if (crypto_pubkey == PSYNC_INVALID_RSA) {
    pthread_rwlock_unlock(&crypto_lock);
    pdbg_logf(D_WARNING, "could not load public key");
    putil_wipe(rsapriv, rsaprivlen);    
    free(rsapriv);
    free(rsapub);
    putil_wipe(salt, saltlen);  
    free(salt);
    return pdbg_return_const(PSYNC_CRYPTO_START_UNKNOWN_KEY_FORMAT);
  }
  pdbg_logf(D_NOTICE, "successfully loaded public key");

  pdbg_logf(D_NOTICE, "generating symmetric key");
  aeskey = psymkey_generate(password, PSYNC_AES256_KEY_SIZE + PSYNC_AES256_BLOCK_SIZE, salt, saltlen, iterations);
  enc = pcrypto_ctr_encdec_create(aeskey);
  psymkey_free(aeskey);
  rsaprivdec = (unsigned char *)malloc(rsaprivlen);
  memcpy(rsaprivdec, rsapriv, rsaprivlen);
  pcrypto_ctr_encdec_decode(enc, rsaprivdec, rsaprivlen, 0);
  pcrypto_ctr_encdec_free(enc);
  pdbg_logf(D_NOTICE, "successfully generated symmetric key");


  pdbg_logf(D_NOTICE, "trying to load private key");
  crypto_privkey = prsa_load_private(rsaprivdec, rsaprivlen);
  putil_wipe(rsaprivdec, rsaprivlen);
  free(rsaprivdec);
  if (crypto_privkey == PSYNC_INVALID_RSA) {
    pdbg_logf(D_NOTICE, "failed to load private key");
    prsa_free_public(crypto_pubkey);
    crypto_pubkey = PSYNC_INVALID_RSA;
    pthread_rwlock_unlock(&crypto_lock);
    putil_wipe(rsapriv, rsaprivlen);
    free(rsapriv);
    free(rsapub);
    putil_wipe(salt, saltlen);
    free(salt);
    return pdbg_return_const(PSYNC_CRYPTO_START_BAD_PASSWORD);
  }
  pdbg_logf(D_NOTICE, "successfully loaded private key");

  pdbg_logf(D_NOTICE, "verify matching public and private key");
  if (!crypto_keys_match()) {
    prsa_free_public(crypto_pubkey);
    crypto_pubkey = PSYNC_INVALID_RSA;
    prsa_free_private(crypto_privkey);
    crypto_privkey = PSYNC_INVALID_RSA;
    pthread_rwlock_unlock(&crypto_lock);
    pdbg_logf(D_ERROR, "keys don't match");
    putil_wipe(rsapriv, rsaprivlen);
    free(rsapriv);
    free(rsapub);
    putil_wipe(salt, saltlen);
    free(salt);
    return pdbg_return_const(PSYNC_CRYPTO_START_KEYS_DONT_MATCH);
  }
  pdbg_logf(D_NOTICE, "public and private keys match, setting crypto started");

  crypto_started_l = 1;
  crypto_started_un = 1;
  pthread_rwlock_unlock(&crypto_lock);
  if (rowcnt < 4) {
    pdbg_logf(D_NOTICE, "saving crypto setup to database");
    save_to_db(rsapriv, rsaprivlen, rsapub, rsapublen,
                                        salt, saltlen, iterations, 0,
                                        publicsha1, privatesha1, flags);
  }
  putil_wipe(rsapriv, rsaprivlen);  
  free(rsapriv);
  free(rsapub);
  putil_wipe(salt, saltlen);
  free(salt);
  pdbg_logf(D_NOTICE, "crypto successfully started");
  return PSYNC_CRYPTO_START_SUCCESS;
}

static void psync_fs_refresh_crypto_folders() {
  psync_folderid_t *fids, *fid;
  fids = psync_crypto_folderids();
  fid = fids;
  while (*fid != PSYNC_CRYPTO_INVALID_FOLDERID) {
    psync_fs_refresh_folder(*fid);
    fid++;
  }
  free(fids);
}

int pcryptofolder_lock() {
  crypto_started_un = 0;
  pthread_rwlock_wrlock(&crypto_lock);
  if (!crypto_started_l) {
    pthread_rwlock_unlock(&crypto_lock);
    return pdbg_return_const(PSYNC_CRYPTO_STOP_NOT_STARTED);
  }
  crypto_started_l = 0;
  prsa_free_public(crypto_pubkey);
  crypto_pubkey = PSYNC_INVALID_RSA;
  prsa_free_private(crypto_privkey);
  crypto_privkey = PSYNC_INVALID_RSA;
  pthread_rwlock_unlock(&crypto_lock);
  pdbg_logf(D_NOTICE, "stopped crypto");
  pcryptofolder_cache_clean();
  psync_fs_refresh_crypto_folders();
  return PSYNC_CRYPTO_STOP_SUCCESS;
}

int pcryptofolder_is_unlocked() {
  int ret;
  pthread_rwlock_rdlock(&crypto_lock);
  ret = crypto_started_l;
  pthread_rwlock_unlock(&crypto_lock);
  return ret;
}

int pcryptofolder_reset() {
  binparam params[] = {PAPI_STR("auth", psync_my_auth)};
  psock_t *api;
  binresult *res;
  uint32_t result;
  int tries;
  if (!pcryptofolder_issetup())
    return pdbg_return_const(PSYNC_CRYPTO_RESET_NOT_SETUP);
  pdbg_logf(D_NOTICE, "resetting crypto");
  tries = 0;
  while (1) {
    api = psync_apipool_get();
    if (!api)
      return pdbg_return_const(PSYNC_CRYPTO_RESET_CANT_CONNECT);
    res = papi_send2(api, "crypto_reset", params);
    if (pdbg_unlikely(!res)) {
      psync_apipool_release_bad(api);
      if (++tries > 5)
        return pdbg_return_const(PSYNC_CRYPTO_RESET_CANT_CONNECT);
    } else {
      psync_apipool_release(api);
      break;
    }
  }
  result = papi_find_result2(res, "result", PARAM_NUM)->num;
  free(res);
  if (result)
    pdbg_logf(D_WARNING, "crypto_reset returned error %u", (unsigned)result);
  if (result == 0)
    return pdbg_return_const(PSYNC_CRYPTO_RESET_SUCCESS);
  psync_process_api_error(result);
  switch (result) {
  case 2000:
    return pdbg_return_const(PSYNC_CRYPTO_RESET_NOT_LOGGED_IN);
  case 2111:
    return pdbg_return_const(PSYNC_CRYPTO_RESET_NOT_SETUP);
  default:
    return pdbg_return_const(PSYNC_CRYPTO_RESET_UNKNOWN_ERROR);
  }
}

static void sha1hex(const void *data, size_t len, char *out) {
  unsigned char sha1bin[PSYNC_SHA1_DIGEST_LEN + 1];
  psync_sha1((const unsigned char *)data, len, (unsigned char *)sha1bin);
  psync_binhex(out, sha1bin, PSYNC_SHA1_DIGEST_LEN);
  out[PSYNC_SHA1_DIGEST_HEXLEN] = 0; // add null terminator
}

static void *errptr(int err) { 
  return (void *)(uintptr_t)(-err); 
}

static void set_crypto_err_msg(const binresult *res) {
  const binresult *msg;
  size_t l;
  msg = papi_find_result2(res, "error", PARAM_STR);
  l = msg->length + 1;
  if (l >= sizeof(crypto_api_err))
    l = sizeof(crypto_api_err) - 1;
  memcpy(crypto_api_err, msg->str, l);
}

static void save_folder_key(psync_folderid_t folderid,
                                  psync_encrypted_symmetric_key_t enckey) {
  // we are likely holding (few) read locks on the database, so executing here
  // will deadlock
  insert_folder_key_task *t;
  t = malloc(sizeof(insert_folder_key_task));
  t->key = psymkey_copy_encrypted(enckey);
  t->id = folderid;
  prun_thread1("save folder key to db task", ptask_cfldr_save_fldrkey, t);
}

static void save_file_key_to_db(psync_fileid_t fileid, uint64_t hash,
                                psync_encrypted_symmetric_key_t enckey) {
  insert_file_key_task *t;
  t = malloc(sizeof(insert_file_key_task));
  t->key = psymkey_copy_encrypted(enckey);
  t->id = fileid;
  t->hash = hash;
  prun_thread1("save file key to db task", ptask_cfldr_save_filekey, t);
}

static psync_encrypted_symmetric_key_t download_fldr_enckey(psync_folderid_t folderid) {
  binparam params[] = {PAPI_STR("auth", psync_my_auth),
                       PAPI_NUM("folderid", folderid)};
  psock_t *api;
  binresult *res;
  const binresult *b64key;
  uint64_t result;
  unsigned char *key;
  psync_encrypted_symmetric_key_t ret;
  size_t keylen;
  int tries;
  tries = 0;
  pdbg_logf(D_NOTICE, "downloading key for folder %lu", (unsigned long)folderid);
  while (1) {
    api = psync_apipool_get();
    if (!api)
      return (psync_encrypted_symmetric_key_t)errptr(
          pdbg_return_const(PSYNC_CRYPTO_CANT_CONNECT));
    res = papi_send2(api, "crypto_getfolderkey", params);
    if (pdbg_unlikely(!res)) {
      psync_apipool_release_bad(api);
      if (++tries > 5)
        return (psync_encrypted_symmetric_key_t)errptr(
            pdbg_return_const(PSYNC_CRYPTO_CANT_CONNECT));
    } else {
      psync_apipool_release(api);
      break;
    }
  }
  result = papi_find_result2(res, "result", PARAM_NUM)->num;
  if (result) {
    pdbg_logf(D_NOTICE, "got error %lu from crypto_getfolderkey",
          (unsigned long)result);
    crypto_api_errno = result;
    set_crypto_err_msg(res);
    free(res);
    psync_process_api_error(result);
    return (psync_encrypted_symmetric_key_t)errptr(
        pdbg_return_const(PSYNC_CRYPTO_API_ERR_INTERNAL));
  }
  b64key = papi_find_result2(res, "key", PARAM_STR);
  key = psync_base64_decode((const unsigned char *)b64key->str, b64key->length,
                            &keylen);
  free(res);
  if (!key)
    return (psync_encrypted_symmetric_key_t)errptr(
        pdbg_return_const(PSYNC_CRYPTO_INVALID_KEY));
  ret = psymkey_alloc_encrypted(keylen);
  memcpy(ret->data, key, keylen);
  free(key);
  save_folder_key(folderid, ret);
  return ret;
}

static psync_encrypted_symmetric_key_t download_file_enckey(psync_fileid_t fileid) {
  binparam params[] = {PAPI_STR("auth", psync_my_auth), PAPI_NUM("fileid", fileid)};
  psock_t *api;
  binresult *res;
  const binresult *b64key;
  uint64_t result;
  unsigned char *key;
  psync_encrypted_symmetric_key_t ret;
  size_t keylen;
  int tries;
  tries = 0;
  pdbg_logf(D_NOTICE, "downloading key for file %lu", (unsigned long)fileid);
  while (1) {
    api = psync_apipool_get();
    if (!api)
      return (psync_encrypted_symmetric_key_t)errptr(
          pdbg_return_const(PSYNC_CRYPTO_CANT_CONNECT));
    res = papi_send2(api, "crypto_getfilekey", params);
    if (pdbg_unlikely(!res)) {
      psync_apipool_release_bad(api);
      if (++tries > 5)
        return (psync_encrypted_symmetric_key_t)errptr(
            pdbg_return_const(PSYNC_CRYPTO_CANT_CONNECT));
    } else {
      psync_apipool_release(api);
      break;
    }
  }
  result = papi_find_result2(res, "result", PARAM_NUM)->num;
  if (result) {
    pdbg_logf(D_NOTICE, "got error %lu from crypto_getfilekey",
          (unsigned long)result);
    crypto_api_errno = result;
    set_crypto_err_msg(res);
    free(res);
    return (psync_encrypted_symmetric_key_t)errptr(
        pdbg_return_const(PSYNC_CRYPTO_API_ERR_INTERNAL));
  }
  result = papi_find_result2(res, "hash", PARAM_NUM)->num;
  b64key = papi_find_result2(res, "key", PARAM_STR);
  key = psync_base64_decode((const unsigned char *)b64key->str, b64key->length,
                            &keylen);
  free(res);
  if (!key)
    return (psync_encrypted_symmetric_key_t)errptr(
        pdbg_return_const(PSYNC_CRYPTO_INVALID_KEY));
  ret = psymkey_alloc_encrypted(keylen);
  memcpy(ret->data, key, keylen);
  free(key);
  save_file_key_to_db(fileid, result, ret);
  return ret;
}

static psync_encrypted_symmetric_key_t get_fldr_enckey(psync_folderid_t folderid) {
  psync_encrypted_symmetric_key_t enckey;
  psync_sql_res *res;
  psync_variant_row row;
  const char *ckey;
  size_t ckeylen;
  res = psql_query_rdlock(
      "SELECT enckey FROM cryptofolderkey WHERE folderid=?");
  psql_bind_uint(res, 1, folderid);
  if ((row = psql_fetch(res))) {
    ckey = psync_get_lstring(row[0], &ckeylen);
    enckey = psymkey_alloc_encrypted(ckeylen);
    memcpy(enckey->data, ckey, ckeylen);
    psql_free(res);
    return enckey;
  }
  psql_free(res);
  return download_fldr_enckey(folderid);
}

static psync_encrypted_symmetric_key_t get_file_enckey(psync_fileid_t fileid, uint64_t hash,
                              int nonetwork) {
  psync_encrypted_symmetric_key_t enckey;
  psync_sql_res *res;
  psync_variant_row row;
  const char *ckey;
  size_t ckeylen;
  res = psql_query_rdlock(
      "SELECT enckey FROM cryptofilekey WHERE fileid=? AND hash=?");
  psql_bind_uint(res, 1, fileid);
  psql_bind_uint(res, 2, hash);
  if ((row = psql_fetch(res))) {
    ckey = psync_get_lstring(row[0], &ckeylen);
    enckey = psymkey_alloc_encrypted(ckeylen);
    memcpy(enckey->data, ckey, ckeylen);
    psql_free(res);
    return enckey;
  }
  psql_free(res);
  if (nonetwork) {
    pdbg_logf(D_NOTICE, "delaying key download for file %lu",
          (unsigned long)fileid);
    return (
        psync_encrypted_symmetric_key_t)PSYNC_CRYPTO_UNLOADED_SECTOR_ENCODER;
  } else
    return download_file_enckey(fileid);
}

static psync_symmetric_key_t get_fldr_symkey_safe(psync_folderid_t folderid) {
  char buff[16];
  psync_encrypted_symmetric_key_t enckey;
  psync_symmetric_key_t symkey;
  psync_get_string_id(buff, "FKEY", folderid);
  symkey = (psync_symmetric_key_t)pcache_get(buff);
  if (symkey)
    return symkey;
  enckey = get_fldr_enckey(folderid);
  if (is_err(enckey))
    return (psync_symmetric_key_t)enckey;

  symkey = prsa_decrypt_symm_key_lock(&crypto_privkey, &enckey);

  free(enckey);
  if (symkey == PSYNC_INVALID_SYM_KEY)
    return (psync_symmetric_key_t)errptr(
        pdbg_return_const(PSYNC_CRYPTO_INVALID_KEY));
  return symkey;
}

static psync_symmetric_key_t get_file_symkey_safe(psync_fileid_t fileid, uint64_t hash,
                                    int nonetwork) {
  char buff[32];
  psync_encrypted_symmetric_key_t enckey;
  psync_symmetric_key_t symkey;
  psync_get_string_id2(buff, "DKEY", fileid, hash);
  symkey = (psync_symmetric_key_t)pcache_get(buff);
  if (symkey) {
    pdbg_logf(D_NOTICE, "got key for file %lu from cache", (unsigned long)fileid);
    return symkey;
  }
  enckey = get_file_enckey(fileid, hash, nonetwork);
  if (pdbg_unlikely(is_err(enckey)))
    return (psync_symmetric_key_t)enckey;
  if (nonetwork &&
      enckey ==
          (psync_encrypted_symmetric_key_t)PSYNC_CRYPTO_UNLOADED_SECTOR_ENCODER)
    return (psync_symmetric_key_t)PSYNC_CRYPTO_UNLOADED_SECTOR_ENCODER;

  symkey = prsa_decrypt_symm_key_lock(&crypto_privkey, &enckey);

  free(enckey);
  if (pdbg_unlikely(symkey == PSYNC_INVALID_SYM_KEY))
    return (psync_symmetric_key_t)errptr(
        pdbg_return_const(PSYNC_CRYPTO_INVALID_KEY));
  return symkey;
}

static void free_symkey(void *ptr) {
  psymkey_free((psync_symmetric_key_t)ptr);
}

static void
psync_crypto_release_folder_symkey_locked(psync_folderid_t folderid,
                                          psync_symmetric_key_t key) {
  char buff[16];
  psync_get_string_id(buff, "FKEY", folderid);
  pcache_add(buff, key, PSYNC_CRYPTO_CACHE_DIR_SYM_KEY,
                  free_symkey, 2);
}

static void psync_crypto_release_file_symkey_locked(psync_fileid_t fileid,
                                                    uint64_t hash,
                                                    psync_symmetric_key_t key) {
  char buff[32];
  psync_get_string_id2(buff, "DKEY", fileid, hash);
  pcache_add(buff, key, PSYNC_CRYPTO_CACHE_FILE_SYM_KEY,
                  free_symkey, 2);
}

static psync_symmetric_key_t symkeyv1_to_symkey(sym_key_ver1 *v1) {
  psync_symmetric_key_t key;
  key = (psync_symmetric_key_t)malloc(
      offsetof(psync_symmetric_key_struct_t, key) + PSYNC_AES256_KEY_SIZE +
      PSYNC_CRYPTO_HMAC_SHA512_KEY_LEN);
  key->keylen = PSYNC_AES256_KEY_SIZE + PSYNC_CRYPTO_HMAC_SHA512_KEY_LEN;
  memcpy(key->key, v1->aeskey, PSYNC_AES256_KEY_SIZE);
  memcpy(key->key + PSYNC_AES256_KEY_SIZE, v1->hmackey,
         PSYNC_CRYPTO_HMAC_SHA512_KEY_LEN);
  return key;
}

static pcrypto_textenc_t get_fldr_encoder(psync_folderid_t folderid) {
  pcrypto_textenc_t enc;
  psync_symmetric_key_t symkey, realkey;
  sym_key_ver1 *skv1;
  symkey = get_fldr_symkey_safe(folderid);
  if (is_err(symkey))
    return (pcrypto_textenc_t)symkey;
  skv1 = (sym_key_ver1 *)symkey->key;
  switch (skv1->type) {
  case PSYNC_CRYPTO_SYM_AES256_1024BIT_HMAC:
    if (symkey->keylen != sizeof(sym_key_ver1)) {
      pdbg_logf(D_WARNING, "bad size of decrypted key, expected %lu got %lu",
            (unsigned long)sizeof(sym_key_ver1), (unsigned long)symkey->keylen);
      goto def1;
    }
    if ((skv1->flags & PSYNC_CRYPTO_SYM_FLAG_ISDIR) == 0) {
      pdbg_logf(D_WARNING,
            "file key found when folder key was expected for folderid %lu",
            (unsigned long)folderid);
      goto def1;
    }
    realkey = symkeyv1_to_symkey(skv1);
    psync_crypto_release_folder_symkey_locked(folderid, symkey);
    enc = pcrypto_textenc_create(realkey);
    psymkey_free(realkey);
    return enc;
  default:
    pdbg_logf(D_WARNING, "unkown key type %u", (unsigned)skv1->type);
  def1:
    psymkey_free(symkey);
    return (pcrypto_textenc_t)errptr(
        pdbg_return_const(PSYNC_CRYPTO_INVALID_KEY));
  }
}

static pcrypto_textenc_t get_fldr_encoder_cache(psync_folderid_t folderid) {
  char buff[16];
  pcrypto_textenc_t enc;
  psync_get_string_id(buff, "FLDE", folderid);
  enc = (pcrypto_textenc_t)pcache_get(buff);
  if (enc)
    return enc;
  else
    return get_fldr_encoder(folderid);
}

static pcrypto_textdec_t get_fldrdecoder_safe(psync_folderid_t folderid) {
  pcrypto_textdec_t dec;
  psync_symmetric_key_t symkey, realkey;
  sym_key_ver1 *skv1;
  symkey = get_fldr_symkey_safe(folderid);
  if (is_err(symkey))
    return (pcrypto_textenc_t)symkey;
  skv1 = (sym_key_ver1 *)symkey->key;
  switch (skv1->type) {
  case PSYNC_CRYPTO_SYM_AES256_1024BIT_HMAC:
    if (symkey->keylen != sizeof(sym_key_ver1)) {
      pdbg_logf(D_WARNING, "bad size of decrypted key, expected %lu got %lu",
            (unsigned long)sizeof(sym_key_ver1), (unsigned long)symkey->keylen);
      goto def1;
    }
    realkey = symkeyv1_to_symkey(skv1);
    psync_crypto_release_folder_symkey_locked(folderid, symkey);
    dec = pcrypto_textdec_create(realkey);
    psymkey_free(realkey);
    return dec;
  default:
    pdbg_logf(D_WARNING, "unkown key type %u", (unsigned)skv1->type);
  def1:
    psymkey_free(symkey);
    return (pcrypto_textdec_t)errptr(
        pdbg_return_const(PSYNC_CRYPTO_INVALID_KEY));
  }
}

static pcrypto_textenc_t get_tmp_fldrencoder_safe(psync_fsfolderid_t folderid) {
  pcrypto_textenc_t enc;
  psync_symmetric_key_t symkey, realkey;
  sym_key_ver1 *skv1;
  psync_sql_res *res;
  psync_variant_row row;
  res = psql_query_rdlock("SELECT text2 FROM fstask WHERE id=?");
  psql_bind_uint(res, 1, -folderid);
  if ((row = psql_fetch(res))) {
    const unsigned char *b64enckey;
    unsigned char *enckey;
    size_t b64enckeylen, enckeylen;
    ;
    if (psync_is_null(row[0])) {
      psql_free(res);
      return (pcrypto_textenc_t)errptr(
          pdbg_return_const(PSYNC_CRYPTO_FOLDER_NOT_ENCRYPTED));
    }
    b64enckey = (const unsigned char *)psync_get_lstring(row[0], &b64enckeylen);
    enckey = psync_base64_decode(b64enckey, b64enckeylen, &enckeylen);
    psql_free(res);
    if (enckey) {
      symkey = prsa_decrypt_data(crypto_privkey, enckey, enckeylen);
      free(enckey);
    } else
      symkey = PSYNC_INVALID_SYM_KEY;
  } else {
    psql_free(res);
    return (pcrypto_textenc_t)errptr(
        pdbg_return_const(PSYNC_CRYPTO_FOLDER_NOT_FOUND));
  }
  if (symkey == PSYNC_INVALID_SYM_KEY)
    return (pcrypto_textenc_t)errptr(
        pdbg_return_const(PSYNC_CRYPTO_INVALID_KEY));
  skv1 = (sym_key_ver1 *)symkey->key;
  switch (skv1->type) {
  case PSYNC_CRYPTO_SYM_AES256_1024BIT_HMAC:
    if (symkey->keylen != sizeof(sym_key_ver1)) {
      pdbg_logf(D_WARNING, "bad size of decrypted key, expected %lu got %lu",
            (unsigned long)sizeof(sym_key_ver1), (unsigned long)symkey->keylen);
      goto def1;
    }
    realkey = symkeyv1_to_symkey(skv1);
    psymkey_free(symkey);
    enc = pcrypto_textenc_create(realkey);
    psymkey_free(realkey);
    return enc;
  default:
    pdbg_logf(D_WARNING, "unkown key type %u", (unsigned)skv1->type);
  def1:
    psymkey_free(symkey);
    return (pcrypto_textenc_t)errptr(
        pdbg_return_const(PSYNC_CRYPTO_INVALID_KEY));
  }
}

static pcrypto_textdec_t get_tmp_fldrdecoder_safe(psync_fsfolderid_t folderid) {
  pcrypto_textdec_t dec;
  psync_symmetric_key_t symkey, realkey;
  sym_key_ver1 *skv1;
  psync_sql_res *res;
  psync_variant_row row;
  res = psql_query_rdlock("SELECT text2 FROM fstask WHERE id=?");
  psql_bind_uint(res, 1, -folderid);
  if ((row = psql_fetch(res))) {
    const unsigned char *b64enckey;
    unsigned char *enckey;
    size_t b64enckeylen, enckeylen;
    ;
    if (psync_is_null(row[0])) {
      psql_free(res);
      return (pcrypto_textdec_t)errptr(
          pdbg_return_const(PSYNC_CRYPTO_FOLDER_NOT_ENCRYPTED));
    }
    b64enckey = (const unsigned char *)psync_get_lstring(row[0], &b64enckeylen);
    enckey = psync_base64_decode(b64enckey, b64enckeylen, &enckeylen);
    psql_free(res);
    if (enckey) {
      symkey = prsa_decrypt_data(crypto_privkey, enckey, enckeylen);

      free(enckey);
      if (symkey == PSYNC_INVALID_SYM_KEY)
        pdbg_logf(D_WARNING, "got key from database that fails rsa decrypt");
    } else {
      symkey = PSYNC_INVALID_SYM_KEY;
      pdbg_logf(D_WARNING, "got key from database that fails base64_decode");
    }
  } else {
    psql_free(res);
    return (pcrypto_textdec_t)errptr(
        pdbg_return_const(PSYNC_CRYPTO_FOLDER_NOT_FOUND));
  }
  if (symkey == PSYNC_INVALID_SYM_KEY)
    return (pcrypto_textdec_t)errptr(
        pdbg_return_const(PSYNC_CRYPTO_INVALID_KEY));
  skv1 = (sym_key_ver1 *)symkey->key;
  switch (skv1->type) {
  case PSYNC_CRYPTO_SYM_AES256_1024BIT_HMAC:
    if (symkey->keylen != sizeof(sym_key_ver1)) {
      pdbg_logf(D_WARNING, "bad size of decrypted key, expected %lu got %lu",
            (unsigned long)sizeof(sym_key_ver1), (unsigned long)symkey->keylen);
      goto def1;
    }
    realkey = symkeyv1_to_symkey(skv1);
    psymkey_free(symkey);
    dec = pcrypto_textdec_create(realkey);
    psymkey_free(realkey);
    return dec;
  default:
    pdbg_logf(D_WARNING, "unkown key type %u", (unsigned)skv1->type);
  def1:
    psymkey_free(symkey);
    return (pcrypto_textdec_t)errptr(
        pdbg_return_const(PSYNC_CRYPTO_INVALID_KEY));
  }
}

pcrypto_textdec_t pcryptofolder_flddecoder_get(psync_fsfolderid_t folderid) {
  char buff[16];
  pcrypto_textdec_t dec;
  if (!crypto_started_un)
    return (pcrypto_textdec_t)errptr(
        pdbg_return_const(PSYNC_CRYPTO_NOT_STARTED));
  if (folderid >= 0) {
    psync_get_string_id(buff, "FLDD", folderid);
    dec = (pcrypto_textdec_t)pcache_get(buff);
    if (dec)
      return dec;
  }
  pthread_rwlock_rdlock(&crypto_lock);
  if (!crypto_started_l) {
    dec = (pcrypto_textdec_t)errptr(
        pdbg_return_const(PSYNC_CRYPTO_NOT_STARTED));
  } else if (folderid > 0) {
    dec = get_fldrdecoder_safe(folderid);
  } else if (folderid < 0) {
    dec = get_tmp_fldrdecoder_safe(folderid);
  } else {
    dec = (pcrypto_textdec_t)errptr(
        pdbg_return_const(PSYNC_CRYPTO_FOLDER_NOT_ENCRYPTED));
  }
  pthread_rwlock_unlock(&crypto_lock);
  return dec;
}

static void psync_crypto_free_folder_decoder(void *ptr) {
  pcrypto_textdec_free(
      (pcrypto_textdec_t)ptr);
}

void pcryptofolder_flddecoder_release(
    psync_fsfolderid_t folderid, pcrypto_textdec_t decoder) {
  char buff[16];
  if (crypto_started_un && folderid >= 0) {
    psync_get_string_id(buff, "FLDD", folderid);
    pcache_add(buff, decoder, PSYNC_CRYPTO_CACHE_DIR_ECODER_SEC,
                    psync_crypto_free_folder_decoder, 2);
  } else
    pcrypto_textdec_free(decoder);
}

char *pcryptofolder_flddecode_filename(pcrypto_textdec_t decoder,
                                   const char *name) {
  unsigned char *filenameenc, *filenamedec;
  size_t filenameenclen;
  filenameenc = psync_base32_decode((const unsigned char *)name, strlen(name),
                                    &filenameenclen);
  if (!filenameenc)
    return NULL;
  filenamedec =
      pcrypto_decode_text(decoder, filenameenc, filenameenclen);
  free(filenameenc);
  return (char *)filenamedec;
}

static void proc_free_direncoder(void *ptr) {
  pcrypto_textenc_free((pcrypto_textenc_t)ptr);
}

static void free_direncoder(
    psync_folderid_t folderid, pcrypto_textenc_t enc) {
  char buff[16];
  psync_get_string_id(buff, "FLDE", folderid);
  pcache_add(buff, enc, PSYNC_CRYPTO_CACHE_DIR_ECODER_SEC, proc_free_direncoder, 2);
}

pcrypto_textenc_t pcryptofolder_fldencoder_get(psync_fsfolderid_t folderid) {
  char buff[16];
  pcrypto_textenc_t enc;
  if (!crypto_started_un) {
    return (pcrypto_textenc_t)errptr(
        pdbg_return_const(PSYNC_CRYPTO_NOT_STARTED));
  }

  if (folderid >= 0) {
    psync_get_string_id(buff, "FLDE", folderid);
    if ((enc = (pcrypto_textenc_t)pcache_get(buff)) !=
        NULL) {
      return enc;
    }
  }

  pthread_rwlock_rdlock(&crypto_lock);
  if (!crypto_started_l) {
    enc = (pcrypto_textenc_t)errptr(
        pdbg_return_const(PSYNC_CRYPTO_NOT_STARTED));
  } else if (folderid > 0) {
    enc = get_fldr_encoder(folderid);
  } else if (folderid < 0) {
    enc = get_tmp_fldrencoder_safe(folderid);
  } else {
    enc = (pcrypto_textenc_t)errptr(
        pdbg_return_const(PSYNC_CRYPTO_FOLDER_NOT_ENCRYPTED));
  }
  pthread_rwlock_unlock(&crypto_lock);
  return enc;
}

void pcryptofolder_fldencoder_release(
    psync_fsfolderid_t folderid, pcrypto_textenc_t encoder) {
  char buff[16];
  if (crypto_started_un && folderid >= 0) {
    psync_get_string_id(buff, "FLDE", folderid);
    pcache_add(buff, encoder, PSYNC_CRYPTO_CACHE_DIR_ECODER_SEC,
                    proc_free_direncoder, 2);
  } else
    pcrypto_textenc_free(encoder);
}

char * pcryptofolder_fldencode_filename(pcrypto_textenc_t encoder,
                                   const char *name) {
  unsigned char *filenameenc, *filenameb32;
  size_t filenameenclen;
  pcrypto_encode_text(encoder, (const unsigned char *)name,
                                  strlen(name), &filenameenc, &filenameenclen);
  filenameb32 =
      psync_base32_encode(filenameenc, filenameenclen, &filenameenclen);
  free(filenameenc);
  return (char *)filenameb32;
}

static pcrypto_sector_encdec_t get_fileencoder(psync_fileid_t fileid, uint64_t hash,
                                     int nonetwork) {
  pcrypto_sector_encdec_t enc;
  psync_symmetric_key_t symkey, realkey;
  sym_key_ver1 *skv1;
  symkey = get_file_symkey_safe(fileid, hash, nonetwork);
  if (pdbg_unlikely(is_err(symkey)))
    return (pcrypto_sector_encdec_t)symkey;
  if (nonetwork && (pcrypto_sector_encdec_t)symkey ==
                       PSYNC_CRYPTO_UNLOADED_SECTOR_ENCODER)
    return PSYNC_CRYPTO_UNLOADED_SECTOR_ENCODER;
  skv1 = (sym_key_ver1 *)symkey->key;
  switch (skv1->type) {
  case PSYNC_CRYPTO_SYM_AES256_1024BIT_HMAC:
    if (symkey->keylen != sizeof(sym_key_ver1)) {
      pdbg_logf(D_WARNING, "bad size of decrypted key, expected %lu got %lu",
            (unsigned long)sizeof(sym_key_ver1), (unsigned long)symkey->keylen);
      goto def1;
    }
    if (skv1->flags & PSYNC_CRYPTO_SYM_FLAG_ISDIR) {
      pdbg_logf(D_WARNING,
            "folder key found when file key was expected for fileid %lu",
            (unsigned long)fileid);
      goto def1;
    }
    realkey = symkeyv1_to_symkey(skv1);
    psync_crypto_release_file_symkey_locked(fileid, hash, symkey);
    enc = pcrypto_sec_encdec_create(realkey);
    psymkey_free(realkey);
    return enc;
  default:
    pdbg_logf(D_WARNING, "unkown key type %u", (unsigned)skv1->type);
  def1:
    psymkey_free(symkey);
    return (pcrypto_sector_encdec_t)errptr(
        pdbg_return_const(PSYNC_CRYPTO_INVALID_KEY));
  }
}

static pcrypto_sector_encdec_t get_fileencoder_tmp(psync_fsfileid_t fileid,
                                          int nonetwork) {
  uint64_t hash;
  psync_sql_res *res;
  psync_variant_row row;
  sym_key_ver1 *skv1;
  psync_symmetric_key_t realkey;
  pcrypto_sector_encdec_t enc;
  const unsigned char *b64enckey;
  unsigned char *enckey;
  size_t enckeylen, b64enckeylen;
  psync_symmetric_key_t symkey;
  res = psql_query_rdlock(
      "SELECT type, fileid, text2, int1 FROM fstask WHERE id=?");
  psql_bind_uint(res, 1, -fileid);
  row = psql_fetch(res);
  if (pdbg_unlikely(!row)) {
    psql_free(res);
    return (pcrypto_sector_encdec_t)errptr(
        pdbg_return_const(PSYNC_CRYPTO_FILE_NOT_FOUND));
  }
  switch (psync_get_number(row[0])) {
  case PSYNC_FS_TASK_CREAT:
    b64enckey = (const unsigned char *)psync_get_lstring(row[2], &b64enckeylen);
    enckey = psync_base64_decode(b64enckey, b64enckeylen, &enckeylen);
    psql_free(res);
    if (enckey) {
      symkey = prsa_decrypt_data(crypto_privkey, enckey, enckeylen);

      free(enckey);
    } else
      symkey = PSYNC_INVALID_SYM_KEY;
    if (symkey == PSYNC_INVALID_SYM_KEY)
      return (pcrypto_sector_encdec_t)errptr(
          pdbg_return_const(PSYNC_CRYPTO_INVALID_KEY));
    skv1 = (sym_key_ver1 *)symkey->key;
    switch (skv1->type) {
    case PSYNC_CRYPTO_SYM_AES256_1024BIT_HMAC:
      if (symkey->keylen != sizeof(sym_key_ver1)) {
        pdbg_logf(D_WARNING, "bad size of decrypted key, expected %lu got %lu",
              (unsigned long)sizeof(sym_key_ver1),
              (unsigned long)symkey->keylen);
        goto def1;
      }
      realkey = symkeyv1_to_symkey(skv1);
      psymkey_free(symkey);
      enc = pcrypto_sec_encdec_create(realkey);
      psymkey_free(realkey);
      return enc;
    default:
      pdbg_logf(D_WARNING, "unkown key type %u", (unsigned)skv1->type);
    def1:
      psymkey_free(symkey);
      return (pcrypto_sector_encdec_t)errptr(
          pdbg_return_const(PSYNC_CRYPTO_INVALID_KEY));
    }
  case PSYNC_FS_TASK_MODIFY:
    fileid = psync_get_number(row[1]);
    hash = psync_get_number(row[3]);
    psql_free(res);
    return get_fileencoder(fileid, hash, nonetwork);
  default:
    psql_free(res);
    return (pcrypto_sector_encdec_t)errptr(
        pdbg_return_const(PSYNC_CRYPTO_INTERNAL_ERROR));
  }
}

pcrypto_sector_encdec_t pcryptofolder_filencoder_get(psync_fsfileid_t fileid, uint64_t hash,
                                    int nonetwork) {
  char buff[32];
  pcrypto_sector_encdec_t enc;
  if (!crypto_started_un)
    return (pcrypto_sector_encdec_t)errptr(
        pdbg_return_const(PSYNC_CRYPTO_NOT_STARTED));
  if (fileid >= 0) {
    psync_get_string_id2(buff, "SEEN", fileid, hash);
    enc = (pcrypto_sector_encdec_t)pcache_get(buff);
    if (enc)
      return enc;
  }
  pthread_rwlock_rdlock(&crypto_lock);
  if (!crypto_started_l) {
    enc = (pcrypto_sector_encdec_t)errptr(
        pdbg_return_const(PSYNC_CRYPTO_NOT_STARTED));
  } else if (fileid > 0) {
    enc = get_fileencoder(fileid, hash, nonetwork);
  } else if (fileid < 0) {
    enc = get_fileencoder_tmp(fileid, nonetwork);
  } else {
    enc = (pcrypto_sector_encdec_t)errptr(
        pdbg_return_const(PSYNC_CRYPTO_FOLDER_NOT_ENCRYPTED));
  }
  pthread_rwlock_unlock(&crypto_lock);
  return enc;
}

pcrypto_sector_encdec_t pcryptofolder_filencoder_from_binresult(psync_fileid_t fileid,
                                                   binresult *res) {
  const binresult *b64key;
  unsigned char *key;
  psync_encrypted_symmetric_key_t esym;
  psync_symmetric_key_t symkey;
  pcrypto_sector_encdec_t enc;
  uint64_t hash;
  size_t keylen;
  b64key = papi_find_result2(res, "key", PARAM_STR);
  key = psync_base64_decode((const unsigned char *)b64key->str, b64key->length,
                            &keylen);
  if (!key)
    return (pcrypto_sector_encdec_t)errptr(
        pdbg_return_const(PSYNC_CRYPTO_INVALID_KEY));
  esym = psymkey_alloc_encrypted(keylen);
  memcpy(esym->data, key, keylen);
  free(key);
  hash = papi_find_result2(res, "hash", PARAM_NUM)->num;
  save_file_key_to_db(fileid, hash, esym);
  pthread_rwlock_rdlock(&crypto_lock);
  if (!crypto_started_l)
    enc = (pcrypto_sector_encdec_t)errptr(
        pdbg_return_const(PSYNC_CRYPTO_NOT_STARTED));
  else {
    // save_file_key_to_db runs thread to save to db, that's why we insert
    // decrypted key to cache, so get_fileencoder finds
    // it
    symkey = prsa_decrypt_symm_key_lock(&crypto_privkey, &esym);

    psync_crypto_release_file_symkey_locked(fileid, hash, symkey);
    enc = get_fileencoder(fileid, hash, 0);
  }
  pthread_rwlock_unlock(&crypto_lock);
  free(esym);
  return enc;
}

static void psync_crypto_free_file_encoder(void *ptr) {
  pcrypto_sec_encdec_free(
      (pcrypto_sector_encdec_t)ptr);
}

void pcryptofolder_filencoder_release(
    psync_fsfileid_t fileid, uint64_t hash,
    pcrypto_sector_encdec_t encoder) {
  if (crypto_started_un && fileid >= 0) {
    char buff[32];
    psync_get_string_id2(buff, "SEEN", fileid, hash);
    pcache_add(buff, encoder, PSYNC_CRYPTO_CACHE_FILE_ECODER_SEC,
                    psync_crypto_free_file_encoder, 2);
  } else
    pcrypto_sec_encdec_free(encoder);
}

static char *get_name_encoded(psync_folderid_t folderid,
                                           const char *name) {
  pcrypto_textenc_t enc;
  unsigned char *nameenc;
  char *ret;
  size_t nameenclen;
  enc = get_fldr_encoder_cache(folderid);
  if (is_err(enc))
    return (char *)enc;
  pcrypto_encode_text(enc, (const unsigned char *)name,
                                  strlen(name), &nameenc, &nameenclen);
  ret = (char *)psync_base32_encode(nameenc, nameenclen, &nameenclen);
  free_direncoder(folderid, enc);
  free(nameenc);
  return ret;
}

static int set_err(int ret, const char **err) {
  if (ret == PSYNC_CRYPTO_API_ERR_INTERNAL) {
    if (err)
      *err = crypto_api_err;
    return crypto_api_errno;
  }
  if (err) {
    if (-ret < ARRAY_SIZE(crypto_errors))
      *err = crypto_errors[-ret];
    else
      *err = "Unkown error.";
  }
  return ret;
}

static int get_cfldr_name(psync_folderid_t folderid,
                                          const char *name, char **ename,
                                          const char **err) {
  char *encname;  

  encname = get_name_encoded(folderid, name);
  if (is_err(encname))
    return set_err(to_err(encname), err);
  *ename = encname;
  return PSYNC_CRYPTO_SUCCESS;
}

static int get_fldr_name(psync_folderid_t folderid,
                                      const char *name, char **ename,
                                      const char **err) {
  if (folderid == 0) {
    *ename = psync_strdup(name);
    return PSYNC_CRYPTO_SUCCESS;
  } else {
    psync_sql_res *res;
    psync_uint_row row;
    int enc;
    res = psql_query_rdlock("SELECT flags FROM folder WHERE id=?");
    psql_bind_uint(res, 1, folderid);
    if ((row = psql_fetch_int(res)))
      enc = (row[0] & PSYNC_FOLDER_FLAG_ENCRYPTED) != 0;
    psql_free(res);
    if (!row)
      return set_err(pdbg_return_const(PSYNC_CRYPTO_FOLDER_NOT_FOUND), err);
    if (enc)
      return get_cfldr_name(folderid, name, ename, err);
    else {
      *ename = psync_strdup(name);
      return PSYNC_CRYPTO_SUCCESS;
    }
  }
}

int psync_cloud_crypto_send_mkdir(psync_folderid_t folderid, const char *name,
                                  const char **err, const char *b64key,
                                  size_t b64keylen,
                                  psync_encrypted_symmetric_key_t encsym,
                                  psync_folderid_t *newfolderid) {
  binparam params[] = {PAPI_STR("auth", psync_my_auth),
                       PAPI_NUM("folderid", folderid),
                       PAPI_STR("name", name),
                       PAPI_BOOL("encrypted", 1),
                       PAPI_LSTR("key", b64key, b64keylen),
                       PAPI_STR("timeformat", "timestamp")};
  psock_t *api;
  binresult *res;
  const binresult *meta;
  uint64_t result;
  int tries;
  tries = 0;
  while (1) {
    api = psync_apipool_get();
    if (!api)
      return set_err(pdbg_return_const(PSYNC_CRYPTO_CANT_CONNECT), err);
    res = papi_send2(api, "createfolder", params);
    if (pdbg_unlikely(!res)) {
      psync_apipool_release_bad(api);
      if (++tries > 5)
        return set_err(pdbg_return_const(PSYNC_CRYPTO_CANT_CONNECT), err);
    } else {
      psync_apipool_release(api);
      break;
    }
  }
  result = papi_find_result2(res, "result", PARAM_NUM)->num;
  if (result) {
    set_crypto_err_msg(res);
    pdbg_logf(D_NOTICE, "createfolder returned error %lu %s", (unsigned long)result,
          crypto_api_err);
    free(res);
    *err = crypto_api_err;
    psync_process_api_error(result);
    return result;
  }
  meta = papi_find_result2(res, "metadata", PARAM_HASH);
  if (newfolderid)
    *newfolderid = papi_find_result2(meta, "folderid", PARAM_NUM)->num;
  psql_start();
  pfileops_create_fldr(meta);
  save_folder_key(papi_find_result2(meta, "folderid", PARAM_NUM)->num,
                        encsym);
  psql_commit();
  free(res);
  return PSYNC_CRYPTO_SUCCESS;
}

char *pcryptofolder_filencoder_key_get(psync_fsfileid_t fileid,
                                              uint64_t hash, size_t *keylen) {
  psync_encrypted_symmetric_key_t encsym;
  char *ret;
  if (fileid < 0)
    return (char *)errptr(pdbg_return_const(PSYNC_CRYPTO_FILE_NOT_FOUND));
  encsym = get_file_enckey(fileid, hash, 0);
  if (is_err(encsym))
    return (char *)encsym;
  ret = (char *)psync_base64_encode(encsym->data, encsym->datalen, keylen);
  free(encsym);
  return ret;
}

char *pcryptofolder_filencoder_key_new(uint32_t flags, size_t *keylen) {
  psync_encrypted_symmetric_key_t encsym;
  sym_key_ver1 sym;
  char *ret;
  if (!crypto_started_un)
    return (char *)errptr(pdbg_return_const(PSYNC_CRYPTO_NOT_STARTED));
  sym.type = PSYNC_CRYPTO_SYM_AES256_1024BIT_HMAC;
  sym.flags = flags;
  pssl_rand_strong(sym.hmackey, PSYNC_CRYPTO_HMAC_SHA512_KEY_LEN);
  pssl_rand_strong(sym.aeskey, PSYNC_AES256_KEY_SIZE);
  pthread_rwlock_rdlock(&crypto_lock);
  if (!crypto_started_l) {
    pthread_rwlock_unlock(&crypto_lock);
    return (char *)errptr(pdbg_return_const(PSYNC_CRYPTO_NOT_STARTED));
  }
  encsym = prsa_encrypt_data(crypto_pubkey, (unsigned char *)&sym,
                                      sizeof(sym));
  pthread_rwlock_unlock(&crypto_lock);
  if (encsym == PSYNC_INVALID_ENC_SYM_KEY) {
    pdbg_logf(D_ERROR, "RSA encryption failed");
    return (char *)errptr(pdbg_return_const(PSYNC_CRYPTO_RSA_ERROR));
  }
  putil_wipe(&sym, sizeof(sym));
  ret = (char *)psync_base64_encode(encsym->data, encsym->datalen, keylen);
  free(encsym);
  return ret;
}

char *pcryptofolder_filencoder_key_newplain(
    uint32_t flags, size_t *keylen, psync_symmetric_key_t *deckey) {
  psync_encrypted_symmetric_key_t encsym;
  sym_key_ver1 sym;
  char *ret;
  if (!crypto_started_un)
    return (char *)errptr(pdbg_return_const(PSYNC_CRYPTO_NOT_STARTED));
  sym.type = PSYNC_CRYPTO_SYM_AES256_1024BIT_HMAC;
  sym.flags = flags;
  pssl_rand_strong(sym.hmackey, PSYNC_CRYPTO_HMAC_SHA512_KEY_LEN);
  pssl_rand_strong(sym.aeskey, PSYNC_AES256_KEY_SIZE);
  pthread_rwlock_rdlock(&crypto_lock);
  if (!crypto_started_l) {
    pthread_rwlock_unlock(&crypto_lock);
    return (char *)errptr(pdbg_return_const(PSYNC_CRYPTO_NOT_STARTED));
  }
  encsym = prsa_encrypt_data(crypto_pubkey, (unsigned char *)&sym,
                                      sizeof(sym));
  pthread_rwlock_unlock(&crypto_lock);
  if (encsym == PSYNC_INVALID_ENC_SYM_KEY) {
    pdbg_logf(D_ERROR, "RSA encryption failed");
    return (char *)errptr(pdbg_return_const(PSYNC_CRYPTO_RSA_ERROR));
  }
  *deckey = symkeyv1_to_symkey(&sym);
  putil_wipe(&sym, sizeof(sym));
  ret = (char *)psync_base64_encode(encsym->data, encsym->datalen, keylen);
  free(encsym);
  return ret;
}

int pcryptofolder_mkdir(psync_folderid_t folderid, const char *name,
                             const char **err, psync_folderid_t *newfolderid) {
  sym_key_ver1 sym;
  psync_encrypted_symmetric_key_t encsym;
  unsigned char *b64encsym;
  size_t b64encsymlen;
  char *ename;
  int ret;
  if (!crypto_started_un)
    return set_err(pdbg_return_const(PSYNC_CRYPTO_NOT_STARTED), err);
  ename = NULL;
  sym.type = PSYNC_CRYPTO_SYM_AES256_1024BIT_HMAC;
  sym.flags = PSYNC_CRYPTO_SYM_FLAG_ISDIR;
  pssl_rand_strong(sym.hmackey, PSYNC_CRYPTO_HMAC_SHA512_KEY_LEN);
  pssl_rand_strong(sym.aeskey, PSYNC_AES256_KEY_SIZE);
  pthread_rwlock_rdlock(&crypto_lock);
  if (!crypto_started_l) {
    pthread_rwlock_unlock(&crypto_lock);
    return set_err(pdbg_return_const(PSYNC_CRYPTO_NOT_STARTED), err);
  }
  encsym = prsa_encrypt_data(crypto_pubkey, (unsigned char *)&sym,
                                      sizeof(sym));
  putil_wipe(&sym, sizeof(sym));
  ret = get_fldr_name(folderid, name, &ename, err);
  pthread_rwlock_unlock(&crypto_lock);
  if (ret) {
    if (encsym != PSYNC_INVALID_ENC_SYM_KEY)
      free(encsym);
    return ret;
  }
  if (encsym == PSYNC_INVALID_ENC_SYM_KEY) {
    free(ename);
    pdbg_logf(D_ERROR, "RSA encryption failed");
    return set_err(pdbg_return_const(PSYNC_CRYPTO_RSA_ERROR), err);
  }
  b64encsym = psync_base64_encode(encsym->data, encsym->datalen, &b64encsymlen);
  ret = psync_cloud_crypto_send_mkdir(folderid, ename, err, (char *)b64encsym,
                                      b64encsymlen, encsym, newfolderid);
  free(encsym);
  free(ename);
  free(b64encsym);
  return ret;
}

int psync_pcloud_crypto_reencode_key(
    const unsigned char *rsapub, size_t rsapublen, const unsigned char *rsapriv,
    size_t rsaprivlen, const char *oldpassphrase, const char *newpassphrase,
    uint32_t flags, char **privenc, char **sign) {
  psync_rsa_publickey_t pub;
  psync_rsa_privatekey_t priv;
  unsigned char *newpriv;
  unsigned char newprivsha[PSYNC_SHA256_DIGEST_LEN];
  psync_rsa_signature_t rsasign;
  size_t newprivlen, dummy;
  if (unlikely(rsapublen <= sizeof(uint32_t) || rsaprivlen <= sizeof(uint32_t)))
    goto err_bk_0;

  switch (*((uint32_t *)rsapub)) {
  case PSYNC_CRYPTO_PUB_TYPE_RSA4096:
    if (offsetof(pub_key_ver1, key) >= rsapublen)
      goto err_bk_0;
    pub = prsa_load_public(rsapub + offsetof(pub_key_ver1, key),
                                    rsapublen - offsetof(pub_key_ver1, key));
    if (pub == PSYNC_INVALID_RSA)
      goto err_bk_0;
    break;
  default:
    goto err_bk_0;
  }

  newpriv = NULL;

  switch (*((uint32_t *)rsapriv)) {
  case PSYNC_CRYPTO_TYPE_RSA4096_64BYTESALT_20000IT: {
    pcrypto_ctr_encdec_t enc;
    psync_symmetric_key_t aeskey;
    priv_key_ver1 *rsapriv_struct;
    unsigned char *rsaprivdec;
    if (offsetof(priv_key_ver1, key) >= rsaprivlen)
      goto err_bk_1;
    rsapriv_struct = (priv_key_ver1 *)rsapriv;
    aeskey = psymkey_generate(
        oldpassphrase, PSYNC_AES256_KEY_SIZE + PSYNC_AES256_BLOCK_SIZE,
        rsapriv_struct->salt, PSYNC_CRYPTO_PBKDF2_SALT_LEN, 20000);
    if (unlikely(aeskey == PSYNC_INVALID_SYM_KEY))
      goto err_nm_1;
    rsaprivlen -= offsetof(priv_key_ver1, key);
    enc = pcrypto_ctr_encdec_create(aeskey);
    psymkey_free(aeskey);
    if (unlikely(enc == PSYNC_CRYPTO_INVALID_ENCODER))
      goto err_nm_1;
    rsaprivdec = (unsigned char *)malloc(rsaprivlen);
    if (unlikely(!rsaprivdec)) {
      pcrypto_ctr_encdec_free(enc);
      goto err_nm_1;
    }
    memcpy(rsaprivdec, rsapriv_struct->key, rsaprivlen);
    pcrypto_ctr_encdec_decode(enc, rsaprivdec, rsaprivlen,
                                                  0);
    pcrypto_ctr_encdec_free(enc);
    newpriv = (unsigned char *)malloc(offsetof(priv_key_ver1, key) +
                                            rsaprivlen);
    if (unlikely(!newpriv))
      goto err_nm_1;
    rsapriv_struct = (priv_key_ver1 *)newpriv;
    rsapriv_struct->type = PSYNC_CRYPTO_TYPE_RSA4096_64BYTESALT_20000IT;
    rsapriv_struct->flags = flags;
    pssl_rand_strong(rsapriv_struct->salt, PSYNC_CRYPTO_PBKDF2_SALT_LEN);
    aeskey = psymkey_generate(
        newpassphrase, PSYNC_AES256_KEY_SIZE + PSYNC_AES256_BLOCK_SIZE,
        rsapriv_struct->salt, PSYNC_CRYPTO_PBKDF2_SALT_LEN, 20000);
    if (unlikely(aeskey == PSYNC_INVALID_SYM_KEY))
      goto err_nm_1;
    // rsaprivlen-=offsetof(priv_key_ver1, key);
    enc = pcrypto_ctr_encdec_create(aeskey);
    psymkey_free(aeskey);
    if (unlikely(enc == PSYNC_CRYPTO_INVALID_ENCODER))
      goto err_nm_1;
    memcpy(rsapriv_struct->key, rsaprivdec, rsaprivlen);
    pcrypto_ctr_encdec_decode(enc, rsapriv_struct->key,
                                                  rsaprivlen, 0);
    pcrypto_ctr_encdec_free(enc);
    newprivlen = offsetof(priv_key_ver1, key) + rsaprivlen;
    priv = prsa_load_private(rsaprivdec, rsaprivlen);
    putil_wipe(rsaprivdec, rsaprivlen);
    free(rsaprivdec);
    if (unlikely(priv == PSYNC_INVALID_RSA))
      goto err_ph_1;
    break;
  }
  default:
    goto err_bk_1;
  }

  if (!crypto_keys_match())
    goto err_ph_2;
  psync_sha256(newpriv, newprivlen, newprivsha);
  rsasign = prsa_sign_sha256_hash(priv, newprivsha);
  if (is_err(rsasign)) {
    free(rsasign);
    prsa_free_public(pub);
    prsa_free_private(priv);
    return to_err(rsasign);
  }
  *privenc = (char *)psync_base64_encode(newpriv, newprivlen, &dummy);
  *sign = (char *)psync_base64_encode(rsasign->data, rsasign->datalen, &dummy);
  free(rsasign);
  free(newpriv);
  prsa_free_public(pub);
  prsa_free_private(priv);

  if (!*privenc || !*sign) {
    free(*privenc);
    free(*sign);
    return PERROR_NO_MEMORY;
  }

  return PSYNC_CRYPTO_SUCCESS;
err_bk_1:
  prsa_free_public(pub);
err_bk_0:
  return PSYNC_CRYPTO_BAD_KEY;
err_nm_1:
  free(newpriv);
  prsa_free_public(pub);
  return PERROR_NO_MEMORY;
err_ph_2:
  prsa_free_private(priv);
err_ph_1:
  free(newpriv);
  prsa_free_public(pub);
  return PSYNC_CRYPTO_BAD_PASSPHRASE;
}

int psync_pcloud_crypto_encode_key(const char *newpassphrase, uint32_t flags,
                                   char **privenc, char **sign) {
  unsigned char *newpriv;
  priv_key_ver1 *rsapriv_struct;
  psync_binary_rsa_key_t rsapriv;
  pcrypto_ctr_encdec_t enc;
  psync_symmetric_key_t aeskey;
  size_t rsaprivlen, dummy;
  unsigned char newprivsha[PSYNC_SHA256_DIGEST_LEN];
  psync_rsa_signature_t rsasign;
  rsapriv = prsa_private_to_binary(crypto_privkey);
  if (rsapriv == PSYNC_INVALID_RSA)
    goto err_nm_0;
  rsaprivlen = rsapriv->datalen;
  newpriv =
      (unsigned char *)malloc(offsetof(priv_key_ver1, key) + rsaprivlen);
  if (unlikely(!newpriv))
    goto err_nm_1;
  rsapriv_struct = (priv_key_ver1 *)newpriv;
  rsapriv_struct->type = PSYNC_CRYPTO_TYPE_RSA4096_64BYTESALT_20000IT;
  rsapriv_struct->flags = flags;
  pssl_rand_strong(rsapriv_struct->salt, PSYNC_CRYPTO_PBKDF2_SALT_LEN);
  aeskey = psymkey_generate(
      newpassphrase, PSYNC_AES256_KEY_SIZE + PSYNC_AES256_BLOCK_SIZE,
      rsapriv_struct->salt, PSYNC_CRYPTO_PBKDF2_SALT_LEN, 20000);
  if (unlikely(aeskey == PSYNC_INVALID_SYM_KEY))
    goto err_nm_1;
  enc = pcrypto_ctr_encdec_create(aeskey);
  psymkey_free(aeskey);
  if (unlikely(enc == PSYNC_CRYPTO_INVALID_ENCODER))
    goto err_nm_1;
  memcpy(rsapriv_struct->key, rsapriv->data, rsaprivlen);
  pcrypto_ctr_encdec_decode(enc, rsapriv_struct->key,
                                                rsaprivlen, 0);
  pcrypto_ctr_encdec_free(enc);
  rsaprivlen += offsetof(priv_key_ver1, key);

  psync_sha256(newpriv, rsaprivlen, newprivsha);
  rsasign = prsa_sign_sha256_hash(crypto_privkey, newprivsha);
  if (is_err(rsasign)) {
    putil_wipe(newpriv, rsaprivlen);
    free(newpriv);
    prsa_free_binary(rsapriv);
    return to_err(rsasign);
  }
  *privenc = (char *)psync_base64_encode(newpriv, rsaprivlen, &dummy);
  *sign = (char *)psync_base64_encode(rsasign->data, rsasign->datalen, &dummy);
  free(rsasign);
  putil_wipe(newpriv, rsaprivlen);
  free(newpriv);
  prsa_free_binary(rsapriv);

  if (!*privenc || !*sign) {
    free(*privenc);
    free(*sign);
    return PERROR_NO_MEMORY;
  }

  return PSYNC_CRYPTO_SUCCESS;

err_nm_1:
  free(newpriv);
  prsa_free_binary(rsapriv);
err_nm_0:
  return PERROR_NO_MEMORY;
}

int pcryptofolder_change_pass(const char *oldpassphrase,
                                   const char *newpassphrase, uint32_t flags,
                                   char **privenc, char **sign) {
  unsigned char *pubkey = NULL;
  unsigned char *privkey = NULL;
  unsigned char *salt = NULL;
  priv_key_ver1 *privatekey_struct = NULL;
  pub_key_ver1 *pubkey_struct = NULL;
  size_t pubkeylen = 0, privkeylen = 0, saltlen = 0;
  int cres;
  psync_sql_res *res;
  psync_variant_row row;
  const char *id;
  uint32_t rowcnt;
  binresult *bres;
  uint64_t result;
  const binresult *data;

  if (!newpassphrase || !newpassphrase[0])
    return PSYNC_CRYPTO_BAD_PASSPHRASE;
  while (psql_trylock()) {
    psys_sleep_milliseconds(1);
  }
  rowcnt = 0;
  res = psql_query_nolock(
      "SELECT id, value FROM setting WHERE id IN ('crypto_private_key', "
      "'crypto_public_key', 'crypto_private_salt') ORDER BY id");
  if (res) {
    while ((row = psql_fetch(res))) {
      id = psync_get_string(row[0]);
      rowcnt++;
      if (!strcmp(id, "crypto_private_key")) {
        load_str_to(&row[1], &privkey, &privkeylen);
        privatekey_struct = (priv_key_ver1 *)malloc(
            offsetof(priv_key_ver1, key) + privkeylen);
        memset(privatekey_struct, 0, offsetof(priv_key_ver1, key) + privkeylen);
        memcpy(privatekey_struct->key, privkey, privkeylen);
        privatekey_struct->type = PSYNC_CRYPTO_TYPE_RSA4096_64BYTESALT_20000IT;
        putil_wipe(privkey, privkeylen);
        free(privkey);
      } else if (!strcmp(id, "crypto_public_key")) {
        load_str_to(&row[1], &pubkey, &pubkeylen);
        pubkey_struct = (pub_key_ver1 *)malloc(
            offsetof(pub_key_ver1, key) + pubkeylen);
        memset(pubkey_struct, 0, offsetof(pub_key_ver1, key) + pubkeylen);
        memcpy(pubkey_struct->key, pubkey, pubkeylen);
        pubkey_struct->type = PSYNC_CRYPTO_PUB_TYPE_RSA4096;
        free(pubkey);
      } else if (!strcmp(id, "crypto_private_salt")) {
        load_str_to(&row[1], &salt, &saltlen);
        if (!privatekey_struct) {
          pdbg_logf(D_ERROR, "Private key struct is not initialized yet and the "
                         "salt can't be copied to it");
          continue;
        }
        memcpy(privatekey_struct->salt, salt, saltlen);
        putil_wipe(salt, saltlen);
        free(salt);
      }
    }
    psql_free(res);
  }
  psql_unlock();
  if (rowcnt < 3) {
    free(privatekey_struct);
    free(pubkey_struct);
    if (!psync_my_auth[0])
      return PERROR_NET_ERROR;
    pdbg_logf(D_NOTICE, "downloading keys");
    bres = psync_get_keys_bin_auth(psync_my_auth);
    if (unlikely(!bres)) {
      cres = PERROR_NET_ERROR;
      goto ex;
    }
    result = papi_find_result2(bres, "result", PARAM_NUM)->num;
    if (unlikely(result)) {
      pdbg_logf(D_WARNING, "crypto_getuserkeys returned error %d: %s", (int)result,
            papi_find_result2(bres, "error", PARAM_STR)->str);
      free(bres);
      cres = (int)result;
      goto ex;
    }
    pdbg_logf(D_NOTICE, "downloaded user keys");
    data = papi_find_result2(bres, "privatekey", PARAM_STR);
    privkey = psync_base64_decode((const unsigned char *)data->str,
                                  data->length, &privkeylen);
    data = papi_find_result2(bres, "publickey", PARAM_STR);
    pubkey = psync_base64_decode((const unsigned char *)data->str, data->length,
                                 &pubkeylen);
    data = papi_find_result2(bres, "salt", PARAM_STR);
    salt = psync_base64_decode((const unsigned char *)data->str, data->length,
                               &saltlen);
    free(bres);
    if (unlikely(!privkey || !pubkey)) {
      free(privkey);
      free(pubkey);
      cres = PERROR_NO_MEMORY;
      goto ex;
    }
    memcpy(((priv_key_ver1 *)privkey)->salt, salt, saltlen);
    cres = psync_pcloud_crypto_reencode_key(
        pubkey, pubkeylen, privkey, privkeylen, oldpassphrase, newpassphrase,
        flags, privenc, sign);
    free(pubkey);
    putil_wipe(privkey, privkeylen);    
    free(privkey);
    putil_wipe(salt, saltlen);    
    free(salt);
    if (cres)
      goto ex;
  } else {
    pdbg_assert(rowcnt == 3);
    cres = psync_pcloud_crypto_reencode_key(
        (unsigned char *)pubkey_struct, pubkeylen + offsetof(pub_key_ver1, key),
        (unsigned char *)privatekey_struct,
        privkeylen + offsetof(priv_key_ver1, key), oldpassphrase, newpassphrase,
        flags, privenc, sign);
    putil_wipe(privatekey_struct, privkeylen + offsetof(priv_key_ver1, key));    
    free(privatekey_struct);
    free(pubkey_struct);
    if (cres)
      goto ex;
  }

ex:
  return cres;
}

int pcryptofolder_change_pass_unlocked(const char *newpassphrase,
                                            uint32_t flags, char **privenc,
                                            char **sign) {
  int cres;
  if (unlikely(!pcryptofolder_is_unlocked())) {
    return PSYNC_CRYPTO_NOT_STARTED;
  }
  if (!newpassphrase || !newpassphrase[0])
    return PSYNC_CRYPTO_BAD_PASSPHRASE;
  cres = psync_pcloud_crypto_encode_key(newpassphrase, flags, privenc, sign);
  return cres;
}
