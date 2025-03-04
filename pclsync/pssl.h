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

#ifndef _PSYNC_SSL_H
#define _PSYNC_SSL_H

#include <mbedtls/aes.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/rsa.h>
#include <mbedtls/sha1.h>
#include <mbedtls/sha256.h>
#include <mbedtls/sha512.h>

#include "pcompiler.h"

// AES256
#define PSYNC_AES256_BLOCK_SIZE 16
#define PSYNC_AES256_KEY_SIZE 32

// SHA1
#define PSYNC_SHA1_BLOCK_LEN 64
#define PSYNC_SHA1_DIGEST_LEN 20
#define PSYNC_SHA1_DIGEST_HEXLEN 40
#define psync_sha1_ctx mbedtls_sha1_context
#define psync_sha1(data, datalen, checksum)                                    \
  mbedtls_sha1(data, datalen, checksum)
#define psync_sha1_init(pctx) mbedtls_sha1_starts(pctx)
#define psync_sha1_update(pctx, data, datalen)                                 \
  mbedtls_sha1_update(pctx, (const unsigned char *)data, datalen)
#define psync_sha1_final(checksum, pctx) mbedtls_sha1_finish(pctx, checksum)

// SHA256
#define PSYNC_SHA256_BLOCK_LEN 64
#define PSYNC_SHA256_DIGEST_LEN 32
#define PSYNC_SHA256_DIGEST_HEXLEN 64
#define psync_sha256_ctx mbedtls_sha256_context
#define psync_sha256(data, datalen, checksum)                                  \
  mbedtls_sha256(data, datalen, checksum, 0)
#define psync_sha256_init(pctx) mbedtls_sha256_starts(pctx, 0)
#define psync_sha256_update(pctx, data, datalen)                               \
  mbedtls_sha256_update(pctx, (const unsigned char *)data, datalen)
#define psync_sha256_final(checksum, pctx) mbedtls_sha256_finish(pctx, checksum)

// SHA512
#define PSYNC_SHA512_BLOCK_LEN 128
#define PSYNC_SHA512_DIGEST_LEN 64
#define PSYNC_SHA512_DIGEST_HEXLEN 128
#define psync_sha512_ctx mbedtls_sha512_context
#define psync_sha512(data, datalen, checksum)                                  \
  mbedtls_sha512(data, datalen, checksum, 0)
#define psync_sha512_init(pctx) mbedtls_sha512_starts(pctx, 0)
#define psync_sha512_update(pctx, data, datalen)                               \
  mbedtls_sha512_update(pctx, (const unsigned char *)data, datalen)
#define psync_sha512_final(checksum, pctx) mbedtls_sha512_finish(pctx, checksum)

// externs
extern PSYNC_THREAD int psync_ssl_errno;

#define PSYNC_INVALID_RSA NULL
#define PSYNC_INVALID_SYM_KEY NULL
#define PSYNC_INVALID_ENC_SYM_KEY NULL
#define PSYNC_INVALID_ENCODER NULL
#define PSYNC_INVALID_BIN_RSA NULL
#define PSYNC_SSL_ERR_WANT_READ 1
#define PSYNC_SSL_ERR_WANT_WRITE 2
#define PSYNC_SSL_ERR_UNKNOWN 3
#define PSYNC_SSL_NEED_FINISH -2
#define PSYNC_SSL_FAIL -1
#define PSYNC_SSL_SUCCESS 0

typedef struct {
  size_t datalen;
  unsigned char data[];
} pssl_enc_data_t;


typedef struct {
  size_t keylen;
  unsigned char key[];
} pssl_symkey_t;

typedef mbedtls_rsa_context *pssl_context_t;
typedef mbedtls_rsa_context *pssl_rsapubkey_t;
typedef mbedtls_rsa_context *pssl_rsaprivkey_t;
typedef mbedtls_aes_context *pssl_encoder_t;
typedef mbedtls_aes_context *pssl_decoder_t;
typedef pssl_enc_data_t *pssl_enc_symkey_t;
typedef pssl_enc_data_t *pssl_rsabinkey_t;
typedef pssl_enc_data_t *pssl_signature_t;

typedef struct {
  mbedtls_net_context srv;
  mbedtls_ssl_context ssl;
  mbedtls_ssl_config cfg;
  int sock;
  int isbroken;
  char cachekey[];
} ssl_connection_t;

typedef void (*psync_ssl_debug_callback_t)(void *ctx, int level, const char *msg, int, const char *);

// AES
void paes_2blk_decode(pssl_decoder_t enc, const unsigned char *src, unsigned char *dst);
void paes_2blk_encode(pssl_decoder_t enc, const unsigned char *src, unsigned char *dst);
void paes_4blk_xor_decode(pssl_decoder_t enc, const unsigned char *src, unsigned char *dst, unsigned char *bxor);
void paes_blk_decode(pssl_decoder_t enc, const unsigned char *src, unsigned char *dst);
void paes_blk_encode(pssl_encoder_t enc, const unsigned char *src, unsigned char *dst);
pssl_encoder_t paes_decoder_create(pssl_symkey_t *key);
void paes_decoder_free(pssl_encoder_t aes);
pssl_encoder_t paes_encoder_create(pssl_symkey_t *key);
void paes_encoder_free(pssl_encoder_t aes);

// RSA
void prsa_binary_free(pssl_rsabinkey_t bin);
pssl_rsabinkey_t prsa_binary_private(pssl_rsaprivkey_t rsa);
pssl_rsabinkey_t prsa_binary_public(pssl_rsapubkey_t rsa);
void prsa_free(pssl_context_t rsa);
void prsa_free_private(pssl_rsaprivkey_t key);
void prsa_free_public(pssl_rsapubkey_t key);
pssl_context_t prsa_generate(int bits);
pssl_rsaprivkey_t prsa_get_private(pssl_context_t rsa);
pssl_rsapubkey_t prsa_get_public(pssl_context_t rsa);
pssl_rsaprivkey_t prsa_load_private(const unsigned char *keydata, size_t keylen);
pssl_rsapubkey_t prsa_load_public(const unsigned char *keydata, size_t keylen);
pssl_signature_t prsa_signature(pssl_rsaprivkey_t rsa, const unsigned char *data);

// SSL
int pssl_bytes_left(ssl_connection_t *sslconn);
void pssl_cleanup(void *ptr, size_t len);
int pssl_close(ssl_connection_t *sslconn);
void pssl_debug_cb(psync_ssl_debug_callback_t cb, void *ctx);
int pssl_finish(ssl_connection_t *sslconn, const char *hostname);
void pssl_free(ssl_connection_t *sslconn);
int pssl_init();
void pssl_log_level(int threshold);
int pssl_open(int sock, ssl_connection_t **sslconn, const char *hostname);
void pssl_random(unsigned char *buf, int num);
int pssl_read(ssl_connection_t *sslconn, void *buf, int num);
int pssl_write(ssl_connection_t *sslconn, const void *buf, int num);

pssl_enc_symkey_t psymkey_alloc(size_t len);
pssl_enc_symkey_t psymkey_copy(pssl_enc_symkey_t src);
pssl_symkey_t *psymkey_decrypt(pssl_rsaprivkey_t rsa, const unsigned char *data, size_t datalen);
pssl_symkey_t *psymkey_decrypt_lock(pssl_rsaprivkey_t *rsa, const pssl_enc_symkey_t *enckey);
char *psymkey_derive_passphrase(const char *username, const char *passphrase);
pssl_enc_symkey_t psymkey_encrypt(pssl_rsapubkey_t rsa, const unsigned char *data, size_t datalen);
void psymkey_free(pssl_symkey_t *key);
pssl_symkey_t *psymkey_generate_passphrase(const char *password, size_t keylen, const unsigned char *salt, size_t saltlen, size_t iterations);


#endif
