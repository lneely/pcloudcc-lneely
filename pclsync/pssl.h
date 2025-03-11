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
#include <mbedtls/rsa.h>
#include <mbedtls/sha1.h>
#include <mbedtls/sha256.h>
#include <mbedtls/sha512.h>

#include "pcompiler.h"

#define PSYNC_AES256_BLOCK_SIZE 16
#define PSYNC_AES256_KEY_SIZE 32

#define PSYNC_INVALID_RSA NULL
#define PSYNC_INVALID_SYM_KEY NULL

#define PSYNC_SHA1_BLOCK_LEN 64
#define PSYNC_SHA1_DIGEST_LEN 20
#define PSYNC_SHA1_DIGEST_HEXLEN 40
#define psync_sha1_ctx mbedtls_sha1_context
#define psync_sha1(data, datalen, checksum) mbedtls_sha1(data, datalen, checksum)
#define psync_sha1_init(pctx) mbedtls_sha1_starts(pctx)
#define psync_sha1_update(pctx, data, datalen) mbedtls_sha1_update(pctx, (const unsigned char *)data, datalen)
#define psync_sha1_final(checksum, pctx) mbedtls_sha1_finish(pctx, checksum)

#define PSYNC_SHA256_BLOCK_LEN 64
#define PSYNC_SHA256_DIGEST_LEN 32
#define PSYNC_SHA256_DIGEST_HEXLEN 64
#define psync_sha256_ctx mbedtls_sha256_context
#define psync_sha256(data, datalen, checksum) mbedtls_sha256(data, datalen, checksum, 0)
#define psync_sha256_init(pctx) mbedtls_sha256_starts(pctx, 0)
#define psync_sha256_update(pctx, data, datalen) mbedtls_sha256_update(pctx, (const unsigned char *)data, datalen)
#define psync_sha256_final(checksum, pctx) mbedtls_sha256_finish(pctx, checksum)

#define PSYNC_SHA512_BLOCK_LEN 128
#define PSYNC_SHA512_DIGEST_LEN 64
#define PSYNC_SHA512_DIGEST_HEXLEN 128
#define psync_sha512_ctx mbedtls_sha512_context
#define psync_sha512(data, datalen, checksum) mbedtls_sha512(data, datalen, checksum, 0)
#define psync_sha512_init(pctx) mbedtls_sha512_starts(pctx, 0)
#define psync_sha512_update(pctx, data, datalen) mbedtls_sha512_update(pctx, (const unsigned char *)data, datalen)
#define psync_sha512_final(checksum, pctx) mbedtls_sha512_finish(pctx, checksum)

typedef mbedtls_rsa_context *psync_rsa_t;
typedef mbedtls_rsa_context *psync_rsa_publickey_t;
typedef mbedtls_rsa_context *psync_rsa_privatekey_t;

typedef struct {
  size_t keylen;
  unsigned char key[];
} psync_symmetric_key_struct_t, *psync_symmetric_key_t;

typedef mbedtls_aes_context *psync_aes256_encoder;
typedef mbedtls_aes_context *psync_aes256_decoder;

// ctx, level, message, ???, ???
typedef void (*pssl_debug_callback_t)(void *, int, const char *, int,
                                           const char *);
void pssl_log_threshold(int threshold);
void pssl_debug_cb(pssl_debug_callback_t cb, void *ctx);

static inline void psync_aes256_encode_block(psync_aes256_encoder enc, const unsigned char *src, unsigned char *dst) {
  mbedtls_aes_crypt_ecb(enc, MBEDTLS_AES_ENCRYPT, src, dst);
}

static inline void psync_aes256_decode_block(psync_aes256_decoder enc, const unsigned char *src, unsigned char *dst) {
  mbedtls_aes_crypt_ecb(enc, MBEDTLS_AES_DECRYPT, src, dst);
}

static inline void psync_aes256_encode_2blocks_consec(psync_aes256_decoder enc, const unsigned char *src, unsigned char *dst) {
  mbedtls_aes_crypt_ecb(enc, MBEDTLS_AES_ENCRYPT, src, dst);
  mbedtls_aes_crypt_ecb(enc, MBEDTLS_AES_ENCRYPT, src + PSYNC_AES256_BLOCK_SIZE, dst + PSYNC_AES256_BLOCK_SIZE);
}

static inline void psync_aes256_decode_2blocks_consec(psync_aes256_decoder enc, const unsigned char *src, unsigned char *dst) {
  mbedtls_aes_crypt_ecb(enc, MBEDTLS_AES_DECRYPT, src, dst);
  mbedtls_aes_crypt_ecb(enc, MBEDTLS_AES_DECRYPT, src + PSYNC_AES256_BLOCK_SIZE, dst + PSYNC_AES256_BLOCK_SIZE);
}

static inline void psync_aes256_decode_4blocks_consec_xor(psync_aes256_decoder enc, const unsigned char *src, unsigned char *dst, unsigned char *bxor) {
  unsigned long i;
  mbedtls_aes_crypt_ecb(enc, MBEDTLS_AES_DECRYPT, src, dst);
  mbedtls_aes_crypt_ecb(enc, MBEDTLS_AES_DECRYPT, src + PSYNC_AES256_BLOCK_SIZE, dst + PSYNC_AES256_BLOCK_SIZE);
  mbedtls_aes_crypt_ecb(enc, MBEDTLS_AES_DECRYPT, src + PSYNC_AES256_BLOCK_SIZE * 2, dst + PSYNC_AES256_BLOCK_SIZE * 2);
  mbedtls_aes_crypt_ecb(enc, MBEDTLS_AES_DECRYPT, src + PSYNC_AES256_BLOCK_SIZE * 3, dst + PSYNC_AES256_BLOCK_SIZE * 3);
  for (i = 0; i < PSYNC_AES256_BLOCK_SIZE * 4 / sizeof(unsigned long); i++) {
    ((unsigned long *)dst)[i] ^= ((unsigned long *)bxor)[i];
  }
}


extern PSYNC_THREAD int psync_ssl_errno;

#define PSYNC_SSL_ERR_WANT_READ 1
#define PSYNC_SSL_ERR_WANT_WRITE 2
#define PSYNC_SSL_ERR_UNKNOWN 3

#define PSYNC_SSL_NEED_FINISH -2
#define PSYNC_SSL_FAIL -1
#define PSYNC_SSL_SUCCESS 0

typedef struct {
  size_t datalen;
  unsigned char data[];
} psync_encrypted_data_struct_t, *psync_encrypted_data_t;

typedef psync_encrypted_data_t psync_encrypted_symmetric_key_t;
typedef psync_encrypted_data_t psync_binary_rsa_key_t;
typedef psync_encrypted_data_t psync_rsa_signature_t;

#define PSYNC_INVALID_ENC_SYM_KEY NULL
#define PSYNC_INVALID_ENCODER NULL
#define PSYNC_INVALID_BIN_RSA NULL

#define pssl_alloc_binary_rsa psymkey_alloc_encrypted

// Lock used to serialize access to RSA decrypt key function

int pssl_init();
int pssl_connect(int sock, void **sslconn, const char *hostname);
int pssl_connect_finish(void *sslconn, const char *hostname);
void pssl_free(void *sslconn);
int pssl_shutdown(void *sslconn);
int pssl_pendingdata(void *sslconn);
int pssl_read(void *sslconn, void *buf, int num);
int pssl_write(void *sslconn, const void *buf, int num);
void pssl_rand_strong(unsigned char *buf, int num);
psync_rsa_t pssl_gen_rsa(int bits);
void pssl_free_rsa(psync_rsa_t rsa);
psync_rsa_publickey_t prsa_get_public(psync_rsa_t rsa);
void prsa_free_public(psync_rsa_publickey_t key);
psync_rsa_privatekey_t prsa_get_private(psync_rsa_t rsa);
void prsa_free_private(psync_rsa_privatekey_t key);
psync_binary_rsa_key_t prsa_public_to_binary(psync_rsa_publickey_t rsa);
psync_binary_rsa_key_t prsa_private_to_binary(psync_rsa_privatekey_t rsa);
psync_rsa_publickey_t prsa_load_public(const unsigned char *keydata, size_t keylen);
psync_rsa_privatekey_t prsa_load_private(const unsigned char *keydata, size_t keylen);
psync_rsa_publickey_t prsa_binary_to_public(psync_binary_rsa_key_t bin);
psync_rsa_privatekey_t prsa_binary_to_private(psync_binary_rsa_key_t bin);
void prsa_free_binary(psync_binary_rsa_key_t bin);
psync_symmetric_key_t psymkey_generate(const char *password, size_t keylen, const unsigned char *salt, size_t saltlen, size_t iterations);
char *psymkey_derive(const char *username, const char *passphrase);
psync_encrypted_symmetric_key_t psymkey_alloc_encrypted(size_t len);
psync_encrypted_symmetric_key_t psymkey_copy_encrypted(psync_encrypted_symmetric_key_t src);
void psymkey_free(psync_symmetric_key_t key);
psync_encrypted_symmetric_key_t prsa_encrypt_data(psync_rsa_publickey_t rsa, const unsigned char *data, size_t datalen);
psync_symmetric_key_t prsa_decrypt_data(psync_rsa_privatekey_t rsa, const unsigned char *data, size_t datalen);
psync_encrypted_symmetric_key_t psymkey_encrypt(psync_rsa_publickey_t rsa, const psync_symmetric_key_t key);
psync_symmetric_key_t psymkey_decrypt(psync_rsa_privatekey_t rsa, const psync_encrypted_symmetric_key_t enckey);
psync_aes256_encoder paes_create_encoder(psync_symmetric_key_t key);
void paes_free_encoder(psync_aes256_encoder aes);
psync_aes256_encoder paes_create_decoder(psync_symmetric_key_t key);
void paes_free_decoder(psync_aes256_encoder aes);
psync_rsa_signature_t prsa_sign_sha256_hash(psync_rsa_privatekey_t rsa, const unsigned char *data);
psync_symmetric_key_t prsa_decrypt_symm_key_lock(psync_rsa_privatekey_t *rsa, const psync_encrypted_symmetric_key_t *enckey);

#endif
