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

/*
  Dependencies:
  - pcompat.h
  - pcompiler.h
  - <polarssl/aes.h>
  - <polarssl/rsa.h>
  - <polarssl/sha1.h>
  - <polarssl/sha256.h>
  - <polarssl/sha512.h>
*/

#ifndef _PSYNC_SSL_H
#define _PSYNC_SSL_H

#define PSYNC_AES256_BLOCK_SIZE 16
#define PSYNC_AES256_KEY_SIZE 32

#define PSYNC_INVALID_RSA NULL
#define PSYNC_INVALID_SYM_KEY NULL

#define PSYNC_SHA1_BLOCK_LEN 64
#define PSYNC_SHA1_DIGEST_LEN 20
#define PSYNC_SHA1_DIGEST_HEXLEN 40
#define psync_sha1_ctx sha1_context
#define psync_sha1(data, datalen, checksum) sha1(data, datalen, checksum)
#define psync_sha1_init(pctx) sha1_starts(pctx)
#define psync_sha1_update(pctx, data, datalen)                                 \
  sha1_update(pctx, (const unsigned char *)data, datalen)
#define psync_sha1_final(checksum, pctx) sha1_finish(pctx, checksum)

#define PSYNC_SHA256_BLOCK_LEN 64
#define PSYNC_SHA256_DIGEST_LEN 32
#define PSYNC_SHA256_DIGEST_HEXLEN 64
#define psync_sha256_ctx sha256_context
#define psync_sha256(data, datalen, checksum) sha256(data, datalen, checksum, 0)
#define psync_sha256_init(pctx) sha256_starts(pctx, 0)
#define psync_sha256_update(pctx, data, datalen)                               \
  sha256_update(pctx, (const unsigned char *)data, datalen)
#define psync_sha256_final(checksum, pctx) sha256_finish(pctx, checksum)

#define PSYNC_SHA512_BLOCK_LEN 128
#define PSYNC_SHA512_DIGEST_LEN 64
#define PSYNC_SHA512_DIGEST_HEXLEN 128
#define psync_sha512_ctx sha512_context
#define psync_sha512(data, datalen, checksum) sha512(data, datalen, checksum, 0)
#define psync_sha512_init(pctx) sha512_starts(pctx, 0)
#define psync_sha512_update(pctx, data, datalen)                               \
  sha512_update(pctx, (const unsigned char *)data, datalen)
#define psync_sha512_final(checksum, pctx) sha512_finish(pctx, checksum)

typedef rsa_context *psync_rsa_t;
typedef rsa_context *psync_rsa_publickey_t;
typedef rsa_context *psync_rsa_privatekey_t;

typedef struct {
  size_t keylen;
  unsigned char key[];
} psync_symmetric_key_struct_t, *psync_symmetric_key_t;

typedef aes_context *psync_aes256_encoder;
typedef aes_context *psync_aes256_decoder;

typedef void (*psync_ssl_debug_callback_t)(void *, int, const char *, int,
                                           const char *);
void psync_ssl_set_log_threshold(int threshold);
void psync_ssl_set_debug_callback(psync_ssl_debug_callback_t cb, void *ctx);

#if defined(__GNUC__) &&                                                       \
    (defined(__amd64__) || defined(__x86_64__) || defined(__i386__))
#define PSYNC_AES_HW
#define PSYNC_AES_HW_GCC
#elif defined(_MSC_VER)
#define PSYNC_AES_HW
#define PSYNC_AES_HW_MSC
#endif

#if defined(PSYNC_AES_HW)
extern int psync_ssl_hw_aes;

void psync_aes256_encode_block_hw(psync_aes256_encoder enc,
                                  const unsigned char *src, unsigned char *dst);
void psync_aes256_decode_block_hw(psync_aes256_decoder enc,
                                  const unsigned char *src, unsigned char *dst);
void psync_aes256_encode_2blocks_consec_hw(psync_aes256_encoder enc,
                                           const unsigned char *src,
                                           unsigned char *dst);
void psync_aes256_decode_2blocks_consec_hw(psync_aes256_decoder enc,
                                           const unsigned char *src,
                                           unsigned char *dst);
void psync_aes256_decode_4blocks_consec_xor_hw(psync_aes256_decoder enc,
                                               const unsigned char *src,
                                               unsigned char *dst,
                                               unsigned char *bxor);
void psync_aes256_decode_4blocks_consec_xor_sw(psync_aes256_decoder enc,
                                               const unsigned char *src,
                                               unsigned char *dst,
                                               unsigned char *bxor);

static inline void psync_aes256_encode_block(psync_aes256_encoder enc,
                                             const unsigned char *src,
                                             unsigned char *dst) {
  if (likely(psync_ssl_hw_aes))
    psync_aes256_encode_block_hw(enc, src, dst);
  else
    aes_crypt_ecb(enc, AES_ENCRYPT, src, dst);
}

static inline void psync_aes256_decode_block(psync_aes256_decoder enc,
                                             const unsigned char *src,
                                             unsigned char *dst) {
  if (likely(psync_ssl_hw_aes))
    psync_aes256_decode_block_hw(enc, src, dst);
  else
    aes_crypt_ecb(enc, AES_DECRYPT, src, dst);
}

static inline void psync_aes256_encode_2blocks_consec(psync_aes256_decoder enc,
                                                      const unsigned char *src,
                                                      unsigned char *dst) {
  if (likely(psync_ssl_hw_aes))
    psync_aes256_encode_2blocks_consec_hw(enc, src, dst);
  else {
    aes_crypt_ecb(enc, AES_ENCRYPT, src, dst);
    aes_crypt_ecb(enc, AES_ENCRYPT, src + PSYNC_AES256_BLOCK_SIZE,
                  dst + PSYNC_AES256_BLOCK_SIZE);
  }
}

static inline void psync_aes256_decode_2blocks_consec(psync_aes256_decoder enc,
                                                      const unsigned char *src,
                                                      unsigned char *dst) {
  if (likely(psync_ssl_hw_aes))
    psync_aes256_decode_2blocks_consec_hw(enc, src, dst);
  else {
    aes_crypt_ecb(enc, AES_DECRYPT, src, dst);
    aes_crypt_ecb(enc, AES_DECRYPT, src + PSYNC_AES256_BLOCK_SIZE,
                  dst + PSYNC_AES256_BLOCK_SIZE);
  }
}

static inline void psync_aes256_decode_4blocks_consec_xor(
    psync_aes256_decoder enc, const unsigned char *src, unsigned char *dst,
    unsigned char *bxor) {
  if (psync_ssl_hw_aes)
    psync_aes256_decode_4blocks_consec_xor_hw(enc, src, dst, bxor);
  else
    psync_aes256_decode_4blocks_consec_xor_sw(enc, src, dst, bxor);
}

#else

static inline void psync_aes256_encode_block(psync_aes256_encoder enc,
                                             const unsigned char *src,
                                             unsigned char *dst) {
  aes_crypt_ecb(enc, AES_ENCRYPT, src, dst);
}

static inline void psync_aes256_decode_block(psync_aes256_decoder enc,
                                             const unsigned char *src,
                                             unsigned char *dst) {
  aes_crypt_ecb(enc, AES_DECRYPT, src, dst);
}

static inline void psync_aes256_encode_2blocks_consec(psync_aes256_decoder enc,
                                                      const unsigned char *src,
                                                      unsigned char *dst) {
  aes_crypt_ecb(enc, AES_ENCRYPT, src, dst);
  aes_crypt_ecb(enc, AES_ENCRYPT, src + PSYNC_AES256_BLOCK_SIZE,
                dst + PSYNC_AES256_BLOCK_SIZE);
}

static inline void psync_aes256_decode_2blocks_consec(psync_aes256_decoder enc,
                                                      const unsigned char *src,
                                                      unsigned char *dst) {
  aes_crypt_ecb(enc, AES_DECRYPT, src, dst);
  aes_crypt_ecb(enc, AES_DECRYPT, src + PSYNC_AES256_BLOCK_SIZE,
                dst + PSYNC_AES256_BLOCK_SIZE);
}

static inline void psync_aes256_decode_4blocks_consec_xor(
    psync_aes256_decoder enc, const unsigned char *src, unsigned char *dst,
    unsigned char *bxor) {
  unsigned long i;
  aes_crypt_ecb(enc, AES_DECRYPT, src, dst);
  aes_crypt_ecb(enc, AES_DECRYPT, src + PSYNC_AES256_BLOCK_SIZE,
                dst + PSYNC_AES256_BLOCK_SIZE);
  aes_crypt_ecb(enc, AES_DECRYPT, src + PSYNC_AES256_BLOCK_SIZE * 2,
                dst + PSYNC_AES256_BLOCK_SIZE * 2);
  aes_crypt_ecb(enc, AES_DECRYPT, src + PSYNC_AES256_BLOCK_SIZE * 3,
                dst + PSYNC_AES256_BLOCK_SIZE * 3);
  for (i = 0; i < PSYNC_AES256_BLOCK_SIZE * 4 / sizeof(unsigned long); i++)
    ((unsigned long *)dst)[i] ^= ((unsigned long *)bxor)[i];
}

#endif

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

#define psync_ssl_alloc_binary_rsa psync_ssl_alloc_encrypted_symmetric_key

// Lock used to serialize access to RSA decrypt key function

int psync_ssl_init();
void psync_ssl_memclean(void *ptr, size_t len);
int psync_ssl_connect(psync_socket_t sock, void **sslconn,
                      const char *hostname);
int psync_ssl_connect_finish(void *sslconn, const char *hostname);
void psync_ssl_free(void *sslconn);
int psync_ssl_shutdown(void *sslconn);
int psync_ssl_pendingdata(void *sslconn);
int psync_ssl_read(void *sslconn, void *buf, int num);
int psync_ssl_write(void *sslconn, const void *buf, int num);

void psync_ssl_rand_strong(unsigned char *buf, int num);
void psync_ssl_rand_weak(unsigned char *buf, int num);

psync_rsa_t psync_ssl_gen_rsa(int bits);
void psync_ssl_free_rsa(psync_rsa_t rsa);
psync_rsa_publickey_t psync_ssl_rsa_get_public(psync_rsa_t rsa);
void psync_ssl_rsa_free_public(psync_rsa_publickey_t key);
psync_rsa_privatekey_t psync_ssl_rsa_get_private(psync_rsa_t rsa);
void psync_ssl_rsa_free_private(psync_rsa_privatekey_t key);
psync_binary_rsa_key_t
psync_ssl_rsa_public_to_binary(psync_rsa_publickey_t rsa);
psync_binary_rsa_key_t
psync_ssl_rsa_private_to_binary(psync_rsa_privatekey_t rsa);
psync_rsa_publickey_t psync_ssl_rsa_load_public(const unsigned char *keydata,
                                                size_t keylen);
psync_rsa_privatekey_t psync_ssl_rsa_load_private(const unsigned char *keydata,
                                                  size_t keylen);
psync_rsa_publickey_t
psync_ssl_rsa_binary_to_public(psync_binary_rsa_key_t bin);
psync_rsa_privatekey_t
psync_ssl_rsa_binary_to_private(psync_binary_rsa_key_t bin);
void psync_ssl_rsa_free_binary(psync_binary_rsa_key_t bin);
psync_symmetric_key_t
psync_ssl_gen_symmetric_key_from_pass(const char *password, size_t keylen,
                                      const unsigned char *salt, size_t saltlen,
                                      size_t iterations);
char *psync_ssl_derive_password_from_passphrase(const char *username,
                                                const char *passphrase);
psync_encrypted_symmetric_key_t
psync_ssl_alloc_encrypted_symmetric_key(size_t len);
psync_encrypted_symmetric_key_t
psync_ssl_copy_encrypted_symmetric_key(psync_encrypted_symmetric_key_t src);
void psync_ssl_free_symmetric_key(psync_symmetric_key_t key);
psync_encrypted_symmetric_key_t
psync_ssl_rsa_encrypt_data(psync_rsa_publickey_t rsa, const unsigned char *data,
                           size_t datalen);
psync_symmetric_key_t psync_ssl_rsa_decrypt_data(psync_rsa_privatekey_t rsa,
                                                 const unsigned char *data,
                                                 size_t datalen);
psync_encrypted_symmetric_key_t
psync_ssl_rsa_encrypt_symmetric_key(psync_rsa_publickey_t rsa,
                                    const psync_symmetric_key_t key);
psync_symmetric_key_t psync_ssl_rsa_decrypt_symmetric_key(
    psync_rsa_privatekey_t rsa, const psync_encrypted_symmetric_key_t enckey);
psync_aes256_encoder psync_ssl_aes256_create_encoder(psync_symmetric_key_t key);
void psync_ssl_aes256_free_encoder(psync_aes256_encoder aes);
psync_aes256_encoder psync_ssl_aes256_create_decoder(psync_symmetric_key_t key);
void psync_ssl_aes256_free_decoder(psync_aes256_encoder aes);
psync_rsa_signature_t psync_ssl_rsa_sign_sha256_hash(psync_rsa_privatekey_t rsa,
                                                     const unsigned char *data);
psync_symmetric_key_t psync_ssl_rsa_decrypt_symm_key_lock(
    psync_rsa_privatekey_t *rsa, const psync_encrypted_symmetric_key_t *enckey);

#endif
