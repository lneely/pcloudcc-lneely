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

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/debug.h>
#include <mbedtls/entropy.h>
#include <mbedtls/pkcs5.h>
#include <mbedtls/ssl.h>
#include <pthread.h>

#include "pfile.h"
#include "pcompiler.h"

#include "pssl.h"

#include "pcrypto.h"
#include "plibs.h"
#include "pmemlock.h"
#include <stddef.h>
#include <string.h>

typedef struct {
  pssl_sha512_ctx sha1ctx;
  unsigned char final[PSSL_SHA512_BLOCK_LEN + PSSL_SHA512_DIGEST_LEN];
} psync_hmac_sha512_ctx;

static void psync_hmac_sha512_init(psync_hmac_sha512_ctx *ctx,
                                   const unsigned char *key, size_t keylen) {
  unsigned char keyxor[PSSL_SHA512_BLOCK_LEN];
  size_t i;
  if (keylen > PSSL_SHA512_BLOCK_LEN)
    keylen = PSSL_SHA512_BLOCK_LEN;
  for (i = 0; i < keylen; i++) {
    keyxor[i] = key[i] ^ 0x36;
    ctx->final[i] = key[i] ^ 0x5c;
  }
  for (; i < PSSL_SHA512_BLOCK_LEN; i++) {
    keyxor[i] = 0x36;
    ctx->final[i] = 0x5c;
  }
  psync_sha512_init(&ctx->sha1ctx);
  psync_sha512_update(&ctx->sha1ctx, keyxor, PSSL_SHA512_BLOCK_LEN);
  pssl_cleanup(keyxor, PSSL_SHA512_BLOCK_LEN);
}

static void psync_hmac_sha512_update(psync_hmac_sha512_ctx *ctx,
                                     const void *data, size_t len) {
  psync_sha512_update(&ctx->sha1ctx, data, len);
}

static void psync_hmac_sha512_final(unsigned char *result,
                                    psync_hmac_sha512_ctx *ctx) {
  psync_sha512_final(ctx->final + PSSL_SHA512_BLOCK_LEN, &ctx->sha1ctx);
  psync_sha512(ctx->final, PSSL_SHA512_BLOCK_LEN + PSSL_SHA512_DIGEST_LEN,
               result);
  pssl_cleanup(ctx->final,
                     PSSL_SHA512_BLOCK_LEN + PSSL_SHA512_DIGEST_LEN);
}

static void psync_hmac_sha512(const unsigned char *msg, size_t msglen,
                              const unsigned char *key, size_t keylen,
                              unsigned char *result) {
  pssl_sha512_ctx sha1ctx;
  unsigned char keyxor[PSSL_SHA512_BLOCK_LEN],
      final[PSSL_SHA512_BLOCK_LEN + PSSL_SHA512_DIGEST_LEN];
  size_t i;
  if (keylen > PSSL_SHA512_BLOCK_LEN)
    keylen = PSSL_SHA512_BLOCK_LEN;
  for (i = 0; i < keylen; i++) {
    keyxor[i] = key[i] ^ 0x36;
    final[i] = key[i] ^ 0x5c;
  }
  for (; i < PSSL_SHA512_BLOCK_LEN; i++) {
    keyxor[i] = 0x36;
    final[i] = 0x5c;
  }
  psync_sha512_init(&sha1ctx);
  psync_sha512_update(&sha1ctx, keyxor, PSSL_SHA512_BLOCK_LEN);
  psync_sha512_update(&sha1ctx, msg, msglen);
  psync_sha512_final(final + PSSL_SHA512_BLOCK_LEN, &sha1ctx);
  psync_sha512(final, PSSL_SHA512_BLOCK_LEN + PSSL_SHA512_DIGEST_LEN, result);
  pssl_cleanup(keyxor, PSSL_SHA512_BLOCK_LEN);
  pssl_cleanup(final, PSSL_SHA512_BLOCK_LEN + PSSL_SHA512_DIGEST_LEN);
}

#define ALIGN_A256_BS(n)                                                       \
  ((((n) + PAES_BLOCK_SIZE - 1) / PAES_BLOCK_SIZE) *           \
   PAES_BLOCK_SIZE)
#define ALIGN_PTR_A256_BS(ptr)                                                 \
  ((unsigned char *)ALIGN_A256_BS((uintptr_t)(ptr)))

#define IS_WORD_ALIGNED(ptr) (((uintptr_t)ptr) % sizeof(unsigned long) == 0)

static void xor16_unaligned_inplace(unsigned char *data,
                                    const unsigned char *key) {
  unsigned long i;
  for (i = 0; i < PAES_BLOCK_SIZE; i++)
    data[i] ^= key[i];
}

#define LONG_DEREF(x, a) ((unsigned long *)(x))[a]

static void xor16_aligned_inplace(unsigned char *data,
                                  const unsigned char *key) {
  if (sizeof(unsigned long) == 8) {
    LONG_DEREF(data, 0) ^= LONG_DEREF(key, 0);
    LONG_DEREF(data, 1) ^= LONG_DEREF(key, 1);
  } else if (sizeof(unsigned long) == 4) {
    LONG_DEREF(data, 0) ^= LONG_DEREF(key, 0);
    LONG_DEREF(data, 1) ^= LONG_DEREF(key, 1);
    LONG_DEREF(data, 2) ^= LONG_DEREF(key, 2);
    LONG_DEREF(data, 3) ^= LONG_DEREF(key, 3);
  } else
    xor16_unaligned_inplace(data, key);
}

static void xor_cnt_inplace(unsigned char *data, const unsigned char *key,
                            size_t count) {
  size_t i;
  for (i = 0; i < count; i++)
    data[i] ^= key[i];
}

static void copy_iv_and_xor_with_counter(unsigned char *dest,
                                         const unsigned char *iv,
                                         uint64_t counter) {
  if (sizeof(unsigned long) == 8) {
    LONG_DEREF(dest, 0) = LONG_DEREF(iv, 0) ^ counter;
  } else if (sizeof(unsigned long) == 4) {
    LONG_DEREF(dest, 0) = LONG_DEREF(iv, 0) ^ (counter & 0xffffffffU);
    LONG_DEREF(dest, 1) = LONG_DEREF(iv, 1) ^ (counter >> 32);
  }
}

pssl_symkey_t *pcrypto_key_len(size_t len) {
  pssl_symkey_t *key;
  key = (pssl_symkey_t *)pmemlock_malloc(
      offsetof(pssl_symkey_t, key) + len);
  key->keylen = len;
  pssl_random(key->key, len);
  return key;
}

pssl_symkey_t *pcrypto_key() {
  return pcrypto_key_len(PAES_KEY_SIZE +
                                         PAES_BLOCK_SIZE);
}

pcrypto_ctr_encdec_t
pcrypto_ctr_encdec_create(pssl_symkey_t *key) {
  pssl_encoder_t enc;
  pcrypto_ctr_encdec_t ret;
  if (unlikely_log(key->keylen <
                   PAES_KEY_SIZE + PAES_BLOCK_SIZE))
    return PSYNC_CRYPTO_INVALID_ENCODER;
  enc = paes_encoder_create(key);
  if (unlikely_log(enc == PAES_INVALID_ENCODER))
    return PSYNC_CRYPTO_INVALID_ENCODER;
  ret = psync_new(pcrypto_key_t);
  ret->encoder = enc;
  memcpy(ret->iv, key->key + PAES_KEY_SIZE, PAES_BLOCK_SIZE);
  return ret;
}

void pcrypto_ctr_encdec_free(
    pcrypto_ctr_encdec_t enc) {
  paes_encoder_free(enc->encoder);
  pssl_cleanup(enc->iv, PAES_BLOCK_SIZE);
  psync_free(enc);
}

void pcrypto_ctr_encdec_decode(
    pcrypto_ctr_encdec_t enc, void *data, size_t datalen,
    uint64_t dataoffset) {
  unsigned char buff[PAES_BLOCK_SIZE * 3], *aessrc, *aesdst;
  uint64_t counter;
  size_t blocksrem;
  aessrc = ALIGN_PTR_A256_BS(buff);
  aesdst = aessrc + PAES_BLOCK_SIZE;
  counter = dataoffset / PAES_BLOCK_SIZE;
  memcpy(aessrc + sizeof(uint64_t), enc->iv + sizeof(uint64_t),
         PAES_BLOCK_SIZE - sizeof(uint64_t));
  dataoffset %= PAES_BLOCK_SIZE;
  if (dataoffset) {
    copy_iv_and_xor_with_counter(aessrc, enc->iv, counter);
    paes_blk_encode(enc->encoder, aessrc, aesdst);
    blocksrem = PAES_BLOCK_SIZE - dataoffset;
    xor_cnt_inplace(data, aesdst + dataoffset, blocksrem);
    datalen -= blocksrem;
    counter++;
    data = (char *)data + blocksrem;
  }
  blocksrem = datalen / PAES_BLOCK_SIZE;
  datalen -= blocksrem * PAES_BLOCK_SIZE;
  if (IS_WORD_ALIGNED(data)) {
    while (blocksrem) {
      copy_iv_and_xor_with_counter(aessrc, enc->iv, counter);
      paes_blk_encode(enc->encoder, aessrc, aesdst);
      xor16_aligned_inplace(data, aesdst);
      blocksrem--;
      counter++;
      data = (char *)data + PAES_BLOCK_SIZE;
    }
  } else {
    while (blocksrem) {
      copy_iv_and_xor_with_counter(aessrc, enc->iv, counter);
      paes_blk_encode(enc->encoder, aessrc, aesdst);
      xor16_unaligned_inplace(data, aesdst);
      blocksrem--;
      counter++;
      data = (char *)data + PAES_BLOCK_SIZE;
    }
  }
  if (datalen) {
    copy_iv_and_xor_with_counter(aessrc, enc->iv, counter);
    paes_blk_encode(enc->encoder, aessrc, aesdst);
    xor_cnt_inplace(data, aesdst, datalen);
  }
}

static void copy_unaligned(unsigned char *dst, const unsigned char *src) {
  memcpy(dst, src, PAES_BLOCK_SIZE);
}

static void copy_aligned(unsigned char *dst, const unsigned char *src) {
  if (sizeof(unsigned long) == 8) {
    LONG_DEREF(dst, 0) = LONG_DEREF(src, 0);
    LONG_DEREF(dst, 1) = LONG_DEREF(src, 1);
  } else if (sizeof(unsigned long) == 4) {
    LONG_DEREF(dst, 0) = LONG_DEREF(src, 0);
    LONG_DEREF(dst, 1) = LONG_DEREF(src, 1);
    LONG_DEREF(dst, 2) = LONG_DEREF(src, 2);
    LONG_DEREF(dst, 3) = LONG_DEREF(src, 3);
  } else
    copy_unaligned(dst, src);
}

static void copy_pad(unsigned char *dst, size_t cnt,
                     const unsigned char **restrict txt,
                     size_t *restrict txtlen) {
  if (cnt <= *txtlen) {
    memcpy(dst, *txt, cnt);
    *txt += cnt;
    *txtlen -= cnt;
  } else {
    memcpy(dst, *txt, *txtlen);
    dst += *txtlen;
    memset(dst, 0, cnt - *txtlen);
    *txtlen = 0;
  }
}

void pcrypto_encode_text(pcrypto_textenc_t enc,
                                     const unsigned char *txt, size_t txtlen,
                                     unsigned char **out, size_t *outlen) {
  unsigned char buff[PAES_BLOCK_SIZE * 3 + PSSL_SHA512_DIGEST_LEN],
      *aessrc, *aesdst, *outptr, *hmac;
  size_t ol;
  aessrc = ALIGN_PTR_A256_BS(buff);
  aesdst = aessrc + PAES_BLOCK_SIZE;
  hmac = aessrc + PAES_BLOCK_SIZE * 2;
  ol = ALIGN_A256_BS(txtlen);
  outptr = psync_new_cnt(unsigned char, ol);
  *out = outptr;
  *outlen = ol;
  if (txtlen <= PAES_BLOCK_SIZE) {
    copy_pad(aessrc, PAES_BLOCK_SIZE, &txt, &txtlen);
    assert(enc->ivlen >= PAES_BLOCK_SIZE);
    xor16_aligned_inplace(aessrc, enc->iv);
    paes_blk_encode(enc->encoder, aessrc, aesdst);
    copy_aligned(outptr, aesdst);
    return;
  }
  psync_hmac_sha512(txt + PAES_BLOCK_SIZE,
                    txtlen - PAES_BLOCK_SIZE, enc->iv, enc->ivlen,
                    hmac);
  copy_unaligned(aessrc, txt);
  txt += PAES_BLOCK_SIZE;
  txtlen -= PAES_BLOCK_SIZE;
  xor16_aligned_inplace(aessrc, hmac);
  paes_blk_encode(enc->encoder, aessrc, aesdst);
  copy_aligned(outptr, aesdst);
  outptr += PAES_BLOCK_SIZE;
  do {
    copy_pad(aessrc, PAES_BLOCK_SIZE, &txt, &txtlen);
    xor16_aligned_inplace(aessrc, aesdst);
    paes_blk_encode(enc->encoder, aessrc, aesdst);
    copy_aligned(outptr, aesdst);
    outptr += PAES_BLOCK_SIZE;
  } while (txtlen);
}

unsigned char *
pcrypto_decode_text(pcrypto_textdec_t enc,
                                const unsigned char *data, size_t datalen) {
  unsigned char buff[PAES_BLOCK_SIZE * 2 + PSSL_SHA512_DIGEST_LEN],
      *aessrc, *aesdst, *outptr, *ret;
  size_t len;
  const unsigned char *xorptr;
  if (unlikely_log(datalen % PAES_BLOCK_SIZE || !datalen))
    return NULL;
  aessrc = ALIGN_PTR_A256_BS(buff);
  aesdst = aessrc + PAES_BLOCK_SIZE;
  outptr = psync_new_cnt(unsigned char, datalen + 1);
  ret = outptr;
  datalen /= PAES_BLOCK_SIZE;
  if (datalen == 1) {
    copy_unaligned(aessrc, data);
    paes_blk_decode(enc->encoder, aessrc, aesdst);
    assert(enc->ivlen >= PAES_BLOCK_SIZE);
    xor16_aligned_inplace(aesdst, enc->iv);
    copy_aligned(outptr, aesdst);
    outptr += PAES_BLOCK_SIZE;
    *outptr = 0;
    len = strlen((char *)ret) + 1;
    while (ret + len < outptr) {
      if (unlikely(ret[len] != 0)) {
        debug(D_WARNING, "non-zero in the padding found");
        psync_free(ret);
        return NULL;
      }
      len++;
    }
    return ret;
  }
  if (IS_WORD_ALIGNED(data)) {
    copy_aligned(aessrc, data);
    paes_blk_decode(enc->encoder, aessrc, aesdst);
    copy_aligned(outptr, aesdst);
    outptr += PAES_BLOCK_SIZE;
    while (--datalen) {
      xorptr = data;
      data += PAES_BLOCK_SIZE;
      copy_aligned(aessrc, data);
      paes_blk_decode(enc->encoder, aessrc, aesdst);
      xor16_aligned_inplace(aesdst, xorptr);
      copy_aligned(outptr, aesdst);
      outptr += PAES_BLOCK_SIZE;
    }
  } else {
    copy_unaligned(aessrc, data);
    paes_blk_decode(enc->encoder, aessrc, aesdst);
    copy_aligned(outptr, aesdst);
    outptr += PAES_BLOCK_SIZE;
    while (--datalen) {
      xorptr = data;
      data += PAES_BLOCK_SIZE;
      copy_unaligned(aessrc, data);
      paes_blk_decode(enc->encoder, aessrc, aesdst);
      xor16_unaligned_inplace(aesdst, xorptr);
      copy_aligned(outptr, aesdst);
      outptr += PAES_BLOCK_SIZE;
    }
  }
  *outptr = 0;
  len = strlen((char *)ret + PAES_BLOCK_SIZE);
  psync_hmac_sha512(ret + PAES_BLOCK_SIZE, len, enc->iv, enc->ivlen,
                    aessrc);
  xor16_aligned_inplace(ret, aessrc);
  len += PAES_BLOCK_SIZE + 1;
  while (ret + len < outptr) {
    if (unlikely(ret[len] != 0)) {
      debug(D_WARNING, "non-zero in the padding found");
      psync_free(ret);
      return NULL;
    }
    len++;
  }
  return ret;
}

pcrypto_textenc_t
pcrypto_textenc_create(pssl_symkey_t *key) {
  pssl_encoder_t enc;
  pcrypto_textenc_t ret;
  if (unlikely_log(key->keylen <
                   PAES_KEY_SIZE + PAES_BLOCK_SIZE))
    return PSYNC_CRYPTO_INVALID_ENCODER;
  enc = paes_encoder_create(key);
  if (unlikely_log(enc == PAES_INVALID_ENCODER))
    return PSYNC_CRYPTO_INVALID_ENCODER;
  ret = (pcrypto_textenc_t)pmemlock_malloc(
      offsetof(pcrypto_key_iv_t, iv) + key->keylen -
      PAES_KEY_SIZE);
  ret->encoder = enc;
  ret->ivlen = key->keylen - PAES_KEY_SIZE;
  memcpy(ret->iv, key->key + PAES_KEY_SIZE, ret->ivlen);
  return ret;
}

void pcrypto_textenc_free(
    pcrypto_textenc_t enc) {
  paes_encoder_free(enc->encoder);
  pssl_cleanup(enc->iv, enc->ivlen);
  pmemlock_free(enc);
}

pcrypto_textdec_t
pcrypto_textdec_create(pssl_symkey_t *key) {
  pssl_encoder_t enc;
  pcrypto_textenc_t ret;
  if (unlikely_log(key->keylen <
                   PAES_KEY_SIZE + PAES_BLOCK_SIZE))
    return PSYNC_CRYPTO_INVALID_ENCODER;
  enc = paes_decoder_create(key);
  if (unlikely_log(enc == PAES_INVALID_ENCODER))
    return PSYNC_CRYPTO_INVALID_ENCODER;
  ret = (pcrypto_textenc_t)pmemlock_malloc(
      offsetof(pcrypto_key_iv_t, iv) + key->keylen -
      PAES_KEY_SIZE);
  ret->encoder = enc;
  ret->ivlen = key->keylen - PAES_KEY_SIZE;
  memcpy(ret->iv, key->key + PAES_KEY_SIZE, ret->ivlen);
  return ret;
}

void pcrypto_textdec_free(
    pcrypto_textdec_t enc) {
  paes_encoder_free(enc->encoder);
  pssl_cleanup(enc->iv, enc->ivlen);
  pmemlock_free(enc);
}

pcrypto_sector_encdec_t
pcrypto_sec_encdec_create(pssl_symkey_t *key) {
  pssl_encoder_t enc;
  pssl_decoder_t dec;
  pcrypto_sector_encdec_t ret;
  if (unlikely_log(key->keylen < PAES_KEY_SIZE))
    return PSYNC_CRYPTO_INVALID_ENCODER;
  enc = paes_encoder_create(key);
  if (unlikely_log(enc == PAES_INVALID_ENCODER))
    return PSYNC_CRYPTO_INVALID_ENCODER;
  dec = paes_decoder_create(key);
  if (unlikely_log(enc == PAES_INVALID_ENCODER)) {
    paes_encoder_free(enc);
    return PSYNC_CRYPTO_INVALID_ENCODER;
  }
  ret = (pcrypto_sector_encdec_t)pmemlock_malloc(
      offsetof(pcrypto_encdec_iv_t, iv) + key->keylen -
      PAES_KEY_SIZE);
  ret->encoder = enc;
  ret->decoder = dec;
  ret->ivlen = key->keylen - PAES_KEY_SIZE;
  memcpy(ret->iv, key->key + PAES_KEY_SIZE, ret->ivlen);
  return ret;
}

void pcrypto_sec_encdec_free(
    pcrypto_sector_encdec_t enc) {
  paes_encoder_free(enc->encoder);
  paes_decoder_free(enc->decoder);
  pssl_cleanup(enc->iv, enc->ivlen);
  pmemlock_free(enc);
}

static int memcmp_const(const unsigned char *s1, const unsigned char *s2,
                        size_t cnt) {
  size_t i;
  uint32_t r;
  r = 0;
  for (i = 0; i < cnt; i++)
    r |= s1[i] ^ s2[i];
  return (((r - 1) >> 8) & 1) ^ 1;
}

void pcrypto_encode_sec(
    pcrypto_sector_encdec_t enc, const unsigned char *data,
    size_t datalen, unsigned char *out, pcrypto_sector_auth_t authout,
    uint64_t sectorid) {
  psync_hmac_sha512_ctx ctx;
  unsigned char buff[PAES_BLOCK_SIZE * 3],
      hmacsha1bin[PSSL_SHA512_DIGEST_LEN], rnd[PAES_BLOCK_SIZE];
  unsigned char *aessrc, *aesdst, *tmp;
  uint32_t needsteal;
  aessrc = ALIGN_PTR_A256_BS(buff);
  aesdst = aessrc + PAES_BLOCK_SIZE;
  assert(PSYNC_CRYPTO_AUTH_SIZE == 2 * PAES_BLOCK_SIZE);
  pssl_random(rnd, PAES_BLOCK_SIZE);
  psync_hmac_sha512_init(&ctx, enc->iv, enc->ivlen);
  psync_hmac_sha512_update(&ctx, data, datalen);
  psync_hmac_sha512_update(&ctx, &sectorid, sizeof(sectorid));
  psync_hmac_sha512_update(&ctx, rnd, PAES_BLOCK_SIZE);
  psync_hmac_sha512_final(hmacsha1bin, &ctx);
  if (unlikely(datalen < PAES_BLOCK_SIZE)) {
    memcpy(aessrc, rnd, PAES_BLOCK_SIZE);
    xor_cnt_inplace(aessrc, data, datalen);
    memcpy(out, rnd, datalen);
    memcpy(aesdst, hmacsha1bin, PAES_BLOCK_SIZE);
    paes_2blk_encode(enc->encoder, aessrc, aessrc);
    memcpy(authout, aessrc, PAES_BLOCK_SIZE * 2);
    return;
  }
  if (unlikely(datalen % 16)) {
    needsteal = datalen % 16;
    datalen -= needsteal + PAES_BLOCK_SIZE;
  } else
    needsteal = 0;
  memcpy(aessrc, rnd, PAES_BLOCK_SIZE / 2);
  memcpy(aessrc + PAES_BLOCK_SIZE / 2, hmacsha1bin,
         PAES_BLOCK_SIZE);
  memcpy(aessrc + PAES_BLOCK_SIZE + PAES_BLOCK_SIZE / 2,
         rnd + PAES_BLOCK_SIZE / 2, PAES_BLOCK_SIZE / 2);
  paes_2blk_encode(enc->encoder, aessrc, aessrc);
  memcpy(authout, aessrc, PAES_BLOCK_SIZE * 2);
  memcpy(aessrc, hmacsha1bin, PAES_BLOCK_SIZE);
  if (IS_WORD_ALIGNED(data) && IS_WORD_ALIGNED(out))
    while (datalen) {
      xor16_aligned_inplace(aessrc, data);
      paes_blk_encode(enc->encoder, aessrc, aesdst);
      copy_aligned(out, aesdst);
      datalen -= PAES_BLOCK_SIZE;
      data += PAES_BLOCK_SIZE;
      out += PAES_BLOCK_SIZE;
      tmp = aessrc;
      aessrc = aesdst;
      aesdst = tmp;
    }
  else
    while (datalen) {
      xor16_unaligned_inplace(aessrc, data);
      paes_blk_encode(enc->encoder, aessrc, aesdst);
      copy_unaligned(out, aesdst);
      datalen -= PAES_BLOCK_SIZE;
      data += PAES_BLOCK_SIZE;
      out += PAES_BLOCK_SIZE;
      tmp = aessrc;
      aessrc = aesdst;
      aesdst = tmp;
    }
  if (unlikely(needsteal)) {
    xor16_unaligned_inplace(aessrc, data);
    data += PAES_BLOCK_SIZE;
    paes_blk_encode(enc->encoder, aessrc, aesdst);
    memcpy(out + PAES_BLOCK_SIZE, aesdst, needsteal);
    xor_cnt_inplace(aesdst, data, needsteal);
    paes_blk_encode(enc->encoder, aesdst, aessrc);
    copy_unaligned(out, aessrc);
  }
}

int pcrypto_decode_sec(
    pcrypto_sector_encdec_t enc, const unsigned char *data,
    size_t datalen, unsigned char *out, const pcrypto_sector_auth_t auth,
    uint64_t sectorid) {
  psync_hmac_sha512_ctx ctx;
  unsigned char buff[PAES_BLOCK_SIZE * 15],
      hmacsha1bin[PSSL_SHA512_DIGEST_LEN];
  unsigned char *aessrc, *aesdst, *aesxor, *hmac, *oout, *tmp;
  size_t odatalen;
  uint32_t needsteal;
  aessrc = ALIGN_PTR_A256_BS(buff);
  aesdst = aessrc + PAES_BLOCK_SIZE * 4;
  aesxor = aessrc + PAES_BLOCK_SIZE * 8;
  hmac = aessrc + PAES_BLOCK_SIZE * 12;
  memcpy(aessrc, auth, PAES_BLOCK_SIZE * 2);
  paes_2blk_decode(enc->decoder, aessrc, hmac);
  oout = out;
  odatalen = datalen;
  if (unlikely(datalen < PAES_BLOCK_SIZE)) {
    xor_cnt_inplace(hmac, data, datalen);
    memcpy(aessrc, data, datalen);
    memcpy(out, hmac, datalen);
    memcpy(hmac, aessrc, datalen);
  } else {
    if (unlikely(datalen % 16)) {
      needsteal = datalen % 16;
      datalen -= needsteal + PAES_BLOCK_SIZE;
    } else
      needsteal = 0;
    memcpy(aesxor, hmac + PAES_BLOCK_SIZE / 2, PAES_BLOCK_SIZE);
    memcpy(hmac + PAES_BLOCK_SIZE / 2,
           hmac + PAES_BLOCK_SIZE + PAES_BLOCK_SIZE / 2,
           PAES_BLOCK_SIZE / 2);
    memcpy(hmac + PAES_BLOCK_SIZE, aesxor, PAES_BLOCK_SIZE);
    while (datalen >= PAES_BLOCK_SIZE * 4) {
      memcpy(aessrc, data, PAES_BLOCK_SIZE * 4);
      memcpy(aesxor + PAES_BLOCK_SIZE, aessrc,
             PAES_BLOCK_SIZE * 3);
      paes_4blk_xor_decode(enc->decoder, aessrc, aesdst,
                                             aesxor);
      memcpy(out, aesdst, PAES_BLOCK_SIZE * 4);
      memcpy(aesxor, aessrc + PAES_BLOCK_SIZE * 3,
             PAES_BLOCK_SIZE);
      datalen -= PAES_BLOCK_SIZE * 4;
      data += PAES_BLOCK_SIZE * 4;
      out += PAES_BLOCK_SIZE * 4;
    }
    while (datalen) {
      copy_unaligned(aessrc, data);
      paes_blk_decode(enc->decoder, aessrc, aesdst);
      xor16_aligned_inplace(aesdst, aesxor);
      copy_unaligned(out, aesdst);
      data += PAES_BLOCK_SIZE;
      out += PAES_BLOCK_SIZE;
      datalen -= PAES_BLOCK_SIZE;
      tmp = aesxor;
      aesxor = aessrc;
      aessrc = tmp;
    }
    if (unlikely(needsteal)) {
      copy_unaligned(aessrc, data);
      paes_blk_decode(enc->decoder, aessrc, aesdst);
      xor_cnt_inplace(aesdst, data + PAES_BLOCK_SIZE, needsteal);
      // can be done with less memcpy's, but this version supports inline
      // decoding (e.g. data==out)
      memcpy(aessrc, data + PAES_BLOCK_SIZE, needsteal);
      memcpy(out + PAES_BLOCK_SIZE, aesdst, needsteal);
      memcpy(aesdst, aessrc, needsteal);
      paes_blk_decode(enc->decoder, aesdst, aessrc);
      xor16_aligned_inplace(aessrc, aesxor);
      copy_unaligned(out, aessrc);
    }
  }
  psync_hmac_sha512_init(&ctx, enc->iv, enc->ivlen);
  psync_hmac_sha512_update(&ctx, oout, odatalen);
  psync_hmac_sha512_update(&ctx, &sectorid, sizeof(sectorid));
  psync_hmac_sha512_update(&ctx, hmac, PAES_BLOCK_SIZE);
  psync_hmac_sha512_final(hmacsha1bin, &ctx);
  return -memcmp_const(hmacsha1bin, hmac + PAES_BLOCK_SIZE,
                       PAES_BLOCK_SIZE);
}

void pcrypto_sign_sec(
    pcrypto_sector_encdec_t enc, const unsigned char *data,
    size_t datalen, pcrypto_sector_auth_t authout) {
  unsigned char buff[PAES_BLOCK_SIZE * 3 + PSSL_SHA512_DIGEST_LEN];
  unsigned char *aessrc, *aesdst;
  aesdst = ALIGN_PTR_A256_BS(buff);
  aessrc = aesdst + PAES_BLOCK_SIZE * 2;
  psync_hmac_sha512(data, datalen, enc->iv, enc->ivlen, aessrc);
  paes_2blk_encode(enc->encoder, aessrc, aesdst);
  memcpy(authout, aesdst, PAES_BLOCK_SIZE * 2);
}
