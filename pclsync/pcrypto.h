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

#ifndef _PSYNC_CRYPTO_H
#define _PSYNC_CRYPTO_H

#include "pssl.h"

#define PSYNC_CRYPTO_AUTH_SIZE (PSYNC_AES256_BLOCK_SIZE * 2)

#define PSYNC_CRYPTO_MAX_HASH_TREE_LEVEL 6

typedef struct {
  uint64_t masterauthoff;
  uint64_t plainsize;
  uint64_t lastauthsectoroff[PSYNC_CRYPTO_MAX_HASH_TREE_LEVEL];
  uint16_t lastauthsectorlen[PSYNC_CRYPTO_MAX_HASH_TREE_LEVEL];
  uint8_t treelevels;
  uint8_t needmasterauth;
} psync_crypto_offsets_t;

typedef unsigned char pcrypto_sector_auth_t[PSYNC_CRYPTO_AUTH_SIZE];

typedef struct {
  pssl_encoder_t encoder;
  union {
    long unsigned __aligner;
    unsigned char iv[PSYNC_AES256_BLOCK_SIZE];
  };
} pcrypto_key_t;

typedef pcrypto_key_t *pcrypto_ctr_encdec_t;

typedef struct {
  pssl_encoder_t encoder;
  unsigned long ivlen;
  unsigned char iv[];
} pcrypto_key_iv_t;

typedef pcrypto_key_iv_t *pcrypto_textenc_t;
typedef pcrypto_key_iv_t *pcrypto_textdec_t;

typedef struct {
  pssl_encoder_t encoder;
  pssl_decoder_t decoder;
  unsigned long ivlen;
  unsigned char iv[];
} pcrypto_encdec_iv_t;

typedef pcrypto_encdec_iv_t *pcrypto_sector_encdec_t;

#define pcrypto_text_gen_key pcrypto_ctr_gen_key
#define pcrypto_sector_gen_key pcrypto_ctr_gen_key

#define PSYNC_CRYPTO_INVALID_ENCODER NULL
#define PSYNC_CRYPTO_INVALID_REVISIONID ((uint32_t)-1)

pcrypto_ctr_encdec_t pcrypto_ctr_encdec_create(pssl_symkey_t *key);
void pcrypto_ctr_encdec_encode(pcrypto_ctr_encdec_t enc, void *data, size_t datalen, uint64_t dataoffset);
void pcrypto_ctr_encdec_free(pcrypto_ctr_encdec_t enc);
int pcrypto_decode_sec(pcrypto_sector_encdec_t enc, const unsigned char *data, size_t datalen, unsigned char *out, const pcrypto_sector_auth_t auth, uint64_t sectorid);
unsigned char * pcrypto_decode_text(pcrypto_textdec_t enc, const unsigned char *data, size_t datalen);
void pcrypto_encode_sec(pcrypto_sector_encdec_t enc, const unsigned char *data, size_t datalen, unsigned char *out, pcrypto_sector_auth_t authout, uint64_t sectorid);
void pcrypto_encode_text(pcrypto_textenc_t enc, const unsigned char *txt, size_t txtlen, unsigned char **out, size_t *outlen);
pssl_symkey_t *pcrypto_key();
pssl_symkey_t *pcrypto_key_len(size_t len);
pcrypto_sector_encdec_t pcrypto_sec_encdec_create(pssl_symkey_t *key);
void pcrypto_sec_encdec_free(pcrypto_sector_encdec_t enc);
void pcrypto_sign_sec(pcrypto_sector_encdec_t enc, const unsigned char *data, size_t datalen, pcrypto_sector_auth_t authout);
pcrypto_textdec_t pcrypto_textdec_create(pssl_symkey_t *key);
void pcrypto_textdec_free(pcrypto_textdec_t enc);
pcrypto_textenc_t pcrypto_textenc_create(pssl_symkey_t *key);
void pcrypto_textenc_free(pcrypto_textenc_t enc);

#endif
