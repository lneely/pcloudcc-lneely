/*
 * pssl_crypto_compat.h provides a compatibility layer for mbedtls 4.x
 * migration.
 *
 * Copyright (c) 2026 Levi Neely. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met: Redistributions of source code must retain the above
 * copyright notice, this list of conditions and the following
 * disclaimer.  Redistributions in binary form must reproduce the
 * above copyright notice, this list of conditions and the following
 * disclaimer in the documentation and/or other materials provided
 * with the distribution.  Neither the name of pCloud Ltd nor the
 * names of its contributors may be used to endorse or promote
 * products derived from this software without specific prior written
 * permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL pCloud
 * Ltd BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

#ifndef __PSYNC_SSL_CRYPTO_COMPAT_H
#define __PSYNC_SSL_CRYPTO_COMPAT_H

#include <stddef.h>

#include <mbedtls/version.h>

#if MBEDTLS_VERSION_MAJOR >= 4

// mbedtls 4.x
#include <psa/crypto.h>

typedef struct {
    psa_hash_operation_t operation;
} psync_sha1_context;

typedef struct {
    psa_hash_operation_t operation;
} psync_sha256_context;

typedef struct {
    psa_hash_operation_t operation;
} psync_sha512_context;

typedef struct psync_rsa_struct {
    psa_key_id_t key_id;
    size_t bits;
} psync_rsa_struct;

typedef struct psync_aes256_encoder_struct {
    psa_key_id_t key_id;
} psync_aes256_encoder_struct;

typedef psync_aes256_encoder_struct psync_aes256_decoder_struct;

#else // MBEDTLS_VERSION_MAJOR >= 4

#include <mbedtls/aes.h>
#include <mbedtls/rsa.h>
#include <mbedtls/sha1.h>
#include <mbedtls/sha256.h>
#include <mbedtls/sha512.h>

typedef struct {
    mbedtls_sha1_context context;
} psync_sha1_context;

typedef struct {
    mbedtls_sha256_context context;
} psync_sha256_context;

typedef struct {
    mbedtls_sha512_context context;
} psync_sha512_context;

typedef struct psync_rsa_struct {
    mbedtls_rsa_context ctx;
} psync_rsa_struct;

typedef struct psync_aes256_encoder_struct {
    mbedtls_aes_context ctx;
} psync_aes256_encoder_struct;

typedef psync_aes256_encoder_struct psync_aes256_decoder_struct;

#endif // MBEDTLS_VERSION_MAJOR >/ 4

typedef psync_sha1_context psync_sha1_ctx;
typedef psync_sha256_context psync_sha256_ctx;
typedef psync_sha512_context psync_sha512_ctx;

typedef struct psync_rsa_struct *psync_rsa_t;
typedef struct psync_rsa_struct *psync_rsa_publickey_t;
typedef struct psync_rsa_struct *psync_rsa_privatekey_t;
typedef struct psync_aes256_encoder_struct *psync_aes256_encoder;
typedef struct psync_aes256_encoder_struct *psync_aes256_decoder;

#endif // __PSYNC_SSL_CRYPTO_COMPAT_H
