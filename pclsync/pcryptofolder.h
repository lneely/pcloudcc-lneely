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

#ifndef __PCRYPTOFOLDER_H
#define __PCRYPTOFOLDER_H

#include "papi.h"
#include "pcrypto.h"
#include "pfsfolder.h"
#include "psynclib.h"

#define PSYNC_CRYPTO_SYM_FLAG_ISDIR 1

#define PSYNC_CRYPTO_SECTOR_SIZE 4096

#define PSYNC_CRYPTO_MAX_ERROR 511

#define PSYNC_CRYPTO_UNLOADED_SECTOR_ENCODER                                   \
  ((pcrypto_sector_encdec_t)(PSYNC_CRYPTO_MAX_ERROR + 1))
#define PSYNC_CRYPTO_LOADING_SECTOR_ENCODER                                    \
  ((pcrypto_sector_encdec_t)(PSYNC_CRYPTO_MAX_ERROR + 2))
#define PSYNC_CRYPTO_FAILED_SECTOR_ENCODER                                     \
  ((pcrypto_sector_encdec_t)(PSYNC_CRYPTO_MAX_ERROR + 3))

void pcryptofolder_cache_clean();
void pcryptofolder_cache_cleanf();
int pcryptofolder_change_pass(const char *oldpassphrase, const char *newpassphrase, uint32_t flags, char **privenc, char **sign);
int pcryptofolder_change_pass_unlocked(const char *newpassphrase, uint32_t flags, char **privenc, char **sign);
pcrypto_sector_encdec_t pcryptofolder_filencoder_from_binresult(psync_fileid_t fileid, binresult *res);
pcrypto_sector_encdec_t pcryptofolder_filencoder_get(psync_fsfileid_t fileid, uint64_t hash, int nonetwork);
char *pcryptofolder_filencoder_key_get(psync_fsfileid_t fileid, uint64_t hash, size_t *keylen);
char *pcryptofolder_filencoder_key_new(uint32_t flags, size_t *keylen);
char * pcryptofolder_filencoder_key_newplain(uint32_t flags, size_t *keylen, psync_symmetric_key_t *deckey);
void pcryptofolder_filencoder_release(psync_fsfileid_t fileid, uint64_t hash, pcrypto_sector_encdec_t encoder);
char * pcryptofolder_flddecode_filename(pcrypto_textdec_t decoder, const char *name);
pcrypto_textdec_t pcryptofolder_flddecoder_get(psync_fsfolderid_t folderid);
void pcryptofolder_flddecoder_release(psync_fsfolderid_t folderid, pcrypto_textdec_t decoder);
char * pcryptofolder_fldencode_filename(pcrypto_textenc_t encoder, const char *name);
pcrypto_textenc_t pcryptofolder_fldencoder_get(psync_fsfolderid_t folderid);
void pcryptofolder_fldencoder_release(psync_fsfolderid_t folderid, pcrypto_textenc_t encoder);
int pcryptofolder_get_hint(char **hint);
int pcryptofolder_is_unlocked();
int pcryptofolder_lock();
int pcryptofolder_mkdir(psync_folderid_t folderid, const char *name, const char **err, psync_folderid_t *newfolderid);
int pcryptofolder_reset();
int pcryptofolder_setup(const char *password, const char *hint);
int pcryptofolder_unlock(const char *password);

#endif
