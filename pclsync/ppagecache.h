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

#ifndef _PSYNC_PAGECACHE_H
#define _PSYNC_PAGECACHE_H

#include "pfs.h"

typedef struct {
  uint64_t offset;
  uint64_t size;
  char *buf;
} psync_pagecache_read_range;

void ppagecache_init();
int ppagecache_flush();
int ppagecache_read_mod_locked(psync_openfile_t *of, char *buf, uint64_t size, uint64_t offset);
int ppagecache_read_unmod_locked(psync_openfile_t *of, char *buf, uint64_t size, uint64_t offset);
int ppagecache_read_unmod_enc_locked(psync_openfile_t *of, char *buf, uint64_t size, uint64_t offset);
int ppagecache_readv_locked(psync_openfile_t *of, psync_pagecache_read_range *ranges, int cnt);
void ppagecache_creat(uint64_t taskid, uint64_t hash, int onthisthread);
void ppagecache_modify(uint64_t taskid, uint64_t hash, uint64_t oldhash);
int ppagecache_have_all_pages(uint64_t hash, uint64_t size);
int ppagecache_copy_to_file_locked(psync_openfile_t *of, uint64_t hash, uint64_t size);
int ppagecache_lock_pages();
void ppagecache_unlock_pages();
void ppagecache_resize();
uint64_t ppagecache_free_read(uint64_t size);
void ppagecache_clean();
void ppagecache_reopen_read();
void ppagecache_clean_read();
int ppagecache_move(const char *path);

#endif
