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

#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#include "pdbg.h"
#include "pfile.h"
#include "plibs.h"
#include "ptimer.h"
#include "putil.h"

struct run_after_ptr {
  struct run_after_ptr *next;
  psync_run_after_t run;
  void *ptr;
};


static const uint8_t __hex_lookupl[513] = {"000102030405060708090a0b0c0d0e0f"
                                           "101112131415161718191a1b1c1d1e1f"
                                           "202122232425262728292a2b2c2d2e2f"
                                           "303132333435363738393a3b3c3d3e3f"
                                           "404142434445464748494a4b4c4d4e4f"
                                           "505152535455565758595a5b5c5d5e5f"
                                           "606162636465666768696a6b6c6d6e6f"
                                           "707172737475767778797a7b7c7d7e7f"
                                           "808182838485868788898a8b8c8d8e8f"
                                           "909192939495969798999a9b9c9d9e9f"
                                           "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"
                                           "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
                                           "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
                                           "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
                                           "e0e1e2e3e4e5e6e7e8e9eaebecedeeef"
                                           "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"};

uint16_t const *__hex_lookup = (uint16_t *)__hex_lookupl;

char psync_my_auth[64] = "", psync_my_2fa_code[32], *psync_my_user = NULL,
     *psync_my_pass = NULL, *psync_my_2fa_token = NULL,
     *psync_my_verify_token = NULL;
int psync_my_2fa_code_type = 0, psync_my_2fa_trust = 0,
    psync_my_2fa_has_devices = 0, psync_my_2fa_type = 1;
uint64_t psync_my_userid = 0;
pthread_mutex_t psync_my_auth_mutex = PTHREAD_MUTEX_INITIALIZER;


int psync_rename_conflicted_file(const char *path) {
  char *npath;
  size_t plen, dotidx;
  struct stat st;
  long num, l;
  plen = strlen(path);
  dotidx = plen;
  while (dotidx && path[dotidx] != '.')
    dotidx--;
  if (!dotidx)
    dotidx = plen;
  npath = (char *)malloc(plen + 32);
  memcpy(npath, path, dotidx);
  num = 0;
  while (1) {
    if (num)
      l = psync_slprintf(npath + dotidx, 32, " (conflicted %ld)", num);
    else {
      l = 13;
      memcpy(npath + dotidx, " (conflicted)", l);
    }
    memcpy(npath + dotidx + l, path + dotidx, plen - dotidx + 1);
    if (stat(npath, &st)) {
      pdbg_logf(D_NOTICE, "renaming conflict %s to %s", path, npath);
      l = pfile_rename(path, npath);
      free(npath);
      return l;
    }
    num++;
  }
}

static void run_after_sec(psync_timer_t timer, void *ptr) {
  struct run_after_ptr *fp = (struct run_after_ptr *)ptr;
  ptimer_stop(timer);
  fp->run(fp->ptr);
  free(fp);
}

void psync_run_after_sec(psync_run_after_t run, void *ptr, uint32_t seconds) {
  struct run_after_ptr *fp;
  fp = malloc(sizeof(struct run_after_ptr));
  fp->run = run;
  fp->ptr = ptr;
  ptimer_register(run_after_sec, seconds, fp);
}

static void proc_free_after(psync_timer_t timer, void *ptr) {
  ptimer_stop(timer);
  free(ptr);
}

void psync_free_after_sec(void *ptr, uint32_t seconds) {
  ptimer_register(proc_free_after, seconds, ptr);
}

int psync_match_pattern(const char *name, const char *pattern, size_t plen) {
  size_t i;
  for (i = 0; i < plen; i++) {
    if (pattern[i] == '*') {
      name += i;
      while (1) {
        if (++i == plen)
          return 1;
        switch (pattern[i]) {
        case '?':
          if (!*name++)
            return 0;
        case '*':
          break;
        default:
          name = strchr(name, pattern[i]);
          pattern += i + 1;
          plen -= i + 1;
          while (name) {
            name++;
            if (psync_match_pattern(name, pattern, plen))
              return 1;
            name = strchr(name, *(pattern - 1));
          }
          return 0;
        }
      }
    } else if (!name[i] || (pattern[i] != name[i] && pattern[i] != '?'))
      return 0;
  }
  return name[i] == 0;
}
