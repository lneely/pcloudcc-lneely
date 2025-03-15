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


static uint32_t pq_rnd() {
  static uint32_t a = 0x95ae3d25, b = 0xe225d755, c = 0xc63a2ae7,
                  d = 0xe4556265;
  uint32_t e = a - rot(b, 27);
  a = b ^ rot(c, 17);
  b = c + d;
  c = d + e;
  d = e + a;
  return d;
}

#define QSORT_TRESH 8
#define QSORT_MTR 64
#define QSORT_REC_M (16 * 1024)

static inline void sw2(unsigned char **a, unsigned char **b) {
  unsigned char *tmp = *a;
  *a = *b;
  *b = tmp;
}

static unsigned char *med5(unsigned char *a, unsigned char *b, unsigned char *c,
                           unsigned char *d, unsigned char *e,
                           int (*compar)(const void *, const void *)) {
  if (compar(b, a) < 0)
    sw2(&a, &b);
  if (compar(d, c) < 0)
    sw2(&c, &d);
  if (compar(a, c) < 0) {
    a = e;
    if (compar(b, a) < 0)
      sw2(&a, &b);
  } else {
    c = e;
    if (compar(d, c) < 0)
      sw2(&c, &d);
  }
  if (compar(a, c) < 0)
    a = b;
  else
    c = d;
  if (compar(a, c) < 0)
    return a;
  else
    return c;
}

unsigned char *pq_choose_part(unsigned char *base, size_t cnt, size_t size,
                              int (*compar)(const void *, const void *)) {
  if (cnt >= QSORT_REC_M) {
    cnt /= 5;
    return med5(pq_choose_part(base, cnt, size, compar),
                pq_choose_part(base + cnt * size, cnt, size, compar),
                pq_choose_part(base + cnt * size * 2, cnt, size, compar),
                pq_choose_part(base + cnt * size * 3, cnt, size, compar),
                pq_choose_part(base + cnt * size * 4, cnt, size, compar),
                compar);
  } else {
    return med5(base + (pq_rnd() % cnt) * size, base + (pq_rnd() % cnt) * size,
                base + (pq_rnd() % cnt) * size, base + (pq_rnd() % cnt) * size,
                base + (pq_rnd() % cnt) * size, compar);
  }
}

static inline void pqsswap(unsigned char *a, unsigned char *b, size_t size) {
  unsigned char tmp;
  do {
    tmp = *a;
    *a++ = *b;
    *b++ = tmp;
  } while (--size);
}

static inline void pqsswap32(unsigned char *a, unsigned char *b, size_t size) {
  uint32_t tmp;
  do {
    tmp = *(uint32_t *)a;
    *(uint32_t *)a = *(uint32_t *)b;
    *(uint32_t *)b = tmp;
    a += sizeof(uint32_t);
    b += sizeof(uint32_t);
  } while (--size);
}

typedef struct {
  unsigned char *lo;
  unsigned char *hi;
} psq_stack_t;

void psync_pqsort(void *base, size_t cnt, size_t sort_first, size_t size,
                  int (*compar)(const void *, const void *)) {
  psq_stack_t stack[sizeof(size_t) * 8];
  psq_stack_t *top;
  unsigned char *lo, *hi, *mid, *l, *r, *sf;
  size_t tresh, n, u32size;

  lo = NULL;
  hi = NULL;
  mid = NULL;
  l = NULL;
  r = NULL;
  sf = NULL;

  tresh = QSORT_TRESH * size;
  sf = (unsigned char *)base + sort_first * size;
  if (size % sizeof(uint32_t) == 0 && (uintptr_t)base % sizeof(uint32_t) == 0)
    u32size = size / sizeof(uint32_t);
  else
    u32size = 0;
  if (cnt > QSORT_TRESH) {
    top = stack + 1;
    lo = (unsigned char *)base;
    hi = lo + (cnt - 1) * size;
    do {
      n = (hi - lo) / size;
      if (n <= QSORT_MTR) {
        mid = lo + (n >> 1) * size;
        if (compar(mid, lo) < 0)
          pqsswap(mid, lo, size);
        if (compar(hi, mid) < 0) {
          pqsswap(mid, hi, size);
          if (compar(mid, lo) < 0)
            pqsswap(mid, lo, size);
        }
        // we already sure *hi and *lo are good, so they will be skipped without
        // checking
        l = lo;
        r = hi;
      } else {
        mid = pq_choose_part(lo, n, size, compar);
        l = lo - size;
        r = hi + size;
      }
      if (u32size) {
        do {
          do {
            l += size;
          } while (compar(l, mid) < 0);
          do {
            r -= size;
          } while (compar(mid, r) < 0);
          if (l >= r)
            break;
          pqsswap32(l, r, u32size);
          if (mid == l) {
            mid = r;
            r += size;
          } else if (mid == r) {
            mid = l;
            l -= size;
          }
        } while (1);
      } else {
        do {
          do {
            l += size;
          } while (compar(l, mid) < 0);
          do {
            r -= size;
          } while (compar(mid, r) < 0);
          if (l >= r)
            break;
          pqsswap(l, r, size);
          if (mid == l) {
            mid = r;
            r += size;
          } else if (mid == r) {
            mid = l;
            l -= size;
          }
        } while (1);
      }
      if (hi - mid <= tresh || mid >= sf) {
        if (mid - lo <= tresh) {
          top--;
          lo = top->lo;
          hi = top->hi;
        } else {
          hi = mid - size;
        }
      } else if (mid - lo <= tresh) {
        lo = mid + size;
      } else if (hi - mid < mid - lo) {
        top->lo = lo;
        top->hi = mid - size;
        top++;
        lo = mid + size;
      } else {
        top->lo = mid + size;
        top->hi = hi;
        top++;
        hi = mid - size;
      }
    } while (top != stack);
  } else if (cnt <= 1) {
    return;
  }
  lo = (unsigned char *)base;
  hi = lo + (cnt - 1) * size;
  sf += size * QSORT_TRESH;
  if (sf < hi)
    hi = sf;
  r = lo + QSORT_TRESH * size + 4;
  if (r > hi)
    r = hi;
  for (l = lo + size; l <= r; l += size)
    if (compar(l, lo) < 0)
      lo = l;
  pqsswap((unsigned char *)base, lo, size);
  l = (unsigned char *)base + size;
  hi -= size;
  while (l <= hi) {
    lo = l;
    l += size;
    while (compar(l, lo) < 0)
      lo -= size;
    lo += size;
    if (lo != l) {
      unsigned char *t = l + size;
      if (u32size) {
        while ((t -= sizeof(uint32_t)) >= l) {
          uint32_t tmp = *(uint32_t *)t;
          for (r = mid = t; (mid -= size) >= lo; r = mid)
            *(uint32_t *)r = *(uint32_t *)mid;
          *(uint32_t *)r = tmp;
        }
      } else {
        while (--t >= l) {
          unsigned char tmp = *t;
          for (r = mid = t; (mid -= size) >= lo; r = mid)
            *r = *mid;
          *r = tmp;
        }
      }
    }
  }
}

void psync_qpartition(void *base, size_t cnt, size_t sort_first, size_t size,
                      int (*compar)(const void *, const void *)) {
  unsigned char *lo, *hi, *mid, *l, *r, *sf;
  size_t n, u32size;
  sf = (unsigned char *)base + sort_first * size;
  if (size % sizeof(uint32_t) == 0 && (uintptr_t)base % sizeof(uint32_t) == 0)
    u32size = size / sizeof(uint32_t);
  else
    u32size = 0;
  if (cnt <= 1) // otherwise cnt-1 will underflow
    return;
  lo = (unsigned char *)base;
  hi = lo + (cnt - 1) * size;
  while (1) {
    n = (hi - lo) / size;
    if (n <= QSORT_MTR) {
      mid = lo + (n >> 1) * size;
      if (compar(mid, lo) < 0)
        pqsswap(mid, lo, size);
      if (compar(hi, mid) < 0) {
        pqsswap(mid, hi, size);
        if (compar(mid, lo) < 0)
          pqsswap(mid, lo, size);
      }
      // we already sure *hi and *lo are good, so they will be skipped without
      // checking
      if (n <= 2) // when n is 2, we have 3 elements
        return;
      l = lo;
      r = hi;
    } else {
      mid = pq_choose_part(lo, n, size, compar);
      l = lo - size;
      r = hi + size;
    }
    if (u32size) {
      do {
        do {
          l += size;
        } while (compar(l, mid) < 0);
        do {
          r -= size;
        } while (compar(mid, r) < 0);
        if (l >= r)
          break;
        pqsswap32(l, r, u32size);
        if (mid == l) {
          mid = r;
          r += size;
        } else if (mid == r) {
          mid = l;
          l -= size;
        }
      } while (1);
    } else {
      do {
        do {
          l += size;
        } while (compar(l, mid) < 0);
        do {
          r -= size;
        } while (compar(mid, r) < 0);
        if (l >= r)
          break;
        pqsswap(l, r, size);
        if (mid == l) {
          mid = r;
          r += size;
        } else if (mid == r) {
          mid = l;
          l -= size;
        }
      } while (1);
    }
    if (mid < sf)
      lo = mid + size;
    else if (mid > sf)
      hi = mid - size;
    else
      return;
  }
}
