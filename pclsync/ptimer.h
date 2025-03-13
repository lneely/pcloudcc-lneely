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

#ifndef _PSYNC_TIMER_H
#define _PSYNC_TIMER_H

#include <stdint.h>
#include <stdlib.h>
#include <time.h>

#include "plist.h"

#define PSYNC_INVALID_TIMER NULL

extern time_t psync_current_time;

struct _psync_timer_t;

typedef void (*psync_timer_callback)(struct _psync_timer_t *, void *);
typedef void (*psync_exception_callback)();

typedef struct _psync_timer_t {
  psync_list list;
  psync_timer_callback call;
  void *param;
  time_t numsec;
  time_t runat;
  uint32_t level;
  uint32_t opts;
} psync_timer_structure_t, *psync_timer_t;

void ptimer_init();
time_t ptimer_time();
void ptimer_wake();
psync_timer_t ptimer_register(psync_timer_callback func, time_t numsec,
                                   void *param);
int ptimer_stop(psync_timer_t timer);
void ptimer_exception_handler(psync_exception_callback func);
void ptimer_sleep_handler(psync_exception_callback func);
void ptimer_do_notify_exception();
void ptimer_wait_next_sec();

#define ptimer_notify_exception()                                         \
  do {                                                                         \
    pdbg_logf(D_NOTICE, "sending exception");                                      \
    ptimer_do_notify_exception();                                         \
  } while (0)

#endif
