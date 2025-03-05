/*
  Copyright (c) 2013-2015 pCloud Ltd.  All rights reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met: Redistributions of source code must retain the above
  copyright notice, this list of conditions and the following
  disclaimer.  Redistributions in binary form must reproduce the above
  copyright notice, this list of conditions and the following
  disclaimer in the documentation and/or other materials provided with
  the distribution.  Neither the name of pCloud Ltd nor the names of
  its contributors may be used to endorse or promote products derived
  from this software without specific prior written permission.

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

// dependencies:
// - poverlay_protocol.h
// - psynclib.h

#ifndef POVERLAY_H
#define POVERLAY_H

#ifdef __cplusplus
extern "C" {
#endif

#ifndef VOID
#define VOID void
#endif

#ifndef LPVOID
#define LPVOID void *
#endif

#ifndef POVERLAY_SOCK_PATH
#define POVERLAY_SOCK_PATH "/tmp/pcloud_unix_soc.sock"
#endif

#include "psynclib.h"

extern int overlays_running;
extern int callbacks_running;

typedef struct _rpc_message_t {
  uint32_t type;
  uint64_t length;
  char value[];
} rpc_message_t;

void prpc_proc(VOID);
void prpc_proc_handle(LPVOID);
void prpc_get_response(rpc_message_t*, rpc_message_t*);
void prpc_stop();
void prpc_start();
void prpc_cb_stop();
void prpc_cb_start();
int prpc_started();
int prpc_cb_started();

void prpc_cb_init();
int prpc_cb_register(int, poverlay_callback);

#ifdef __cplusplus
}
#endif

#endif // POVERLAY_H
