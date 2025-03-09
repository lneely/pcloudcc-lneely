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

#include <stdint.h>

#ifndef PRPC_SOCK_PATH
#define PRPC_SOCK_PATH "/tmp/pcloud_unix_soc.sock"
#endif

typedef struct _rpc_message_t {
  uint32_t type;
  uint64_t length;
  char value[];
} rpc_message_t;


// Defines the function signature of an overlay server-side
// callback. prpc_handler implementations must satisfy the
// following:
//
// - Accepts request data as a string.
//
// - Returns 0 on success, and non-zero on failure
//
// - If the function invoked by the callback function returns data
//   that can be used by the client (e.g., list_sync_folders), then
//   allocate the void** pointer and write the data there. If the
//   void** pointer is null, then do not write any data back out for
//   the client.
//
typedef int (*prpc_handler)(const char *);

void prpc_main_loop(void);
void prpc_init();
int prpc_register(int cmdid, prpc_handler h);

#ifdef __cplusplus
}
#endif

#endif // POVERLAY_H
