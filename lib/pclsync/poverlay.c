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

#include "poverlay.h"
#include "pcache.h"
#include "pcompat.h"
#include "plibs.h"
#include "ppathstatus.h"

int overlays_running = 1;
int callbacks_running = 1;

#if defined(P_OS_LINUX)
#include "poverlay_lin.c"
#else
void overlay_main_loop(VOID) {}
void instance_thread(LPVOID) {}
#endif

poverlay_callback *callbacks;
static int callbacks_size = 15;
static const int calbacks_lower_band = 20;

int psync_add_overlay_callback(int id, poverlay_callback callback) {
  poverlay_callback *callbacks_old = callbacks;
  int callbacks_size_old = callbacks_size;
  if (id < calbacks_lower_band)
    return -1;
  if (id > (calbacks_lower_band + callbacks_size)) {
    callbacks_size = id - calbacks_lower_band + 1;
    init_overlay_callbacks();
    memcpy(callbacks, callbacks_old,
           callbacks_size_old * sizeof(poverlay_callback));
    psync_free(callbacks_old);
  }
  callbacks[id - calbacks_lower_band] = callback;
  return 0;
}

void init_overlay_callbacks() {
  callbacks = (poverlay_callback *)psync_malloc(sizeof(poverlay_callback) *
                                                callbacks_size);
  memset(callbacks, 0, sizeof(poverlay_callback) * callbacks_size);
}

void psync_stop_overlays() { overlays_running = 0; }
void psync_start_overlays() { overlays_running = 1; }

void psync_stop_overlay_callbacks() { callbacks_running = 0; }
void psync_start_overlay_callbacks() { callbacks_running = 1; }

void get_answer_to_request(message *request, message *reply) {
  psync_path_status_t stat = PSYNC_PATH_STATUS_NOT_OURS;
  memcpy(reply->value, "Ok.", 4);
  reply->length = sizeof(message) + 4;

  if (request->type == 20 /* STARTCRYPTO, see control_tools.cpp */) {
    // don't publish the crypto password to the logs in plain text...
    debug(D_NOTICE, "Client Request type [%u] len [%lu] string: [%s]",
          request->type, request->length, "REDACTED");
  } else {
    debug(D_NOTICE, "Client Request type [%u] len [%lu] string: [%s]",
          request->type, request->length, request->value);
  }

  if (request->type < 20) {
    if (overlays_running)
      stat = psync_path_status_get(request->value);
    switch (psync_path_status_get_status(stat)) {
    case PSYNC_PATH_STATUS_IN_SYNC:
      reply->type = 10;
      break;
    case PSYNC_PATH_STATUS_IN_PROG:
      reply->type = 12;
      break;
    case PSYNC_PATH_STATUS_PAUSED:
    case PSYNC_PATH_STATUS_REMOTE_FULL:
    case PSYNC_PATH_STATUS_LOCAL_FULL:
      reply->type = 11;
      break;
    default:
      reply->type = 13;
      memcpy(reply->value, "No.", 4);
    }
  } else if ((callbacks_running) &&
             (request->type < (calbacks_lower_band + callbacks_size))) {
    int ind = request->type - 20;
    int ret = 0;
    message *rep = NULL;

    if (callbacks[ind]) {
      ret = callbacks[ind](request->value, rep);
      if (ret == 0) {
        if (rep) {
          psync_free(reply);
          reply = rep;
        } else
          reply->type = 0;
      } else {
        reply->type = ret;
        memcpy(reply->value, "No.", 4);
      }
    } else {
      reply->type = 13;
      memcpy(reply->value, "No callback with this id registered.", 37);
      reply->length = sizeof(message) + 37;
    }
  } else {
    reply->type = 13;
    memcpy(reply->value, "Invalid type.", 14);
    reply->length = sizeof(message) + 14;
  }
}

int psync_overlays_running() { return overlays_running; }
int psync_ovr_callbacks_running() { return callbacks_running; }
