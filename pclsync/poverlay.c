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
#include "pcompat.h"
#include "ppathstatus.h"

#include "plibs.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>

#define POVERLAY_BUFSIZE 512

int overlays_running = 1;
int callbacks_running = 1;

char *mysoc = "/tmp/pcloud_unix_soc.sock";

void overlay_main_loop() {
  struct sockaddr_un addr;
  int fd, cl;

  if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
    // debug(D_NOTICE, "Unix socket error failed to open %s", mysoc);
    return;
  }

  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  strncpy(addr.sun_path, mysoc, sizeof(addr.sun_path) - 1);

  unlink(mysoc);

  if (bind(fd, (struct sockaddr *)&addr,
           strlen(mysoc) + sizeof(addr.sun_family)) == -1) {
    debug(D_ERROR, "Unix socket bind error");
    return;
  }

  if (listen(fd, 5) == -1) {
    debug(D_ERROR, "Unix socket listen error");
    return;
  }

  while (1) {
    if ((cl = accept(fd, NULL, NULL)) == -1) {
      debug(D_ERROR, "Unix socket accept error");
      continue;
    }
    psync_run_thread1("Pipe request handle routine",
                      instance_thread, // thread proc
                      (LPVOID)&cl      // thread parameter
    );
  }

  return;
}

void instance_thread(void *lpvParam) {
  int *cl, rc;
  char chbuf[POVERLAY_BUFSIZE];
  message *request = NULL;
  char *curbuf = &chbuf[0];
  int bytes_read = 0;
  response *reply = (response *)psync_malloc(POVERLAY_BUFSIZE);

  memset(reply, 0, POVERLAY_BUFSIZE);
  memset(chbuf, 0, POVERLAY_BUFSIZE);

  cl = (int *)lpvParam;

  while ((rc = read(*cl, curbuf, (POVERLAY_BUFSIZE - bytes_read))) > 0) {
    bytes_read += rc;
    curbuf = curbuf + rc;
    if (bytes_read > 12) {
      request = (message *)chbuf;
      if (request->length == (uint64_t)bytes_read)
        break;
    }
  }

  if (rc == -1) {
    debug(D_ERROR, "Unix socket read error");
    goto cleanup;
  } else if (rc == 0 && bytes_read == 0) {
    debug(D_NOTICE, "Connection closed by client before sending data");
    goto cleanup;
  }

  // XXX: the chbuf is getting truncated here. chbuf + 16 offset
  // contains the full request message, but request->value is
  // truncated. why?? Note that this impacts all API functions, not
  // just syncadd.
  request = (message *)chbuf;
  if (request) {
    get_answer_to_request(request, reply);

    // Send the reply structure
    size_t bytes_written = 0;
    while (bytes_written < reply->msg->length) {
      rc = write(*cl, (char *)reply + bytes_written,
                 reply->msg->length - bytes_written);
      if (rc <= 0) {
        debug(D_ERROR, "Unix socket write error (reply structure)");
        goto cleanup;
      }
      bytes_written += rc;
    }

    // Send the additional reply data if present
    if (reply->payload && reply->payloadsz > 0) {
      bytes_written = 0;

      while (bytes_written < reply->payloadsz) {
        rc = write(*cl, reply->payload + bytes_written,
                   reply->payloadsz - bytes_written);
        if (rc <= 0) {
          debug(D_ERROR, "Unix socket write error (reply data)");
          goto cleanup;
        }
        bytes_written += rc;
      }
    }

    debug(D_NOTICE,
          "Successfully sent full reply: %zu bytes structure, %zu bytes "
          "additional data",
          reply->msg->length, reply->payloadsz);
  } else {
    debug(D_ERROR, "No valid request received");
  }

cleanup:
  if (cl) {
    close(*cl);
  }
  if (reply) {
    if (reply->msg) {
      psync_free(reply->msg);
    }
    if (reply->payload) {
      psync_free(reply->payload);
    }
    psync_free(reply);
  }

  debug(D_NOTICE, "InstanceThread exiting.");
}

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

void get_answer_to_request(message *request, response *reply) {
  psync_path_status_t stat;
  int ind, ret;
  psync_folder_list_t *folders;
  const char *debug_string;

  // Declarations
  stat = PSYNC_PATH_STATUS_NOT_OURS;
  ind = 0;
  ret = 0;
  folders = NULL;
  debug_string = NULL;

  // Initializations
  reply->msg = (message *)psync_malloc(POVERLAY_BUFSIZE);
  reply->msg->length = sizeof(message) + 4;
  reply->payload = NULL;
  reply->payloadsz = 0;

  // Main logic
  if (request->type == 20) {
    debug_string = "REDACTED";
  } else {
    debug_string = request->value;
  }

  debug(D_NOTICE, "Client Request type [%u] len [%lu] string: [%s]",
        request->type, request->length, debug_string);

  if (request->type < 20) {
    if (overlays_running) {
      stat = psync_path_status_get(request->value);
    }
    switch (psync_path_status_get_status(stat)) {
    case PSYNC_PATH_STATUS_IN_SYNC:
      reply->msg->type = 10;
      break;
    case PSYNC_PATH_STATUS_IN_PROG:
      reply->msg->type = 12;
      break;
    case PSYNC_PATH_STATUS_PAUSED:
    case PSYNC_PATH_STATUS_REMOTE_FULL:
    case PSYNC_PATH_STATUS_LOCAL_FULL:
      reply->msg->type = 11;
      break;
    default:
      reply->msg->type = 13;
      memcpy(reply->msg->value, "No.", 4);
    }
  } else if ((callbacks_running) &&
             (request->type <
              ((uint32_t)calbacks_lower_band + (uint32_t)callbacks_size))) {
    ind = request->type - 20;

    if (callbacks[ind]) {
      ret = callbacks[ind](request->value, &reply->payload);
      if (ret == 0) {
        reply->msg->type = 0;
        reply->msg->length = sizeof(message) + strlen(reply->msg->value) + 1;

        if (reply->payload) {
          if (request->type == 23) { // LISTSYNC
            folders = (psync_folder_list_t *)reply->payload;
            reply->payloadsz = sizeof(psync_folder_list_t) +
                               folders->foldercnt * sizeof(psync_folder_t);
          } else if (request->type == 24) { // ADDSYNC
            reply->payloadsz = sizeof(psync_syncid_t);
          }
          debug(D_NOTICE, "Callback succeeded with reply data, length: %zu",
                reply->payloadsz);
        } else {
          debug(D_NOTICE, "Callback succeeded with no reply data");
        }
      } else {
        reply->msg->type = ret;
        memcpy(reply->msg->value, "No.", 4);
        debug(D_NOTICE, "Callback failed with return code: %d", ret);
      }
    } else {
      reply->msg->type = 13;
      memcpy(reply->msg->value, "No callback with this id registered.", 37);
      reply->msg->length = sizeof(message) + 37;
      debug(D_NOTICE, "No callback registered for type: %u", request->type);
    }
  } else {
    reply->msg->type = 13;
    memcpy(reply->msg->value, "Invalid type.", 14);
    reply->msg->length = sizeof(message) + 14;
    debug(D_NOTICE, "Invalid request type: %u", request->type);
  }

  if (reply->payload == NULL) {
    debug(D_NOTICE, "No reply data received");
  }

  // Set default reply value if not set elsewhere
  if (reply->msg->type != 13) {
    memcpy(reply->msg->value, "Ok.", 4);
  }

  return;
}

int psync_overlays_running() { return overlays_running; }
int psync_ovr_callbacks_running() { return callbacks_running; }
