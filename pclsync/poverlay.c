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
  message *reply = (message *)psync_malloc(POVERLAY_BUFSIZE);
  void *reply_data = NULL;
  size_t reply_data_length = 0;

  memset(reply, 0, POVERLAY_BUFSIZE);
  memset(chbuf, 0, POVERLAY_BUFSIZE);

  cl = (int *)lpvParam;

  while ((rc = read(*cl, curbuf, (POVERLAY_BUFSIZE - bytes_read))) > 0) {
    bytes_read += rc;
    curbuf = curbuf + rc;
    if (bytes_read > 12) {
      request = (message *)chbuf;
      if (request->length == bytes_read)
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
  // truncated. why??
  request = (message *)chbuf;
  if (request) {
    get_answer_to_request(request, reply, &reply_data, &reply_data_length);

    // Send the reply structure
    size_t bytes_written = 0;
    while (bytes_written < reply->length) {
      rc = write(*cl, (char *)reply + bytes_written,
                 reply->length - bytes_written);
      if (rc <= 0) {
        debug(D_ERROR, "Unix socket write error (reply structure)");
        goto cleanup;
      }
      bytes_written += rc;
    }

    // Send the additional reply data if present
    if (reply_data && reply_data_length > 0) {
      bytes_written = 0;

      while (bytes_written < reply_data_length) {
        rc = write(*cl, reply_data + bytes_written,
                   reply_data_length - bytes_written);
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
          reply->length, reply_data_length);
  } else {
    debug(D_ERROR, "No valid request received");
  }

cleanup:
  if (cl) {
    close(*cl);
  }
  if (reply) {
    psync_free(reply);
  }
  if (reply_data) {
    psync_free(reply_data);
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

void get_answer_to_request(message *request, message *reply, void **reply_data,
                           size_t *reply_data_length) {
  psync_path_status_t stat = PSYNC_PATH_STATUS_NOT_OURS;
  memcpy(reply->value, "Ok.", 4);
  reply->length = sizeof(message) + 4;
  *reply_data = NULL;
  *reply_data_length = 0;

  if (request->type == 20 /* STARTCRYPTO, see control_tools.cpp */) {
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
    void *rep = NULL;

    if (callbacks[ind]) {
      ret = callbacks[ind](request->value, &rep);
      if (ret == 0) {
        reply->type = 0;
        reply->length = sizeof(message) + strlen(reply->value) + 1;
        if (rep) {
          *reply_data = rep;
          switch (request->type) {
          case 23:
            debug(D_NOTICE, "got reply data for LISTSYNC message");

            psync_folder_list_t *folders = (psync_folder_list_t *)rep;
            size_t total_size = sizeof(psync_folder_list_t) +
                                folders->foldercnt * sizeof(psync_folder_t);

            debug(D_NOTICE, "Calculating reply_data_length for %zu folders",
                  folders->foldercnt);
            debug(D_NOTICE, "Base size: %zu", total_size);

            // Add the length of all strings, carefully handling NULL pointers
            for (size_t i = 0; i < folders->foldercnt; i++) {
              debug(D_NOTICE, "Processing folder %zu", i);
              if (folders->folders[i].localname) {
                total_size += strlen(folders->folders[i].localname) + 1;
                debug(D_NOTICE, "  localname: %s",
                      folders->folders[i].localname);
              }
              if (folders->folders[i].localpath) {
                total_size += strlen(folders->folders[i].localpath) + 1;
                debug(D_NOTICE, "  localpath: %s",
                      folders->folders[i].localpath);
              }
              if (folders->folders[i].remotename) {
                total_size += strlen(folders->folders[i].remotename) + 1;
                debug(D_NOTICE, "  remotename: %s",
                      folders->folders[i].remotename);
              }
              if (folders->folders[i].remotepath) {
                total_size += strlen(folders->folders[i].remotepath) + 1;
                debug(D_NOTICE, "  remotepath: %s",
                      folders->folders[i].remotepath);
              }
            }

            *reply_data_length = total_size;
            debug(D_NOTICE, "Final reply_data_length: %zu", *reply_data_length);

            debug(D_NOTICE, "reply data length is %zu", *reply_data_length);
            break;
          }
          debug(D_NOTICE, "Reply data received, length: %zu",
                *reply_data_length);
        } else {
          debug(D_NOTICE, "Callback succeeded but no reply data received");
        }
      } else {
        reply->type = ret;
        memcpy(reply->value, "No.", 4);
        debug(D_NOTICE, "Callback failed with return code: %d", ret);
      }
    } else {
      reply->type = 13;
      memcpy(reply->value, "No callback with this id registered.", 37);
      reply->length = sizeof(message) + 37;
      debug(D_NOTICE, "No callback registered for type: %u", request->type);
    }
  } else {
    reply->type = 13;
    memcpy(reply->value, "Invalid type.", 14);
    reply->length = sizeof(message) + 14;
    debug(D_NOTICE, "Invalid request type: %u", request->type);
  }

  if (*reply_data == NULL) {
    debug(D_NOTICE, "No reply data received");
  }
}

int psync_overlays_running() { return overlays_running; }
int psync_ovr_callbacks_running() { return callbacks_running; }
