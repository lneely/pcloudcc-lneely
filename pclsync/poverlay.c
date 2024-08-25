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

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>

#include "pcompat.h"
#include "poverlay.h"
#include "ppathstatus.h"

#include "plibs.h"

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
  int *sockfd;                  // pcloud socket file descriptor
  int rc;                       // bytes read / written per iteration
  int readbytes;                // total bytes read from request
  char rqbuf[POVERLAY_BUFSIZE]; // request buffer, contains the request message
  char *rqbufp;                 // request buffer ptr, for convenient iteration
  request_message *request;     // request message
  response_message *response;   // response message and payload

  request = NULL;
  response = NULL;
  readbytes = 0;
  rqbufp = &rqbuf[0];
  sockfd = (int *)lpvParam;

  // read the request from the socket into the request buffer
  memset(rqbuf, 0, POVERLAY_BUFSIZE);
  while ((rc = read(*sockfd, rqbufp, (POVERLAY_BUFSIZE - readbytes))) > 0) {
    readbytes += rc;
    rqbufp = rqbufp + rc;
    if (readbytes > 12) {
      request = (message *)rqbuf;
      if (request->length == (uint64_t)readbytes)
        break;
    }
  }
  if (rc == -1) {
    debug(D_ERROR, "Unix socket read error");
    goto cleanup;
  } else if (rc == 0 && readbytes == 0) {
    debug(D_NOTICE, "Connection closed by client before sending data");
    goto cleanup;
  }

  // allocate and initialize response message
  response = (response_message *)psync_malloc(sizeof(response_message));
  memset(response, 0, sizeof(response_message));
  response->msg = NULL;
  response->payload = NULL;
  response->payloadsz = 0;

  // get the response for the request, and write the response to the
  // sockfd.
  request = (message *)rqbuf;
  if (request) {
    get_response(request, response);

    size_t bytes_written = 0;
    while (bytes_written < response->msg->length) {
      rc = write(*sockfd, (char *)response + bytes_written,
                 response->msg->length - bytes_written);
      if (rc <= 0) {
        debug(D_ERROR, "Unix socket write error (reply structure)");
        goto cleanup;
      }
      bytes_written += rc;
    }

    // Send the additional reply data if present
    if (response->payload && response->payloadsz > 0) {
      bytes_written = 0;

      while (bytes_written < response->payloadsz) {
        rc = write(*sockfd, response->payload + bytes_written,
                   response->payloadsz - bytes_written);
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
          response->msg->length, response->payloadsz);
  } else {
    debug(D_ERROR, "No valid request received");
  }

cleanup:
  if (sockfd) {
    close(*sockfd);
  }
  if (response) {
    if (response->msg) {
      psync_free(response->msg);
    }
    if (response->payload) {
      psync_free(response->payload);
    }
    psync_free(response);
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

void get_response(request_message *request, response_message *response) {
  psync_path_status_t stat;
  int ind, ret;
  psync_folder_list_t *folders;
  const char *debug_string;
  size_t available_space;

  // Declarations
  stat = PSYNC_PATH_STATUS_NOT_OURS;
  ind = 0;
  ret = 0;
  folders = NULL;
  debug_string = NULL;

  // Initializations
  response->msg = (message *)psync_malloc(POVERLAY_BUFSIZE);
  if (!response->msg) {
    debug(D_ERROR, "Failed to allocate memory for response message");
    return;
  }
  memset(response->msg, 0,
         POVERLAY_BUFSIZE); // Initialize the entire buffer to zero
  response->msg->length = sizeof(message);
  response->payload = NULL;
  response->payloadsz = 0;
  available_space = POVERLAY_BUFSIZE - sizeof(message);

  // Main logic
  debug_string = (request->type == 20) ? "REDACTED" : request->value;

  debug(D_NOTICE, "Client Request type [%u] len [%lu] string: [%s]",
        request->type, request->length, debug_string);

  if (request->type < 20) {
    if (overlays_running) {
      stat = psync_path_status_get(request->value);
    }
    switch (psync_path_status_get_status(stat)) {
    case PSYNC_PATH_STATUS_IN_SYNC:
      response->msg->type = 10;
      break;
    case PSYNC_PATH_STATUS_IN_PROG:
      response->msg->type = 12;
      break;
    case PSYNC_PATH_STATUS_PAUSED:
    case PSYNC_PATH_STATUS_REMOTE_FULL:
    case PSYNC_PATH_STATUS_LOCAL_FULL:
      response->msg->type = 11;
      break;
    default:
      response->msg->type = 13;
      snprintf(response->msg->value, available_space, "No.");
    }
  } else if (callbacks_running &&
             (request->type <
              ((uint32_t)calbacks_lower_band + (uint32_t)callbacks_size))) {
    ind = request->type - 20;

    if (callbacks[ind]) {
      ret = callbacks[ind](request->value, &response->payload);
      if (ret == 0) {
        response->msg->type = 0;
        if (response->payload) {
          if (request->type == 23) { // LISTSYNC
            folders = (psync_folder_list_t *)response->payload;
            response->payloadsz = sizeof(psync_folder_list_t) +
                                  folders->foldercnt * sizeof(psync_folder_t);
          } else if (request->type == 24) { // ADDSYNC
            response->payloadsz = sizeof(psync_syncid_t);
          } else {
            response->payloadsz = 0;
          }
          debug(D_NOTICE, "Callback succeeded with reply data, length: %zu",
                response->payloadsz);
        } else {
          response->payloadsz = 0;
          debug(D_NOTICE, "Callback succeeded with no reply data");
        }
      } else {
        response->msg->type = ret;
        snprintf(response->msg->value, available_space, "No.");
        response->payloadsz = 0;
        debug(D_NOTICE, "Callback failed with return code: %d", ret);
      }
    } else {
      response->msg->type = 13;
      snprintf(response->msg->value, available_space,
               "No callback with this id registered.");
      debug(D_NOTICE, "No callback registered for type: %u", request->type);
    }
  } else {
    response->msg->type = 13;
    snprintf(response->msg->value, available_space, "Invalid type.");
    debug(D_NOTICE, "Invalid request type: %u", request->type);
  }

  if (response->payload == NULL) {
    response->payloadsz = 0;
    debug(D_NOTICE, "No reply data received");
  }

  // Set default reply value if not set elsewhere
  if (response->msg->type != 13 && response->msg->value[0] == '\0') {
    snprintf(response->msg->value, available_space, "Ok.");
  }

  // Calculate final message length (safely)
  size_t value_length = strnlen(response->msg->value, available_space);
  response->msg->length =
      sizeof(message) + value_length + 1; // +1 for null terminator

  // Ensure we don't exceed the allocated buffer
  if (response->msg->length > POVERLAY_BUFSIZE) {
    response->msg->length = POVERLAY_BUFSIZE;
    response->msg->value[available_space - 1] = '\0'; // Ensure null termination
    debug(D_WARNING, "Response message truncated to fit buffer");
  }
}

int psync_overlays_running() { return overlays_running; }
int psync_ovr_callbacks_running() { return callbacks_running; }
