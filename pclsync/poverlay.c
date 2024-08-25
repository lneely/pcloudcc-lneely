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

/*
  poverlay is the "overlay server" (contrast with overlay_client). It
  listens for request messages generated by overlay_client on a unix
  socket, invokes the appropriate callback based on the message type,
  and generates a response message. It then writes the response
  message back to the socket where the overlay_client will read and
  act upon it.
*/

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>

#include "pcompat.h"
#include "poverlay_protocol.h"

#include "poverlay.h"
#include "ppathstatus.h"

#include "plibs.h"

#define POVERLAY_BUFSIZE 512

int overlays_running = 1;
int callbacks_running = 1;

// Serialization function
size_t serialize_response_message(const response_message *resp,
                                  char **out_buffer) {
  // Calculate total size needed
  size_t msg_size = sizeof(uint32_t) + sizeof(uint64_t) + resp->msg->length;
  size_t total_size =
      sizeof(size_t) + msg_size + sizeof(size_t) + resp->payloadsz;

  // Allocate buffer
  *out_buffer = (char *)malloc(total_size);
  if (*out_buffer == NULL)
    return 0;

  char *ptr = *out_buffer;

  // Serialize msg size
  *(size_t *)ptr = htobe64(msg_size);
  ptr += sizeof(size_t);

  // Serialize msg
  *(uint32_t *)ptr = htonl(resp->msg->type);
  ptr += sizeof(uint32_t);

  *(uint64_t *)ptr = htobe64(resp->msg->length);
  ptr += sizeof(uint64_t);

  memcpy(ptr, resp->msg->value, resp->msg->length);
  ptr += resp->msg->length;

  // Serialize payload size
  *(size_t *)ptr = htobe64(resp->payloadsz);
  ptr += sizeof(size_t);

  // Serialize payload
  if (resp->payloadsz > 0 && resp->payload != NULL) {
    memcpy(ptr, resp->payload, resp->payloadsz);
  }

  return total_size;
}

// Helper function to free a deserialized response_message
void free_response_message(response_message *resp) {
  if (resp) {
    free(resp->msg);
    free(resp->payload);
    free(resp);
  }
}

void psync_overlay_main_loop() {
  struct sockaddr_un addr;
  int fd, cl;

  if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
    debug(D_ERROR, "Unix socket error failed to open %s", POVERLAY_SOCK_PATH);
    return;
  }

  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  strncpy(addr.sun_path, POVERLAY_SOCK_PATH, sizeof(addr.sun_path) - 1);

  unlink(POVERLAY_SOCK_PATH);

  if (bind(fd, (struct sockaddr *)&addr,
           strlen(POVERLAY_SOCK_PATH) + sizeof(addr.sun_family)) == -1) {
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

    // handle the request in a new thread
    psync_run_thread1("Pipe request handle routine",
                      psync_overlay_handle_request, // thread proc
                      (LPVOID)&cl                   // thread parameter
    );
  }

  return;
}

void psync_overlay_handle_request(void *lpvParam) {
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
      request = (request_message *)rqbuf;
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
  request = (request_message *)rqbuf;
  if (request) {
    psync_overlay_get_response(request, response);

    char *rsbufp;
    size_t bytes_written = 0;
    size_t responsesz = serialize_response_message(response, &rsbufp);
    if (responsesz <= 0) {
      debug(D_ERROR, "failed to serialize response message");
      return;
    }

    while (bytes_written < responsesz) {
      ssize_t written =
          write(*sockfd, rsbufp + bytes_written, responsesz - bytes_written);
      if (written == -1) {
        if (errno == EINTR) {
          // Interrupted by signal, try again
          continue;
        }
        debug(D_ERROR, "failed to write to socket: %s", strerror(errno));
        break;
      }
      bytes_written += written;
    }
    free(rsbufp);
    if (bytes_written < responsesz) {
      debug(D_ERROR, "failed to write entire message to socket");
      return;
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

// registers an overlay callback for a given message type.
int psync_overlay_register_callback(int msgtype, poverlay_callback callback) {
  poverlay_callback *callbacks_old = callbacks;
  int callbacks_size_old = callbacks_size;
  if (msgtype < calbacks_lower_band)
    return -1;
  if (msgtype > (calbacks_lower_band + callbacks_size)) {
    callbacks_size = msgtype - calbacks_lower_band + 1;
    psync_overlay_init_callbacks();
    memcpy(callbacks, callbacks_old,
           callbacks_size_old * sizeof(poverlay_callback));
    psync_free(callbacks_old);
  }
  callbacks[msgtype - calbacks_lower_band] = callback;
  return 0;
}

void psync_overlay_init_callbacks() {
  callbacks = (poverlay_callback *)psync_malloc(sizeof(poverlay_callback) *
                                                callbacks_size);
  memset(callbacks, 0, sizeof(poverlay_callback) * callbacks_size);
}

static void psync_overlay_get_status_response(request_message *request,
                                              response_message *response,
                                              size_t available_space) {
  psync_path_status_t stat;

  stat = PSYNC_PATH_STATUS_NOT_OURS;

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
}

static void
psync_overlay_get_overlay_response_payload(request_message *request,
                                           response_message *response) {
  if (!response->payload) {
    response->payloadsz = 0;
    debug(D_NOTICE, "Callback succeeded with no reply data");
    return;
  }

  if (request->type == 23) {
    // LISTSYNC
    psync_folder_list_t *folders = (psync_folder_list_t *)response->payload;
    response->payloadsz = sizeof(psync_folder_list_t) +
                          folders->foldercnt * sizeof(psync_folder_t);
  } else if (request->type == 24) {
    // ADDSYNC
    response->payloadsz = sizeof(psync_syncid_t);
  } else {
    // default: response has no payload
    response->payloadsz = 0;
  }

  if (response->payload == NULL) {
    response->payloadsz = 0;
    debug(D_NOTICE, "No reply data received");
    return;
  }

  debug(D_NOTICE, "Callback succeeded with reply data, length: %zu",
        response->payloadsz);
}

static void psync_overlay_get_overlay_response(request_message *request,
                                               response_message *response,
                                               size_t available_space) {
  int cbidx; // callback index (based on message type)
  int cbret; // callback return value

  cbidx = request->type - 20;
  cbret = 0;

  if (!callbacks_running || (request->type >= ((uint32_t)calbacks_lower_band +
                                               (uint32_t)callbacks_size))) {
    response->msg->type = 13;
    snprintf(response->msg->value, available_space, "Invalid type.");
    debug(D_NOTICE, "Invalid request type: %u", request->type);
    return;
  }

  if (!callbacks[cbidx]) {
    response->msg->type = 13;
    snprintf(response->msg->value, available_space,
             "No callback with this id registered.");
    debug(D_NOTICE, "No callback registered for type: %u", request->type);
    return;
  }

  cbret = callbacks[cbidx](request->value, &response->payload);
  if (cbret == 0) {
    response->msg->type = 0;
    psync_overlay_get_overlay_response_payload(request, response);
  } else {
    response->msg->type = 13;
    snprintf(response->msg->value, available_space, "No.");
    response->payloadsz = 0;
    debug(D_NOTICE, "Callback failed with return code: %d", cbret);
  }
}

void psync_overlay_get_response(request_message *request,
                                response_message *response) {

  const char *dbgmsg; // debug messages
  size_t value_avail; // space available to store value (flexible array)

  dbgmsg = NULL;
  response->msg = (message *)psync_malloc(POVERLAY_BUFSIZE);
  memset(response->msg, 0, POVERLAY_BUFSIZE);
  response->msg->length = 0;
  response->payload = NULL;
  response->payloadsz = 0;
  value_avail = POVERLAY_BUFSIZE - sizeof(message);

  // never print the crypto password to the logs in plain text
  dbgmsg = (request->type == 20) ? "REDACTED" : request->value;
  debug(D_NOTICE, "Client Request type [%u] len [%lu] string: [%s]",
        request->type, request->length, dbgmsg);

  if (request->type < 20) {
    psync_overlay_get_status_response(request, response, value_avail);
  } else {
    psync_overlay_get_overlay_response(request, response, value_avail);
  }

  // a message with a type != 13 and a null string value after
  // processing is considered successful. set value to "Ok."
  if (response->msg->type != 13 && response->msg->value[0] == '\0') {
    snprintf(response->msg->value, value_avail, "Ok.");
  }

  // truncate messages that exceed the buffer boundaries
  size_t value_length = strnlen(response->msg->value, value_avail);
  response->msg->length = sizeof(message) + value_length + 1;
  if (response->msg->length > POVERLAY_BUFSIZE) {
    response->msg->length = POVERLAY_BUFSIZE;
    response->msg->value[value_avail - 1] = '\0';
    debug(D_WARNING, "Response message truncated to fit buffer");
  }
}

void psync_overlay_stop_overlays() { overlays_running = 0; }
void psync_overlay_start_overlays() { overlays_running = 1; }
void psync_overlay_stop_overlay_callbacks() { callbacks_running = 0; }
void psync_overlay_start_overlay_callbacks() { callbacks_running = 1; }
int psync_overlay_overlays_running() { return overlays_running; }
int psync_overlay_callbacks_running() { return callbacks_running; }
