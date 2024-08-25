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
  overlay_client is responsible for invoking the pCloud API and
  directing the result back to the calling function. It defines the
  core logic of the request-response flow:

  - SendCall (this function) writes the request to the socket.

  - instance_thread reads the request from the socket and calls
  get_response (see poverlay.c).

  - get_response invokes the appropriate callback function and
  generates a response_message. The callback functions are
  registered in pclsync_lib.cpp using psync_add_overlay_callback
  (see poverlay.c).

  - instance_thread writes the resulting response_message to the
  socket (see poverlay.c).

  - SendCall reads the response from the socket. It writes the
  response output data back to its caller (see control_tools.cpp).
*/

#include <errno.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "debug.h"
#include "overlay_client.h"
#include "poverlay_protocol.h"

#define POVERLAY_BUFSIZE 16 * 1024

// for easier error tracing...
#define POVERLAY_SOCKET_CREATE_FAILED -100
#define POVERLAY_SOCKET_CONNECT_FAILED -101
#define POVERLAY_WRITE_SOCK_ERR -102
#define POVERLAY_WRITE_COMM_ERR -103
#define POVERLAY_READ_SOCK_ERR -104
#define POVERLAY_READ_INCOMPLETE -105
#define POVERLAY_READ_INVALID_RESPONSE -106

response_message *deserialize_response_message(const char *buffer,
                                               size_t buffer_size) {
  if (buffer_size < 2 * sizeof(size_t) + sizeof(uint32_t) + sizeof(uint64_t)) {
    debug(D_ERROR, "Buffer size too small: %zu", buffer_size);
    return NULL;
  }

  const char *ptr = buffer;

  // Allocate response_message
  response_message *resp = (response_message *)malloc(sizeof(response_message));
  if (resp == NULL) {
    debug(D_ERROR, "Failed to allocate response_message");
    return NULL;
  }

  // Get message size
  size_t msg_size = be64toh(*(size_t *)ptr);
  ptr += sizeof(size_t);

  debug(D_ERROR, "Message size: %zu", msg_size);

  if (msg_size < sizeof(uint32_t) + sizeof(uint64_t)) {
    debug(D_ERROR, "Invalid message size: %zu", msg_size);
    free(resp);
    return NULL;
  }

  // Allocate message with extra space for the flexible array member
  size_t alloc_size =
      sizeof(message) + msg_size - sizeof(uint32_t) - sizeof(uint64_t);
  resp->msg = (message *)malloc(alloc_size);
  if (resp->msg == NULL) {
    debug(D_ERROR, "Failed to allocate message");
    free(resp);
    return NULL;
  }

  resp->msg->type = ntohl(*(uint32_t *)ptr);
  ptr += sizeof(uint32_t);

  resp->msg->length = be64toh(*(uint64_t *)ptr);
  ptr += sizeof(uint64_t);

  debug(D_ERROR, "Message type: %u, length: %lu", resp->msg->type,
        resp->msg->length);

  // Calculate the size of the value array
  size_t value_size = msg_size - sizeof(uint32_t) - sizeof(uint64_t);

  if (value_size > 0) {
    if (ptr + value_size > buffer + buffer_size) {
      debug(D_ERROR, "Buffer overflow detected");
      free(resp->msg);
      free(resp);
      return NULL;
    }
    memcpy(resp->msg->value, ptr, value_size);
    ptr += value_size;
  }

  // Deserialize payload size
  if (ptr + sizeof(size_t) > buffer + buffer_size) {
    debug(D_ERROR, "Buffer overflow detected when reading payload size");
    free(resp->msg);
    free(resp);
    return NULL;
  }
  resp->payloadsz = be64toh(*(size_t *)ptr);
  ptr += sizeof(size_t);

  debug(D_ERROR, "Payload size: %zu", resp->payloadsz);

  // Deserialize payload
  if (resp->payloadsz > 0) {
    if (ptr + resp->payloadsz > buffer + buffer_size) {
      debug(D_ERROR, "Buffer overflow detected when reading payload");
      free(resp->msg);
      free(resp);
      return NULL;
    }
    resp->payload = malloc(resp->payloadsz);
    if (resp->payload == NULL) {
      debug(D_ERROR, "Failed to allocate payload");
      free(resp->msg);
      free(resp);
      return NULL;
    }
    memcpy(resp->payload, ptr, resp->payloadsz);
  } else {
    resp->payload = NULL;
  }

  return resp;
}

void free_response_message(response_message *resp) {
  if (resp) {
    free(resp->msg);
    free(resp->payload);
    free(resp);
  }
}

int QueryState(pCloud_FileState *state, char *path) {
  int rep = 0;
  char *errm;
  size_t errm_size;

  if (!SendCall(4, path /*IN*/, &rep, &errm, &errm_size, NULL, NULL)) {
    debug(D_NOTICE, "QueryState responese rep[%d] path[%s]", rep, path);
    if (errm)
      debug(D_NOTICE, "The error is %s", errm);
    if (rep == 10)
      *state = FileStateInSync;
    else if (rep == 12)
      *state = FileStateInProgress;
    else if (rep == 11)
      *state = FileStateNoSync;
    else
      *state = FileStateInvalid;
  } else
    debug(D_ERROR, "QueryState ERROR rep[%d] path[%s]", rep, path);
  free(errm);
  return 0;
}

// socket_connect creates and connects to a unix socket at the
// specified sockpath. it may write an error message and error message
// size to out and out_size, and a "ret" value to ret (i think this is
// redundant maybe...)
int socket_connect(const char *sockpath, char **out, size_t *out_size,
                   int *ret) {
  int fd;
  struct sockaddr_un addr;
  const char *error_msg;

  if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
    error_msg = "Unable to create unix socket";
    *out = strdup(error_msg);
    *out_size = strlen(error_msg) + 1;
    *ret = POVERLAY_SOCKET_CREATE_FAILED;
    return POVERLAY_SOCKET_CREATE_FAILED;
  }

  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  strncpy(addr.sun_path, sockpath, sizeof(addr.sun_path) - 1);
  if (connect(fd, (struct sockaddr *)&addr, SUN_LEN(&addr)) == -1) {
    error_msg = "Unable to connect to UNIX socket";
    *out = strdup(error_msg);
    *out_size = strlen(error_msg) + 1;
    *ret = POVERLAY_SOCKET_CONNECT_FAILED;
    return POVERLAY_SOCKET_CONNECT_FAILED;
  }
  return fd;
}

// write_request writes a request_message to given socket file
// descriptor of a given type and value. it may write out an error
// message and error message size to out and out_size, and a "ret"
// value to ret (i think this is redundant, maybe...)
int write_request(int fd, int msgtype, const char *value, char **out,
                  size_t *out_size, int *ret) {
  uint64_t bytes_written;
  int rc;
  int len;
  int size;
  char *buf;
  const char *err;
  request_message *request;
  char *curbuf;

  *ret = 0; // Initialize ret to 0

  len = strlen(value);
  size = sizeof(request_message) + len + 1;
  buf = (char *)malloc(size);
  request = (request_message *)buf;
  memset(request, 0, size);
  request->type = msgtype;
  strncpy(request->value, value, len + 1);
  request->length = size;
  bytes_written = 0;
  curbuf = (char *)request;

  while (bytes_written < request->length && *ret == 0) {
    rc = write(fd, curbuf, (request->length - bytes_written));
    if (rc <= 0) {
      if (errno != EINTR) {
        err = "failed to write to socket.";
        *out = strdup(err);
        *ret = POVERLAY_WRITE_SOCK_ERR;
      }
    } else {
      bytes_written += rc;
      curbuf += rc;
    }
  }

  if (*ret == 0 && bytes_written != request->length) {
    err = "Communication error";
    *out = strdup(err);
    *out_size = strlen(err) + 1;
    *ret = POVERLAY_WRITE_COMM_ERR;
  }

  free(buf);
  return *ret;
}

// read_response reads a response message from a given socket. it may
// write an error message OR an API response value to out (and its
// size to out_size), a "ret" value to ret (redundant?), and the
// callback's return data to payload and payloadsz.
int read_response(int fd, char **out, size_t *out_size, int *ret,
                  void **payload, size_t *payloadsz) {
  char buffer[POVERLAY_BUFSIZE];
  ssize_t bytes_read = read(fd, buffer, POVERLAY_BUFSIZE);

  if (bytes_read <= 0) {
    const char *error_msg =
        (bytes_read == 0) ? "Connection closed" : strerror(errno);
    *out = strdup(error_msg);
    *out_size = strlen(error_msg) + 1;
    *ret = -1;
    return -1;
  }

  if (bytes_read < sizeof(response_message)) {
    const char *error_msg = "Incomplete response";
    *out = strdup(error_msg);
    *out_size = strlen(error_msg) + 1;
    *ret = -1;
    return -1;
  }

  // response_message *resp = (response_message *)buffer;
  response_message *resp = deserialize_response_message(buffer, bytes_read);
  if (resp == NULL) {
    const char *error_msg = "Failed to deserialize response";
    *out = strdup(error_msg);
    *out_size = strlen(error_msg) + 1;
    *ret = -1;
    return -1;
  }

  // Validate the response_message structure
  if (resp->msg == NULL ||
      (size_t)bytes_read < sizeof(response_message) + sizeof(message) ||
      (size_t)bytes_read < sizeof(response_message) + resp->msg->length) {
    const char *error_msg = "Invalid response structure";
    *out = strdup(error_msg);
    *out_size = strlen(error_msg) + 1;
    *ret = -1;
    return -1;
  }

  message *msg = resp->msg;
  size_t value_size = msg->length - sizeof(message);

  // Validate message length
  if (msg->length < sizeof(message) ||
      (size_t)bytes_read < sizeof(response_message) + msg->length) {
    const char *error_msg = "Invalid message length";
    *out = strdup(error_msg);
    *out_size = strlen(error_msg) + 1;
    *ret = -1;
    return -1;
  }

  *out = malloc(value_size + 1);
  if (*out == NULL) {
    const char *error_msg = "Memory allocation failed";
    *out = strdup(error_msg);
    *out_size = strlen(error_msg) + 1;
    *ret = -1;
    free_response_message(resp);
    return -1;
  }

  memcpy(*out, msg->value, value_size);
  (*out)[value_size] = '\0';
  *out_size = value_size + 1;

  *ret = msg->type;

  if (payload != NULL && payloadsz != NULL) {
    if (resp->payload != NULL && resp->payloadsz > 0) {
      *payload = malloc(resp->payloadsz);
      if (*payload == NULL) {
        const char *error_msg = "Memory allocation failed for payload";
        free(*out);
        *out = strdup(error_msg);
        *out_size = strlen(error_msg) + 1;
        *ret = -1;
        free_response_message(resp);
        return -1;
      }
      memcpy(*payload, resp->payload, resp->payloadsz);
      *payloadsz = resp->payloadsz;
    } else {
      *payload = NULL;
      *payloadsz = 0;
    }
  }

  free_response_message(resp);
  return 0;
}

int SendCall(int id /*IN*/, const char *path /*IN*/, int *ret /*OUT*/,
             char **out /*OUT*/, size_t *out_size, void **reply_data,
             size_t *reply_size) {
  int result;
  int sockfd;

  sockfd = -1;
  result = 0;
  *out = NULL;
  *out_size = 0;
  *ret = 0;

  // side effects: modify out, out_size, ret
  sockfd = socket_connect(POVERLAY_SOCK_PATH, out, out_size, ret);
  if (sockfd >= 0) {
    // side effects: modify out, out_size, ret
    if ((result = write_request(sockfd, id, path, out, out_size, ret)) == 0) {
      // side effects: modify out, out_size, ret, reply_data, reply_size
      result =
          read_response(sockfd, out, out_size, ret, reply_data, reply_size);
    }
    close(sockfd);
  } else {
    result = -1;
  }
  return *ret; // always 0 on success
}
