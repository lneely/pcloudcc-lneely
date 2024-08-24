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
#define POVERLAY_BUFSIZE 512

typedef struct _message {
  uint32_t type;
  uint64_t length;
  char value[];
} message;

const char *clsoc = "/tmp/pcloud_unix_soc.sock";

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

int SendCall(int id /*IN*/, const char *path /*IN*/, int *ret /*OUT*/,
             char **out /*OUT*/, size_t *out_size, void **reply_data,
             size_t *reply_size) {
  struct sockaddr_un addr;
  int result, rc;
  uint64_t sendbytes = 0;
  int fd = -1;
  int sendlen = strlen(path);
  int sendsize = sizeof(message) + sendlen + 1;

  char sendbuf[sendsize];

  char *recvbuf = NULL;
  size_t recvsize = 0;
  size_t recvbytes = 0;
  size_t recvchunk = 32; // read response in 32-byte chunks

  message *rep = NULL;
  const char *error_msg;

  // init output params
  *out = NULL;
  *out_size = 0;
  *ret = 0;
  result = 0;

  printf("Sendcall about to send path: %s\n", path);

  // prepare socket fd
  if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
    error_msg = "Unable to create unix socket";
    *out = strdup(error_msg);
    if (*out == NULL) {
      debug(D_ERROR,
            "on socket(): failed to allocate memory for output message");
      *ret = -255;
      return -255;
    }
    *out_size = strlen(error_msg) + 1;
    *ret = -3;
    return -3;
  }

  // connect to socket
  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  strncpy(addr.sun_path, clsoc, sizeof(addr.sun_path) - 1);
  if (connect(fd, (struct sockaddr *)&addr, SUN_LEN(&addr)) == -1) {
    error_msg = "Unable to connect to UNIX socket";
    *out = strdup(error_msg);
    if (*out == NULL) {
      debug(D_ERROR,
            "on connect(): failed to allocate memory for output message");
      *ret = -254;
      return -254;
    }
    *out_size = strlen(error_msg) + 1;
    *ret = -4;
    return -4;
  }

  // prepare and send the message to the socket
  message *mes = (message *)sendbuf;
  memset(mes, 0, sendsize);
  mes->type = id;
  strncpy(mes->value, path, sendlen + 1);
  mes->length = sendsize;

  char *curbuf = (char *)mes;
  while (sendbytes < mes->length) {
    rc = write(fd, curbuf, (mes->length - sendbytes));
    if (rc <= 0) {
      if (errno == EINTR)
        continue; // try again on interrupt

      error_msg = "failed to write to socket.";
      *out = strdup(error_msg);
      if (*out == NULL) {
        debug(D_ERROR, "failed to allocate memory for output message");
        *ret = -253;
        return -253;
      }
      *ret = -248;
      return -248;
    }
    sendbytes += rc;
  }

  if (sendbytes != mes->length) {
    error_msg = "Communication error";
    *out = strdup(error_msg);
    if (*out == NULL) {
      debug(D_ERROR, "while checking bytes_written: failed to allocate memory "
                     "for output message");
      *ret = -253;
      return -253;
    }
    *out_size = strlen(error_msg) + 1;
    *ret = -5;
    return -5;
  }

  // read the response from the socket
  bool received_data = false;
  for (;;) {
    char *new_buf = realloc(recvbuf, recvsize + recvchunk);
    if (!new_buf) {
      debug(D_ERROR, "failed to allocate memory to response buffer");
      *ret = -252;
      result = -252;
      goto cleanup;
    }
    recvbuf = new_buf;

    rc = read(fd, recvbuf + recvsize, recvchunk);
    if (rc < 0) {
      if (errno == EINTR) {
        continue; // try again on interrupt
      }
      debug(D_ERROR, "failed to read from socket into response buffer");
      *ret = -251;
      result = -251;
      goto cleanup;
    }

    if (rc == 0) {
      break; // end of response
    }
    received_data = true;
    recvsize += rc;
    recvbytes += rc;
  }

  if (!received_data) {
    *ret = 0;
    *out = strdup("");
    if (*out == NULL) {
      debug(D_ERROR, "failed to allocate memory for empty output message");
      *ret = -248;
      result = -248;
      goto cleanup;
    }
    *out_size = 1;
    result = 0;
    goto cleanup;
  }

  if (recvbytes >= sizeof(message)) {
    message *rep = (message *)recvbuf;
  }

  if (recvbytes < sizeof(message)) {
    debug(D_ERROR, "got incomplete message from socket");
    *ret = -250;
    result = -250;
    goto cleanup;
  }

  rep = (message *)recvbuf;
  *ret = rep->type;

  size_t value_size = rep->length - sizeof(message);
  *out = malloc(value_size + 1);
  if (!*out) {
    debug(D_ERROR, "failed to allocate memory to output buffer");
    *ret = -249;
    result = -249;
    goto cleanup;
  }
  memcpy(*out, rep->value, value_size);
  (*out)[value_size] = '\0';
  *out_size = value_size + 1;

  if (reply_data != NULL && reply_size != NULL) {
    if (recvbytes > rep->length) {
      size_t reply_data_size = recvbytes - rep->length;
      *reply_data = malloc(reply_data_size);
      if (*reply_data == NULL) {
        debug(D_ERROR, "Failed to allocate memory for reply_data");
        *ret = -248;
        result = -248;
        goto cleanup;
      }
      memcpy(*reply_data, recvbuf + rep->length, reply_data_size);
      *reply_size = reply_data_size; // Set the reply_size
    } else {
      *reply_data = NULL;
      *reply_size = 0; // Set reply_size to 0 if no extra data
    }
  }

cleanup:
  if (fd != -1)
    close(fd);
  if (recvbuf)
    free(recvbuf);

  return result;
}
