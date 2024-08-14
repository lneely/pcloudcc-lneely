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

#include <netinet/in.h>
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

static int read_x_bytes(int socket, unsigned int x, char *buffer) {
  int bytesRead = 0;
  int result;
  while (bytesRead < x) {
    result = read(socket, buffer + bytesRead, x - bytesRead);
    if (result < 1) {
      return result;
    }
    bytesRead += result;
  }
  return result;
}

const char *clsoc = "/tmp/pcloud_unix_soc.sock";

int QueryState(pCloud_FileState *state, char *path) {
  int rep = 0;
  char *errm;
  size_t errm_size;

  if (!SendCall(4, path /*IN*/, &rep, &errm, &errm_size)) {
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
             char **out /*OUT*/, size_t *out_size) {
  struct sockaddr_un addr;

  int result, sendbytes, rc;
  int fd = -1;
  int sendlen = strlen(path);
  int sendsize = sizeof(message) + sendlen + 1;

  char *curbuf = NULL;
  char sendbuf[sendsize];

  char *recvbuf = NULL;
  size_t recvsize, recvbytes;
  size_t recvchunk = 32; // read response in 32-byte chunks

  message *rep = NULL;
  const char *error_msg;

  // init output params
  *out = NULL;
  *out_size = 0;
  *ret = 0;
  result = 0;

  debug(D_NOTICE, "SendCall id[%d] path[%s]\n", id, path);

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
  strncpy(mes->value, path, sendlen);
  mes->length = sendsize;
  curbuf = (char *)mes;
  while ((rc = write(fd, curbuf, (mes->length - sendbytes))) > 0) {
    sendbytes += rc;
    curbuf = curbuf + rc;
  }
  debug(D_NOTICE, "QueryState bytes send[%d]\n", sendbytes);
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
  rc = 0;
  for (;;) {
    recvbuf = realloc(recvbuf, recvsize + recvchunk);
    if (!recvbuf) {
      debug(D_ERROR, "failed to allocate memory to response buffer");
      *ret = -252;
      return -252;
    }

    rc = read(fd, recvbuf + recvsize, recvchunk);
    if (rc < 0) {
      debug(D_ERROR, "failed to read from socket into response buffer");
      *ret = -251;
      return -251;
    }
    if (rc == 0) {
      break; // end of response
    }
    recvsize += rc;
    recvbytes += rc;

    if (recvbytes >= sizeof(message)) {
      message *rep = (message *)recvbuf;
      if (recvbytes >= rep->length) {
        break; // entire message read
      }
    }
  }

  if (recvbytes < sizeof(message)) {
    debug(D_ERROR, "got incomplete message from socket");
    *ret = -250;
    return -250;
  }

  rep = (message *)recvbuf;
  *ret = rep->type;

  size_t value_size = rep->length - sizeof(message);
  *out = malloc(value_size + 1);
  if (!*out) {
    debug(D_ERROR, "failed to allocate memory to output buffer");
    *ret = -249;
    return -249;
  }
  memcpy(*out, rep->value, value_size);
  (*out)[value_size] = '\0';
  *out_size = value_size + 1;

  if (fd != -1)
    close(fd);
  if (recvbuf)
    free(recvbuf);

  return result;
}

#ifdef PCLOUD_TESTING
int main(int arc, char **argv) {
  int i, j = 0;
  pCloud_FileState state;
  char *errm;
  size_t errm_size;

  for (i = 1; i < arc; ++i) {
    QueryState(&state, argv[i]);
    if (state == FileStateInSync)
      printf("File %s FileStateInSync\n", argv[i]);
    else if (state == FileStateNoSync)
      printf("File %s FileStateNoSync\n", argv[i]);
    else if (state == FileStateInProgress)
      printf("File %s FileStateInProgress\n", argv[i]);
    else if (state == FileStateInvalid)
      printf("File %s FileStateInvalid\n", argv[i]);
    else
      printf("Not valid state returned for file %s\n", argv[i]);
    SendCall(20, argv[i], &j, &errm, &errm_size);
    printf("Call 20 returned %d msg %s \n", j, errm);
    SendCall(21, argv[i], &j, &errm, &errm_size);
    printf("Call 21 returned %d msg %s \n", j, errm);
    SendCall(22, argv[i], &j, &errm, &errm_size);
    printf("Call 22 returned %d msg %s \n", j, errm);
    SendCall(23, argv[i], &j, &errm, &errm_size);
    printf("Call 22 returned %d msg %s \n", j, errm);
  }
  return 0;
}
#endif
