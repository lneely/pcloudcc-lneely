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
  if (!SendCall(4, path /*IN*/, &rep, &errm)) {
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
             char **out /*OUT*/) {
  struct sockaddr_un addr;

  int fd, rc;
  int path_size = strlen(path);
  int mess_size = sizeof(message) + path_size + 1;
  int bytes_writen = 0;
  char *curbuf = NULL;
  char *buf = NULL;
  uint32_t bufflen = 0;
  char sendbuf[mess_size];
  int bytes_read = 0;
  message *rep = NULL;

  debug(D_NOTICE, "SendCall id[%d] path[%s]\n", id, path);

  if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
    *out = strndup("Unable to create UNIX socket", 27);
    *ret = -3;
    return -3;
  }
  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  strncpy(addr.sun_path, clsoc, sizeof(addr.sun_path) - 1);

  if (connect(fd, (struct sockaddr *)&addr, SUN_LEN(&addr)) == -1) {
    *out = strndup("Unable to connect to UNIX socket", 32);
    *ret = -4;
    return -4;
  }

  message *mes = (message *)sendbuf;
  memset(mes, 0, mess_size);
  mes->type = id;
  strncpy(mes->value, path, path_size);
  mes->length = mess_size;
  curbuf = (char *)mes;
  while ((rc = write(fd, curbuf, (mes->length - bytes_writen))) > 0) {
    bytes_writen += rc;
    curbuf = curbuf + rc;
  }
  debug(D_NOTICE, "QueryState bytes send[%d]\n", bytes_writen);
  if (bytes_writen != mes->length) {
    *out = strndup("Communication error", 19);
    close(fd);
    *ret = -5;
    return -5;
  }

  bufflen = read_x_bytes(fd, 4, buf);

  if (bufflen <= 0) {
    debug(D_NOTICE, "Message size could not be read![%d]\n", bufflen);
    return -6;
  }
  buf = (char *)malloc(bufflen);
  rep = (message *)buf;
  rep->length = bufflen;

  read_x_bytes(fd, bufflen - 4, buf + 4);

  *ret = rep->type;
  *out = strndup(rep->value, rep->length - sizeof(message));

  close(fd);

  return 0;
}

#ifdef PCLOUD_TESTING
int main(int arc, char **argv) {
  int i, j = 0;
  pCloud_FileState state;
  char *errm;

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
    SendCall(20, argv[i], &j, &errm);
    printf("Call 20 returned %d msg %s \n", j, errm);
    SendCall(21, argv[i], &j, &errm);
    printf("Call 21 returned %d msg %s \n", j, errm);
    SendCall(22, argv[i], &j, &errm);
    printf("Call 22 returned %d msg %s \n", j, errm);

    SendCall(23, argv[i], &j, &errm);
    printf("Call 22 returned %d msg %s \n", j, errm);
  }
  return 0;
}
#endif
