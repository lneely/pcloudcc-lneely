#include <errno.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "rpcclient.h"
#include "plibs.h"
#include "pdbg.h"
#include "prpc.h"
#include "putil.h"


#define POVERLAY_BUFSIZE 512

#define POVERLAY_SOCKET_CREATE_FAILED -100
#define POVERLAY_SOCKET_CONNECT_FAILED -101
#define POVERLAY_WRITE_SOCK_ERR -102
#define POVERLAY_WRITE_COMM_ERR -103
#define POVERLAY_READ_SOCK_ERR -104
#define POVERLAY_READ_INCOMPLETE -105
#define POVERLAY_READ_INVALID_RESPONSE -106

RpcClient::RpcClient() {}

RpcClient::~RpcClient() {}

// socket_connect creates and connects to a unix socket at the
// specified sockpath. it may write an error message and error message
// size to out and out_size, and a "ret" value to ret (i think this is
// redundant maybe...)
int RpcClient::connectSocket(const char *sockpath, char **out, size_t *out_size) {
  int fd;
  struct sockaddr_un addr;
  const char *error_msg;

  if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
    error_msg = "Unable to create unix socket";
    *out = strdup(error_msg);
    *out_size = strlen(error_msg) + 1;
    return POVERLAY_SOCKET_CREATE_FAILED;
  }

  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  strncpy(addr.sun_path, sockpath, sizeof(addr.sun_path) - 1);
  if (connect(fd, (struct sockaddr *)&addr, SUN_LEN(&addr)) == -1) {
    error_msg = "Unable to connect to UNIX socket";
    *out = strdup(error_msg);
    *out_size = strlen(error_msg) + 1;
    return POVERLAY_SOCKET_CONNECT_FAILED;
  }
  return fd;
}

int RpcClient::writeRequest(int fd, int msgtype, const char *value, char **out, size_t *out_size) {
  uint64_t bytes_written;
  int len = strlen(value);
  int size = sizeof(rpc_message_t) + len + 1;
  char *buf = (char *)malloc(size);

  // prepare the message
  rpc_message_t *request = (rpc_message_t *)buf;
  memset(request, 0, size);
  request->type = msgtype;
  strncpy(request->value, value, len + 1);
  request->length = size;
  bytes_written = 0;

  // write to the socket
  char *curbuf = (char *)request;
  int writeerr = 0;
  while (bytes_written < request->length && !writeerr) {
    int rc = write(fd, curbuf, (request->length - bytes_written));
    if (rc <= 0) {
      if (errno != EINTR) {
        const char *err = "failed to write to socket.";
        *out = strdup(err);
        *out_size = strlen(err) + 1;
        writeerr = POVERLAY_WRITE_SOCK_ERR;
      }
    } else {
      bytes_written += rc;
      curbuf += rc;
    }
  }

  // return error if only partial data written
  if (!writeerr && bytes_written != request->length) {
    const char *err = "communication error";
    *out = strdup(err);
    *out_size = strlen(err) + 1;
    writeerr = POVERLAY_WRITE_COMM_ERR;
  }

  putil_wipe(buf, size);
  free(buf);
  return writeerr;
}

int RpcClient::readResponse(int fd, char **out, size_t *out_size) {
    char buf[POVERLAY_BUFSIZE];
    rpc_message_t *msg = (rpc_message_t *)buf;
    size_t header_size = offsetof(rpc_message_t, value);
    ssize_t total_read = 0;
    ssize_t bytes_read;

    // Loop to handle partial reads into fixed-size buffer
    while (total_read < (ssize_t)POVERLAY_BUFSIZE) {
        bytes_read = read(fd, buf + total_read, POVERLAY_BUFSIZE - total_read);
        if (bytes_read < 0) {
            if (errno == EINTR)
                continue;
            const char *error_msg = "Read error";
            *out = strdup(error_msg);
            *out_size = strlen(error_msg) + 1;
            return POVERLAY_READ_SOCK_ERR;
        }
        if (bytes_read == 0)
            break; // EOF
        total_read += bytes_read;
        // Stop once we have received the complete message
        if (total_read >= (ssize_t)header_size &&
            msg->length <= (uint64_t)total_read)
            break;
    }

    // Validate msg->length <= bytes_read and msg->length <= POVERLAY_BUFSIZE
    // before malloc/memcpy to prevent heap over-read
    if ((uint64_t)total_read < header_size ||
        msg->length < header_size ||
        msg->length > (uint64_t)total_read ||
        msg->length > POVERLAY_BUFSIZE) {
        const char *error_msg = "Invalid response length";
        *out = strdup(error_msg);
        *out_size = strlen(error_msg) + 1;
        return POVERLAY_READ_INVALID_RESPONSE;
    }

    size_t value_length = (size_t)msg->length - header_size;
    *out = (char *)malloc(value_length + 1);
    if (*out == NULL) {
        const char *error_msg = "Memory allocation failed";
        *out = strdup(error_msg);
        *out_size = strlen(error_msg) + 1;
        return -1;
    }
    memcpy(*out, msg->value, value_length);
    (*out)[value_length] = '\0';
    *out_size = value_length;

    return 0;
}

int RpcClient::GetState(pCloud_FileState *state, char *path) {
  char *errm = NULL;
  size_t errm_size = 0;
  int rep = 0;

  if ((rep = this->Call(4, path, &errm, &errm_size)) == 0) {
    pdbg_logf(D_NOTICE, "rpc_get_state responese rep[%d] path[%s]", rep, path);
    if (errm) {
      pdbg_logf(D_NOTICE, "The error is %s", errm);
    }
    if (rep == 10) {
      *state = FileStateInSync;
    } else if (rep == 12) {
      *state = FileStateInProgress;
    } else if (rep == 11) {
      *state = FileStateNoSync;
    } else {
      *state = FileStateInvalid;
    }
  } else {
    pdbg_logf(D_ERROR, "rpc_get_state ERROR rep[%d] path[%s]", rep, path);
  }
  if(errm) {
    free(errm);    
  }
  return 0;
}

int RpcClient::Call(int id, const char *path, char **errm, size_t *errmsz) {
  int result = 0;
  int sockfd = -1;

  char *sockpath = prpc_sockpath();
  sockfd = this->connectSocket(sockpath, errm, errmsz);
  free(sockpath);
  if (sockfd >= 0) {
    if ((result = this->writeRequest(sockfd, id, path, errm, errmsz)) == 0) {
      result = this->readResponse(sockfd, errm, errmsz);
    }
    close(sockfd);
  } else {
    result = -1;
  }
  return result; // always 0 on success
}
