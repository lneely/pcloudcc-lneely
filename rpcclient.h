#ifndef __RPCCLIENT_H
#define __RPCCLIENT_H

#include <cstddef>

typedef enum _pCloud_FileState {
  FileStateInSync = 0,
  FileStateNoSync,
  FileStateInProgress,
  FileStateInvalid
} pCloud_FileState;

class RpcClient {

private:
  const char *sockpath;

  int connectSocket(const char *sockpath, char **out, size_t *out_size);
  int writeRequest(int fd, int msgtype, const char *value, char **out, size_t *out_size);
  int readResponse(int fd, char **out, size_t *out_size);
public:
  RpcClient();
  ~RpcClient();
  int GetState(pCloud_FileState *, char *);
  int Call(int id, const char *path, char **errm, size_t *errmsz);
};

#endif