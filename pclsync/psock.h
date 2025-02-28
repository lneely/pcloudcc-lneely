#ifndef __PSOCK_H
#define __PSOCK_H

#include <stdint.h>
#include <sys/socket.h>

#include "pcompiler.h"

typedef struct _psock_buf_t {
  struct _psock_buf_t *next;
  uint32_t size;
  uint32_t woffset;
  uint32_t roffset;
  char buff[];
} psock_buf_t;

typedef struct {
  void *ssl;
  psock_buf_t *buffer;
  int sock;
  int pending;
  uint32_t misc;
} psock_t;

typedef struct {
  struct sockaddr_storage address;
  struct sockaddr_storage broadcast;
  struct sockaddr_storage netmask;
  int addrsize;
} psock_iface_t;

typedef struct {
  size_t interfacecnt;
  psock_iface_t interfaces[];
} psock_ifaces_t;

int psock_create(int domain, int type, int protocol);
psock_t *psock_connect(const char *host, int unsigned port, int ssl);
void psock_close(psock_t *sock);
void psock_close_bad(psock_t *sock);
int psock_read(psock_t *sock, void *buff, int num);
int psock_write(psock_t *sock, const void *buff, int num);
int psock_readall(psock_t *sock, void *buff, int num);
int psock_writeall(psock_t *sock, const void *buff, int num);
int psock_read_noblock(psock_t *sock, void *buff, int num);
int psock_read_thread(psock_t *sock, void *buff, int num);
int psock_readall_thread(psock_t *sock, void *buff, int num);
int psock_writeall_thread(psock_t *sock, const void *buff, int num);
int psock_is_ssl(psock_t *sock) PSYNC_PURE;
int psock_is_broken(int sock);
int psock_readable(psock_t *sock);
int psock_writable(psock_t *sock);
int psock_pendingdata(psock_t *sock);
int psock_pendingdata_buf(psock_t *sock);
int psock_pendingdata_buf_thread(psock_t *sock);
int psock_set_recvbuf(psock_t *sock, int bufsize);
int psock_set_sendbuf(psock_t *sock, int bufsize);
void psock_set_write_buffered(psock_t *sock);
void psock_clear_write_buffered(psock_t *sock);
void psock_set_write_buffered_thread(psock_t *sock);
void psock_clear_write_buffered_thread(psock_t *sock);
int psock_try_write_buffer(psock_t *sock);
int psock_try_write_buffer_thread(psock_t *sock);
int psock_wait_read_timeout(int sock);
int psock_wait_write_timeout(int sock);
int psock_select_in(int *sockets, int cnt, int64_t timeoutmillisec);
psock_ifaces_t *psock_list_adapters();

#endif