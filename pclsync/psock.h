#ifndef __PSOCK_H
#define __PSOCK_H

#include <stdint.h>
#include <sys/socket.h>

#include "pcompiler.h"

typedef struct _psync_socket_buffer {
  struct _psync_socket_buffer *next;
  uint32_t size;
  uint32_t woffset;
  uint32_t roffset;
  char buff[];
} psync_socket_buffer;

typedef struct {
  void *ssl;
  psync_socket_buffer *buffer;
  int sock;
  int pending;
  uint32_t misc;
} psync_socket_t;

typedef struct {
  struct sockaddr_storage address;
  struct sockaddr_storage broadcast;
  struct sockaddr_storage netmask;
  int addrsize;
} psync_interface_t;

typedef struct {
  size_t interfacecnt;
  psync_interface_t interfaces[];
} psock_interface_list_t;

int psock_create(int domain, int type, int protocol);
psync_socket_t *psock_connect(const char *host, int unsigned port, int ssl);
void psock_close(psync_socket_t *sock);
void psock_close_bad(psync_socket_t *sock);
int psock_read(psync_socket_t *sock, void *buff, int num);
int psock_write(psync_socket_t *sock, const void *buff, int num);
int psock_readall(psync_socket_t *sock, void *buff, int num);
int psock_writeall(psync_socket_t *sock, const void *buff, int num);
int psock_read_noblock(psync_socket_t *sock, void *buff, int num);
int psock_read_thread(psync_socket_t *sock, void *buff, int num);
int psock_readall_thread(psync_socket_t *sock, void *buff, int num);
int psock_writeall_thread(psync_socket_t *sock, const void *buff, int num);
int psock_is_ssl(psync_socket_t *sock) PSYNC_PURE;
int psock_is_broken(int sock);
int psock_readable(psync_socket_t *sock);
int psock_writable(psync_socket_t *sock);
int psock_pendingdata(psync_socket_t *sock);
int psock_pendingdata_buf(psync_socket_t *sock);
int psock_pendingdata_buf_thread(psync_socket_t *sock);
int psock_set_recvbuf(psync_socket_t *sock, int bufsize);
int psock_set_sendbuf(psync_socket_t *sock, int bufsize);
void psock_set_write_buffered(psync_socket_t *sock);
void psock_clear_write_buffered(psync_socket_t *sock);
void psock_set_write_buffered_thread(psync_socket_t *sock);
void psock_clear_write_buffered_thread(psync_socket_t *sock);
int psync_socket_try_write_buffer(psync_socket_t *sock);
int psync_socket_try_write_buffer_thread(psync_socket_t *sock);
int psock_wait_read_timeout(int sock);
int psock_wait_write_timeout(int sock);
int psock_select_in(int *sockets, int cnt, int64_t timeoutmillisec);
psock_interface_list_t *psock_list_adapters();

#endif