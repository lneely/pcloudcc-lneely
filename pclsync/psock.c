/*
   Copyright (c) 2013 Anton Titov.

   Copyright (c) 2013 pCloud Ltd.  All rights reserved.

   Redistribution and use in source and binary forms, with or without
   modification, are permitted provided that the following conditions
   are met: Redistributions of source code must retain the above
   copyright notice, this list of conditions and the following
   disclaimer.  Redistributions in binary form must reproduce the
   above copyright notice, this list of conditions and the following
   disclaimer in the documentation and/or materials provided with the
   distribution.  Neither the name of pCloud Ltd nor the names of its
   contributors may be used to endorse or promote products derived
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
#include <ifaddrs.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <unistd.h>

#include "plibs.h"
#include "psettings.h"
#include "psock.h"
#include "ptimer.h"

#define PROXY_NONE 0
#define PROXY_CONNECT 1

typedef struct {
  const char *host;
  const char *port;
} resolve_host_port;

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

static int wait_readable(int sock, long sec, long usec) {
  fd_set rfds;
  struct timeval tv;
#if IS_DEBUG
  struct timespec start, end;
  unsigned long msec;
#endif
  int res;
  tv.tv_sec = sec;
  tv.tv_usec = usec;
  FD_ZERO(&rfds);
  FD_SET(sock, &rfds);
#if IS_DEBUG
  clock_gettime(CLOCK_REALTIME, &start);
#endif
  res = select(sock + 1, &rfds, NULL, NULL, &tv);

  if (res == 1) {
#if IS_DEBUG
    clock_gettime(CLOCK_REALTIME, &end);
    msec = (end.tv_sec - start.tv_sec) * 1000 + end.tv_nsec / 1000000 -
           start.tv_nsec / 1000000;
    if (msec >= 30000)
      debug(D_WARNING, "got response from socket after %lu milliseconds", msec);
    else if (msec >= 5000)
      debug(D_NOTICE, "got response from socket after %lu milliseconds", msec);
#endif
    return 0;
  }
  if (res == 0) {
    if (sec)
      debug(D_WARNING, "socket read timeouted on %ld seconds", sec);
    errno = (ETIMEDOUT);
  } else
    debug(D_WARNING, "select returned %d", res);

  return SOCKET_ERROR;
}

static int wait_writable(int sock, long sec, long usec) {
  fd_set wfds;
  struct timeval tv;
  int res;
  tv.tv_sec = sec;
  tv.tv_usec = usec;
  FD_ZERO(&wfds);
  FD_SET(sock, &wfds);
  res = select(sock + 1, NULL, &wfds, NULL, &tv);
  if (res == 1)
    return 0;
  if (res == 0)
    errno = (ETIMEDOUT);
  return SOCKET_ERROR;
}

static int wait_ssl_ready(int sock) {
  fd_set fds, *rfds, *wfds;
  struct timeval tv;
  int res;
  FD_ZERO(&fds);
  FD_SET(sock, &fds);
  if (psync_ssl_errno == PSYNC_SSL_ERR_WANT_READ) {
    rfds = &fds;
    wfds = NULL;
    tv.tv_sec = PSYNC_SOCK_READ_TIMEOUT;
  } else if (psync_ssl_errno == PSYNC_SSL_ERR_WANT_WRITE) {
    rfds = NULL;
    wfds = &fds;
    tv.tv_sec = PSYNC_SOCK_WRITE_TIMEOUT;
  } else {
    debug(D_BUG, "this functions should only be called when SSL returns "
                 "WANT_READ/WANT_WRITE");
    errno = (EINVAL);
    return SOCKET_ERROR;
  }
  tv.tv_usec = 0;
  res = select(sock + 1, rfds, wfds, NULL, &tv);
  if (res == 1)
    return 0;
  if (res == 0) {
    debug(D_WARNING, "socket timeouted");
    errno = (ETIMEDOUT);
  }
  return PRINT_RETURN_CONST(SOCKET_ERROR);
}

static int addr_valid(struct addrinfo *olda, struct addrinfo *newa) {
  struct addrinfo *a;
  do {
    a = newa;
    while (1) {
      if (a->ai_addrlen == olda->ai_addrlen &&
          !memcmp(a->ai_addr, olda->ai_addr, a->ai_addrlen))
        break;
      a = a->ai_next;
      if (!a)
        return 0;
    }
    olda = olda->ai_next;
  } while (olda);
  return 1;
}

static struct addrinfo *addr_load(const char *host, const char *port) {
  psync_sql_res *res;
  psync_uint_row row;
  psync_variant_row vrow;
  struct addrinfo *ret;
  char *data;
  const char *str;
  uint64_t i;
  size_t len;
  psync_sql_rdlock();
  res = psync_sql_query_nolock("SELECT COUNT(*), SUM(LENGTH(data)) FROM "
                               "resolver WHERE hostname=? AND port=?");
  psync_sql_bind_string(res, 1, host);
  psync_sql_bind_string(res, 2, port);
  if (!(row = psync_sql_fetch_rowint(res)) || row[0] == 0) {
    psync_sql_free_result(res);
    psync_sql_rdunlock();
    return NULL;
  }
  ret = (struct addrinfo *)psync_malloc(sizeof(struct addrinfo) * row[0] +
                                        row[1]);
  data = (char *)(ret + row[0]);
  for (i = 0; i < row[0] - 1; i++)
    ret[i].ai_next = &ret[i + 1];
  ret[i].ai_next = NULL;
  psync_sql_free_result(res);
  res = psync_sql_query_nolock(
      "SELECT family, socktype, protocol, data FROM resolver WHERE hostname=? "
      "AND port=? ORDER BY prio");
  psync_sql_bind_string(res, 1, host);
  psync_sql_bind_string(res, 2, port);
  i = 0;
  while ((vrow = psync_sql_fetch_row(res))) {
    ret[i].ai_family = psync_get_snumber(vrow[0]);
    ret[i].ai_socktype = psync_get_snumber(vrow[1]);
    ret[i].ai_protocol = psync_get_snumber(vrow[2]);
    str = psync_get_lstring(vrow[3], &len);
    ret[i].ai_addr = (struct sockaddr *)data;
    ret[i].ai_addrlen = len;
    i++;
    memcpy(data, str, len);
    data += len;
  }
  psync_sql_free_result(res);
  psync_sql_rdunlock();
  return ret;
}

static void addr_save(const char *host, const char *port,
                            struct addrinfo *addr) {
  psync_sql_res *res;
  uint64_t id;
  if (psync_sql_isrdlocked()) {
    if (psync_sql_tryupgradelock())
      return;
    else
      debug(D_NOTICE, "upgraded read to write lock to save data to DB");
  }
  psync_sql_start_transaction();
  res = psync_sql_prep_statement(
      "DELETE FROM resolver WHERE hostname=? AND port=?");
  psync_sql_bind_string(res, 1, host);
  psync_sql_bind_string(res, 2, port);
  psync_sql_run_free(res);
  res = psync_sql_prep_statement(
      "INSERT INTO resolver (hostname, port, prio, created, family, socktype, "
      "protocol, data) VALUES (?, ?, ?, ?, ?, ?, ?, ?)");
  psync_sql_bind_string(res, 1, host);
  psync_sql_bind_string(res, 2, port);
  psync_sql_bind_uint(res, 4, ptimer_time());
  id = 0;
  do {
    psync_sql_bind_uint(res, 3, id++);
    psync_sql_bind_int(res, 5, addr->ai_family);
    psync_sql_bind_int(res, 6, addr->ai_socktype);
    psync_sql_bind_int(res, 7, addr->ai_protocol);
    psync_sql_bind_blob(res, 8, (char *)addr->ai_addr, addr->ai_addrlen);
    psync_sql_run(res);
    addr = addr->ai_next;
  } while (addr);
  psync_sql_free_result(res);
  psync_sql_commit_transaction();
}

static int connect_res(struct addrinfo *res) {
  int sock;
#if defined(SOCK_NONBLOCK)
#if defined(SOCK_CLOEXEC)
#define PSOCK_TYPE_OR (SOCK_NONBLOCK | SOCK_CLOEXEC)
#else
#define PSOCK_TYPE_OR SOCK_NONBLOCK
#endif
#else
#define PSOCK_TYPE_OR 0
#define PSOCK_NEED_NOBLOCK
#endif
  while (res) {
    sock = socket(res->ai_family, res->ai_socktype | PSOCK_TYPE_OR,
                  res->ai_protocol);
    if (likely_log(sock != INVALID_SOCKET)) {
#if defined(PSOCK_NEED_NOBLOCK)
      fcntl(sock, F_SETFD, FD_CLOEXEC);
      fcntl(sock, F_SETFL, fcntl(sock, F_GETFL) | O_NONBLOCK);
#endif
      if ((connect(sock, res->ai_addr, res->ai_addrlen) != SOCKET_ERROR) ||
          (errno == EINPROGRESS &&
           !wait_writable(sock, PSYNC_SOCK_CONNECT_TIMEOUT, 0)))
        return sock;
      close(sock);
    }
    res = res->ai_next;
  }
  return INVALID_SOCKET;
}

static void cb_connect_res(void *h, void *ptr) {
  struct addrinfo *res;
  int sock;
  int r;
  res = (struct addrinfo *)ptr;
  sock = connect_res(res);
  r = psync_task_complete(h, (void *)(uintptr_t)sock);
  psync_free(res);
  if (r && sock != INVALID_SOCKET)
    close(sock);
}

static void cb_resolve(void *h, void *ptr) {
  resolve_host_port *hp;
  struct addrinfo *res;
  struct addrinfo hints;
  int rc;
  hp = (resolve_host_port *)ptr;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  res = NULL;
  rc = getaddrinfo(hp->host, hp->port, &hints, &res);
  if (unlikely(rc != 0))
    res = NULL;
  psync_task_complete(h, res);
}

static int connect_socket(const char *host, const char *port) {
  struct addrinfo *res, *dbres;
  struct addrinfo hints;
  int sock;
  int rc;
  debug(D_NOTICE, "connecting to %s:%s", host, port);
  dbres = addr_load(host, port);
  if (dbres) {
    resolve_host_port resolv;
    void *params[2];
    psync_task_callback_t callbacks[2];
    psync_task_manager_t tasks;
    resolv.host = host;
    resolv.port = port;
    params[0] = dbres;
    params[1] = &resolv;
    callbacks[0] = cb_connect_res;
    callbacks[1] = cb_resolve;
    tasks = psync_task_run_tasks(callbacks, params, 2);
    res = (struct addrinfo *)psync_task_papi_result(tasks, 1);
    if (unlikely(!res)) {
      psync_task_free(tasks);
      debug(D_WARNING, "failed to resolve %s", host);
      return INVALID_SOCKET;
    }
    addr_save(host, port, res);
    if (addr_valid(dbres, res)) {
      debug(D_NOTICE, "successfully reused cached IP for %s:%s", host, port);
      sock = (int)(uintptr_t)psync_task_papi_result(tasks, 0);
    } else {
      debug(D_NOTICE, "cached IP not valid for %s:%s", host, port);
      sock = connect_res(res);
    }
    freeaddrinfo(res);
    psync_task_free(tasks);
  } else {
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    res = NULL;
    rc = getaddrinfo(host, port, &hints, &res);
    if (unlikely(rc != 0)) {
      debug(D_WARNING, "failed to resolve %s", host);
      return INVALID_SOCKET;
    }
    addr_save(host, port, res);
    sock = connect_res(res);
    freeaddrinfo(res);
  }
  if (likely(sock != INVALID_SOCKET)) {
    int sock_opt = 1;
    setsockopt(sock, SOL_TCP, TCP_NODELAY, (char *)&sock_opt, sizeof(sock_opt));
    setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, (char *)&sock_opt,
               sizeof(sock_opt));
#if defined(SOL_TCP)
#if defined(TCP_KEEPCNT)
    sock_opt = 3;
    setsockopt(sock, SOL_TCP, TCP_KEEPCNT, (char *)&sock_opt, sizeof(sock_opt));
#endif
#if defined(TCP_KEEPIDLE)
    sock_opt = 60;
    setsockopt(sock, SOL_TCP, TCP_KEEPIDLE, (char *)&sock_opt,
               sizeof(sock_opt));
#endif
#if defined(TCP_KEEPINTVL)
    sock_opt = 20;
    setsockopt(sock, SOL_TCP, TCP_KEEPINTVL, (char *)&sock_opt,
               sizeof(sock_opt));
#endif
#endif
  } else {
    debug(D_WARNING, "failed to connect to %s:%s", host, port);
  }
  return sock;
}

int psock_try_write_buffer(psock_t *sock) {
  if (sock->buffer) {
    psock_buf_t *b;
    int wrt, cw;
    wrt = 0;
    while ((b = sock->buffer)) {
      if (b->roffset == b->woffset) {
        sock->buffer = b->next;
        psync_free(b);
        continue;
      }
      if (sock->ssl) {
        cw = psync_ssl_write(sock->ssl, b->buff + b->roffset,
                             b->woffset - b->roffset);
        if (cw == PSYNC_SSL_FAIL) {
          if (likely_log(psync_ssl_errno == PSYNC_SSL_ERR_WANT_READ ||
                         psync_ssl_errno == PSYNC_SSL_ERR_WANT_WRITE))
            break;
          else {
            if (!wrt)
              wrt = -1;
            break;
          }
        }
      } else {
        cw = write(sock->sock, b->buff + b->roffset, b->woffset - b->roffset);
        if (cw == SOCKET_ERROR) {
          if (likely_log(errno == EWOULDBLOCK || errno == EAGAIN ||
                         errno == EINTR))
            break;
          else {
            if (!wrt)
              wrt = -1;
            break;
          }
        }
      }
      wrt += cw;
      b->roffset += cw;
      if (b->roffset != b->woffset)
        break;
    }
    if (wrt > 0)
      debug(D_NOTICE, "wrote %d bytes to socket from buffers", wrt);
    return wrt;
  } else
    return 0;
}

int psock_try_write_buffer_thread(psock_t *sock) {
  int ret;
  pthread_mutex_lock(&mutex);
  ret = psock_try_write_buffer(sock);
  pthread_mutex_unlock(&mutex);
  return ret;
}

int psock_readable(psock_t *sock) {
  psock_try_write_buffer(sock);
  if (sock->ssl && psync_ssl_pendingdata(sock->ssl))
    return 1;
  else if (wait_readable(sock->sock, 0, 0))
    return 0;
  else {
    sock->pending = 1;
    return 1;
  }
}

int psock_writable(psock_t *sock) {
  if (sock->buffer)
    return 1;
  return !wait_writable(sock->sock, 0, 0);
}

int psock_create(int domain, int type, int protocol) {
  int ret;
  ret = socket(domain, type, protocol);
  return ret;
}

psock_t *psock_connect(const char *host, int unsigned port, int ssl) {
  psock_t *ret;
  void *sslc;
  int sock;
  char sport[8];
  psync_slprintf(sport, sizeof(sport), "%d", port);

  sock = connect_socket(host, sport);
  if (unlikely_log(sock == INVALID_SOCKET)) {
    return NULL;
  }

  if (ssl) {
    ssl = psync_ssl_connect(sock, &sslc, host);
    while (ssl == PSYNC_SSL_NEED_FINISH) {
      if (wait_ssl_ready(sock)) {
        psync_ssl_free(sslc);
        break;
      }
      ssl = psync_ssl_connect_finish(sslc, host);
    }
    if (unlikely_log(ssl != PSYNC_SSL_SUCCESS)) {
      close(sock);
      return NULL;
    }
  } else {
    sslc = NULL;
  }
  ret = psync_new(psock_t);
  ret->ssl = sslc;
  ret->buffer = NULL;
  ret->sock = sock;
  ret->pending = 0;
  return ret;
}

int psock_wait_write_timeout(int sock) {
  return wait_writable(sock, PSYNC_SOCK_WRITE_TIMEOUT, 0);
}

void psock_close(psock_t *sock) {
  if (sock->ssl)
    while (psync_ssl_shutdown(sock->ssl) == PSYNC_SSL_NEED_FINISH)
      if (wait_ssl_ready(sock->sock)) {
        psync_ssl_free(sock->ssl);
        break;
      }
  psock_clear_write_buffered(sock);
  close(sock->sock);
  psync_free(sock);
}

void psock_close_bad(psock_t *sock) {
  if (sock->ssl)
    psync_ssl_free(sock->ssl);
  psock_clear_write_buffered(sock);
  close(sock->sock);
  psync_free(sock);
}

void psock_set_write_buffered(psock_t *sock) {
  psock_buf_t *sb;
  if (sock->buffer)
    return;
  sb = (psock_buf_t *)psync_malloc(offsetof(psock_buf_t, buff) +
                                   PSYNC_FIRST_SOCK_WRITE_BUFF_SIZE);
  sb->next = NULL;
  sb->size = PSYNC_FIRST_SOCK_WRITE_BUFF_SIZE;
  sb->woffset = 0;
  sb->roffset = 0;
  sock->buffer = sb;
}

void psock_set_write_buffered_thread(psock_t *sock) {
  pthread_mutex_lock(&mutex);
  psock_set_write_buffered(sock);
  pthread_mutex_unlock(&mutex);
}

void psock_clear_write_buffered(psock_t *sock) {
  psock_buf_t *nb;
  while (sock->buffer) {
    nb = sock->buffer->next;
    free(sock->buffer);
    sock->buffer = nb;
  }
}

void psock_clear_write_buffered_thread(psock_t *sock) {
  pthread_mutex_lock(&mutex);
  psock_clear_write_buffered(sock);
  pthread_mutex_unlock(&mutex);
}

int psock_set_recvbuf(psock_t *sock, int bufsize) {
#if defined(SO_RCVBUF) && defined(SOL_SOCKET)
  return setsockopt(sock->sock, SOL_SOCKET, SO_RCVBUF, (const char *)&bufsize,
                    sizeof(bufsize));
#else
  return -1;
#endif
}

int psock_set_sendbuf(psock_t *sock, int bufsize) {
#if defined(SO_SNDBUF) && defined(SOL_SOCKET)
  return setsockopt(sock->sock, SOL_SOCKET, SO_SNDBUF, (const char *)&bufsize,
                    sizeof(bufsize));
#else
  return -1;
#endif
}

int psock_is_ssl(psock_t *sock) {
  if (sock->ssl)
    return 1;
  else
    return 0;
}

int psock_pendingdata(psock_t *sock) {
  if (sock->pending)
    return 1;
  if (sock->ssl)
    return psync_ssl_pendingdata(sock->ssl);
  else
    return 0;
}

int psock_pendingdata_buf(psock_t *sock) {
  int ret;
#if defined(FIONREAD)
  if (ioctl(sock->sock, FIONREAD, &ret))
    return -1;
#else
  return -1;
#endif
  if (sock->ssl)
    ret += psync_ssl_pendingdata(sock->ssl);
  return ret;
}

int psock_pendingdata_buf_thread(psock_t *sock) {
  int ret;
  pthread_mutex_lock(&mutex);
  ret = psock_pendingdata_buf(sock);
  pthread_mutex_unlock(&mutex);
  return ret;
}

static int psync_socket_read_ssl(psock_t *sock, void *buff, int num) {
  int r;
  psock_try_write_buffer(sock);
  if (!psync_ssl_pendingdata(sock->ssl) && !sock->pending &&
      psock_wait_read_timeout(sock->sock))
    return -1;
  sock->pending = 0;
  while (1) {
    psock_try_write_buffer(sock);
    r = psync_ssl_read(sock->ssl, buff, num);
    if (r == PSYNC_SSL_FAIL) {
      if (likely_log(psync_ssl_errno == PSYNC_SSL_ERR_WANT_READ ||
                     psync_ssl_errno == PSYNC_SSL_ERR_WANT_WRITE)) {
        if (wait_ssl_ready(sock->sock)) {
          if (sock->buffer)
            debug(D_WARNING, "timeouted on socket with pending buffers");
          return -1;
        } else
          continue;
      } else {
        errno = (ECONNRESET);
        return -1;
      }
    } else
      return r;
  }
}

static int psync_socket_read_plain(psock_t *sock, void *buff, int num) {
  int r;
  while (1) {
    psock_try_write_buffer(sock);
    if (sock->pending)
      sock->pending = 0;
    else if (psock_wait_read_timeout(sock->sock)) {
      debug(D_WARNING, "timeouted on socket with pending buffers");
      return -1;
    } else
      psock_try_write_buffer(sock);
    r = read(sock->sock, buff, num);
    if (r == SOCKET_ERROR) {
      if (likely_log(errno == EWOULDBLOCK || errno == EAGAIN))
        continue;
      else
        return -1;
    } else
      return r;
  }
}

int psock_read(psock_t *sock, void *buff, int num) {
  if (sock->ssl)
    return psync_socket_read_ssl(sock, buff, num);
  else
    return psync_socket_read_plain(sock, buff, num);
}

static int psync_socket_read_noblock_ssl(psock_t *sock, void *buff, int num) {
  int r;
  r = psync_ssl_read(sock->ssl, buff, num);
  if (r == PSYNC_SSL_FAIL) {
    sock->pending = 0;
    if (likely_log(psync_ssl_errno == PSYNC_SSL_ERR_WANT_READ ||
                   psync_ssl_errno == PSYNC_SSL_ERR_WANT_WRITE))
      return PSYNC_SOCKET_WOULDBLOCK;
    else {
      errno = (ECONNRESET);
      return -1;
    }
  } else
    return r;
}

static int psync_socket_read_noblock_plain(psock_t *sock, void *buff, int num) {
  int r;
  r = read(sock->sock, buff, num);
  if (r == SOCKET_ERROR) {
    sock->pending = 0;
    if (likely_log(errno == EWOULDBLOCK || errno == EAGAIN))
      return PSYNC_SOCKET_WOULDBLOCK;
    else
      return -1;
  } else
    return r;
}

int psock_read_noblock(psock_t *sock, void *buff, int num) {
  psock_try_write_buffer(sock);
  if (sock->ssl)
    return psync_socket_read_noblock_ssl(sock, buff, num);
  else
    return psync_socket_read_noblock_plain(sock, buff, num);
}

static int psync_socket_read_ssl_thread(psock_t *sock, void *buff, int num) {
  int r;
  pthread_mutex_lock(&mutex);
  psock_try_write_buffer(sock);
  pthread_mutex_unlock(&mutex);
  if (!psync_ssl_pendingdata(sock->ssl) && !sock->pending &&
      psock_wait_read_timeout(sock->sock))
    return -1;
  sock->pending = 0;
  while (1) {
    pthread_mutex_lock(&mutex);
    psock_try_write_buffer(sock);
    r = psync_ssl_read(sock->ssl, buff, num);
    pthread_mutex_unlock(&mutex);
    if (r == PSYNC_SSL_FAIL) {
      if (likely_log(psync_ssl_errno == PSYNC_SSL_ERR_WANT_READ ||
                     psync_ssl_errno == PSYNC_SSL_ERR_WANT_WRITE)) {
        if (wait_ssl_ready(sock->sock))
          return -1;
        else
          continue;
      } else {
        errno = (ECONNRESET);
        return -1;
      }
    } else
      return r;
  }
}

static int psync_socket_read_plain_thread(psock_t *sock, void *buff, int num) {
  int r;
  pthread_mutex_lock(&mutex);
  psock_try_write_buffer(sock);
  pthread_mutex_unlock(&mutex);
  while (1) {
    if (sock->pending)
      sock->pending = 0;
    else if (psock_wait_read_timeout(sock->sock))
      return -1;
    pthread_mutex_lock(&mutex);
    psock_try_write_buffer(sock);
    r = read(sock->sock, buff, num);
    pthread_mutex_unlock(&mutex);
    if (r == SOCKET_ERROR) {
      if (likely_log(errno == EWOULDBLOCK || errno == EAGAIN))
        continue;
      else
        return -1;
    } else
      return r;
  }
}

int psock_read_thread(psock_t *sock, void *buff, int num) {
  if (sock->ssl)
    return psync_socket_read_ssl_thread(sock, buff, num);
  else
    return psync_socket_read_plain_thread(sock, buff, num);
}

static int psync_socket_write_to_buf(psock_t *sock, const void *buff, int num) {
  psock_buf_t *b;
  assert(sock->buffer);
  b = sock->buffer;
  while (b->next)
    b = b->next;
  if (likely(b->size - b->woffset >= num)) {
    memcpy(b->buff + b->woffset, buff, num);
    b->woffset += num;
    return num;
  } else {
    uint32_t rnum, wr;
    rnum = num;
    do {
      wr = b->size - b->woffset;
      if (!wr) {
        b->next = (psock_buf_t *)psync_malloc(
            offsetof(psock_buf_t, buff) + PSYNC_SECOND_SOCK_WRITE_BUFF_SIZE);
        b = b->next;
        b->next = NULL;
        b->size = PSYNC_SECOND_SOCK_WRITE_BUFF_SIZE;
        b->woffset = 0;
        b->roffset = 0;
        wr = PSYNC_SECOND_SOCK_WRITE_BUFF_SIZE;
      }
      if (wr > rnum)
        wr = rnum;
      memcpy(b->buff + b->woffset, buff, wr);
      b->woffset += wr;
      buff = (const char *)buff + wr;
      rnum -= wr;
    } while (rnum);
    return num;
  }
}

int psock_write(psock_t *sock, const void *buff, int num) {
  int r;
  if (sock->buffer)
    return psync_socket_write_to_buf(sock, buff, num);
  if (psock_wait_write_timeout(sock->sock))
    return -1;
  if (sock->ssl) {
    r = psync_ssl_write(sock->ssl, buff, num);
    if (r == PSYNC_SSL_FAIL) {
      if (likely_log(psync_ssl_errno == PSYNC_SSL_ERR_WANT_READ ||
                     psync_ssl_errno == PSYNC_SSL_ERR_WANT_WRITE))
        return 0;
      else
        return -1;
    }
  } else {
    r = write(sock->sock, buff, num);
    if (r == SOCKET_ERROR) {
      if (likely_log(errno == EWOULDBLOCK || errno == EAGAIN || errno == EINTR))
        return 0;
      else
        return -1;
    }
  }
  return r;
}

static int psync_socket_readall_ssl(psock_t *sock, void *buff, int num) {
  int br, r;
  br = 0;

  psock_try_write_buffer(sock);

  if (!psync_ssl_pendingdata(sock->ssl) && !sock->pending &&
      psock_wait_read_timeout(sock->sock)) {
    return -1;
  }

  sock->pending = 0;

  while (br < num) {
    psock_try_write_buffer(sock);

    r = psync_ssl_read(sock->ssl, (char *)buff + br, num - br);

    if (r == PSYNC_SSL_FAIL) {
      if (likely_log(psync_ssl_errno == PSYNC_SSL_ERR_WANT_READ ||
                     psync_ssl_errno == PSYNC_SSL_ERR_WANT_WRITE)) {
        if (wait_ssl_ready(sock->sock))
          return -1;
        else
          continue;
      } else {
        errno = (ECONNRESET);
        return -1;
      }
    }
    if (r == 0)
      return br;
    br += r;
  }

  return br;
}

static int psync_socket_readall_plain(psock_t *sock, void *buff, int num) {
  int br, r;
  br = 0;
  while (br < num) {
    psock_try_write_buffer(sock);
    if (sock->pending)
      sock->pending = 0;
    else if (psock_wait_read_timeout(sock->sock))
      return -1;
    else
      psock_try_write_buffer(sock);
    r = read(sock->sock, (char *)buff + br, num - br);
    if (r == SOCKET_ERROR) {
      if (likely_log(errno == EWOULDBLOCK || errno == EAGAIN))
        continue;
      else
        return -1;
    }
    if (r == 0)
      return br;
    br += r;
  }
  return br;
}

int psock_readall(psock_t *sock, void *buff, int num) {
  if (sock->ssl) {
    return psync_socket_readall_ssl(sock, buff, num);
  } else {
    return psync_socket_readall_plain(sock, buff, num);
  }
}

static int psync_socket_writeall_ssl(psock_t *sock, const void *buff, int num) {
  int br, r;
  br = 0;
  while (br < num) {
    r = psync_ssl_write(sock->ssl, (char *)buff + br, num - br);
    if (r == PSYNC_SSL_FAIL) {
      if (psync_ssl_errno == PSYNC_SSL_ERR_WANT_READ ||
          psync_ssl_errno == PSYNC_SSL_ERR_WANT_WRITE) {
        if (wait_ssl_ready(sock->sock))
          return -1;
        else
          continue;
      } else {
        errno = (ECONNRESET);
        return -1;
      }
    }
    if (r == 0)
      return br;
    br += r;
  }
  return br;
}

static int psync_socket_writeall_plain(int sock, const void *buff, int num) {
  int br, r;
  br = 0;
  while (br < num) {
    r = write(sock, (const char *)buff + br, num - br);
    if (r == SOCKET_ERROR) {
      if (errno == EWOULDBLOCK || errno == EAGAIN) {
        if (psock_wait_write_timeout(sock))
          return -1;
        else
          continue;
      } else
        return -1;
    }
    br += r;
  }
  return br;
}

int psock_writeall(psock_t *sock, const void *buff, int num) {
  if (sock->buffer)
    return psync_socket_write_to_buf(sock, buff, num);
  if (sock->ssl)
    return psync_socket_writeall_ssl(sock, buff, num);
  else
    return psync_socket_writeall_plain(sock->sock, buff, num);
}

static int psync_socket_readall_ssl_thread(psock_t *sock, void *buff, int num) {
  int br, r;
  br = 0;
  pthread_mutex_lock(&mutex);
  psock_try_write_buffer(sock);
  r = psync_ssl_pendingdata(sock->ssl);
  pthread_mutex_unlock(&mutex);
  if (!r && !sock->pending && psock_wait_read_timeout(sock->sock))
    return -1;
  sock->pending = 0;
  while (br < num) {
    pthread_mutex_lock(&mutex);
    psock_try_write_buffer(sock);
    r = psync_ssl_read(sock->ssl, (char *)buff + br, num - br);
    pthread_mutex_unlock(&mutex);
    if (r == PSYNC_SSL_FAIL) {
      if (likely_log(psync_ssl_errno == PSYNC_SSL_ERR_WANT_READ ||
                     psync_ssl_errno == PSYNC_SSL_ERR_WANT_WRITE)) {
        if (wait_ssl_ready(sock->sock))
          return -1;
        else
          continue;
      } else {
        errno = (ECONNRESET);
        return -1;
      }
    }
    if (r == 0)
      return br;
    br += r;
  }
  return br;
}

static int psync_socket_readall_plain_thread(psock_t *sock, void *buff,
                                             int num) {
  int br, r;
  br = 0;
  pthread_mutex_lock(&mutex);
  psock_try_write_buffer(sock);
  pthread_mutex_unlock(&mutex);
  while (br < num) {
    if (sock->pending)
      sock->pending = 0;
    else if (psock_wait_read_timeout(sock->sock))
      return -1;
    pthread_mutex_lock(&mutex);
    psock_try_write_buffer(sock);
    r = read(sock->sock, (char *)buff + br, num - br);
    pthread_mutex_unlock(&mutex);
    if (r == SOCKET_ERROR) {
      if (likely_log(errno == EWOULDBLOCK || errno == EAGAIN))
        continue;
      else
        return -1;
    }
    if (r == 0)
      return br;
    br += r;
  }
  return br;
}

int psock_readall_thread(psock_t *sock, void *buff, int num) {
  if (sock->ssl)
    return psync_socket_readall_ssl_thread(sock, buff, num);
  else
    return psync_socket_readall_plain_thread(sock, buff, num);
}

static int psync_socket_writeall_ssl_thread(psock_t *sock, const void *buff,
                                            int num) {
  int br, r;
  br = 0;
  while (br < num) {
    pthread_mutex_lock(&mutex);
    if (sock->buffer)
      r = psync_socket_write_to_buf(sock, buff, num);
    else
      r = psync_ssl_write(sock->ssl, (char *)buff + br, num - br);
    pthread_mutex_unlock(&mutex);
    if (r == PSYNC_SSL_FAIL) {
      if (psync_ssl_errno == PSYNC_SSL_ERR_WANT_READ ||
          psync_ssl_errno == PSYNC_SSL_ERR_WANT_WRITE) {
        if (wait_ssl_ready(sock->sock))
          return -1;
        else
          continue;
      } else {
        errno = (ECONNRESET);
        return -1;
      }
    }
    if (r == 0)
      return br;
    br += r;
  }
  return br;
}

static int psync_socket_writeall_plain_thread(psock_t *sock, const void *buff,
                                              int num) {
  int br, r;
  br = 0;
  while (br < num) {
    pthread_mutex_lock(&mutex);
    if (sock->buffer)
      r = psync_socket_write_to_buf(sock, buff, num);
    else
      r = write(sock->sock, (const char *)buff + br, num - br);
    pthread_mutex_unlock(&mutex);
    if (r == SOCKET_ERROR) {
      if (errno == EWOULDBLOCK || errno == EAGAIN) {
        if (psock_wait_write_timeout(sock->sock))
          return -1;
        else
          continue;
      } else
        return -1;
    }
    br += r;
  }
  return br;
}

int psock_writeall_thread(psock_t *sock, const void *buff, int num) {
  if (sock->ssl)
    return psync_socket_writeall_ssl_thread(sock, buff, num);
  else
    return psync_socket_writeall_plain_thread(sock, buff, num);
}

static void copy_address(struct sockaddr_storage *dst,
                         const struct sockaddr *src) {
  dst->ss_family = src->sa_family;
  if (src->sa_family == AF_INET)
    memcpy(&((struct sockaddr_in *)dst)->sin_addr,
           &((const struct sockaddr_in *)src)->sin_addr,
           sizeof(((struct sockaddr_in *)dst)->sin_addr));
  else
    memcpy(&((struct sockaddr_in6 *)dst)->sin6_addr,
           &((const struct sockaddr_in6 *)src)->sin6_addr,
           sizeof(((struct sockaddr_in6 *)dst)->sin6_addr));
}

psock_ifaces_t *psock_list_adapters() {
  psock_ifaces_t *ret;
  size_t cnt;
  struct ifaddrs *addrs, *addr;
  sa_family_t family;
  size_t sz;
  if (unlikely_log(getifaddrs(&addrs)))
    goto empty;
  cnt = 0;
  addr = addrs;
  while (addr) {
    if (addr->ifa_addr) {
      family = addr->ifa_addr->sa_family;
      if ((family == AF_INET || family == AF_INET6) && addr->ifa_broadaddr &&
          addr->ifa_netmask)
        cnt++;
    }
    addr = addr->ifa_next;
  }
  ret = psync_malloc(offsetof(psock_ifaces_t, interfaces) +
                     sizeof(psock_iface_t) * cnt);
  memset(ret, 0,
         offsetof(psock_ifaces_t, interfaces) + sizeof(psock_iface_t) * cnt);
  ret->interfacecnt = cnt;
  addr = addrs;
  cnt = 0;
  while (addr) {
    if (addr->ifa_addr) {
      family = addr->ifa_addr->sa_family;
      if ((family == AF_INET || family == AF_INET6) && addr->ifa_broadaddr &&
          addr->ifa_netmask) {
        if (family == AF_INET)
          sz = sizeof(struct sockaddr_in);
        else
          sz = sizeof(struct sockaddr_in6);
        copy_address(&ret->interfaces[cnt].address, addr->ifa_addr);
        copy_address(&ret->interfaces[cnt].broadcast, addr->ifa_broadaddr);
        copy_address(&ret->interfaces[cnt].netmask, addr->ifa_netmask);
        ret->interfaces[cnt].addrsize = sz;
        cnt++;
      }
    }
    addr = addr->ifa_next;
  }
  freeifaddrs(addrs);
  return ret;
empty:
  ret = psync_malloc(offsetof(psock_ifaces_t, interfaces));
  ret->interfacecnt = 0;
  return ret;
}

int psock_is_broken(int sock) {
  fd_set rfds;
  struct timeval tv;
  memset(&tv, 0, sizeof(tv));
  FD_ZERO(&rfds);
  FD_SET(sock, &rfds);
  return select(sock + 1, NULL, NULL, &rfds, &tv) == 1;
}

int psock_wait_read_timeout(int sock) {
  return wait_readable(sock, PSYNC_SOCK_READ_TIMEOUT, 0);
}

int psock_select_in(int *sockets, int cnt, int64_t timeoutmillisec) {
  fd_set rfds;
  struct timeval tv, *ptv;
  int max;
  int i;
  if (timeoutmillisec < 0)
    ptv = NULL;
  else {
    tv.tv_sec = timeoutmillisec / 1000;
    tv.tv_usec = (timeoutmillisec % 1000) * 1000;
    ptv = &tv;
  }
  FD_ZERO(&rfds);
  max = 0;
  for (i = 0; i < cnt; i++) {
    FD_SET(sockets[i], &rfds);
    if (sockets[i] >= max)
      max = sockets[i] + 1;
  }
  i = select(max, &rfds, NULL, NULL, ptv);
  if (i > 0) {
    for (i = 0; i < cnt; i++)
      if (FD_ISSET(sockets[i], &rfds))
        return i;
  } else if (i == 0)
    errno = (ETIMEDOUT);
  return SOCKET_ERROR;
}
