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

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <pwd.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <utime.h>

#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/sysinfo.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/debug.h>
#include <mbedtls/entropy.h>
#include <mbedtls/pkcs5.h>
#include <mbedtls/ssl.h>

#include "pcompat.h"
#include "pdevice.h"
#include "plibs.h"
#include "pmemlock.h"
#include "prun.h"
#include "psettings.h"
#include "pssl.h"
#include "psynclib.h"
#include "ptimer.h"
#include "ppath.h"

extern char **environ;

#define PROXY_NONE 0
#define PROXY_CONNECT 1

static uid_t psync_uid;
static gid_t psync_gid;
static gid_t *psync_gids;
static int psync_gids_cnt;

static int proxy_type = PROXY_NONE;
static int proxy_detected = 0;
static char proxy_host[256];
static char proxy_port[8];

PSYNC_THREAD const char *psync_thread_name = "no name";
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

const unsigned char psync_invalid_filename_chars[256] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

void psync_sys_init() {
  struct rlimit limit;
  limit.rlim_cur = limit.rlim_max = 2048;
  if (setrlimit(RLIMIT_NOFILE, &limit))
    debug(D_ERROR, "setrlimit failed errno=%d", errno);
#if IS_DEBUG
  if (getrlimit(RLIMIT_CORE, &limit))
    debug(D_ERROR, "getrlimit failed errno=%d", errno);
  else {
    limit.rlim_cur = limit.rlim_max;
    if (setrlimit(RLIMIT_CORE, &limit))
      debug(D_ERROR, "setrlimit failed errno=%d", errno);
  }
#endif
  signal(SIGPIPE, SIG_IGN);
  psync_uid = getuid();
  psync_gid = getgid();
  psync_gids_cnt = getgroups(0, NULL);
  psync_gids = psync_new_cnt(gid_t, psync_gids_cnt);
  if (unlikely_log(getgroups(psync_gids_cnt, psync_gids) != psync_gids_cnt))
    psync_gids_cnt = 0;
  pmemlock_set_pagesize(sysconf(_SC_PAGESIZE));
  debug(D_NOTICE, "detected page size %d", pmemlock_get_pagesize());
}

int psync_stat_mode_ok(struct stat *buf, unsigned int bits) {
  int i;
  if (psync_uid == 0)
    return 1;
  if (buf->st_uid == psync_uid) {
    bits <<= 6;
    return (buf->st_mode & bits) == bits;
  }
  if (buf->st_gid == psync_gid) {
    bits <<= 3;
    return (buf->st_mode & bits) == bits;
  }
  for (i = 0; i < psync_gids_cnt; i++)
    if (buf->st_gid == psync_gids[i]) {
      bits <<= 3;
      return (buf->st_mode & bits) == bits;
    }
  return (buf->st_mode & bits) == bits;
}

static void psync_check_no_sql_lock(uint64_t millisec) {
#if IS_DEBUG
  if (psync_sql_islocked()) {
    debug(D_CRITICAL, "trying to sleep while holding sql lock, aborting");
    psync_sql_dump_locks();
    abort();
  }
#endif
}

void psync_milisleep_nosqlcheck(uint64_t millisec) {
  struct timespec tm;
  tm.tv_sec = millisec / 1000;
  tm.tv_nsec = (millisec % 1000) * 1000000;
  nanosleep(&tm, NULL);
}

void psync_milisleep(uint64_t millisec) {
  psync_check_no_sql_lock(millisec);
  psync_milisleep_nosqlcheck(millisec);
}

time_t psync_time() {
#if defined(_POSIX_TIMERS) && _POSIX_TIMERS > 0
  struct timespec ts;
  if (likely_log(clock_gettime(CLOCK_REALTIME, &ts) == 0))
    return ts.tv_sec;
  else
    return time(NULL);
#else
  return time(NULL);
#endif
}

uint64_t psync_millitime() {
  struct timespec tm;
  clock_gettime(CLOCK_REALTIME, &tm);
  return tm.tv_sec * 1000 + tm.tv_nsec / 1000000;
}

static void psync_add_file_to_seed(const char *fn, psync_lhash_ctx *hctx,
                                   size_t max) {
  char buff[4096];
  ssize_t rd;
  int fd, mode;
  mode = O_RDONLY;
#if defined(O_NONBLOCK)
  mode += O_NONBLOCK;
#elif defined(O_NDELAY)
  mode += O_NDELAY;
#endif
  fd = open(fn, mode);
  if (fd != -1) {
    if (!max || max > sizeof(buff))
      max = sizeof(buff);
    rd = read(fd, buff, max);
    if (rd > 0)
      psync_lhash_update(hctx, buff, rd);
    close(fd);
  }
}

static void psync_get_random_seed_linux(psync_lhash_ctx *hctx) {
  struct sysinfo si;
  if (likely_log(!sysinfo(&si)))
    psync_lhash_update(hctx, &si, sizeof(si));
  psync_add_file_to_seed("/proc/stat", hctx, 0);
  psync_add_file_to_seed("/proc/vmstat", hctx, 0);
  psync_add_file_to_seed("/proc/meminfo", hctx, 0);
  psync_add_file_to_seed("/proc/modules", hctx, 0);
  psync_add_file_to_seed("/proc/mounts", hctx, 0);
  psync_add_file_to_seed("/proc/diskstats", hctx, 0);
  psync_add_file_to_seed("/proc/interrupts", hctx, 0);
  psync_add_file_to_seed("/proc/net/dev", hctx, 0);
  psync_add_file_to_seed("/proc/net/arp", hctx, 0);
}

static void psync_get_random_seed_from_query(psync_lhash_ctx *hctx,
                                             psync_sql_res *res) {
  psync_variant_row row;
  struct timespec tm;
  int i;
  while ((row = psync_sql_fetch_row(res))) {
    for (i = 0; i < res->column_count; i++)
      if (row[i].type == PSYNC_TSTRING)
        psync_lhash_update(hctx, row[i].str, row[i].length);
    psync_lhash_update(hctx, row, sizeof(psync_variant) * res->column_count);
  }
  psync_sql_free_result(res);
  clock_gettime(CLOCK_REALTIME, &tm);
  psync_lhash_update(hctx, &tm, sizeof(&tm));
}

static void psync_get_random_seed_from_db(psync_lhash_ctx *hctx) {
  psync_sql_res *res;
  struct timespec tm;
  unsigned char rnd[PSYNC_LHASH_DIGEST_LEN];
  clock_gettime(CLOCK_REALTIME, &tm);
  psync_lhash_update(hctx, &tm, sizeof(&tm));
  res = psync_sql_query_rdlock("SELECT * FROM setting ORDER BY RANDOM()");
  psync_get_random_seed_from_query(hctx, res);
  res = psync_sql_query_rdlock(
      "SELECT * FROM resolver ORDER BY RANDOM() LIMIT 50");
  psync_get_random_seed_from_query(hctx, res);
  psync_sql_statement(
      "REPLACE INTO setting (id, value) VALUES ('random', RANDOM())");
  clock_gettime(CLOCK_REALTIME, &tm);
  psync_lhash_update(hctx, &tm, sizeof(&tm));
  psync_sql_sync();
  clock_gettime(CLOCK_REALTIME, &tm);
  psync_lhash_update(hctx, &tm, sizeof(&tm));
  sqlite3_randomness(sizeof(rnd), rnd);
  psync_lhash_update(hctx, rnd, sizeof(rnd));
}

static void psync_rehash_cnt(unsigned char *hashbin, unsigned long cnt) {
  psync_lhash_ctx hctx;
  unsigned long i;
  struct timespec tm;
  for (i = 0; i < cnt; i++) {
    psync_lhash_init(&hctx);
    if ((i & 511) == 0) {
      clock_gettime(CLOCK_REALTIME, &tm);
      psync_lhash_update(&hctx, &tm, sizeof(&tm));
    } else
      psync_lhash_update(&hctx, &i, sizeof(i));
    psync_lhash_update(&hctx, hashbin, PSYNC_LHASH_DIGEST_LEN);
    psync_lhash_final(hashbin, &hctx);
  }
}

static void psync_store_seed_in_db(const unsigned char *seed) {
  psync_sql_res *res;
  unsigned char hashbin[PSYNC_LHASH_DIGEST_LEN];
  char hashhex[PSYNC_LHASH_DIGEST_HEXLEN], nm[16];
  memcpy(hashbin, seed, PSYNC_LHASH_DIGEST_LEN);
  psync_rehash_cnt(hashbin, 2000);
  psync_binhex(hashhex, hashbin, PSYNC_LHASH_DIGEST_LEN);
  res = psync_sql_prep_statement(
      "REPLACE INTO setting (id, value) VALUES ('randomhash', ?)");
  psync_sql_bind_lstring(res, 1, hashhex, PSYNC_LHASH_DIGEST_HEXLEN);
  psync_sql_run_free(res);
  psync_rehash_cnt(hashbin, 2000);
  psync_binhex(hashhex, hashbin, PSYNC_LHASH_DIGEST_LEN);
  memcpy(nm, "randomhash", 10);
  nm[10] = hashhex[0];
  nm[11] = 0;
  res = psync_sql_prep_statement(
      "REPLACE INTO setting (id, value) VALUES (?, ?)");
  psync_sql_bind_lstring(res, 1, nm, 11);
  psync_sql_bind_lstring(res, 2, hashhex, PSYNC_LHASH_DIGEST_HEXLEN);
  psync_sql_run_free(res);
}

void psync_get_random_seed(unsigned char *seed, const void *addent,
                           size_t aelen, int fast) {
  static unsigned char lastseed[PSYNC_LHASH_DIGEST_LEN];
  psync_lhash_ctx hctx;
  struct timespec tm;
  struct stat st;
  char *home;
  void *ptr;
  unsigned long i, j;
  int64_t i64;
  pthread_t threadid;
  unsigned char lsc[64][PSYNC_LHASH_DIGEST_LEN];
  debug(D_NOTICE, "in");
  struct utsname un;
  struct statvfs stfs;
  char **env;
  pid_t pid;
  clock_gettime(CLOCK_REALTIME, &tm);
  psync_lhash_init(&hctx);
  psync_lhash_update(&hctx, &tm, sizeof(tm));
  if (likely_log(!uname(&un)))
    psync_lhash_update(&hctx, &un, sizeof(un));
  pid = getpid();
  psync_lhash_update(&hctx, &pid, sizeof(pid));
  if (!statvfs("/", &stfs))
    psync_lhash_update(&hctx, &stfs, sizeof(stfs));
  for (env = environ; *env != NULL; env++)
    psync_lhash_update(&hctx, *env, strlen(*env));
#if defined(_POSIX_TIMERS) && _POSIX_TIMERS > 0 &&                             \
    defined(_POSIX_MONOTONIC_CLOCK)
  if (likely_log(!clock_gettime(CLOCK_MONOTONIC, &tm)))
    psync_lhash_update(&hctx, &tm, sizeof(tm));
#endif

  psync_add_file_to_seed("/dev/urandom", &hctx, PSYNC_HASH_DIGEST_LEN);
  psync_get_random_seed_linux(&hctx);

  threadid = pthread_self();
  psync_lhash_update(&hctx, &threadid, sizeof(threadid));
  ptr = (void *)&ptr;
  psync_lhash_update(&hctx, &ptr, sizeof(ptr));
  ptr = (void *)psync_get_random_seed;
  psync_lhash_update(&hctx, &ptr, sizeof(ptr));
  ptr = (void *)pthread_self;
  psync_lhash_update(&hctx, &ptr, sizeof(ptr));
  ptr = (void *)malloc;
  psync_lhash_update(&hctx, &ptr, sizeof(ptr));
  ptr = (void *)&lastseed;
  psync_lhash_update(&hctx, &ptr, sizeof(ptr));
  home = ppath_home();
  if (home) {
    i64 = ppath_free_space(home);
    psync_lhash_update(&hctx, &i64, sizeof(i64));
    psync_lhash_update(&hctx, home, strlen(home));
    if (likely_log(!stat(home, &st)))
      psync_lhash_update(&hctx, &st, sizeof(st));
    psync_free(home);
  }
  if (!fast) {
    debug(D_NOTICE, "db in");
    psync_get_random_seed_from_db(&hctx);
    debug(D_NOTICE, "db out");
  }
  if (aelen)
    psync_lhash_update(&hctx, addent, aelen);
  debug(D_NOTICE, "adding bulk data");
  for (i = 0; i < ARRAY_SIZE(lsc); i++) {
    memcpy(&lsc[i], lastseed, PSYNC_LHASH_DIGEST_LEN);
    for (j = 0; j < PSYNC_LHASH_DIGEST_LEN; j++)
      lsc[i][j] ^= (unsigned char)i;
  }
  for (j = fast ? 3 : 0; j < 5; j++) {
    for (i = 0; i < 100; i++) {
      psync_lhash_update(&hctx, &i, sizeof(i));
      psync_lhash_update(&hctx, &j, sizeof(j));
      psync_lhash_update(&hctx, lsc, sizeof(lsc));
    }
    clock_gettime(CLOCK_REALTIME, &tm);
    psync_lhash_update(&hctx, &tm, sizeof(&tm));
  }
  psync_lhash_final(seed, &hctx);
  memcpy(lastseed, seed, PSYNC_LHASH_DIGEST_LEN);
  debug(D_NOTICE, "storing in db");
  psync_store_seed_in_db(seed);
  debug(D_NOTICE, "out");
}

static int psync_wait_socket_writable_microsec(int sock, long sec,
                                               long usec) {
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

#define psync_wait_socket_writable(sock, sec)                                  \
  psync_wait_socket_writable_microsec(sock, sec, 0)

int psync_wait_socket_write_timeout(int sock) {
  return psync_wait_socket_writable(sock, PSYNC_SOCK_WRITE_TIMEOUT);
}

static int psync_wait_socket_readable_microsec(int sock, long sec,
                                               long usec) {
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

#define psync_wait_socket_readable(sock, sec)                                  \
  psync_wait_socket_readable_microsec(sock, sec, 0)

int psync_wait_socket_read_timeout(int sock) {
  return psync_wait_socket_readable(sock, PSYNC_SOCK_READ_TIMEOUT);
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
           !psync_wait_socket_writable(sock, PSYNC_SOCK_CONNECT_TIMEOUT)))
        return sock;
      close(sock);
    }
    res = res->ai_next;
  }
  return INVALID_SOCKET;
}

int psync_create_socket(int domain, int type, int protocol) {
  int ret;
  ret = socket(domain, type, protocol);
  return ret;
}

static void addr_save_to_db(const char *host, const char *port,
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
  psync_sql_bind_uint(res, 4, psync_timer_time());
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

static struct addrinfo *addr_load_from_db(const char *host, const char *port) {
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

static int addr_still_valid(struct addrinfo *olda, struct addrinfo *newa) {
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

typedef struct {
  const char *host;
  const char *port;
} resolve_host_port;

static void connect_res_callback(void *h, void *ptr) {
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

static void resolve_callback(void *h, void *ptr) {
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

#if defined(PSYNC_HAS_PROXY_CODE)
static int recent_detect() {
  static time_t lastdetect = 0;
  if (psync_timer_time() < lastdetect + 60)
    return 1;
  else {
    lastdetect = psync_timer_time();
    return 0;
  }
}
#endif

static void detect_proxy() {
  // noop, only implemented for windows
}

static int connect_socket_direct(const char *host,
                                            const char *port) {
  struct addrinfo *res, *dbres;
  struct addrinfo hints;
  int sock;
  int rc;
  debug(D_NOTICE, "connecting to %s:%s", host, port);
  dbres = addr_load_from_db(host, port);
  if (dbres) {
    resolve_host_port resolv;
    void *params[2];
    psync_task_callback_t callbacks[2];
    psync_task_manager_t tasks;
    resolv.host = host;
    resolv.port = port;
    params[0] = dbres;
    params[1] = &resolv;
    callbacks[0] = connect_res_callback;
    callbacks[1] = resolve_callback;
    tasks = psync_task_run_tasks(callbacks, params, 2);
    res = (struct addrinfo *)psync_task_get_result(tasks, 1);
    if (unlikely(!res)) {
      psync_task_free(tasks);
      detect_proxy();
      debug(D_WARNING, "failed to resolve %s", host);
      return INVALID_SOCKET;
    }
    addr_save_to_db(host, port, res);
    if (addr_still_valid(dbres, res)) {
      debug(D_NOTICE, "successfully reused cached IP for %s:%s", host, port);
      sock = (int)(uintptr_t)psync_task_get_result(tasks, 0);
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
      detect_proxy();
      return INVALID_SOCKET;
    }
    addr_save_to_db(host, port, res);
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
    detect_proxy();
    debug(D_WARNING, "failed to connect to %s:%s", host, port);
  }
  return sock;
}

static int check_http_resp(char *str) {
  if (memcmp(str, "HTTP", 4)) {
    debug(D_WARNING, "bad proxy response %s", str);
    return 0;
  }
  while (*str && !isspace(*str))
    str++;
  while (*str && isspace(*str))
    str++;
  if (!isdigit(*str)) {
    debug(D_WARNING, "bad proxy response %s", str);
    return 0;
  }
  if (atoi(str) != 200) {
    debug(D_NOTICE, "proxy returned HTTP code %d", atoi(str));
    return 0;
  }
  return 1;
}

static int connect_socket_connect_proxy(const char *host,
                                                   const char *port) {
  char buff[2048], *str;
  int sock;
  int ln, wr, r, rc;
  sock = connect_socket_direct(proxy_host, proxy_port);
  if (unlikely(sock == INVALID_SOCKET)) {
    debug(D_NOTICE, "connection to proxy %s:%s failed", proxy_host, proxy_port);
    goto err0;
  }
  ln = psync_slprintf(
      buff, sizeof(buff),
      "CONNECT %s:%s HTTP/1.0\015\012User-Agent: %s\015\012\015\012", host,
      port, pdevice_get_software());
  wr = 0;
  while (wr < ln) {
    r = write(sock, buff + wr, ln - wr);
    if (unlikely(r == SOCKET_ERROR)) {
      if (likely_log((errno == EWOULDBLOCK ||
                      errno == EAGAIN ||
                      errno == EINTR) &&
                     !psync_wait_socket_write_timeout(sock)))
        continue;
      else
        goto err1;
    }
    wr += r;
  }
  wr = 0;
  rc = 0;
  while (1) {
    if (unlikely(psync_wait_socket_read_timeout(sock))) {
      debug(D_WARNING, "connection to %s:%s via %s:%s timeouted", host, port,
            proxy_host, proxy_port);
      goto err1;
    }
    r = read(sock, buff + wr, sizeof(buff) - 1 - wr);
    if (unlikely(r == 0 || r == SOCKET_ERROR)) {
      if (r == 0) {
        debug(D_NOTICE, "proxy server %s:%s closed connection", proxy_host,
              proxy_port);
        goto err1;
      }
      if (likely_log(errno == EWOULDBLOCK ||
                     errno == EAGAIN || errno == EINTR))
        continue;
      else
        goto err1;
    }
    wr += r;
    buff[wr] = 0;
    str = strstr(buff, "\015\012\015\012");
    if (str) {
      if (rc || check_http_resp(buff)) {
        debug(D_NOTICE, "connected to %s:%s via %s:%s", host, port, proxy_host,
              proxy_port);
        return sock;
      } else
        goto err1;
    }
    if (wr == sizeof(buff) - 1) {
      rc = check_http_resp(buff);
      if (!rc)
        goto err1;
      memcpy(buff, buff + sizeof(buff) - 8, 8);
      wr = 7; // yes, 7
    }
  }
err1:
  close(sock);
err0:
  detect_proxy();
  if (proxy_type != PROXY_CONNECT)
    return connect_socket_direct(host, port);
  else
    return INVALID_SOCKET;
}

static int connect_socket(const char *host, const char *port) {
  if (unlikely(!proxy_detected)) {
    proxy_detected = 1;
    detect_proxy();
  }
  if (likely(proxy_type != PROXY_CONNECT))
    return connect_socket_direct(host, port);
  else
    return connect_socket_connect_proxy(host, port);
}

static int wait_sock_ready_for_ssl(int sock) {
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

psync_socket *psync_socket_connect(const char *host, int unsigned port,
                                   int ssl) {
  psync_socket *ret;
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
      if (wait_sock_ready_for_ssl(sock)) {
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
  ret = psync_new(psync_socket);
  ret->ssl = sslc;
  ret->buffer = NULL;
  ret->sock = sock;
  ret->pending = 0;
  return ret;
}

void psync_socket_close(psync_socket *sock) {
  if (sock->ssl)
    while (psync_ssl_shutdown(sock->ssl) == PSYNC_SSL_NEED_FINISH)
      if (wait_sock_ready_for_ssl(sock->sock)) {
        psync_ssl_free(sock->ssl);
        break;
      }
  psync_socket_clear_write_buffered(sock);
  close(sock->sock);
  psync_free(sock);
}

void psync_socket_close_bad(psync_socket *sock) {
  if (sock->ssl)
    psync_ssl_free(sock->ssl);
  psync_socket_clear_write_buffered(sock);
  close(sock->sock);
  psync_free(sock);
}

void psync_socket_set_write_buffered(psync_socket *sock) {
  psync_socket_buffer *sb;
  if (sock->buffer)
    return;
  sb = (psync_socket_buffer *)psync_malloc(offsetof(psync_socket_buffer, buff) +
                                           PSYNC_FIRST_SOCK_WRITE_BUFF_SIZE);
  sb->next = NULL;
  sb->size = PSYNC_FIRST_SOCK_WRITE_BUFF_SIZE;
  sb->woffset = 0;
  sb->roffset = 0;
  sock->buffer = sb;
}

void psync_socket_set_write_buffered_thread(psync_socket *sock) {
  pthread_mutex_lock(&mutex);
  psync_socket_set_write_buffered(sock);
  pthread_mutex_unlock(&mutex);
}

void psync_socket_clear_write_buffered(psync_socket *sock) {
  psync_socket_buffer *nb;
  while (sock->buffer) {
    nb = sock->buffer->next;
    free(sock->buffer);
    sock->buffer = nb;
  }
}

void psync_socket_clear_write_buffered_thread(psync_socket *sock) {
  pthread_mutex_lock(&mutex);
  psync_socket_clear_write_buffered(sock);
  pthread_mutex_unlock(&mutex);
}

int psync_socket_set_recvbuf(psync_socket *sock, int bufsize) {
#if defined(SO_RCVBUF) && defined(SOL_SOCKET)
  return setsockopt(sock->sock, SOL_SOCKET, SO_RCVBUF, (const char *)&bufsize,
                    sizeof(bufsize));
#else
  return -1;
#endif
}

int psync_socket_set_sendbuf(psync_socket *sock, int bufsize) {
#if defined(SO_SNDBUF) && defined(SOL_SOCKET)
  return setsockopt(sock->sock, SOL_SOCKET, SO_SNDBUF, (const char *)&bufsize,
                    sizeof(bufsize));
#else
  return -1;
#endif
}

int psync_socket_isssl(psync_socket *sock) {
  if (sock->ssl)
    return 1;
  else
    return 0;
}

int psync_socket_pendingdata(psync_socket *sock) {
  if (sock->pending)
    return 1;
  if (sock->ssl)
    return psync_ssl_pendingdata(sock->ssl);
  else
    return 0;
}

int psync_socket_pendingdata_buf(psync_socket *sock) {
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

int psync_socket_pendingdata_buf_thread(psync_socket *sock) {
  int ret;
  pthread_mutex_lock(&mutex);
  ret = psync_socket_pendingdata_buf(sock);
  pthread_mutex_unlock(&mutex);
  return ret;
}

int intry_write_buffer(psync_socket *sock) {
  if (sock->buffer) {
    psync_socket_buffer *b;
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
        cw = write(sock->sock, b->buff + b->roffset,
                                b->woffset - b->roffset);
        if (cw == SOCKET_ERROR) {
          if (likely_log(errno == EWOULDBLOCK ||
                         errno == EAGAIN ||
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

int intry_write_buffer_thread(psync_socket *sock) {
  int ret;
  pthread_mutex_lock(&mutex);
  ret = intry_write_buffer(sock);
  pthread_mutex_unlock(&mutex);
  return ret;
}

int psync_socket_readable(psync_socket *sock) {
  intry_write_buffer(sock);
  if (sock->ssl && psync_ssl_pendingdata(sock->ssl))
    return 1;
  else if (psync_wait_socket_readable(sock->sock, 0))
    return 0;
  else {
    sock->pending = 1;
    return 1;
  }
}

int psync_socket_writable(psync_socket *sock) {
  if (sock->buffer)
    return 1;
  return !psync_wait_socket_writable(sock->sock, 0);
}

static int psync_socket_read_ssl(psync_socket *sock, void *buff, int num) {
  int r;
  intry_write_buffer(sock);
  if (!psync_ssl_pendingdata(sock->ssl) && !sock->pending &&
      psync_wait_socket_read_timeout(sock->sock))
    return -1;
  sock->pending = 0;
  while (1) {
    intry_write_buffer(sock);
    r = psync_ssl_read(sock->ssl, buff, num);
    if (r == PSYNC_SSL_FAIL) {
      if (likely_log(psync_ssl_errno == PSYNC_SSL_ERR_WANT_READ ||
                     psync_ssl_errno == PSYNC_SSL_ERR_WANT_WRITE)) {
        if (wait_sock_ready_for_ssl(sock->sock)) {
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

static int psync_socket_read_plain(psync_socket *sock, void *buff, int num) {
  int r;
  while (1) {
    intry_write_buffer(sock);
    if (sock->pending)
      sock->pending = 0;
    else if (psync_wait_socket_read_timeout(sock->sock)) {
      debug(D_WARNING, "timeouted on socket with pending buffers");
      return -1;
    } else
      intry_write_buffer(sock);
    r = read(sock->sock, buff, num);
    if (r == SOCKET_ERROR) {
      if (likely_log(errno == EWOULDBLOCK ||
                     errno == EAGAIN))
        continue;
      else
        return -1;
    } else
      return r;
  }
}

int psync_socket_read(psync_socket *sock, void *buff, int num) {
  if (sock->ssl)
    return psync_socket_read_ssl(sock, buff, num);
  else
    return psync_socket_read_plain(sock, buff, num);
}

static int psync_socket_read_noblock_ssl(psync_socket *sock, void *buff,
                                         int num) {
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

static int psync_socket_read_noblock_plain(psync_socket *sock, void *buff,
                                           int num) {
  int r;
  r = read(sock->sock, buff, num);
  if (r == SOCKET_ERROR) {
    sock->pending = 0;
    if (likely_log(errno == EWOULDBLOCK ||
                   errno == EAGAIN))
      return PSYNC_SOCKET_WOULDBLOCK;
    else
      return -1;
  } else
    return r;
}

int psync_socket_read_noblock(psync_socket *sock, void *buff, int num) {
  intry_write_buffer(sock);
  if (sock->ssl)
    return psync_socket_read_noblock_ssl(sock, buff, num);
  else
    return psync_socket_read_noblock_plain(sock, buff, num);
}

static int psync_socket_read_ssl_thread(psync_socket *sock, void *buff,
                                        int num) {
  int r;
  pthread_mutex_lock(&mutex);
  intry_write_buffer(sock);
  pthread_mutex_unlock(&mutex);
  if (!psync_ssl_pendingdata(sock->ssl) && !sock->pending &&
      psync_wait_socket_read_timeout(sock->sock))
    return -1;
  sock->pending = 0;
  while (1) {
    pthread_mutex_lock(&mutex);
    intry_write_buffer(sock);
    r = psync_ssl_read(sock->ssl, buff, num);
    pthread_mutex_unlock(&mutex);
    if (r == PSYNC_SSL_FAIL) {
      if (likely_log(psync_ssl_errno == PSYNC_SSL_ERR_WANT_READ ||
                     psync_ssl_errno == PSYNC_SSL_ERR_WANT_WRITE)) {
        if (wait_sock_ready_for_ssl(sock->sock))
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

static int psync_socket_read_plain_thread(psync_socket *sock, void *buff,
                                          int num) {
  int r;
  pthread_mutex_lock(&mutex);
  intry_write_buffer(sock);
  pthread_mutex_unlock(&mutex);
  while (1) {
    if (sock->pending)
      sock->pending = 0;
    else if (psync_wait_socket_read_timeout(sock->sock))
      return -1;
    pthread_mutex_lock(&mutex);
    intry_write_buffer(sock);
    r = read(sock->sock, buff, num);
    pthread_mutex_unlock(&mutex);
    if (r == SOCKET_ERROR) {
      if (likely_log(errno == EWOULDBLOCK ||
                     errno == EAGAIN))
        continue;
      else
        return -1;
    } else
      return r;
  }
}

int psync_socket_read_thread(psync_socket *sock, void *buff, int num) {
  if (sock->ssl)
    return psync_socket_read_ssl_thread(sock, buff, num);
  else
    return psync_socket_read_plain_thread(sock, buff, num);
}

static int psync_socket_write_to_buf(psync_socket *sock, const void *buff,
                                     int num) {
  psync_socket_buffer *b;
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
        b->next = (psync_socket_buffer *)psync_malloc(
            offsetof(psync_socket_buffer, buff) +
            PSYNC_SECOND_SOCK_WRITE_BUFF_SIZE);
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

int psync_socket_write(psync_socket *sock, const void *buff, int num) {
  int r;
  if (sock->buffer)
    return psync_socket_write_to_buf(sock, buff, num);
  if (psync_wait_socket_write_timeout(sock->sock))
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
      if (likely_log(errno == EWOULDBLOCK ||
                     errno == EAGAIN || errno == EINTR))
        return 0;
      else
        return -1;
    }
  }
  return r;
}

static int psync_socket_readall_ssl(psync_socket *sock, void *buff, int num) {
  int br, r;
  br = 0;

  intry_write_buffer(sock);

  if (!psync_ssl_pendingdata(sock->ssl) && !sock->pending &&
      psync_wait_socket_read_timeout(sock->sock)) {
    return -1;
  }

  sock->pending = 0;

  while (br < num) {
    intry_write_buffer(sock);

    r = psync_ssl_read(sock->ssl, (char *)buff + br, num - br);

    if (r == PSYNC_SSL_FAIL) {
      if (likely_log(psync_ssl_errno == PSYNC_SSL_ERR_WANT_READ ||
                     psync_ssl_errno == PSYNC_SSL_ERR_WANT_WRITE)) {
        if (wait_sock_ready_for_ssl(sock->sock))
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

static int psync_socket_readall_plain(psync_socket *sock, void *buff, int num) {
  int br, r;
  br = 0;
  while (br < num) {
    intry_write_buffer(sock);
    if (sock->pending)
      sock->pending = 0;
    else if (psync_wait_socket_read_timeout(sock->sock))
      return -1;
    else
      intry_write_buffer(sock);
    r = read(sock->sock, (char *)buff + br, num - br);
    if (r == SOCKET_ERROR) {
      if (likely_log(errno == EWOULDBLOCK ||
                     errno == EAGAIN))
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

int psync_socket_readall(psync_socket *sock, void *buff, int num) {
  if (sock->ssl) {
    return psync_socket_readall_ssl(sock, buff, num);
  } else {
    return psync_socket_readall_plain(sock, buff, num);
  }
}

static int psync_socket_writeall_ssl(psync_socket *sock, const void *buff,
                                     int num) {
  int br, r;
  br = 0;
  while (br < num) {
    r = psync_ssl_write(sock->ssl, (char *)buff + br, num - br);
    if (r == PSYNC_SSL_FAIL) {
      if (psync_ssl_errno == PSYNC_SSL_ERR_WANT_READ ||
          psync_ssl_errno == PSYNC_SSL_ERR_WANT_WRITE) {
        if (wait_sock_ready_for_ssl(sock->sock))
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

static int psync_socket_writeall_plain(int sock, const void *buff,
                                       int num) {
  int br, r;
  br = 0;
  while (br < num) {
    r = write(sock, (const char *)buff + br, num - br);
    if (r == SOCKET_ERROR) {
      if (errno == EWOULDBLOCK || errno == EAGAIN) {
        if (psync_wait_socket_write_timeout(sock))
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

int psync_socket_writeall(psync_socket *sock, const void *buff, int num) {
  if (sock->buffer)
    return psync_socket_write_to_buf(sock, buff, num);
  if (sock->ssl)
    return psync_socket_writeall_ssl(sock, buff, num);
  else
    return psync_socket_writeall_plain(sock->sock, buff, num);
}

static int psync_socket_readall_ssl_thread(psync_socket *sock, void *buff,
                                           int num) {
  int br, r;
  br = 0;
  pthread_mutex_lock(&mutex);
  intry_write_buffer(sock);
  r = psync_ssl_pendingdata(sock->ssl);
  pthread_mutex_unlock(&mutex);
  if (!r && !sock->pending && psync_wait_socket_read_timeout(sock->sock))
    return -1;
  sock->pending = 0;
  while (br < num) {
    pthread_mutex_lock(&mutex);
    intry_write_buffer(sock);
    r = psync_ssl_read(sock->ssl, (char *)buff + br, num - br);
    pthread_mutex_unlock(&mutex);
    if (r == PSYNC_SSL_FAIL) {
      if (likely_log(psync_ssl_errno == PSYNC_SSL_ERR_WANT_READ ||
                     psync_ssl_errno == PSYNC_SSL_ERR_WANT_WRITE)) {
        if (wait_sock_ready_for_ssl(sock->sock))
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

static int psync_socket_readall_plain_thread(psync_socket *sock, void *buff,
                                             int num) {
  int br, r;
  br = 0;
  pthread_mutex_lock(&mutex);
  intry_write_buffer(sock);
  pthread_mutex_unlock(&mutex);
  while (br < num) {
    if (sock->pending)
      sock->pending = 0;
    else if (psync_wait_socket_read_timeout(sock->sock))
      return -1;
    pthread_mutex_lock(&mutex);
    intry_write_buffer(sock);
    r = read(sock->sock, (char *)buff + br, num - br);
    pthread_mutex_unlock(&mutex);
    if (r == SOCKET_ERROR) {
      if (likely_log(errno == EWOULDBLOCK ||
                     errno == EAGAIN))
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

int psync_socket_readall_thread(psync_socket *sock, void *buff, int num) {
  if (sock->ssl)
    return psync_socket_readall_ssl_thread(sock, buff, num);
  else
    return psync_socket_readall_plain_thread(sock, buff, num);
}

static int psync_socket_writeall_ssl_thread(psync_socket *sock,
                                            const void *buff, int num) {
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
        if (wait_sock_ready_for_ssl(sock->sock))
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

static int psync_socket_writeall_plain_thread(psync_socket *sock,
                                              const void *buff, int num) {
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
        if (psync_wait_socket_write_timeout(sock->sock))
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

int psync_socket_writeall_thread(psync_socket *sock, const void *buff,
                                 int num) {
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

psync_interface_list_t *psync_list_ip_adapters() {
  psync_interface_list_t *ret;
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
  ret = psync_malloc(offsetof(psync_interface_list_t, interfaces) +
                     sizeof(psync_interface_t) * cnt);
  memset(ret, 0,
         offsetof(psync_interface_list_t, interfaces) +
             sizeof(psync_interface_t) * cnt);
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
  ret = psync_malloc(offsetof(psync_interface_list_t, interfaces));
  ret->interfacecnt = 0;
  return ret;
}

int psync_socket_is_broken(int sock) {
  fd_set rfds;
  struct timeval tv;
  memset(&tv, 0, sizeof(tv));
  FD_ZERO(&rfds);
  FD_SET(sock, &rfds);
  return select(sock + 1, NULL, NULL, &rfds, &tv) == 1;
}

int psync_select_in(int *sockets, int cnt, int64_t timeoutmillisec) {
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

int psync_file_rename(const char *oldpath, const char *newpath) {
  return rename(oldpath, newpath);
}

int psync_file_rename_overwrite(const char *oldpath, const char *newpath) {
  if (!strcmp(oldpath, newpath))
    return 0;
  return rename(oldpath, newpath);
}

int psync_file_delete(const char *path) { return unlink(path); }

int psync_file_open(const char *path, int access, int flags) {
  int fd;
#if defined(O_CLOEXEC)
  flags |= O_CLOEXEC;
#endif
#if defined(O_NOATIME)
  flags |= O_NOATIME;
#endif
  fd = open(path, access | flags, PSYNC_DEFAULT_POSIX_FILE_MODE);
  if (unlikely(fd == -1)) {
    while (errno == EINTR) {
      debug(D_NOTICE, "got EINTR while opening file");
      fd = open(path, access | flags, PSYNC_DEFAULT_POSIX_FILE_MODE);
      if (fd != -1)
        return fd;
    }
  }
  return fd;
}

int psync_file_close(int fd) { return close(fd); }

int psync_file_sync(int fd) {
#if defined(F_FULLFSYNC)
  if (unlikely(fcntl(fd, F_FULLFSYNC))) {
    while (errno == EINTR) {
      debug(D_NOTICE, "got EINTR while fsyncing file");
      if (!fcntl(fd, F_FULLFSYNC))
        return 0;
    }
    debug(D_NOTICE,
          "got error %d, when doing fcntl(F_FULLFSYNC), trying fsync()", errno);
    if (fsync(fd)) {
      debug(D_NOTICE, "fsync also failed, error %d", errno);
      return -1;
    } else {
      debug(D_NOTICE, "fsync succeded");
      return 0;
    }
  } else
    return 0;
#else
#if _POSIX_SYNCHRONIZED_IO > 0
  if (unlikely(fdatasync(fd))) {
#else
  if (unlikely(fsync(fd))) {
#endif
    while (errno == EINTR) {
      debug(D_NOTICE, "got EINTR while fsyncing file");
      if (!fsync(fd))
        return 0;
    }
    debug(D_NOTICE, "got error %d", errno);
    return -1;
  } else
    return 0;
#endif
}

int psync_file_schedulesync(int fd) {
#if defined(SYNC_FILE_RANGE_WRITE)
  return sync_file_range(fd, 0, 0, SYNC_FILE_RANGE_WRITE);
#elif _POSIX_MAPPED_FILES > 0 && _POSIX_SYNCHRONIZED_IO > 0
  struct stat st;
  void *fmap;
  int ret;
  if (unlikely(fstat(fd, &st))) {
    debug(D_NOTICE, "fstat failed, errno=%d", errno);
    return -1;
  }
  fmap = mmap(NULL, st.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (unlikely(fmap == MAP_FAILED)) {
    debug(D_NOTICE, "mmap failed, errno=%d", errno);
    return -1;
  }
  ret = msync(fmap, st.st_size, MS_ASYNC);
  if (unlikely(ret))
    debug(D_NOTICE, "msync failed, errno=%d", errno);
  munmap(fmap, st.st_size);
  return ret;
#else
  return 0;
#endif
}

int psync_folder_sync(const char *path) {
  int fd, ret;
  fd = open(path, O_RDONLY);
  if (fd == -1) {
    debug(D_NOTICE, "could not open folder %s, error %d", path, errno);
    return -1;
  }
  if (unlikely(psync_file_sync(fd))) {
    debug(D_NOTICE, "could not fsync folder %s, error %d", path, errno);
    ret = -1;
  } else
    ret = 0;
  close(fd);
  return ret;
}

int psync_file_dup(int fd) { return dup(fd); }

int psync_file_set_creation(int fd, time_t ctime) { return -1; }

int psync_set_crtime_mtime(const char *path, time_t crtime, time_t mtime) {
  if (mtime) {
    struct timeval tm[2];
    tm[0].tv_sec = mtime;
    tm[0].tv_usec = 0;
    tm[1].tv_sec = mtime;
    tm[1].tv_usec = 0;
    if (unlikely(utimes(path, tm))) {
      debug(D_NOTICE,
            "got errno %d while setting modification time of %s to %lu: %s",
            errno, path, mtime, strerror(errno));
      return -1;
    } else
      return 0;
  } else
    return 0;
}

int psync_set_crtime_mtime_by_fd(int fd, const char *path,
                                 time_t crtime, time_t mtime) {
  return psync_set_crtime_mtime(path, crtime, mtime);
}

typedef struct {
  uint64_t offset;
  size_t count;
  int fd;
} psync_file_preread_t;

static void psync_file_preread_thread(void *ptr) {
  char buff[16 * 1024];
  psync_file_preread_t *pr;
  ssize_t rd;
  pr = (psync_file_preread_t *)ptr;
  while (pr->count) {
    rd = psync_file_pread(pr->fd, buff,
                          pr->count > sizeof(buff) ? sizeof(buff) : pr->count,
                          pr->offset);
    if (rd <= 0)
      break;
    pr->offset += rd;
    pr->count -= rd;
  }
  psync_file_close(pr->fd);
  psync_free(pr);
}

int psync_file_preread(int fd, uint64_t offset, size_t count) {
  psync_file_preread_t *pr;
  int cfd;
  cfd = psync_file_dup(fd);
  if (cfd == INVALID_HANDLE_VALUE)
    return -1;
  pr = psync_new(psync_file_preread_t);
  pr->offset = offset;
  pr->count = count;
  pr->fd = cfd;
  prun_thread1("pre-read (readahead) thread", psync_file_preread_thread,
                    pr);
  return 0;
}

int psync_file_readahead(int fd, uint64_t offset, size_t count) {
#if defined(POSIX_FADV_WILLNEED)
  return posix_fadvise(fd, offset, count, POSIX_FADV_WILLNEED);
#elif defined(F_RDADVISE)
  struct radvisory ra;
  ra.ra_offset = offset;
  ra.ra_count = count;
  return fcntl(fd, F_RDADVISE, &ra);
#endif
}

ssize_t psync_file_read(int fd, void *buf, size_t count) {
  ssize_t ret;
  ret = read(fd, buf, count);
  if (unlikely(ret == -1)) {
    while (errno == EINTR) {
      debug(D_NOTICE, "got EINTR while reading from file");
      ret = read(fd, buf, count);
      if (ret != -1)
        return ret;
    }
    debug(D_NOTICE, "got error %d", errno);
  }
  return ret;
}

ssize_t psync_file_pread(int fd, void *buf, size_t count,
                         uint64_t offset) {
  ssize_t ret;
  ret = pread(fd, buf, count, offset);
  if (unlikely(ret == -1)) {
    while (errno == EINTR) {
      debug(D_NOTICE, "got EINTR while writing to file");
      ret = pread(fd, buf, count, offset);
      if (ret != -1)
        return ret;
    }
    debug(D_NOTICE, "got error %d", errno);
  }
  return ret;
}

ssize_t psync_file_write(int fd, const void *buf, size_t count) {
  ssize_t ret;
  ret = write(fd, buf, count);
  if (unlikely(ret == -1)) {
    while (errno == EINTR) {
      debug(D_NOTICE, "got EINTR while writing to file");
      ret = write(fd, buf, count);
      if (ret != -1)
        return ret;
    }
    debug(D_NOTICE, "got error %d", errno);
  }
  return ret;
}

ssize_t psync_file_pwrite(int fd, const void *buf, size_t count,
                          uint64_t offset) {
  ssize_t ret;
  ret = pwrite(fd, buf, count, offset);
  if (unlikely(ret == -1)) {
    while (errno == EINTR) {
      debug(D_NOTICE, "got EINTR while writing to file");
      ret = pwrite(fd, buf, count, offset);
      if (ret != -1)
        return ret;
    }
    debug(D_NOTICE, "got error %d", errno);
  }
  return ret;
}

int64_t psync_file_seek(int fd, uint64_t offset, int whence) {
  return lseek(fd, offset, whence);
}

int intruncate(int fd) {
  off_t off;
  off = lseek(fd, 0, SEEK_CUR);
  if (likely_log(off != (off_t)-1)) {
    if (unlikely(ftruncate(fd, off))) {
      while (errno == EINTR) {
        debug(D_NOTICE, "got EINTR while truncating file");
        if (!ftruncate(fd, off))
          return 0;
      }
      debug(D_NOTICE, "got error %d", errno);
      return -1;
    } else
      return 0;
  } else
    return -1;
}

int64_t psync_file_size(int fd) {
  struct stat st;
  if (unlikely_log(fstat(fd, &st)))
    return -1;
  else
    return st.st_size;
}

#define PSYNC_RUN_CMD "xdg-open" // XXX: verify this...

int psync_run_update_file(const char *path) {
  pid_t pid;
  debug(D_NOTICE, "running %s with " PSYNC_RUN_CMD, path);
  pid = fork();
  if (unlikely(pid == -1)) {
    debug(D_ERROR, "fork failed");
    return -1;
  } else if (pid) {
    int status;
    psync_milisleep(100);
    if (waitpid(pid, &status, WNOHANG) == 0)
      return 0;
    else
      return -1;
  } else {
    char *ex;
    int fd;
    fd = open("/dev/null", O_RDWR);
    dup2(fd, STDIN_FILENO);
    dup2(fd, STDOUT_FILENO);
    dup2(fd, STDERR_FILENO);
    close(fd);
    setsid();
    ex = psync_strcat(PSYNC_RUN_CMD " \"", path, "\"", NULL);
    execl("/bin/sh", "/bin/sh", "-c", ex, NULL);
    debug(D_ERROR, "exec of %s failed", ex);
    psync_free(ex);
    exit(1);
  }
}

int psync_invalidate_os_cache_needed() { return 0; }

extern int overlays_running;

int psync_invalidate_os_cache(const char *path) { return 0; }
