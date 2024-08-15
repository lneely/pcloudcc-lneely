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

#ifndef _PSYNC_COMPAT_H
#define _PSYNC_COMPAT_H

#include "pcompiler.h"

// figure out which OS...
// XXX: goal is to remove
// ---
#if defined(__linux__)
// linux os
#ifndef P_OS_LINUX // HACK: need to rework includes
#define P_OS_LINUX
#endif
#define P_OS_ID 7 // linux
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#else
// non-linux posix-compliant OS
#define P_OS_ID 0
#endif

#define _FILE_OFFSET_BITS 64

#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/types.h>

typedef long psync_int_t;
typedef unsigned long psync_uint_t;

#define P_PRI_I "ld"
#define P_PRI_U "lu"

#ifndef PRIu64
#define PRIu64 "I64u"
#endif

#define psync_32to64(hi, lo) ((((uint64_t)(hi)) << 32) + (lo))
#define psync_bool_to_zero(x) (((int)(!!(x))) - 1)

#define NTO_STR(s) TO_STR(s)
#define TO_STR(s) #s

#include <arpa/inet.h>
#include <fcntl.h>
#include <inttypes.h>
#include <netdb.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#define P_PRI_U64 PRIu64
#define P_PRI_D64 PRId64

#define psync_stat stat
#define psync_fstat fstat
#define psync_stat_isfolder(s) S_ISDIR((s)->st_mode)
#define psync_stat_size(s) ((s)->st_size)
#define psync_stat_birthtime(s) ((s)->st_mtime)
#define psync_stat_ctime(s) ((s)->st_ctime)
#define psync_stat_mtime(s) ((s)->st_mtime)

#if defined(st_mtime)
#if defined(st_mtimensec)
#define psync_stat_mtime_native(s)                                             \
  ((s)->st_mtime * 1000000ULL + (s)->st_mtimensec / 1000)
#else
#define psync_stat_mtime_native(s)                                             \
  ((s)->st_mtime * 1000000ULL +                                                \
   ((struct timespec *)(&(s)->st_mtime))->tv_nsec / 1000)
#endif

#define psync_mtime_native_to_mtime(n) ((n) / 1000000ULL)

#define psync_stat_inode(s) ((s)->st_ino)
#define psync_stat_device(s) ((s)->st_dev)
#define psync_stat_device_full(s) ((s)->st_dev)

#define psync_deviceid_short(deviceid) (deviceid)

typedef struct stat psync_stat_t;

#define psync_sock_err() errno
#define psync_sock_set_err(e) errno = (e)

#define psync_fs_err() errno

typedef int psync_sock_err_t;
typedef int psync_fs_err_t;

#define psync_inode_supported(path) 1

#define PSYNC_DIRECTORY_SEPARATOR "/"
#define PSYNC_DIRECTORY_SEPARATORC '/'

#define P_WOULDBLOCK EWOULDBLOCK
#define P_AGAIN EAGAIN
#define P_INPROGRESS EINPROGRESS
#define P_TIMEDOUT ETIMEDOUT
#define P_INVAL EINVAL
#define P_CONNRESET ECONNRESET
#define P_INTR EINTR

#define P_NOENT ENOENT
#define P_EXIST EEXIST
#define P_NOSPC ENOSPC
#define P_DQUOT EDQUOT
#define P_NOTEMPTY ENOTEMPTY
#define P_NOTDIR ENOTDIR
#define P_BUSY EBUSY
#define P_ROFS EROFS

#define P_O_RDONLY O_RDONLY
#define P_O_WRONLY O_WRONLY
#define P_O_RDWR O_RDWR
#define P_O_CREAT O_CREAT
#define P_O_TRUNC O_TRUNC
#define P_O_EXCL O_EXCL

#define P_SEEK_SET SEEK_SET
#define P_SEEK_CUR SEEK_CUR
#define P_SEEK_END SEEK_END

typedef int psync_socket_t;
typedef int psync_file_t;

#define PSYNC_FILENAMES_CASESENSITIVE 1
#define psync_filename_cmp strcmp
#define psync_filename_cmpn memcmp

#define psync_def_var_arr(name, type, size) type name[size]
#define psync_close_socket close
#define psync_read_socket read
#define psync_write_socket write

#else
#error "Need to define types for your operating system"
#endif

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
  psync_socket_t sock;
  int pending;
  uint32_t misc;
} psync_socket;

typedef uint64_t psync_inode_t;
typedef uint64_t psync_deviceid_t;

typedef struct {
  const char *name;
  const char *path;
  psync_stat_t stat;
} psync_pstat;

typedef struct {
  const char *name;
  uint8_t isfolder;
} psync_pstat_fast;
#define psync_stat_fast_isfolder(a) ((a)->isfolder)

typedef struct {
  struct sockaddr_storage address;
  struct sockaddr_storage broadcast;
  struct sockaddr_storage netmask;
  int addrsize;
} psync_interface_t;

typedef struct {
  size_t interfacecnt;
  psync_interface_t interfaces[];
} psync_interface_list_t;

#ifndef INVALID_SOCKET
#define INVALID_SOCKET -1
#endif

#ifndef SOCKET_ERROR
#define SOCKET_ERROR -1
#endif

#ifndef INVALID_HANDLE_VALUE
#define INVALID_HANDLE_VALUE -1
#endif

#define PSYNC_SOCKET_ERROR -1
#define PSYNC_SOCKET_WOULDBLOCK -2

#if !defined(__socklen_t_defined) && !defined(HAVE_SOCKET_LEN_T) &&            \
    !defined(socklen_t)

typedef unsigned int socklen_t;

#define __socklen_t_defined
#define HAVE_SOCKET_LEN_T
#endif

typedef void (*psync_list_dir_callback)(void *, psync_pstat *);
typedef void (*psync_list_dir_callback_fast)(void *, psync_pstat_fast *);
typedef void (*psync_thread_start0)();
typedef void (*psync_thread_start1)(void *);

extern PSYNC_THREAD const char *psync_thread_name;

extern const unsigned char psync_invalid_filename_chars[];

void psync_compat_init();
int psync_user_is_admin();
int psync_stat_mode_ok(psync_stat_t *buf, unsigned int bits) PSYNC_PURE;
char *psync_get_pcloud_path();
char *psync_get_private_dir(char *name);
char *psync_get_private_tmp_dir();
char *psync_get_default_database_path();
char *psync_get_home_dir();
void psync_run_thread(const char *name, psync_thread_start0 run);
void psync_run_thread1(const char *name, psync_thread_start1 run, void *ptr);
void psync_milisleep_nosqlcheck(uint64_t millisec);
void psync_milisleep(uint64_t millisec);
time_t psync_time();
void psync_nanotime(struct timespec *tm);
uint64_t psync_millitime();
void psync_yield_cpu();

void psync_get_random_seed(unsigned char *seed, const void *addent,
                           size_t aelen, int fast);

psync_socket_t psync_create_socket(int domain, int type, int protocol);
psync_socket *psync_socket_connect(const char *host, int unsigned port,
                                   int ssl);
void psync_socket_close(psync_socket *sock);
void psync_socket_close_bad(psync_socket *sock);
void psync_socket_set_write_buffered(psync_socket *sock);
void psync_socket_set_write_buffered_thread(psync_socket *sock);
void psync_socket_clear_write_buffered(psync_socket *sock);
void psync_socket_clear_write_buffered_thread(psync_socket *sock);
int psync_socket_set_recvbuf(psync_socket *sock, int bufsize);
int psync_socket_set_sendbuf(psync_socket *sock, int bufsize);
int psync_socket_isssl(psync_socket *sock) PSYNC_PURE;
int psync_socket_pendingdata(psync_socket *sock);
int psync_socket_pendingdata_buf(psync_socket *sock);
int psync_socket_pendingdata_buf_thread(psync_socket *sock);
int psync_socket_try_write_buffer(psync_socket *sock);
int psync_socket_try_write_buffer_thread(psync_socket *sock);
int psync_socket_readable(psync_socket *sock);
int psync_socket_writable(psync_socket *sock);
int psync_socket_read(psync_socket *sock, void *buff, int num);
int psync_socket_read_noblock(psync_socket *sock, void *buff, int num);
int psync_socket_read_thread(psync_socket *sock, void *buff, int num);
int psync_socket_write(psync_socket *sock, const void *buff, int num);
int psync_socket_readall(psync_socket *sock, void *buff, int num);
int psync_socket_writeall(psync_socket *sock, const void *buff, int num);
int psync_socket_readall_thread(psync_socket *sock, void *buff, int num);
int psync_socket_writeall_thread(psync_socket *sock, const void *buff, int num);

psync_interface_list_t *psync_list_ip_adapters();

/* pipefd[0] is the read end, pipefd[1] is for writing */
int psync_pipe(psync_socket_t pipefd[2]);
int psync_pipe_close(psync_socket_t pfd);
int psync_pipe_read(psync_socket_t pfd, void *buff, int num);
int psync_pipe_write(psync_socket_t pfd, const void *buff, int num);

int psync_socket_pair(psync_socket_t sfd[2]);
int psync_wait_socket_write_timeout(psync_socket_t sock);
int psync_wait_socket_read_timeout(psync_socket_t sock);

int psync_socket_is_broken(psync_socket_t sock);
int psync_select_in(psync_socket_t *sockets, int cnt, int64_t timeoutmillisec);

int psync_list_dir(const char *path, psync_list_dir_callback callback,
                   void *ptr);
int psync_list_dir_fast(const char *path, psync_list_dir_callback_fast callback,
                        void *ptr);

int64_t psync_get_free_space_by_path(const char *path);

int psync_mkdir(const char *path);
int psync_rmdir(const char *path);
#define psync_rendir psync_file_rename
int psync_file_rename(const char *oldpath, const char *newpath);
int psync_file_rename_overwrite(const char *oldpath, const char *newpath);
int psync_file_delete(const char *path);

psync_file_t psync_file_open(const char *path, int access, int flags);
int psync_file_close(psync_file_t fd);
int psync_file_sync(psync_file_t fd);
int psync_file_schedulesync(psync_file_t fd);
int psync_folder_sync(const char *path);
psync_file_t psync_file_dup(psync_file_t fd);
int psync_file_set_creation(psync_file_t fd, time_t ctime);
int psync_set_crtime_mtime(const char *path, time_t crtime, time_t mtime);
int psync_set_crtime_mtime_by_fd(psync_file_t fd, const char *path,
                                 time_t crtime, time_t mtime);
int psync_file_preread(psync_file_t fd, uint64_t offset, size_t count);
int psync_file_readahead(psync_file_t fd, uint64_t offset, size_t count);
ssize_t psync_file_read(psync_file_t fd, void *buf, size_t count);
ssize_t psync_file_pread(psync_file_t fd, void *buf, size_t count,
                         uint64_t offset);
ssize_t psync_file_write(psync_file_t fd, const void *buf, size_t count);
ssize_t psync_file_pwrite(psync_file_t fd, const void *buf, size_t count,
                          uint64_t offset);
int64_t psync_file_seek(psync_file_t fd, uint64_t offset, int whence);
int psync_file_truncate(psync_file_t fd);
int64_t psync_file_size(psync_file_t fd);

void psync_set_software_name(const char *snm);
void psync_set_os_name(const char *osnm);
char *psync_deviceos();
const char *psync_appname();
char *psync_device_string();
char *psync_deviceid();

int psync_run_update_file(const char *path);
int psync_invalidate_os_cache_needed();
int psync_invalidate_os_cache(const char *path);

void *psync_mmap_anon(size_t size);
void *psync_mmap_anon_safe(size_t size);
int psync_munmap_anon(void *ptr, size_t size);
void psync_anon_reset(void *ptr, size_t size);

int psync_mlock(void *ptr, size_t size);
int psync_munlock(void *ptr, size_t size);

int psync_get_page_size();

void psync_rebuild_icons();

#endif
