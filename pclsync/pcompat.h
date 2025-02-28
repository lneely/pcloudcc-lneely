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

// required for pcloud api; 7=>linux
#define P_OS_ID 7 

#include <fcntl.h>
#include <inttypes.h>
#include <netdb.h>
#include <pthread.h>
#include <stdint.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>

#include "pcompiler.h"

extern PSYNC_THREAD const char *psync_thread_name;
extern const unsigned char psync_invalid_filename_chars[];

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
} psync_socket;

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

// callback signatures
typedef void (*psync_thread_start0)();
typedef void (*psync_thread_start1)(void *);

// constants
#define INVALID_HANDLE_VALUE -1
#define INVALID_SOCKET -1
#define PSYNC_SOCKET_ERROR -1
#define PSYNC_SOCKET_WOULDBLOCK -2
#define SOCKET_ERROR -1

// macros
#define psync_32to64(hi, lo) ((((uint64_t)(hi)) << 32) + (lo))
#define psync_bool_to_zero(x) (((int)(!!(x))) - 1)
#define NTO_STR(s) TO_STR(s)
#define TO_STR(s) #s
#define psync_stat_isfolder(s) S_ISDIR((s)->st_mode)
#define psync_stat_size(s) ((s)->st_size)
#define psync_stat_birthtime(s) ((s)->st_mtime)
#define psync_stat_ctime(s) ((s)->st_ctime)
#define psync_stat_mtime(s) ((s)->st_mtime)
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
#define pdevice_id_short(deviceid) (deviceid)
#define psync_def_var_arr(name, type, size) type name[size]
#define psync_stat_fast_isfolder(a) ((a)->isfolder)

// System Initialization and Configuration
void psync_sys_init();

// Time and Sleep Functions
time_t psync_time();
uint64_t psync_millitime();
void psync_milisleep(uint64_t millisec);
void psync_milisleep_nosqlcheck(uint64_t millisec);

// Memory Management
void *psync_mmap_anon(size_t size);
void *psync_mmap_anon_safe(size_t size);
int psync_munmap_anon(void *ptr, size_t size);
int psync_mlock(void *ptr, size_t size);
int psync_munlock(void *ptr, size_t size);
void psync_anon_reset(void *ptr, size_t size);
void psync_get_random_seed(unsigned char *seed, const void *addent, size_t aelen, int fast);
int psync_get_page_size();

// Thread Management
void psync_run_thread(const char *name, psync_thread_start0 run);
void psync_run_thread1(const char *name, psync_thread_start1 run, void *ptr);

// File Operations
int psync_file_open(const char *path, int access, int flags);
int psync_file_close(int fd);
int psync_file_dup(int fd);
ssize_t psync_file_read(int fd, void *buf, size_t count);
ssize_t psync_file_write(int fd, const void *buf, size_t count);
ssize_t psync_file_pread(int fd, void *buf, size_t count, uint64_t offset);
ssize_t psync_file_pwrite(int fd, const void *buf, size_t count, uint64_t offset);
int64_t psync_file_seek(int fd, uint64_t offset, int whence);
int64_t psync_file_size(int fd);
int psync_file_sync(int fd);
int psync_file_schedulesync(int fd);
int psync_file_readahead(int fd, uint64_t offset, size_t count);
int psync_file_preread(int fd, uint64_t offset, size_t count);
int psync_file_delete(const char *path);
int psync_file_rename(const char *oldpath, const char *newpath);
int psync_file_rename_overwrite(const char *oldpath, const char *newpath);
int psync_file_set_creation(int fd, time_t ctime);
int intruncate(int fd);
int psync_folder_sync(const char *path);
int psync_run_update_file(const char *path);
int psync_set_crtime_mtime(const char *path, time_t crtime, time_t mtime);
int psync_set_crtime_mtime_by_fd(int fd, const char *path, time_t crtime, time_t mtime);
int psync_invalidate_os_cache(const char *path);
int psync_invalidate_os_cache_needed();
int psync_stat_mode_ok(struct stat *buf, unsigned int bits) PSYNC_PURE;

// Socket and Network Operations
int psync_create_socket(int domain, int type, int protocol);
psync_socket *psync_socket_connect(const char *host, int unsigned port, int ssl);
void psync_socket_close(psync_socket *sock);
void psync_socket_close_bad(psync_socket *sock);
int psync_socket_read(psync_socket *sock, void *buff, int num);
int psync_socket_write(psync_socket *sock, const void *buff, int num);
int psync_socket_readall(psync_socket *sock, void *buff, int num);
int psync_socket_writeall(psync_socket *sock, const void *buff, int num);
int psync_socket_read_noblock(psync_socket *sock, void *buff, int num);
int psync_socket_read_thread(psync_socket *sock, void *buff, int num);
int psync_socket_readall_thread(psync_socket *sock, void *buff, int num);
int psync_socket_writeall_thread(psync_socket *sock, const void *buff, int num);
int psync_socket_isssl(psync_socket *sock) PSYNC_PURE;
int psync_socket_is_broken(int sock);
int psync_socket_readable(psync_socket *sock);
int psync_socket_writable(psync_socket *sock);
int psync_socket_pendingdata(psync_socket *sock);
int psync_socket_pendingdata_buf(psync_socket *sock);
int psync_socket_pendingdata_buf_thread(psync_socket *sock);
int psync_socket_set_recvbuf(psync_socket *sock, int bufsize);
int psync_socket_set_sendbuf(psync_socket *sock, int bufsize);
void psync_socket_set_write_buffered(psync_socket *sock);
void psync_socket_clear_write_buffered(psync_socket *sock);
void psync_socket_set_write_buffered_thread(psync_socket *sock);
void psync_socket_clear_write_buffered_thread(psync_socket *sock);
int intry_write_buffer(psync_socket *sock);
int intry_write_buffer_thread(psync_socket *sock);
int psync_wait_socket_read_timeout(int sock);
int psync_wait_socket_write_timeout(int sock);
int psync_select_in(int *sockets, int cnt, int64_t timeoutmillisec);
psync_interface_list_t *psync_list_ip_adapters();


#endif
