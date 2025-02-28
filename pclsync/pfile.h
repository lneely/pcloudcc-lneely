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

#ifndef __PFILE_H
#define __PFILE_H

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

// constants
#define INVALID_HANDLE_VALUE -1

// macros
#define pfile_stat_isfolder(s) S_ISDIR((s)->st_mode)
#define pfile_stat_size(s) ((s)->st_size)
#define pfile_stat_birthtime(s) ((s)->st_mtime)
#define pfile_stat_ctime(s) ((s)->st_ctime)
#define pfile_stat_mtime(s) ((s)->st_mtime)
#if defined(st_mtimensec)
#define pfile_stat_mtime_native(s)                                             \
  ((s)->st_mtime * 1000000ULL + (s)->st_mtimensec / 1000)
#else
#define pfile_stat_mtime_native(s)                                             \
  ((s)->st_mtime * 1000000ULL +                                                \
   ((struct timespec *)(&(s)->st_mtime))->tv_nsec / 1000)
#endif
#define pfile_stat_inode(s) ((s)->st_ino)
#define pfile_stat_device(s) ((s)->st_dev)
#define pfile_stat_device_full(s) ((s)->st_dev)
#define pfile_stat_fast_isfolder(a) ((a)->isfolder)

// File Operations
int pfile_open(const char *path, int access, int flags);
int pfile_close(int fd);
int pfile_dup(int fd);
ssize_t pfile_read(int fd, void *buf, size_t count);
ssize_t pfile_write(int fd, const void *buf, size_t count);
ssize_t pfile_pread(int fd, void *buf, size_t count, uint64_t offset);
ssize_t pfile_pwrite(int fd, const void *buf, size_t count, uint64_t offset);
int64_t pfile_seek(int fd, uint64_t offset, int whence);
int64_t pfile_size(int fd);
int pfile_sync(int fd);
int pfile_schedulesync(int fd);
int pfile_readahead(int fd, uint64_t offset, size_t count);
int pfile_preread(int fd, uint64_t offset, size_t count);
int pfile_delete(const char *path);
int pfile_rename(const char *oldpath, const char *newpath);
int pfile_rename_overwrite(const char *oldpath, const char *newpath);
int pfile_set_creation(int fd, time_t ctime);
int pfile_truncate(int fd);
int pfile_folder_sync(const char *path);
int pfile_run_update(const char *path);
int pfile_set_crtime_mtime(const char *path, time_t crtime, time_t mtime);
int pfile_set_crtime_mtime_by_fd(int fd, const char *path, time_t crtime, time_t mtime);
int pfile_invalidate_os_cache(const char *path);
int pfile_invalidate_os_cache_needed();
int pfile_stat_mode_ok(struct stat *buf, unsigned int bits) PSYNC_PURE;

#endif
