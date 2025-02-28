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

#include "pfile.h"
#include "plibs.h"
#include "prun.h"
#include "psettings.h"
#include "psynclib.h"
#include "psys.h"

extern char **environ;

PSYNC_THREAD const char *psync_thread_name = "no name";

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

int pfile_stat_mode_ok(struct stat *buf, unsigned int bits) {
  int i;
  uid_t psync_uid;
  gid_t *psync_gids;
  int psync_gids_cnt;

  psync_uid = psys_get_uid();
  if (psync_uid == 0) {
    return 1;
  }
  if (buf->st_uid == psync_uid) {
    bits <<= 6;
    return (buf->st_mode & bits) == bits;
  }
  if (buf->st_gid == psys_get_gid()) {
    bits <<= 3;
    return (buf->st_mode & bits) == bits;
  }

  psync_gids = psys_get_gids();
  psync_gids_cnt = psys_get_gids_cnt();
  for (i = 0; i < psync_gids_cnt; i++) {
    if (buf->st_gid == psync_gids[i]) {
      bits <<= 3;
      return (buf->st_mode & bits) == bits;
    }
  }
  return (buf->st_mode & bits) == bits;
}

int pfile_rename(const char *oldpath, const char *newpath) {
  return rename(oldpath, newpath);
}

int pfile_rename_overwrite(const char *oldpath, const char *newpath) {
  if (!strcmp(oldpath, newpath))
    return 0;
  return rename(oldpath, newpath);
}

int pfile_delete(const char *path) { return unlink(path); }

int pfile_open(const char *path, int access, int flags) {
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

int pfile_close(int fd) { return close(fd); }

int pfile_sync(int fd) {
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

int pfile_schedulesync(int fd) {
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

int pfile_folder_sync(const char *path) {
  int fd, ret;
  fd = open(path, O_RDONLY);
  if (fd == -1) {
    debug(D_NOTICE, "could not open folder %s, error %d", path, errno);
    return -1;
  }
  if (unlikely(pfile_sync(fd))) {
    debug(D_NOTICE, "could not fsync folder %s, error %d", path, errno);
    ret = -1;
  } else
    ret = 0;
  close(fd);
  return ret;
}

int pfile_dup(int fd) { return dup(fd); }

int pfile_set_creation(int fd, time_t ctime) { return -1; }

int pfile_set_crtime_mtime(const char *path, time_t crtime, time_t mtime) {
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

int pfile_set_crtime_mtime_by_fd(int fd, const char *path,
                                 time_t crtime, time_t mtime) {
  return pfile_set_crtime_mtime(path, crtime, mtime);
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
    rd = pfile_pread(pr->fd, buff,
                          pr->count > sizeof(buff) ? sizeof(buff) : pr->count,
                          pr->offset);
    if (rd <= 0)
      break;
    pr->offset += rd;
    pr->count -= rd;
  }
  pfile_close(pr->fd);
  psync_free(pr);
}

int pfile_preread(int fd, uint64_t offset, size_t count) {
  psync_file_preread_t *pr;
  int cfd;
  cfd = pfile_dup(fd);
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

int pfile_readahead(int fd, uint64_t offset, size_t count) {
#if defined(POSIX_FADV_WILLNEED)
  return posix_fadvise(fd, offset, count, POSIX_FADV_WILLNEED);
#elif defined(F_RDADVISE)
  struct radvisory ra;
  ra.ra_offset = offset;
  ra.ra_count = count;
  return fcntl(fd, F_RDADVISE, &ra);
#endif
}

ssize_t pfile_read(int fd, void *buf, size_t count) {
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

ssize_t pfile_pread(int fd, void *buf, size_t count,
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

ssize_t pfile_write(int fd, const void *buf, size_t count) {
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

ssize_t pfile_pwrite(int fd, const void *buf, size_t count,
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

int64_t pfile_seek(int fd, uint64_t offset, int whence) {
  return lseek(fd, offset, whence);
}

int pfile_truncate(int fd) {
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

int64_t pfile_size(int fd) {
  struct stat st;
  if (unlikely_log(fstat(fd, &st)))
    return -1;
  else
    return st.st_size;
}

#define PSYNC_RUN_CMD "xdg-open" // XXX: verify this...

int pfile_run_update(const char *path) {
  pid_t pid;
  debug(D_NOTICE, "running %s with " PSYNC_RUN_CMD, path);
  pid = fork();
  if (unlikely(pid == -1)) {
    debug(D_ERROR, "fork failed");
    return -1;
  } else if (pid) {
    int status;
    psys_sleep_milliseconds(100);
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

int pfile_invalidate_os_cache_needed() { return 0; }

extern int overlays_running;

int pfile_invalidate_os_cache(const char *path) { return 0; }
