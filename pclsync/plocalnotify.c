/*
   Copyright (c) 2014 Anton Titov.

   Copyright (c) 2014 pCloud Ltd.  All rights reserved.

   Redistribution and use in source and binary forms, with or without
   modification, are permitted provided that the following conditions
   are met: Redistributions of source code must retain the above
   copyright notice, this list of conditions and the following
   disclaimer.  Redistributions in binary form must reproduce the
   above copyright notice, this list of conditions and the following
   disclaimer in the documentation and/or other materials provided
   with the distribution.  Neither the name of pCloud Ltd nor the
   names of its contributors may be used to endorse or promote
   products derived from this software without specific prior written
   permission.

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

#include "plocalnotify.h"
#include "pcompat.h"
#include "plibs.h"
#include "plist.h"
#include "plocalscan.h"
#include "psettings.h"

#define NOTIFY_MSG_ADD 0
#define NOTIFY_MSG_DEL 1

typedef struct {
  uint32_t type;
  psync_syncid_t syncid;
} localnotify_msg;

#include <dirent.h>
#include <stddef.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/inotify.h>
#include <sys/types.h>
#include <unistd.h>

static int pipe_read, pipe_write, epoll_fd;
static psync_list dirs = PSYNC_LIST_STATIC_INIT(dirs);

#define WATCH_HASH 512

typedef struct _localnotify_watch {
  struct _localnotify_watch *next;
  int watchid;
  uint32_t pathlen;
  uint32_t namelen;
  char path[];
} localnotify_watch;

typedef struct {
  psync_list list;
  psync_syncid_t syncid;
  int inotifyfd;
  localnotify_watch *watches[WATCH_HASH];
  char path[];
} localnotify_dir;

static void add_dir_scan(localnotify_dir *dir, const char *path) {
  DIR *dh;
  char *cpath;
  size_t pl, entrylen;
  long namelen;
  struct dirent *entry, *de;
  localnotify_watch *wch;
  struct stat st;
  int wid;
  pl = strlen(path);
  if (unlikely((wid = inotify_add_watch(dir->inotifyfd, path,
                                        IN_CLOSE_WRITE | IN_CREATE | IN_DELETE |
                                            IN_MOVED_FROM | IN_MOVED_TO |
                                            IN_DELETE_SELF)) == -1)) {
    debug(D_ERROR, "inotify_add_watch failed");
    return;
  }
  namelen = pathconf(path, _PC_NAME_MAX);
  if (namelen == -1)
    namelen = 255;
  if (namelen < sizeof(de->d_name) - 1)
    namelen = sizeof(de->d_name) - 1;
  wch = (localnotify_watch *)psync_malloc(offsetof(localnotify_watch, path) +
                                          pl + 1 + namelen + 1);
  wch->next = dir->watches[wid % WATCH_HASH];
  dir->watches[wid % WATCH_HASH] = wch;
  wch->watchid = wid;
  wch->pathlen = pl;
  wch->namelen = namelen;
  memcpy(wch->path, path, pl + 1);
  if (likely_log(dh = opendir(path))) {
    entrylen = offsetof(struct dirent, d_name) + namelen + 1;
    cpath = (char *)psync_malloc(pl + namelen + 2);
    entry = (struct dirent *)psync_malloc(entrylen);
    memcpy(cpath, path, pl);
    if (!pl || cpath[pl - 1] != PSYNC_DIRECTORY_SEPARATORC)
      cpath[pl++] = PSYNC_DIRECTORY_SEPARATORC;
    // while (!readdir_r(dh, entry, &de) && de) { // DELETEME: deprecated
    while ((de = readdir(dh))) {
      if (de->d_name[0] != '.' ||
          (de->d_name[1] != 0 &&
           (de->d_name[1] != '.' || de->d_name[2] != 0))) {
        psync_strlcpy(cpath + pl, de->d_name, namelen + 1);
        if (!lstat(cpath, &st) && S_ISDIR(st.st_mode))
          add_dir_scan(dir, cpath);
      }
    }
    psync_free(entry);
    psync_free(cpath);
    closedir(dh);
  }
}

static void add_syncid(psync_syncid_t syncid) {
  psync_sql_res *res;
  psync_variant_row row;
  localnotify_dir *dir;
  const char *str;
  size_t len;
  struct epoll_event e;
  res = psync_sql_query("SELECT localpath FROM syncfolder WHERE id=?");
  psync_sql_bind_uint(res, 1, syncid);
  if (likely(row = psync_sql_fetch_row(res))) {
    str = psync_get_lstring(row[0], &len);
    len++;
    dir =
        (localnotify_dir *)psync_malloc(offsetof(localnotify_dir, path) + len);
    memcpy(dir->path, str, len);
    psync_sql_free_result(res);
  } else {
    psync_sql_free_result(res);
    debug(D_ERROR, "could not find syncfolder with id %u",
          (unsigned int)syncid);
    return;
  }
  dir->syncid = syncid;
  dir->inotifyfd = inotify_init();
  if (unlikely_log(dir->inotifyfd == -1))
    goto err;
  memset(dir->watches, 0, sizeof(dir->watches));
  add_dir_scan(dir, dir->path);
  e.events = EPOLLIN;
  e.data.ptr = dir;
  if (unlikely_log(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, dir->inotifyfd, &e)))
    goto err2;
  psync_list_add_tail(&dirs, &dir->list);
  return;
err2:
  close(dir->inotifyfd);
err:
  psync_free(dir);
}

static void del_syncid(psync_syncid_t syncid) {
  localnotify_dir *dir;
  localnotify_watch *wch, *next;
  psync_uint_t i;
  psync_list_for_each_element(dir, &dirs, localnotify_dir,
                              list) if (dir->syncid == syncid) {
    psync_list_del(&dir->list);
    for (i = 0; i < WATCH_HASH; i++) {
      wch = dir->watches[i];
      while (wch) {
        next = wch->next;
        inotify_rm_watch(dir->inotifyfd, wch->watchid);
        psync_free(wch);
        wch = next;
      }
    }
    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, dir->inotifyfd, NULL);
    close(dir->inotifyfd);
    psync_free(dir);
    return;
  }
}

static void process_pipe() {
  localnotify_msg msg;
  if (read(pipe_read, &msg, sizeof(msg)) != sizeof(msg)) {
    debug(D_ERROR, "read from pipe failed");
    return;
  }
  if (msg.type == NOTIFY_MSG_ADD)
    add_syncid(msg.syncid);
  else if (msg.type == NOTIFY_MSG_DEL)
    del_syncid(msg.syncid);
  else
    debug(D_ERROR, "invalid message type %u", (unsigned int)msg.type);
}

static uint32_t process_notification(localnotify_dir *dir) {
  ssize_t rd, off;
  struct inotify_event ev;
  localnotify_watch *wch, **pwch;
  struct stat st;
  char buff[8 * 1024];
  rd = read(dir->inotifyfd, buff, sizeof(buff));
  off = 0;
  while (off < rd) {
    memcpy(&ev, buff + off, offsetof(struct inotify_event, name));
    if (ev.mask & (IN_CREATE | IN_MOVED_TO)) {
      wch = dir->watches[ev.wd % WATCH_HASH];
      while (wch) {
        if (wch->watchid == ev.wd) {
          wch->path[wch->pathlen] = '/';
          psync_strlcpy(wch->path + wch->pathlen + 1,
                        buff + off + offsetof(struct inotify_event, name),
                        wch->namelen + 1);
          if (!lstat(wch->path, &st) && S_ISDIR(st.st_mode))
            add_dir_scan(dir, wch->path);
          wch->path[wch->pathlen] = 0;
          break;
        } else
          wch = wch->next;
      }
    } else if (ev.mask & IN_DELETE_SELF) {
      wch = dir->watches[ev.wd % WATCH_HASH];
      pwch = &dir->watches[ev.wd % WATCH_HASH];
      while (wch) {
        if (wch->watchid == ev.wd) {
          *pwch = wch->next;
          inotify_rm_watch(dir->inotifyfd, wch->watchid);
          psync_free(wch);
          break;
        } else {
          pwch = &wch->next;
          wch = wch->next;
        }
      }
    }
    off += offsetof(struct inotify_event, name) + ev.len;
  }
  if (rd > 0)
    return 1;
  else
    return 0;
}

static void psync_localnotify_thread() {
  struct epoll_event ev;
  uint32_t ncnt;
  int cnt;
  ncnt = 0;
  while (psync_do_run) {
    if ((cnt = epoll_wait(epoll_fd, &ev, 1, 1000)) != 1) {
      if (cnt == -1) {
        if (errno != EINTR)
          debug(D_WARNING, "epoll_wait failed errno %d", errno);
      } else if (cnt == 0 && ncnt) {
        ncnt = 0;
        psync_wake_localscan();
      }
    } else {
      if (ev.data.ptr)
        ncnt += process_notification((localnotify_dir *)ev.data.ptr);
      else
        process_pipe();
    }
  }
}

int psync_localnotify_init() {
  struct epoll_event e;
  int pfd[2];
  if (unlikely_log(pipe(pfd)))
    goto err0;
  pipe_read = pfd[0];
  pipe_write = pfd[1];
  epoll_fd = epoll_create(1);
  if (unlikely_log(epoll_fd == -1))
    goto err1;
  e.events = EPOLLIN;
  e.data.ptr = NULL;
  if (unlikely_log(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, pipe_read, &e)))
    goto err2;
  psync_run_thread("localnotify", psync_localnotify_thread);
  return 0;
err2:
  close(epoll_fd);
err1:
  close(pfd[0]);
  close(pfd[1]);
err0:
  pipe_read = pipe_write = -1;
  return -1;
}

void psync_localnotify_add_sync(psync_syncid_t syncid) {
  localnotify_msg msg;
  msg.type = NOTIFY_MSG_ADD;
  msg.syncid = syncid;
  if (write(pipe_write, &msg, sizeof(msg)) != sizeof(msg))
    debug(D_ERROR, "write to pipe failed");
}

void psync_localnotify_del_sync(psync_syncid_t syncid) {
  localnotify_msg msg;
  msg.type = NOTIFY_MSG_DEL;
  msg.syncid = syncid;
  if (write(pipe_write, &msg, sizeof(msg)) != sizeof(msg))
    debug(D_ERROR, "write to pipe failed");
}
