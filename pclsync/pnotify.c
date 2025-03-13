/*
   Copyright (c) 2015 Anton Titov.

   Copyright (c) 2015 pCloud Ltd.  All rights reserved.

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

#include "pnotify.h"
#include "plibs.h"
#include "pnetlibs.h"
#include "psettings.h"
#include "ptree.h"
#include "ppath.h"
#include "prun.h"
#include "pfile.h"


typedef struct {
  psync_tree tree;
  char name[];
} psync_thumb_list_t;

static char *ntf_thumb_size = NULL;
static pnotification_callback_t ntf_callback = NULL;
static pthread_mutex_t ntf_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t ntf_cond = PTHREAD_COND_INITIALIZER;
static int ntf_thread_running = 0;
static int ntf_processing = 0;
static binresult *ntf_result = NULL;
static binresult *ntf_processed_result = NULL;

int pnotify_running() { return ntf_thread_running; }

const char *pnotify_get_thumb_size() { return ntf_thumb_size; }

void pnotify_notify(binresult *res) {
  pthread_mutex_lock(&ntf_mutex);
  if (ntf_result)
    free(ntf_result);
  ntf_result = res;
  pthread_cond_signal(&ntf_cond);
  pthread_mutex_unlock(&ntf_mutex);
}

static void psync_notifications_download_thumb(const binresult *thumb,
                                               const char *thumbpath) {
  const char *path, *filename, *host;
  char *filepath, *tmpfilepath, *buff;
  char cookie[128];
  psync_http_socket *sock;
  struct stat st;
  int fd;
  int rd;
  rd = -1;
  path = papi_find_result2(thumb, "path", PARAM_STR)->str;
  filename = strrchr(path, '/');
  if (pdbg_unlikely(!filename++))
    return;
  filepath = psync_strcat(thumbpath, "/", filename, NULL);
  if (!stat(filepath, &st)) {
    pdbg_logf(D_NOTICE, "skipping download of %s as it already exists", filename);
    goto err0;
  }
  tmpfilepath = psync_strcat(filepath, ".part", NULL);
  pdbg_logf(D_NOTICE, "downloading thumbnail %s", filename);
  if (pdbg_unlikely((fd = pfile_open(tmpfilepath, O_WRONLY,
                                         O_CREAT | O_TRUNC)) ==
                   INVALID_HANDLE_VALUE))
    goto err1;
  sock = psync_http_connect_multihost(
      papi_find_result2(thumb, "hosts", PARAM_ARRAY), &host);
  if (pdbg_unlikely(!sock))
    goto err2;
  psync_slprintf(cookie, sizeof(cookie), "Cookie: dwltag=%s\015\012",
                 papi_find_result2(thumb, "dwltag", PARAM_STR)->str);
  if (pdbg_unlikely(psync_http_request(sock, host, path, 0, 0, cookie)))
    goto err3;
  if (pdbg_unlikely(psync_http_next_request(sock)))
    goto err3;
  buff = (char *)malloc(PSYNC_COPY_BUFFER_SIZE);
  while (1) {
    rd = psync_http_request_readall(sock, buff, PSYNC_COPY_BUFFER_SIZE);
    if (rd <= 0)
      break;
    if (pfile_write(fd, buff, rd) != rd)
      break;
  }
  free(buff);
err3:
  psync_http_close(sock);
err2:
  pfile_close(fd);
err1:
  if (rd == 0 && !pfile_rename_overwrite(tmpfilepath, filepath))
    pdbg_logf(D_NOTICE, "downloaded thumbnail %s", filename);
  else
    pdbg_logf(D_WARNING, "downloading of thumbnail %s failed", filename);
  free(tmpfilepath);
err0:
  free(filepath);
}

static void psync_notifications_set_current_list(binresult *res,
                                                 const char *thumbpath) {
  binresult *ores;
  const binresult *notifications, *thumb;
  pnotification_callback_t cb;
  uint32_t cntnew, cnttotal, i;
  notifications = papi_find_result2(res, "notifications", PARAM_ARRAY);
  cnttotal = notifications->length;
  pdbg_logf(D_NOTICE, "got list with %u notifications", (unsigned)cnttotal);
  cntnew = 0;
  for (i = 0; i < cnttotal; i++) {
    if (papi_find_result2(notifications->array[i], "isnew", PARAM_BOOL)->num)
      cntnew++;
    thumb = papi_check_result2(notifications->array[i], "thumb", PARAM_HASH);
    if (thumb && thumbpath)
      psync_notifications_download_thumb(thumb, thumbpath);
  }
  pthread_mutex_lock(&ntf_mutex);
  ores = ntf_processed_result;
  if (ntf_processing == 2) {
    ntf_processed_result = NULL;
    free(res);
  } else
    ntf_processed_result = res;
  ntf_processing = 0;
  cb = ntf_callback;
  pthread_mutex_unlock(&ntf_mutex);
  free(ores);
  if (cb) {
    pdbg_logf(D_NOTICE, "calling notification callback, cnt=%u, newcnt=%u",
          (unsigned)cnttotal, (unsigned)cntnew);
    cb(cnttotal, cntnew);
  }
}

static void psync_notifications_thread() {
  char *thumbpath;
  binresult *res;
  thumbpath = ppath_private(PSYNC_DEFAULT_NTF_THUMB_DIR);
  while (psync_do_run) {
    pthread_mutex_lock(&ntf_mutex);
    if (unlikely(!ntf_callback)) {
      ntf_thread_running = 0;
      pthread_mutex_unlock(&ntf_mutex);
      break;
    }
    while (!ntf_result)
      pthread_cond_wait(&ntf_cond, &ntf_mutex);
    res = ntf_result;
    ntf_result = NULL;
    ntf_processing = 1;
    pthread_mutex_unlock(&ntf_mutex);
    psync_notifications_set_current_list(res, thumbpath);
  }
  free(thumbpath);
}

void pnotify_set_callback(
    pnotification_callback_t notification_callback, const char *thumbsize) {
  char *ts;
  pthread_mutex_lock(&ntf_mutex);
  ts = ntf_thumb_size;
  if (thumbsize)
    ntf_thumb_size = psync_strdup(thumbsize);
  else
    ntf_thumb_size = NULL;
  if (ts)
    psync_free_after_sec(ts, 10);
  ntf_callback = notification_callback;
  if (!ntf_thread_running && notification_callback) {
    ntf_thread_running = 1;
    prun_thread("notifications", psync_notifications_thread);
  }
  pthread_mutex_unlock(&ntf_mutex);
}

static void fill_actionid(const binresult *ntf, psync_notification_t *pntf,
                          psync_list_builder_t *builder) {
  const char *action;
  action = papi_find_result2(ntf, "action", PARAM_STR)->str;
  if (!strcmp(action, "gotofolder")) {
    pntf->actionid = PNOTIFICATION_ACTION_GO_TO_FOLDER;
    pntf->actiondata.folderid =
        papi_find_result2(ntf, "folderid", PARAM_NUM)->num;
  } else if (!strcmp(action, "opensharerequest")) {
    pntf->actionid = PNOTIFICATION_ACTION_SHARE_REQUEST;
    pntf->actiondata.sharerequestid =
        papi_find_result2(ntf, "sharerequestid", PARAM_NUM)->num;
  } else if (!strcmp(action, "openurl")) {
    pntf->actionid = PNOTIFICATION_ACTION_GO_TO_URL;
    pntf->actiondata.url = papi_find_result2(ntf, "url", PARAM_STR)->str;
    psync_list_add_string_offset(
        builder, offsetof(psync_notification_t, actiondata.url));
  } else
    pntf->actionid = PNOTIFICATION_ACTION_NONE;
}

static void psync_notifications_thumb_dir_list(void *ptr,
                                               ppath_fast_stat *st) {
  psync_tree **tree, **addto, *tr;
  psync_thumb_list_t *tl;
  size_t len;
  int cmp;
  if (pfile_stat_fast_isfolder(st))
    return;
  tree = (psync_tree **)ptr;
  tr = *tree;
  if (tr) {
    while (1) {
      cmp = strcmp(
          st->name, ptree_element(tr, psync_thumb_list_t, tree)->name);
      if (cmp < 0) {
        if (tr->left)
          tr = tr->left;
        else {
          addto = &tr->left;
          break;
        }
      } else if (cmp > 0) {
        if (tr->right)
          tr = tr->right;
        else {
          addto = &tr->right;
          break;
        }
      } else {
        pdbg_logf(D_WARNING, "duplicate name in file list %s, should not happen",
              st->name);
        return;
      }
    }
  } else
    addto = tree;
  len = strlen(st->name) + 1;
  tl = (psync_thumb_list_t *)malloc(offsetof(psync_thumb_list_t, name) +
                                          len);
  memcpy(tl->name, st->name, len);
  *addto = &tl->tree;
  ptree_added_at(tree, tr, &tl->tree);
}

static void psync_notification_remove_from_list(psync_tree **tree,
                                                const char *name) {
  psync_tree *tr;
  int cmp;
  tr = *tree;
  while (tr) {
    cmp = strcmp(
        name, ptree_element(tr, psync_thumb_list_t, tree)->name);
    if (cmp < 0)
      tr = tr->left;
    else if (cmp > 0)
      tr = tr->right;
    else {
      ptree_del(tree, tr);
      break;
    }
  }
}

psync_notification_list_t *pnotify_get() {
  psync_list_builder_t *builder;
  psync_notification_list_t *res;
  const binresult *ntf_res, *notifications, *ntf, *br;
  const char *filename;
  char *thumbpath, *filepath;
  psync_notification_t *pntf;
  psync_tree *thumbs, *nx;
  struct stat st;
  uint32_t cntnew, cnttotal, i;
  cntnew = 0;
  thumbpath = ppath_private(PSYNC_DEFAULT_NTF_THUMB_DIR);
  thumbs = PSYNC_TREE_EMPTY;
  if (likely(thumbpath))
    ppath_ls_fast(thumbpath, psync_notifications_thumb_dir_list, &thumbs);
  builder = psync_list_builder_create(
      sizeof(psync_notification_t),
      offsetof(psync_notification_list_t, notifications));
  pthread_mutex_lock(&ntf_mutex);
  if (ntf_processed_result)
    ntf_res = ntf_processed_result;
  else if (ntf_result) {
    ntf_res = ntf_result;
    pdbg_logf(D_NOTICE, "using not processed result for now");
  } else
    ntf_res = NULL;
  if (ntf_res) {
    notifications = papi_find_result2(ntf_res, "notifications", PARAM_ARRAY);
    cnttotal = notifications->length;
    for (i = 0; i < cnttotal; i++) {
      ntf = notifications->array[i];
      pntf = (psync_notification_t *)psync_list_bulder_add_element(builder);
      br = papi_find_result2(ntf, "notification", PARAM_STR);
      pntf->text = br->str;
      psync_list_add_lstring_offset(
          builder, offsetof(psync_notification_t, text), br->length);
      pntf->thumb = NULL;
      br = papi_check_result2(ntf, "thumb", PARAM_HASH);
      if (br && thumbpath) {
        filename = strrchr(papi_find_result2(br, "path", PARAM_STR)->str, '/');
        if (filename++) {
          psync_notification_remove_from_list(&thumbs, filename);
          filepath = psync_strcat(thumbpath, "/",
                                  filename, NULL);
          if (!stat(filepath, &st)) {
            pntf->thumb = filepath;
            psync_list_add_string_offset(builder,
                                         offsetof(psync_notification_t, thumb));
          } else
            pdbg_logf(D_WARNING,
                  "could not stat thumb %s which is supposed to be downloaded",
                  filename);
          free(filepath);
        }
      }
      pntf->mtime = papi_find_result2(ntf, "mtime", PARAM_NUM)->num;
      pntf->notificationid =
          papi_find_result2(ntf, "notificationid", PARAM_NUM)->num;
      pntf->isnew = papi_find_result2(ntf, "isnew", PARAM_BOOL)->num;
      if (pntf->isnew)
        cntnew++;
      pntf->iconid = papi_find_result2(ntf, "iconid", PARAM_NUM)->num;
      fill_actionid(ntf, pntf, builder);
    }
  }
  pthread_mutex_unlock(&ntf_mutex);
  thumbs = ptree_get_first_safe(thumbs);
  while (thumbs) {
    nx = ptree_get_next_safe(thumbs);
    pdbg_logf(D_NOTICE, "deleting unused thumb %s",
          ptree_element(thumbs, psync_thumb_list_t, tree)->name);
    filepath = psync_strcat(
        thumbpath, "/",
        ptree_element(thumbs, psync_thumb_list_t, tree)->name, NULL);
    pfile_delete(filepath);
    free(filepath);
    free(ptree_element(thumbs, psync_thumb_list_t, tree));
    thumbs = nx;
  }
  free(thumbpath);
  res = (psync_notification_list_t *)psync_list_builder_finalize(builder);
  res->newnotificationcnt = cntnew;
  return res;
}

static void psync_notifications_del_thumb(void *ptr, ppath_stat *st) {
  if (pfile_stat_isfolder(&st->stat))
    return;
  pdbg_logf(D_NOTICE, "deleting thumb %s", st->path);
  pfile_delete(st->path);
}

void pnotify_clean() {
  char *thumbpath;
  pthread_mutex_lock(&ntf_mutex);
  thumbpath = ppath_private(PSYNC_DEFAULT_NTF_THUMB_DIR);
  if (thumbpath) {
    ppath_ls(thumbpath, psync_notifications_del_thumb, NULL);
    free(thumbpath);
  }
  if (ntf_processed_result) {
    free(ntf_processed_result);
    ntf_processed_result = NULL;
  }
  if (ntf_result) {
    free(ntf_result);
    ntf_result = NULL;
  }
  if (ntf_processing == 1)
    ntf_processing = 2;
  pthread_mutex_unlock(&ntf_mutex);
}
