/*
   Copyright (c) 2013-2014 Anton Titov.

   Copyright (c) 2013-2014 pCloud Ltd.  All rights reserved.

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

#include <stdarg.h>
#include <string.h>

#include "pfile.h"
#include "pfstasks.h"
#include "plibs.h"
#include "prunthrottled.h"
#include "psettings.h"
#include "psql.h"
#include "pstatus.h"
#include "ptask.h"
#include "putil.h"

static uint32_t statuses[PSTATUS_NUM_STATUSES] = {
    PSTATUS_INVALID,     PSTATUS_ONLINE_OFFLINE,
    PSTATUS_INVALID,     PSTATUS_ACCFULL_QUOTAOK,
    PSTATUS_DISKFULL_OK, PSTATUS_LOCALSCAN_SCANNING};

static pthread_mutex_t status_internal_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t statuscond = PTHREAD_COND_INITIALIZER;
static unsigned long status_waiters = 0;

static uint32_t calc_status() {
  if (statuses[PSTATUS_TYPE_AUTH] != PSTATUS_AUTH_PROVIDED &&
      statuses[PSTATUS_TYPE_AUTH] != PSTATUS_INVALID) {
    if (statuses[PSTATUS_TYPE_AUTH] == PSTATUS_AUTH_REQUIRED)
      return PSTATUS_LOGIN_REQUIRED;
    else if (statuses[PSTATUS_TYPE_AUTH] == PSTATUS_AUTH_MISMATCH)
      return PSTATUS_USER_MISMATCH;
    else if (statuses[PSTATUS_TYPE_AUTH] == PSTATUS_AUTH_BADLOGIN)
      return PSTATUS_BAD_LOGIN_DATA;
    else if (statuses[PSTATUS_TYPE_AUTH] == PSTATUS_AUTH_BADTOKEN)
      return PSTATUS_BAD_LOGIN_TOKEN;
    else if (statuses[PSTATUS_TYPE_AUTH] == PSTATUS_AUTH_EXPIRED)
      return PSTATUS_ACCOUNT_EXPIRED;
    else if (statuses[PSTATUS_TYPE_AUTH] == PSTATUS_AUTH_TFAREQ)
      return PSTATUS_TFA_REQUIRED;
    else if (statuses[PSTATUS_TYPE_AUTH] == PSTATUS_AUTH_VERIFYREQ)
      return PSTATUS_VERIFY_REQUIRED;
    else if (statuses[PSTATUS_TYPE_AUTH] == PSTATUS_AUTH_BADCODE)
      return PSTATUS_BAD_TFA_CODE;
    else if (statuses[PSTATUS_TYPE_AUTH] == PSTATUS_AUTH_RELOCATING)
      return PSTATUS_RELOCATION;
    else if (statuses[PSTATUS_TYPE_AUTH] == PSTATUS_AUTH_RELOCATED)
      return PSTATUS_RELOCATED;
    else {
      pdbg_logf(D_BUG, "invalid PSTATUS_TYPE_AUTH %d", statuses[PSTATUS_TYPE_AUTH]);
      return -1;
    }
  }
  if (statuses[PSTATUS_TYPE_RUN] != PSTATUS_RUN_RUN) {
    if (statuses[PSTATUS_TYPE_RUN] == PSTATUS_RUN_PAUSE)
      return PSTATUS_PAUSED;
    else if (statuses[PSTATUS_TYPE_RUN] == PSTATUS_RUN_STOP)
      return PSTATUS_STOPPED;
    else {
      pdbg_logf(D_BUG, "invalid PSTATUS_TYPE_RUN %d", statuses[PSTATUS_TYPE_RUN]);
      return -1;
    }
  }
  if (statuses[PSTATUS_TYPE_ONLINE] != PSTATUS_ONLINE_ONLINE) {
    if (statuses[PSTATUS_TYPE_ONLINE] == PSTATUS_ONLINE_CONNECTING)
      return PSTATUS_CONNECTING;
    else if (statuses[PSTATUS_TYPE_ONLINE] == PSTATUS_ONLINE_SCANNING)
      return PSTATUS_SCANNING;
    else if (statuses[PSTATUS_TYPE_ONLINE] == PSTATUS_ONLINE_OFFLINE)
      return PSTATUS_OFFLINE;
    else {
      pdbg_logf(D_BUG, "invalid PSTATUS_TYPE_ONLINE %d",
            statuses[PSTATUS_TYPE_ONLINE]);
      return -1;
    }
  }
  if (statuses[PSTATUS_TYPE_LOCALSCAN] != PSTATUS_LOCALSCAN_READY) {
    if (statuses[PSTATUS_TYPE_LOCALSCAN] == PSTATUS_LOCALSCAN_SCANNING)
      return PSTATUS_SCANNING;
    else {
      pdbg_logf(D_BUG, "invalid PSTATUS_TYPE_LOCALSCAN %d",
            statuses[PSTATUS_TYPE_LOCALSCAN]);
      return -1;
    }
  }
  if (statuses[PSTATUS_TYPE_ACCFULL] != PSTATUS_ACCFULL_QUOTAOK) {
    if (statuses[PSTATUS_TYPE_ACCFULL] == PSTATUS_ACCFULL_OVERQUOTA)
      return PSTATUS_ACCOUNT_FULL;
    else {
      pdbg_logf(D_BUG, "invalid PSTATUS_TYPE_ACCFULL %d",
            statuses[PSTATUS_TYPE_ACCFULL]);
      return -1;
    }
  }
  if (statuses[PSTATUS_TYPE_DISKFULL] != PSTATUS_DISKFULL_OK) {
    if (statuses[PSTATUS_TYPE_DISKFULL] == PSTATUS_DISKFULL_FULL)
      return PSTATUS_DISK_FULL;
    else {
      pdbg_logf(D_BUG, "invalid PSTATUS_TYPE_DISKFULL %d",
            statuses[PSTATUS_TYPE_DISKFULL]);
      return -1;
    }
  }

  if ((psync_status.filesdownloading || psync_status.filestodownload) &&
      (psync_status.filesuploading || psync_status.filestoupload))
    return PSTATUS_DOWNLOADINGANDUPLOADING;
  else if (psync_status.filesdownloading || psync_status.filestodownload)
    return PSTATUS_DOWNLOADING;
  else if (psync_status.filesuploading || psync_status.filestoupload)
    return PSTATUS_UPLOADING;
  else
    return PSTATUS_READY;
}

static void proc_recalc_download() {
  pstatus_download_recalc();
  pstatus_send_status_update();
}

static void proc_recalc_upload() {
  pstatus_upload_recalc();
  pstatus_send_status_update();
}

void pstatus_init() {
  memset(&psync_status, 0, sizeof(psync_status));
  statuses[PSTATUS_TYPE_RUN] =
      psql_cellint("SELECT value FROM setting WHERE id='runstatus'", 0);
  if (statuses[PSTATUS_TYPE_RUN] < PSTATUS_RUN_RUN ||
      statuses[PSTATUS_TYPE_RUN] > PSTATUS_RUN_STOP) {
    statuses[PSTATUS_TYPE_RUN] = PSTATUS_RUN_RUN;
    psql_statement(
        "REPLACE INTO setting (id, value) VALUES ('runstatus', " NTO_STR(
            PSTATUS_RUN_RUN) ")");
  }
  pstatus_download_recalc();
  pstatus_upload_recalc();
  psync_status.status = calc_status();
}

void pstatus_download_recalc() {
  psync_sql_res *res;
  psync_uint_row row;
  res = psql_query_rdlock("SELECT COUNT(*), SUM(f.size) FROM task t, file "
                               "f WHERE t.type=? AND t.itemid=f.id");
  psql_bind_uint(res, 1, PSYNC_DOWNLOAD_FILE);
  if ((row = psql_fetch_int(res))) {
    psync_status.filestodownload = row[0];
    psync_status.bytestodownload = row[1];
  } else {
    psync_status.filestodownload = 0;
    psync_status.bytestodownload = 0;
  }
  psql_free(res);
  if (!psync_status.filestodownload) {
    psync_status.downloadspeed = 0;
  }
  psync_status.status = calc_status();
}

void pstatus_upload_recalc() {
  char fileidhex[sizeof(psync_fsfileid_t) * 2 + 2];
  char *filename;
  const char *fscpath;
  psync_sql_res *res;
  psync_uint_row row;
  struct stat st;
  uint64_t bytestou;
  uint32_t filestou;
  res = psql_query_rdlock(
      "SELECT COUNT(*), SUM(f.size) FROM task t, localfile f WHERE t.type=? "
      "AND t.localitemid=f.id");
  psql_bind_uint(res, 1, PSYNC_UPLOAD_FILE);
  if ((row = psql_fetch_int(res))) {
    filestou = row[0];
    bytestou = row[1];
  } else {
    filestou = 0;
    bytestou = 0;
  }
  psql_free(res);
  fscpath = psync_setting_get_string(_PS(fscachepath));
  res = psql_query_rdlock("SELECT id FROM fstask WHERE type IN (" NTO_STR(
      PSYNC_FS_TASK_CREAT) ", " NTO_STR(PSYNC_FS_TASK_MODIFY) ") AND text1 NOT "
                                                              "LIKE '.%'"
                                                              " AND status!=3");
  while ((row = psql_fetch_int(res))) {
    psync_binhex(fileidhex, &row[0], sizeof(psync_fsfileid_t));
    fileidhex[sizeof(psync_fsfileid_t)] = 'd';
    fileidhex[sizeof(psync_fsfileid_t) + 1] = 0;
    filename =
        psync_strcat(fscpath, "/", fileidhex, NULL);
    if (!stat(filename, &st)) {
      filestou++;
      bytestou += pfile_stat_size(&st);
    }
    free(filename);
  }
  psql_free(res);
  psync_status.filestoupload = filestou;
  psync_status.bytestoupload = bytestou;
  if (!filestou)
    psync_status.uploadspeed = 0;
  psync_status.status = calc_status();
}

void pstatus_download_recalc_async() {
  prun_throttled("recalc download", proc_recalc_download, PSYNC_MIN_INTERVAL_RECALC_DOWNLOAD, 1);
}

void pstatus_upload_recalc_async() {
  prun_throttled("recalc upload", proc_recalc_upload, PSYNC_MIN_INTERVAL_RECALC_UPLOAD, 1);
}

uint32_t pstatus_get(uint32_t statusid) {
  pthread_mutex_lock(&status_internal_mutex);
  statusid = statuses[statusid];
  pthread_mutex_unlock(&status_internal_mutex);
  return statusid;
}

void pstatus_set(uint32_t statusid, uint32_t status) {
  pthread_mutex_lock(&status_internal_mutex);
  statuses[statusid] = status;
  if (status_waiters)
    pthread_cond_broadcast(&statuscond);
  psync_status.remoteisfull =
      (statuses[PSTATUS_TYPE_ACCFULL] == PSTATUS_ACCFULL_OVERQUOTA);
  psync_status.localisfull =
      (statuses[PSTATUS_TYPE_DISKFULL] == PSTATUS_DISKFULL_FULL);
  pthread_mutex_unlock(&status_internal_mutex);
  status = calc_status();
  if (psync_status.status != status) {
    psync_status.status = status;
    pstatus_send_status_update();
  }
}

void pstatus_wait(uint32_t statusid, uint32_t status) {
  pthread_mutex_lock(&status_internal_mutex);
  while ((statuses[statusid] & status) == 0 && psync_do_run) {
    status_waiters++;
    pthread_cond_wait(&statuscond, &status_internal_mutex);
    status_waiters--;
  }
  pthread_mutex_unlock(&status_internal_mutex);
  if (unlikely(!psync_do_run)) {
    pdbg_logf(D_NOTICE, "exiting");
    pthread_exit(NULL);
  }
}

void pstatus_wait_term() {
  pthread_mutex_lock(&status_internal_mutex);
  if (status_waiters)
    pthread_cond_broadcast(&statuscond);
  pthread_mutex_unlock(&status_internal_mutex);
}

void pstatus_wait_statuses_arr(const uint32_t *combinedstatuses, uint32_t cnt) {
  uint32_t waited, i, statusid, status;
  pthread_mutex_lock(&status_internal_mutex);
  do {
    waited = 0;
    for (i = 0; i < cnt; i++) {
      statusid = combinedstatuses[i] >> 24;
      status = combinedstatuses[i] & 0x00ffffff;
      while ((statuses[statusid] & status) == 0) {
        waited = 1;
        status_waiters++;
        pthread_cond_wait(&statuscond, &status_internal_mutex);
        status_waiters--;
      }
    }
  } while (waited);
  pthread_mutex_unlock(&status_internal_mutex);
}

void pstatus_wait_status(uint32_t first, ...) {
  uint32_t arr[PSTATUS_NUM_STATUSES];
  uint32_t cnt;
  va_list ap;
  cnt = 0;
  va_start(ap, first);
  do {
    arr[cnt++] = first;
  } while ((first = va_arg(ap, uint32_t)));
  va_end(ap);
  pstatus_wait_statuses_arr(arr, cnt);
}

int pstatus_ok_status_arr(const uint32_t *combinedstatuses, uint32_t cnt) {
  uint32_t i, statusid, status;
  pthread_mutex_lock(&status_internal_mutex);
  for (i = 0; i < cnt; i++) {
    statusid = combinedstatuses[i] >> 24;
    status = combinedstatuses[i] & 0x00ffffff;
    if ((statuses[statusid] & status) == 0) {
      pthread_mutex_unlock(&status_internal_mutex);
      return 0;
    }
  }
  pthread_mutex_unlock(&status_internal_mutex);
  return 1;
}

void pstatus_download_set_speed(uint32_t speed) {
  if (psync_status.downloadspeed != speed) {
    if (psync_status.filesdownloading)
      psync_status.downloadspeed = speed;
    else
      psync_status.downloadspeed = 0;
    pstatus_send_status_update();
  }
}

void pstatus_upload_set_speed(uint32_t speed) {
  if (psync_status.uploadspeed != speed) {
    if (psync_status.filesuploading)
      psync_status.uploadspeed = speed;
    else
      psync_status.uploadspeed = 0;
    pstatus_send_status_update();
  }
}

void pstatus_send_update() {
  psync_status.status = calc_status();
  pstatus_send_status_update();
}
