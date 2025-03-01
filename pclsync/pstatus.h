/*
  Copyright (c) 2013-2014 Anton Titov.

  Copyright (c) 2013-2014 pCloud Ltd.  All rights reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met: Redistributions of source code must retain the above
  copyright notice, this list of conditions and the following
  disclaimer.  Redistributions in binary form must reproduce the above
  copyright notice, this list of conditions and the following
  disclaimer in the documentation and/or other materials provided with
  the distribution.  Neither the name of pCloud Ltd nor the names of
  its contributors may be used to endorse or promote products derived
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

#ifndef _PSYNC_STATUS_H
#define _PSYNC_STATUS_H

#include <stdint.h>

#include "plist.h"

#define PSTATUS_NUM_STATUSES 6

#define PSTATUS_READY 0
#define PSTATUS_DOWNLOADING 1
#define PSTATUS_UPLOADING 2
#define PSTATUS_DOWNLOADINGANDUPLOADING 3
#define PSTATUS_LOGIN_REQUIRED 4
#define PSTATUS_BAD_LOGIN_DATA 5
#define PSTATUS_BAD_LOGIN_TOKEN 6
#define PSTATUS_ACCOUNT_FULL 7
#define PSTATUS_DISK_FULL 8
#define PSTATUS_PAUSED 9
#define PSTATUS_STOPPED 10
#define PSTATUS_OFFLINE 11
#define PSTATUS_CONNECTING 12
#define PSTATUS_SCANNING 13
#define PSTATUS_USER_MISMATCH 14
#define PSTATUS_ACCOUNT_EXPIRED 15
#define PSTATUS_TFA_REQUIRED 16
#define PSTATUS_BAD_TFA_CODE 17
#define PSTATUS_VERIFY_REQUIRED 18
#define PSTATUS_RELOCATION 19
#define PSTATUS_RELOCATED 20
#define PSTATUS_ACCOUT_TFAERR PSTATUS_TFA_REQUIRED
#define PSTATUS_ACCOUT_EXPIRED PSTATUS_ACCOUNT_EXPIRED

#define PSTATUS_TYPE_RUN 0
#define PSTATUS_TYPE_ONLINE 1
#define PSTATUS_TYPE_AUTH 2
#define PSTATUS_TYPE_ACCFULL 3
#define PSTATUS_TYPE_DISKFULL 4
#define PSTATUS_TYPE_LOCALSCAN 5

#define PSTATUS_INVALID 0

#define PSTATUS_RUN_RUN 1
#define PSTATUS_RUN_PAUSE 2
#define PSTATUS_RUN_STOP 4

#define PSTATUS_ONLINE_CONNECTING 1
#define PSTATUS_ONLINE_SCANNING 2
#define PSTATUS_ONLINE_ONLINE 4
#define PSTATUS_ONLINE_OFFLINE 8

#define PSTATUS_AUTH_PROVIDED 1
#define PSTATUS_AUTH_REQUIRED 2
#define PSTATUS_AUTH_MISMATCH 4
#define PSTATUS_AUTH_BADLOGIN 8
#define PSTATUS_AUTH_BADTOKEN 16
#define PSTATUS_AUTH_EXPIRED 32
#define PSTATUS_AUTH_TFAREQ 64
#define PSTATUS_AUTH_BADCODE 128
#define PSTATUS_AUTH_VERIFYREQ 256
#define PSTATUS_AUTH_RELOCATING 512
#define PSTATUS_AUTH_RELOCATED 1024

#define PSTATUS_ACCFULL_QUOTAOK 1
#define PSTATUS_ACCFULL_OVERQUOTA 2

#define PSTATUS_DISKFULL_OK 1
#define PSTATUS_DISKFULL_FULL 2

#define PSTATUS_LOCALSCAN_SCANNING 1
#define PSTATUS_LOCALSCAN_READY 2

typedef struct {
  psync_list list;
  char *str;
} string_list_t;

typedef enum Status { INSYNC, INPROG, NOSYNC, INVSYNC } external_status_t;

#define PSTATUS_COMBINE(type, statuses) (((type) << 24) + (statuses))

typedef struct pstatus_struct_ {
  const char *downloadstr;          // formatted string with the status of uploads
  const char *uploadstr;            // formatted string with the status of downloads 
  uint64_t bytestoupload;           // sum of the sizes of files that need to be uploaded to sync state
  uint64_t bytestouploadcurrent;    // sum of the sizes of files in filesuploading
  uint64_t bytesuploaded;           // bytes uploaded in files accounted in filesuploading
  uint64_t bytestodownload;         // sum of the sizes of files that need to be downloaded to sync state
  uint64_t bytestodownloadcurrent;  // sum of the sizes of files in filesdownloading
  uint64_t bytesdownloaded;         // bytes downloaded in files accounted in filesdownloading
  uint32_t status;                  // current status, one of PSTATUS_ constants
  uint32_t filestoupload;           // number of files to upload in order to sync state, including filesuploading
  uint32_t filesuploading;          // number of files currently uploading
  uint32_t uploadspeed;             // in bytes/sec
  uint32_t filestodownload;         // number of files to download in order to sync state, including filesdownloading
  uint32_t filesdownloading;        // number of files currently downloading
  uint32_t downloadspeed;           // in bytes/sec 
  uint8_t remoteisfull;             // account is full and no files will be synced upwards
  uint8_t localisfull;              // (some) local hard drive is full and no files will be synced from the cloud
} pstatus_t;

/* Status change callback is called every time value is changed. It may be
 * called quite often when there are active uploads/downloads. Callbacks are
 * issued from a special callback thread (e.g. the same thread all the time) and
 * are guaranteed not to overlap.
 */
typedef void (*pstatus_change_callback_t)(pstatus_t *status);

void pstatus_init();
void pstatus_download_recalc();
void pstatus_download_recalc_async();
void pstatus_upload_recalc();
void pstatus_upload_recalc_async();
uint32_t pstatus_get(uint32_t statusid);
void pstatus_set(uint32_t statusid, uint32_t status);
void pstatus_wait(uint32_t statusid, uint32_t status);
void pstatus_wait_term();
void pstatus_wait_statuses_arr(const uint32_t *combinedstatuses, uint32_t cnt);
void pstatus_wait_status(uint32_t first, ...);
int pstatus_ok_status_arr(const uint32_t *combinedstatuses, uint32_t cnt);
void pstatus_download_set_speed(uint32_t speed);
void pstatus_upload_set_speed(uint32_t speed);
void pstatus_send_update();
void pstatus_get_cb(pstatus_t *status);
void pstatus_set_cb(pstatus_change_callback_t callback);
void pstatus_send_status_update();

#endif
