/* 
   Copyright (c) 2013-2015 pCloud Ltd.  All rights reserved.

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

/*
  Library containing tool functions, not used in the main
  functionality. Keeping statistics, getting data for them etc.
*/
#pragma once

#include "papi.h"

#define EVENT_WS "loganalyticsevent"

#define EPARAM_CATEG  "category"
#define EPARAM_ACTION "action"
#define EPARAM_LABEL  "label"
#define EPARAM_OS     "os"
#define EPARAM_TIME   "etime"
#define EPARAM_AUTH   "auth"
#define EPARAM_MAC    "mac_address"
#define EPARAM_KEY    "keys"

#define INST_EVENT_CATEG  "INSTALLATION_PROCESS"
#define INST_EVENT_FLOGIN "FIRST_LOGIN"

//Syncs count constants
#define PSYNC_SYNCS_COUNT  "syncs_count"

#define PSYNC_EVENT_CATEG  "SYNCS_EVENTS"
#define PSYNC_EVENT_ACTION "SYNCS_LOG_COUNT"
#define PSYNC_EVENT_LABEL  "SYNCS_COUNT"


//Payload name constants
#define FOLDER_META "metadata"
#define NO_PAYLOAD         ""

//Parameter name constants
#define FOLDER_ID          "folderid"
#define PARENT_FOLDER_NAME "parentname"

//Parser delimeter symbols
#define DELIM_SEMICOLON ';'

#define DELIM_DIR  '/'

typedef struct _eventParams {
  int paramCnt;
  binparam Params[100];
} eventParams;

typedef struct _folderPath {
  int cnt;
  char* folders[50];
} folderPath;

int create_backend_event(
  const char* binapi,
  const char* category,
  const char* action,
  const char* label,
  const char* auth,
  int          os,
  time_t          etime,
  eventParams* params,
  char** err);

int backend_call(const char* binapi,
  const char*  wsPath,
  const char* payloadName,
  eventParams* requiredParams,
  eventParams* optionalParams,
  binresult**  resData,
  char** err);

char* getMACaddr();

char* get_machine_name();

void parse_os_path(char* path, folderPath* folders, char* delim, int mode);

void send_psyncs_event(const char* binapi,
                       const char* auth);

int set_be_file_dates(uint64_t fileid, time_t ctime, time_t mtime);

 uint32_t get_sync_id_from_fid(uint64_t fid);

 char* get_sync_folder_by_syncid(uint64_t syncId);
 
 char* get_folder_name_from_path(char* path);
 
