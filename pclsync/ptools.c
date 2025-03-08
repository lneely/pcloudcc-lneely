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

#include <stdio.h>

#include "papi.h"

#include "plibs.h"
#include "pnetlibs.h"
#include "psettings.h"
#include "ptools.h"
#include "stdlib.h"
#include "string.h"

#if defined(P_OS_LINUX)
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#endif

char *getMACaddr() {
  char buffer[128];

  memset(buffer, 0, sizeof(buffer));

#if defined(P_OS_LINUX)
  int fd;
  struct ifreq ifr;
  char *iface = "eth0";
  unsigned char *mac;

  fd = socket(AF_INET, SOCK_DGRAM, 0);

  ifr.ifr_addr.sa_family = AF_INET;
  strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);

  ioctl(fd, SIOCGIFHWADDR, &ifr);

  close(fd);

  mac = (unsigned char *)ifr.ifr_hwaddr.sa_data;

  sprintf(buffer, "%.2x%.2x%.2x%.2x%.2x%.2x", mac[0], mac[1], mac[2], mac[3],
          mac[4], mac[5]);
  buffer[12] = 0;
#endif

  if (buffer[0] == 0) {
    return psync_strdup("GENERIC_MAC");

  } else {
    return psync_strdup(buffer);
  }
}

int create_backend_event(const char *binapi, const char *category,
                         const char *action, const char *label,
                         const char *auth, int os, time_t etime,
                         eventParams *params, char **err) {
  binresult *res;
  psync_socket *sock;
  uint64_t result;
  binparam *paramsLocal;
  int i;
  int pCnt = params->paramCnt; // Number of optional parameters
  int mpCnt = 6;               // Number of mandatory params
  int tpCnt;                   // Total number of parameters
  char *keyParams;
  char charBuff[30][258];

  sock = psync_api_connect(binapi, psync_setting_get_bool(0));

  if (unlikely_log(!sock)) {
    if (err) {
      *err = psync_strdup("Could not connect to the server.");
    }

    return -1;
  }

  if (pCnt > 0) {             // We have optional parameters
    tpCnt = pCnt + mpCnt + 1; //+1 for the "key" parameter.
  } else {
    tpCnt = mpCnt; // Manadatory parameters only.
  }

  paramsLocal = (binparam *)malloc(
      (tpCnt) * sizeof(binparam)); // Allocate size for all parameters.

  // Set the mandatory pramaters.
  paramsLocal[0] = (binparam)P_STR(EPARAM_CATEG, category);
  paramsLocal[1] = (binparam)P_STR(EPARAM_ACTION, action);
  paramsLocal[2] = (binparam)P_STR(EPARAM_LABEL, label);
  paramsLocal[3] = (binparam)P_STR(EPARAM_AUTH, auth);
  paramsLocal[4] = (binparam)P_NUM(EPARAM_OS, os);
  paramsLocal[5] = (binparam)P_NUM(EPARAM_TIME, etime);

  if (pCnt > 0) {
    keyParams = (char *)malloc(258 * pCnt);
    keyParams[0] = 0;

    for (i = 0; i < pCnt; i++) {
      charBuff[i][0] = 0;

      if (i > 0) {
        strcat(keyParams, ",");
        strcat(keyParams, params->Params[i].paramname);
      } else {
        strcat(keyParams, params->Params[i].paramname);
      }

      sprintf(charBuff[i], "key%s", params->Params[i].paramname);

      if (params->Params[i].paramtype == 0) {
        paramsLocal[mpCnt + i] =
            (binparam)P_STR(charBuff[i], params->Params[i].str);

        continue;
      }

      if (params->Params[i].paramtype == 1) {
        paramsLocal[mpCnt + i] =
            (binparam)P_NUM(charBuff[i], params->Params[i].num);

        continue;
      }

      if (params->Params[i].paramtype == 2) {
        paramsLocal[mpCnt + i] =
            (binparam)P_BOOL(*charBuff, params->Params[i].num);
        continue;
      }
    }

    paramsLocal[mpCnt + pCnt] = (binparam)P_STR(EPARAM_KEY, keyParams);
  }

  for (i = 0; i < tpCnt; i++) {
    if (paramsLocal[i].paramtype == 0) {
      debug(D_NOTICE, "%d: String Param: [%s] - [%s]", i,
            paramsLocal[i].paramname, paramsLocal[i].str);
      continue;
    }

    if (paramsLocal[i].paramtype == 1) {
      debug(D_NOTICE, "%d: Number Param: [%s] - [%lu]", i,
            paramsLocal[i].paramname, paramsLocal[i].num);
      continue;
    }
  }

  res = do_send_command(sock, EVENT_WS, strlen(EVENT_WS), paramsLocal, tpCnt,
                        -1, 1);

  free(keyParams);
  free(paramsLocal);

  if (unlikely_log(!res)) {
    psync_socket_close(sock);

    if (err) {
      *err = psync_strdup("Could not connect to the server.");
    }

    return -1;
  }

  result = psync_find_result(res, "result", PARAM_NUM)->num;

  psync_socket_close(sock);

  if (result) {
    if (err) {
      *err = psync_strdup(psync_find_result(res, "error", PARAM_STR)->str);
    }

    debug(D_CRITICAL, "Event command failed. Error:[%s]", *err);
  }

  return result;
}

int backend_call(const char *binapi, const char *wsPath,
                 const char *payloadName, eventParams *requiredParams,
                 eventParams *optionalParams, binresult **resData, char **err) {
  int reqParCnt = requiredParams->paramCnt;
  int optParCnt = optionalParams->paramCnt;
  int totalParCnt = reqParCnt + optParCnt;
  int i;

  binparam *localParams;
  binresult *res;
  binresult *payload;
  psync_socket *sock;
  uint64_t result;

  if (totalParCnt > 0) {
    localParams = (binparam *)malloc(
        (totalParCnt) *
        sizeof(binparam)); // Allocate size for all required parameters.
  } else {
    localParams = (binparam *)malloc(sizeof(binparam));
  }

  // Add required parameters to the structure
  for (i = 0; i < reqParCnt; i++) {
    if (requiredParams->Params[i].paramtype == 0) {
      localParams[i] = (binparam)P_STR(requiredParams->Params[i].paramname,
                                       requiredParams->Params[i].str);

      continue;
    }

    if (requiredParams->Params[i].paramtype == 1) {
      localParams[i] = (binparam)P_NUM(requiredParams->Params[i].paramname,
                                       requiredParams->Params[i].num);

      continue;
    }

    if (requiredParams->Params[i].paramtype == 2) {
      localParams[i] = (binparam)P_BOOL(requiredParams->Params[i].paramname,
                                        requiredParams->Params[i].num);

      continue;
    }
  }

  // Add optional parameters to the structure
  for (i = reqParCnt; i < totalParCnt; i++) {
    int j = 0;

    if (optionalParams->Params[i].paramtype == 0) {
      localParams[i] = (binparam)P_STR(optionalParams->Params[j].paramname,
                                       optionalParams->Params[j].str);

      continue;
    }

    if (optionalParams->Params[i].paramtype == 1) {
      localParams[i] = (binparam)P_NUM(optionalParams->Params[j].paramname,
                                       optionalParams->Params[j].num);

      continue;
    }

    if (optionalParams->Params[i].paramtype == 2) {
      localParams[i] = (binparam)P_BOOL(optionalParams->Params[j].paramname,
                                        optionalParams->Params[j].num);

      continue;
    }

    j++;
  }

  for (i = 0; i < totalParCnt; i++) {
    if (localParams[i].paramtype == 0) {
      continue;
    }

    if (localParams[i].paramtype == 1) {
      continue;
    }
  }

  sock = psync_api_connect(binapi, psync_setting_get_bool(0));

  if (unlikely_log(!sock)) {
    if (err) {
      *err = psync_strdup("Could not connect to the server.");
    }

    return -1;
  }

  res = do_send_command(sock, wsPath, strlen(wsPath), localParams, totalParCnt,
                        -1, 1);

  free(localParams);

  if (unlikely_log(!res)) {
    psync_socket_close(sock);

    if (err) {
      *err = psync_strdup("Could not connect to the server.");
    }

    return -1;
  }

  result = psync_find_result(res, "result", PARAM_NUM)->num;

  psync_socket_close(sock);

  if (result) {
    if (err) {
      *err = psync_strdup(psync_find_result(res, "error", PARAM_STR)->str);
    }

    debug(D_CRITICAL, "Backend command failed. Error:[%s]", *err);
  } else {
    if (strlen(payloadName) > 0) {
      payload = (binresult *)psync_find_result(res, payloadName, PARAM_HASH);

      *resData = (binresult *)malloc(payload->length * sizeof(binresult));
      memcpy(*resData, payload, (payload->length * sizeof(binresult)));
    }
  }

  return result;
}

char *get_machine_name() {
  int nameSize = 1024;
  char pcName[1024];

  pcName[0] = 0;

#if defined(P_OS_LINUX)
  gethostname(pcName, nameSize);
#endif

  if (pcName[0] == 0) {

#if defined(P_OS_LINUX)
    strcpy(pcName, "LinuxMachine");
#endif
  }

  return psync_strdup(pcName);
}

void parse_os_path(char *path, folderPath *folders, char *delim, int mode) {
  char fName[255];
  char *buff;
  int i = 0, j = 0, k = 0;

  if (strlen(path) < 1) {
    return;
  }

  while (1) {
    if (path[i] != *delim) {
      if ((path[i] == ':') && (mode == 1)) {
        // In case we meet a ":" as in C:\ we set the name to Drive + the string
        // before the ":"
        fName[k] = '\0';
        buff = psync_strcat("Drive ", &fName, NULL);
        psync_strlcpy(fName, buff, strlen(buff) + 1);

        k = k + strlen("Drive ");
      } else {
        fName[k] = path[i];
        k++;
      }
    } else {
      fName[k] = 0;
      folders->folders[j] = psync_strdup(fName);

      k = 0;
      j++;
    }

    i++;

    if (path[i] == 0) {
      fName[k] = 0;

      if (strlen(fName) > 0) {
        folders->folders[j] = psync_strdup(fName);
        j++;
      }

      break;
    }
  }
  folders->cnt = j;
}

void send_psyncs_event(const char *binapi, const char *auth) {
  psync_folderid_t syncEventFlag = 0;
  time_t rawtime;
  char *errMsg;
  psync_sql_res *sql;

  int intRes;
  int syncCnt = 0;

  errMsg = (char *)psync_malloc(1024 * sizeof(char));
  errMsg[0] = 0;

  time(&rawtime);

  syncEventFlag = psync_sql_cellint(
      "SELECT value FROM setting WHERE id='syncEventSentFlag'", 0);

  if (syncEventFlag != 1) {
    syncCnt = psync_sql_cellint(
        "SELECT COUNT(*) FROM syncfolder WHERE synctype != 7", 0);

    if (syncCnt < 1) {
      debug(D_NOTICE, "No syncs, skip the event.");
      psync_free(errMsg);
      return;
    }

    eventParams params = {1, // Number of parameters passed below
                          {P_NUM(PSYNC_SYNCS_COUNT, syncCnt)}};

    intRes = create_backend_event(binapi,
                                  PSYNC_EVENT_CATEG,  // "SYNCS_EVENTS"
                                  PSYNC_EVENT_ACTION, // "SYNCS_LOG_COUNT"
                                  PSYNC_EVENT_LABEL,  // "SYNCS_COUNT"
                                  auth, P_OS_ID, rawtime, &params, &errMsg);

    debug(D_NOTICE, "Syncs Count Event Result:[%d], Message: [%s] .", intRes,
          errMsg);

    sql = psync_sql_prep_statement(
        "REPLACE INTO setting (id, value) VALUES ('syncEventSentFlag', ?)");
    psync_sql_bind_uint(sql, 1, 1);
    psync_sql_run_free(sql);
  }

  psync_free(errMsg);
}

int set_be_file_dates(uint64_t fileid, time_t ctime, time_t mtime) {
  int callRes;
  char msgErr[1024];
  binresult *retData;

  debug(D_NOTICE,
        "Update file date in the backend. FileId: [%lu], ctime: [%lu], mtime: "
        "[%lu]",
        fileid, ctime, mtime);

  eventParams optionalParams = {0};

  eventParams requiredParams1 = {5,
                                 {P_STR("auth", psync_my_auth),
                                  P_NUM("fileid", fileid),
                                  P_STR("timeformat", "timestamp"),
                                  P_NUM("newtm", ctime), P_BOOL("isctime", 1)}};

  callRes =
      backend_call(apiserver, "setfilemtime", FOLDER_META, &requiredParams1,
                   &optionalParams, &retData, (char **)msgErr);

  debug(D_NOTICE, "cTime res: [%d]", callRes);

  eventParams requiredParams = {5,
                                {P_STR("auth", psync_my_auth),
                                 P_NUM("fileid", fileid),
                                 P_STR("timeformat", "timestamp"),
                                 P_NUM("newtm", mtime), P_BOOL("isctime", 0)}};

  callRes =
      backend_call(apiserver, "setfilemtime", FOLDER_META, &requiredParams,
                   &optionalParams, &retData, (char **)msgErr);

  debug(D_NOTICE, "mTime res: [%d]", callRes);

  return callRes;
}

psync_syncid_t get_sync_id_from_fid(psync_folderid_t fid) {
  psync_sql_res *res;
  psync_variant_row row;
  psync_syncid_t syncId = -1;

  res = psync_sql_query("SELECT syncid FROM syncedfolder WHERE folderid = ?");

  psync_sql_bind_uint(res, 1, fid);

  if ((row = psync_sql_fetch_row(res))) {
    syncId = psync_get_number(row[0]);
  }

  psync_sql_free_result(res);

  return syncId;
}

char *get_sync_folder_by_syncid(uint64_t syncId) {
  psync_sql_res *res;
  psync_variant_row row;
  const char *syncName;
  char *retName;

  res = psync_sql_query("SELECT localpath FROM syncfolder sf WHERE sf.id = ?");

  psync_sql_bind_uint(res, 1, syncId);

  if ((row = psync_sql_fetch_row(res))) {
    syncName = psync_get_string(row[0]);
  } else {
    psync_sql_free_result(res);
    return NULL;
  }

  retName = strdup(syncName);

  psync_sql_free_result(res);

  return retName;
}

char *get_folder_name_from_path(char *path) {
  char *folder;

  folder = "";
  while (*path != 0) {
    if ((*path == '\\') || (*path == '/')) {
      folder = ++path;
    }

    path++;
  }

  return strdup(folder);
}
