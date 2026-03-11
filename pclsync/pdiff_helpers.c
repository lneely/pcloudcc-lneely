/*
 * pdiff_helpers.c — pure helpers extracted from pdiff.c.
 *
 * Only deps: papi.h, pfoldersync.h, pmem.h, psql.h, putil.h, pdbg.h.
 * No networking, no threading — safe to link into unit tests.
 */

#include <stdlib.h>  /* atof */
#include <string.h>  /* memcpy, strcmp */

#include "pdiff_helpers.h"
#include "plibs.h"   /* psync_get_result_cell, pdbg_assert */

/* ------------------------------------------------------------------ */
/* Local bind macros (mirror those in pdiff.c)                         */
/* ------------------------------------------------------------------ */

#define bind_num(s) \
  psql_bind_uint(res, off++, papi_find_result2(meta, s, PARAM_NUM)->num)
#define bind_bool(s) \
  psql_bind_uint(res, off++, papi_find_result2(meta, s, PARAM_BOOL)->num)
#define bind_str(s)                                                     \
  do {                                                                  \
    br = papi_find_result2(meta, s, PARAM_STR);                        \
    psql_bind_lstr(res, off++, br->str, br->length);                   \
  } while (0)
#define bind_opt_str(s)                                                 \
  do {                                                                  \
    br = papi_check_result2(meta, s, PARAM_STR);                       \
    if (br)                                                             \
      psql_bind_lstr(res, off++, br->str, br->length);                 \
    else                                                                \
      psql_bind_null(res, off++);                                       \
  } while (0)
#define bind_opt_num(s)                                                 \
  do {                                                                  \
    br = papi_check_result2(meta, s, PARAM_NUM);                       \
    if (br)                                                             \
      psql_bind_uint(res, off++, br->num);                             \
    else                                                                \
      psql_bind_null(res, off++);                                       \
  } while (0)
#define bind_opt_double(s)                                              \
  do {                                                                  \
    br = papi_check_result2(meta, s, PARAM_STR);                       \
    if (br)                                                             \
      psql_bind_double(res, off++, atof(br->str));                     \
    else                                                                \
      psql_bind_null(res, off++);                                       \
  } while (0)

/* ------------------------------------------------------------------ */
/* check_active_subscribtion                                            */
/* ------------------------------------------------------------------ */

int pdiff_check_active_subscribtion(const binresult *res) {
  const binresult *sub;
  char *status;
  sub = papi_check_result2(res, "lastsubscription", PARAM_HASH);
  if (sub) {
    status = putil_strdup(papi_find_result2(sub, "status", PARAM_STR)->str);
    if (!strcmp(status, "active")) {
      pmem_free(PMEM_SUBSYS_SYNC, status);
      return 1;
    }
    pmem_free(PMEM_SUBSYS_SYNC, status);
  }
  return 0;
}

/* ------------------------------------------------------------------ */
/* extract_meta_folder_flags                                            */
/* ------------------------------------------------------------------ */

uint64_t pdiff_extract_meta_folder_flags(const binresult *meta) {
  const binresult *res;
  uint64_t flags = 0;
  if ((res = papi_check_result2(meta, "encrypted", PARAM_BOOL)) && res->num)
    flags |= PSYNC_FOLDER_FLAG_ENCRYPTED;
  if ((res = papi_check_result2(meta, "ispublicroot", PARAM_BOOL)) && res->num)
    flags |= PSYNC_FOLDER_FLAG_PUBLIC_ROOT;
  if ((res = papi_check_result2(meta, "isbackupdevicelist", PARAM_BOOL)) &&
      res->num)
    flags |= PSYNC_FOLDER_FLAG_BACKUP_DEVICE_LIST;
  if ((res = papi_check_result2(meta, "isbackupdevice", PARAM_BOOL)) &&
      res->num)
    flags |= PSYNC_FOLDER_FLAG_BACKUP_DEVICE;
  if ((res = papi_check_result2(meta, "isbackuproot", PARAM_BOOL)) && res->num)
    flags |= PSYNC_FOLDER_FLAG_BACKUP_ROOT;
  if ((res = papi_check_result2(meta, "isbackup", PARAM_BOOL)) && res->num)
    flags |= PSYNC_FOLDER_FLAG_BACKUP;
  return flags;
}

/* ------------------------------------------------------------------ */
/* group_results_by_col                                                 */
/* ------------------------------------------------------------------ */

void pdiff_group_results_by_col(psync_full_result_int *restrict r1,
                                psync_full_result_int *restrict r2,
                                uint32_t col) {
  VAR_ARRAY(buff, uint64_t, r1->cols);
  size_t rowsize;
  uint32_t i, j, l;
  l = 0;
  rowsize = sizeof(r1->data[0]) * r1->cols;
  pdbg_assert(r1->cols == r2->cols);
  for (i = 0; i < r1->rows; i++)
    for (j = 0; j < r2->rows; j++)
      if (psync_get_result_cell(r1, i, col) ==
          psync_get_result_cell(r2, j, col)) {
        if (i != l) {
          memcpy(buff, r1->data + i * r1->cols, rowsize);
          memcpy(r1->data + i * r1->cols, r1->data + l * r1->cols, rowsize);
          memcpy(r1->data + l * r1->cols, buff, rowsize);
        }
        if (j != l) {
          memcpy(buff, r2->data + j * r2->cols, rowsize);
          memcpy(r2->data + j * r2->cols, r2->data + l * r2->cols, rowsize);
          memcpy(r2->data + l * r2->cols, buff, rowsize);
        }
        l++;
      }
}

/* ------------------------------------------------------------------ */
/* cmp_folderid                                                         */
/* ------------------------------------------------------------------ */

int pdiff_cmp_folderid(const void *ptr1, const void *ptr2) {
  psync_folderid_t *folderid1 = (psync_folderid_t *)ptr1;
  psync_folderid_t *folderid2 = (psync_folderid_t *)ptr2;
  if (folderid1 < folderid2)
    return -1;
  else if (folderid1 > folderid2)
    return 1;
  else
    return 0;
}

/* ------------------------------------------------------------------ */
/* bind_meta                                                            */
/* ------------------------------------------------------------------ */

int pdiff_bind_meta(psync_sql_res *res, const binresult *meta, int off) {
  const binresult *br;
  bind_num("created");
  bind_num("modified");
  bind_num("category");
  bind_bool("thumb");
  bind_str("icon");
  bind_opt_str("artist");
  bind_opt_str("album");
  bind_opt_str("title");
  bind_opt_str("genre");
  bind_opt_num("trackno");
  bind_opt_num("width");
  bind_opt_num("height");
  bind_opt_double("duration");
  bind_opt_double("fps");
  bind_opt_str("videocodec");
  bind_opt_str("audiocodec");
  bind_opt_num("videobitrate");
  bind_opt_num("audiobitrate");
  bind_opt_num("audiosamplerate");
  bind_opt_num("rotate");
  return off;
}

#undef bind_num
#undef bind_bool
#undef bind_str
#undef bind_opt_str
#undef bind_opt_num
#undef bind_opt_double
