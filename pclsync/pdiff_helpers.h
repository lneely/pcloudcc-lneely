/*
 * pdiff_helpers.h — pure, separately-compilable helpers extracted from
 * pdiff.c to enable unit testing without the full diff/sync stack.
 *
 * Included by pdiff.c and by tests/unit-tests/test_pdiff_helpers.c.
 */
#ifndef PDIFF_HELPERS_H
#define PDIFF_HELPERS_H

#include <stdint.h>
#include <string.h>

#include "papi.h"        /* binresult, papi_find_result2, papi_check_result2, PARAM_* */
#include "pfoldersync.h" /* PSYNC_FOLDER_FLAG_*, psync_folderid_t */
#include "pmem.h"        /* pmem_free, PMEM_SUBSYS_SYNC */
#include "psql.h"        /* psync_full_result_int, psync_sql_res */
#include "putil.h"       /* VAR_ARRAY, putil_strdup */

/*
 * pdiff_check_active_subscribtion — return 1 if 'res' contains a
 * "lastsubscription" hash whose "status" field equals "active"; 0 otherwise.
 *
 * The name preserves the original typo from pdiff.c.
 * Reads the binresult tree only; no network I/O or side effects.
 */
int pdiff_check_active_subscribtion(const binresult *res);

/*
 * pdiff_extract_meta_folder_flags — compute the PSYNC_FOLDER_FLAG_*
 * bitmask from a metadata binresult hash.
 *
 * Pure function: no side effects, no I/O.
 */
uint64_t pdiff_extract_meta_folder_flags(const binresult *meta);

/*
 * pdiff_group_results_by_col — reorder rows of r1 and r2 in-place so that
 * every (r1[i], r2[j]) pair sharing the same value in column `col` appears
 * at position l, starting from l=0.  Both arrays must have identical col
 * counts (asserted).
 */
void pdiff_group_results_by_col(psync_full_result_int *restrict r1,
                                psync_full_result_int *restrict r2,
                                uint32_t col);

/*
 * pdiff_cmp_folderid — qsort-compatible comparator for psync_folderid_t
 * arrays.  Compares pointer addresses (faithfully extracted from pdiff.c).
 * Returns -1, 0, or 1.
 */
int pdiff_cmp_folderid(const void *ptr1, const void *ptr2);

/*
 * pdiff_bind_meta — bind file metadata fields from 'meta' into prepared
 * statement 'res', starting at parameter index 'off'.
 * Returns the updated offset (off + number of fields bound = off + 20).
 */
int pdiff_bind_meta(psync_sql_res *res, const binresult *meta, int off);

#endif /* PDIFF_HELPERS_H */
