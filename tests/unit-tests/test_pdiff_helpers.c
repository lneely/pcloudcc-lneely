/*
 * Test: pdiff_helpers.c
 *
 * Covers:
 *  1. pdiff_check_active_subscribtion: no sub, inactive, active.
 *  2. pdiff_extract_meta_folder_flags: empty, single flag, multiple flags.
 *  3. pdiff_group_results_by_col: matching pairs reordered, no-match unchanged.
 *  4. pdiff_cmp_folderid: equal, ordered (pointer-address comparison).
 *  5. pdiff_bind_meta: total bind calls and returned offset.
 *
 * Provides real papi_find_result / papi_check_result via --wrap so the
 * test_stubs.c NULL-returning stubs are overridden for this binary only.
 * SQL bind functions are wrapped with counters so no SQLite DB is needed.
 */

#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "pdiff_helpers.h"

/* psync_get_result_cell is a macro in plibs.h; redeclare it here to avoid
 * pulling in the full plibs / psynclib dependency chain in the test. */
#ifndef psync_get_result_cell
#define psync_get_result_cell(res, row, col) \
    ((res)->data[(row) * (res)->cols + (col)])
#endif

/* ------------------------------------------------------------------ */
static int passes = 0, failures = 0;
#define PASS(n)      do { printf("PASS: %s\n", n); passes++; } while (0)
#define FAIL(n, ...) do { printf("FAIL: %s — ", n); \
                          printf(__VA_ARGS__); printf("\n"); failures++; } while (0)

/* ------------------------------------------------------------------ */
/* Minimal papi_find_result / papi_check_result overrides (--wrap)     */
/* ------------------------------------------------------------------ */

static binresult g_empty_num  = {PARAM_NUM,  0, {0}};
static binresult g_empty_bool = {PARAM_BOOL, 0, {0}};
static binresult g_empty_str  = {PARAM_STR,  0, {0}};

static const binresult *empty_for(uint32_t type) {
    if (type == PARAM_NUM)  return &g_empty_num;
    if (type == PARAM_BOOL) return &g_empty_bool;
    return &g_empty_str;
}

/* Override the stub from test_stubs.c */
const binresult *__wrap_papi_find_result(const binresult *res, const char *name,
                                         uint32_t type, const char *file,
                                         const char *function,
                                         unsigned int line) {
    uint32_t i;
    (void)file; (void)function; (void)line;
    if (!res || res->type != PARAM_HASH)
        return empty_for(type);
    for (i = 0; i < res->length; i++)
        if (!strcmp(res->hash[i].key, name) &&
            res->hash[i].value->type == type)
            return res->hash[i].value;
    return empty_for(type);
}

/* papi_check_result is not in test_stubs.c; --wrap provides it */
const binresult *__wrap_papi_check_result(const binresult *res, const char *name,
                                          uint32_t type, const char *file,
                                          const char *function,
                                          unsigned int line) {
    uint32_t i;
    (void)file; (void)function; (void)line;
    if (!res || res->type != PARAM_HASH)
        return NULL;
    for (i = 0; i < res->length; i++)
        if (!strcmp(res->hash[i].key, name) &&
            res->hash[i].value->type == type)
            return res->hash[i].value;
    return NULL;
}

/* ------------------------------------------------------------------ */
/* SQL bind call counters (--wrap)                                      */
/* ------------------------------------------------------------------ */

static int g_bind_uint_n   = 0;
static int g_bind_lstr_n   = 0;
static int g_bind_null_n   = 0;
static int g_bind_double_n = 0;

static void reset_bind_counts(void) {
    g_bind_uint_n = g_bind_lstr_n = g_bind_null_n = g_bind_double_n = 0;
}

void __wrap_psql_bind_uint(psync_sql_res *res, int n, uint64_t val) {
    (void)res; (void)n; (void)val;
    g_bind_uint_n++;
}
void __wrap_psql_bind_lstr(psync_sql_res *res, int n, const char *str,
                           size_t len) {
    (void)res; (void)n; (void)str; (void)len;
    g_bind_lstr_n++;
}
void __wrap_psql_bind_null(psync_sql_res *res, int n) {
    (void)res; (void)n;
    g_bind_null_n++;
}
void __wrap_psql_bind_double(psync_sql_res *res, int n, double val) {
    (void)res; (void)n; (void)val;
    g_bind_double_n++;
}

/* ------------------------------------------------------------------ */
/* binresult construction helpers                                       */
/* ------------------------------------------------------------------ */

/*
 * init_bool — write a PARAM_BOOL binresult into *r.
 * Uses memset+assignment via the num union member to avoid the
 * "assignment of read-only member" error caused by const char str[8].
 */
static void init_bool(binresult *r, uint64_t v) {
    memset(r, 0, sizeof(*r));
    r->type   = PARAM_BOOL;
    r->length = 0;
    r->num    = v;
}

static void init_num(binresult *r, uint64_t v) {
    memset(r, 0, sizeof(*r));
    r->type   = PARAM_NUM;
    r->length = 0;
    r->num    = v;
}

/*
 * init_str — write a PARAM_STR binresult for a short string (≤ 7 chars).
 * The string bytes are stored in the num union field (same memory as str[8]).
 */
static void init_str(binresult *r, const char *s) {
    size_t len = strlen(s);
    memset(r, 0, sizeof(*r));
    r->type   = PARAM_STR;
    r->length = (uint32_t)len;
    /* num shares bytes with str[8]; memcpy here is well-defined via the
     * union's common initial sequence and the char aliasing rule. */
    memcpy(&r->num, s, len < 8 ? len : 7);
}

static void init_hash(binresult *r, hashpair *pairs, uint32_t npairs) {
    memset(r, 0, sizeof(*r));
    r->type   = PARAM_HASH;
    r->length = npairs;
    r->hash   = pairs;
}

/* ------------------------------------------------------------------ */
/* Test 1: pdiff_check_active_subscribtion                              */
/* ------------------------------------------------------------------ */
static void test_check_active_subscribtion(void) {
    binresult outer, sub_hash, status_br;
    hashpair  outer_pairs[1], sub_pairs[1];

    /* Case 1: no "lastsubscription" field → 0 */
    init_hash(&outer, outer_pairs, 0);
    if (pdiff_check_active_subscribtion(&outer) != 0)
        FAIL("subscribtion: no lastsubscription", "expected 0");
    else
        PASS("subscribtion: no lastsubscription → 0");

    /* Case 2: lastsubscription present but status = "pending" → 0 */
    init_str(&status_br, "pending");
    sub_pairs[0].key   = "status";
    sub_pairs[0].value = &status_br;
    init_hash(&sub_hash, sub_pairs, 1);
    outer_pairs[0].key   = "lastsubscription";
    outer_pairs[0].value = &sub_hash;
    init_hash(&outer, outer_pairs, 1);
    if (pdiff_check_active_subscribtion(&outer) != 0)
        FAIL("subscribtion: status=pending", "expected 0");
    else
        PASS("subscribtion: status=\"pending\" → 0");

    /* Case 3: lastsubscription present, status = "active" → 1 */
    init_str(&status_br, "active");
    if (pdiff_check_active_subscribtion(&outer) != 1)
        FAIL("subscribtion: status=active", "expected 1");
    else
        PASS("subscribtion: status=\"active\" → 1");
}

/* ------------------------------------------------------------------ */
/* Test 2: pdiff_extract_meta_folder_flags                              */
/* ------------------------------------------------------------------ */
static void test_extract_meta_folder_flags(void) {
    binresult meta, enc_false, enc_true, pub_true;
    hashpair  pairs[2];
    uint64_t  flags;

    /* Case 1: empty meta → flags = 0 */
    init_hash(&meta, pairs, 0);
    flags = pdiff_extract_meta_folder_flags(&meta);
    if (flags != 0)
        FAIL("flags: empty meta", "expected 0, got %lu", (unsigned long)flags);
    else
        PASS("flags: empty meta → 0");

    /* Case 2: encrypted=false → flags = 0 */
    init_bool(&enc_false, 0);
    pairs[0].key   = "encrypted";
    pairs[0].value = &enc_false;
    init_hash(&meta, pairs, 1);
    flags = pdiff_extract_meta_folder_flags(&meta);
    if (flags != 0)
        FAIL("flags: encrypted=false", "expected 0, got %lu",
             (unsigned long)flags);
    else
        PASS("flags: encrypted=false → 0");

    /* Case 3: encrypted=true → PSYNC_FOLDER_FLAG_ENCRYPTED */
    init_bool(&enc_true, 1);
    pairs[0].value = &enc_true;
    flags = pdiff_extract_meta_folder_flags(&meta);
    if (flags != PSYNC_FOLDER_FLAG_ENCRYPTED)
        FAIL("flags: encrypted=true", "expected %u, got %lu",
             PSYNC_FOLDER_FLAG_ENCRYPTED, (unsigned long)flags);
    else
        PASS("flags: encrypted=true → PSYNC_FOLDER_FLAG_ENCRYPTED");

    /* Case 4: encrypted=true + ispublicroot=true → both flags */
    init_bool(&pub_true, 1);
    pairs[1].key   = "ispublicroot";
    pairs[1].value = &pub_true;
    init_hash(&meta, pairs, 2);
    flags = pdiff_extract_meta_folder_flags(&meta);
    if (flags != (PSYNC_FOLDER_FLAG_ENCRYPTED | PSYNC_FOLDER_FLAG_PUBLIC_ROOT))
        FAIL("flags: encrypted+public_root",
             "expected %u, got %lu",
             PSYNC_FOLDER_FLAG_ENCRYPTED | PSYNC_FOLDER_FLAG_PUBLIC_ROOT,
             (unsigned long)flags);
    else
        PASS("flags: encrypted+ispublicroot → both flags set");
}

/* ------------------------------------------------------------------ */
/* Test 3: pdiff_group_results_by_col                                   */
/* ------------------------------------------------------------------ */

/*
 * Stack-allocated psync_full_result_int with embedded data storage.
 */
typedef struct {
    psync_full_result_int hdr;
    uint64_t              storage[16];
} test_result_int_t;

static void init_result(test_result_int_t *r, uint32_t rows, uint32_t cols,
                        const uint64_t *vals) {
    uint32_t i;
    r->hdr.rows = rows;
    r->hdr.cols = cols;
    for (i = 0; i < rows * cols; i++)
        r->hdr.data[i] = vals[i];
}

static void test_group_results_by_col(void) {
    test_result_int_t r1, r2;
    uint32_t i;
    int all_match;

    /*
     * r1: [[10, 1], [20, 2], [30, 3]]   (col 0 = id)
     * r2: [[30, 9], [10, 8], [20, 7]]   (col 0 = id, different order)
     *
     * After grouping on col 0, each r1[i].col0 must equal r2[i].col0.
     */
    uint64_t v1[] = {10, 1,  20, 2,  30, 3};
    uint64_t v2[] = {30, 9,  10, 8,  20, 7};

    init_result(&r1, 3, 2, v1);
    init_result(&r2, 3, 2, v2);

    pdiff_group_results_by_col(&r1.hdr, &r2.hdr, 0);

    all_match = 1;
    for (i = 0; i < 3; i++) {
        if (psync_get_result_cell(&r1.hdr, i, 0) !=
            psync_get_result_cell(&r2.hdr, i, 0)) {
            all_match = 0;
            break;
        }
    }
    if (!all_match)
        FAIL("group_results: matching pairs aligned",
             "r1[%u].col0=%lu != r2[%u].col0=%lu", i,
             (unsigned long)psync_get_result_cell(&r1.hdr, i, 0), i,
             (unsigned long)psync_get_result_cell(&r2.hdr, i, 0));
    else
        PASS("group_results: 3-row matching pairs aligned after group");

    /* No-match: r1 and r2 share no values in col 0 → rows unchanged */
    {
        uint64_t nv1[] = {1, 0,  2, 0};
        uint64_t nv2[] = {3, 0,  4, 0};
        init_result(&r1, 2, 2, nv1);
        init_result(&r2, 2, 2, nv2);
        pdiff_group_results_by_col(&r1.hdr, &r2.hdr, 0);
        if (psync_get_result_cell(&r1.hdr, 0, 0) != 1 ||
            psync_get_result_cell(&r2.hdr, 0, 0) != 3)
            FAIL("group_results: no-match rows unchanged",
                 "r1[0]=%lu r2[0]=%lu",
                 (unsigned long)psync_get_result_cell(&r1.hdr, 0, 0),
                 (unsigned long)psync_get_result_cell(&r2.hdr, 0, 0));
        else
            PASS("group_results: no-match case leaves rows unchanged");
    }
}

/* ------------------------------------------------------------------ */
/* Test 4: pdiff_cmp_folderid                                           */
/* ------------------------------------------------------------------ */
static void test_cmp_folderid(void) {
    psync_folderid_t arr[2] = {5, 10};
    int r;

    /* Same pointer → 0 */
    r = pdiff_cmp_folderid(&arr[0], &arr[0]);
    if (r != 0)
        FAIL("cmp_folderid: same pointer", "expected 0, got %d", r);
    else
        PASS("cmp_folderid: same pointer → 0");

    /*
     * C guarantees &arr[0] < &arr[1].  The function compares pointer
     * addresses (faithfully extracted from pdiff.c), so arr[0] < arr[1] → -1.
     */
    r = pdiff_cmp_folderid(&arr[0], &arr[1]);
    if (r != -1)
        FAIL("cmp_folderid: &arr[0] < &arr[1]", "expected -1, got %d", r);
    else
        PASS("cmp_folderid: &arr[0] < &arr[1] → -1 (pointer comparison)");

    r = pdiff_cmp_folderid(&arr[1], &arr[0]);
    if (r != 1)
        FAIL("cmp_folderid: &arr[1] > &arr[0]", "expected 1, got %d", r);
    else
        PASS("cmp_folderid: &arr[1] > &arr[0] → 1 (antisymmetric)");
}

/* ------------------------------------------------------------------ */
/* Test 5: pdiff_bind_meta                                              */
/* ------------------------------------------------------------------ */
static void test_bind_meta(void) {
    /*
     * Build a minimal binresult meta with only the five required fields:
     *   created  (PARAM_NUM)
     *   modified (PARAM_NUM)
     *   category (PARAM_NUM)
     *   thumb    (PARAM_BOOL)
     *   icon     (PARAM_STR, required by bind_str)
     *
     * All 15 optional fields absent → psql_bind_null for each.
     *
     * Expected: 20 total bind calls; return value = 7 + 20 = 27.
     */
    binresult created, modified, category, thumb, icon, meta;
    hashpair  pairs[5];
    int       ret, total;

    init_num(&created,  1000);
    init_num(&modified, 2000);
    init_num(&category, 1);
    init_bool(&thumb, 0);
    init_str(&icon, "jpg");

    pairs[0].key = "created";  pairs[0].value = &created;
    pairs[1].key = "modified"; pairs[1].value = &modified;
    pairs[2].key = "category"; pairs[2].value = &category;
    pairs[3].key = "thumb";    pairs[3].value = &thumb;
    pairs[4].key = "icon";     pairs[4].value = &icon;
    init_hash(&meta, pairs, 5);

    reset_bind_counts();
    ret = pdiff_bind_meta((psync_sql_res *)1 /* dummy non-NULL */, &meta, 7);

    total = g_bind_uint_n + g_bind_lstr_n + g_bind_null_n + g_bind_double_n;

    if (total != 20)
        FAIL("bind_meta: total bind calls",
             "expected 20, got %d (uint=%d lstr=%d null=%d dbl=%d)",
             total, g_bind_uint_n, g_bind_lstr_n, g_bind_null_n,
             g_bind_double_n);
    else
        PASS("bind_meta: exactly 20 bind calls for minimal meta");

    if (ret != 27)
        FAIL("bind_meta: return offset", "expected 27, got %d", ret);
    else
        PASS("bind_meta: return offset = off_initial(7) + 20 = 27");

    /* bind_uint: 3 bind_num + 1 bind_bool = 4 */
    if (g_bind_uint_n != 4)
        FAIL("bind_meta: bind_uint count",
             "expected 4 (3*bind_num + 1*bind_bool), got %d", g_bind_uint_n);
    else
        PASS("bind_meta: bind_uint called 4 times (created/modified/category/thumb)");

    /* bind_lstr: 1 bind_str(icon) */
    if (g_bind_lstr_n != 1)
        FAIL("bind_meta: bind_lstr count",
             "expected 1 (icon only), got %d", g_bind_lstr_n);
    else
        PASS("bind_meta: bind_lstr called 1 time (icon)");

    /* bind_null: 15 optional absent fields */
    if (g_bind_null_n != 15)
        FAIL("bind_meta: bind_null count",
             "expected 15 optional-absent NULLs, got %d", g_bind_null_n);
    else
        PASS("bind_meta: bind_null called 15 times (all optional fields absent)");
}

/* ------------------------------------------------------------------ */
int main(void) {
    test_check_active_subscribtion();
    test_extract_meta_folder_flags();
    test_group_results_by_col();
    test_cmp_folderid();
    test_bind_meta();

    printf("\n%d passed, %d failed\n", passes, failures);
    return failures ? 1 : 0;
}
