/*
 * Test: ptools_create_backend_event() parameter validation (pcl-a1j)
 *
 * Exercises the guards added in commits bb7fc67 + cda963c:
 *   1. pCnt > PTOOLS_MAX_PARAMS → clamped to 30
 *   2. paramname > 254 bytes    → skipped (continue)
 *   3. snprintf fits in charBuff[i] (258 bytes) after namelen guard
 *   4. keyParams strcat length check prevents buffer overrun
 *   5. Normal short paramname   → accepted, charBuff populated correctly
 *
 * The function under test requires a live network connection, so we
 * replicate its validation logic inline (identical to ptools.c) and
 * drive it with crafted inputs.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PTOOLS_MAX_PARAMS 30

static int passes = 0;
static int failures = 0;

#define PASS(name) do { printf("PASS: %s\n", name); passes++; } while(0)
#define FAIL(name, ...) do { printf("FAIL: " name " — " __VA_ARGS__); printf("\n"); failures++; } while(0)

/* ------------------------------------------------------------------ */
/* Replica: pCnt clamping                                              */
/* ------------------------------------------------------------------ */
static int clamp_pCnt(int raw) {
    int pCnt = raw;
    if (pCnt > PTOOLS_MAX_PARAMS)
        pCnt = PTOOLS_MAX_PARAMS;
    return pCnt;
}

/* ------------------------------------------------------------------ */
/* Replica: per-param validation loop body                             */
/* Returns 1 if param is accepted, 0 if skipped                       */
/* ------------------------------------------------------------------ */
typedef struct {
    int   skipped_namelen;   /* namelen > 254 */
    int   skipped_keybuf;    /* keyParams full */
    int   skipped_snprintf;  /* snprintf truncation (should never fire
                                after namelen guard, but guarded) */
    char  charBuff[258];
    char  keyParams_contrib[258];
} param_result_t;

static param_result_t validate_param(const char *paramname,
                                     const char *keyParams_so_far,
                                     int i,
                                     int pCnt) {
    param_result_t r;
    memset(&r, 0, sizeof(r));

    size_t namelen = strlen(paramname);
    if (namelen > 254) {
        r.skipped_namelen = 1;
        return r;
    }

    size_t used   = strlen(keyParams_so_far);
    size_t needed = namelen + (i > 0 ? 2 : 1);
    if (used + needed > (size_t)(258 * pCnt)) {
        r.skipped_keybuf = 1;
        return r;
    }

    int n = snprintf(r.charBuff, sizeof(r.charBuff), "key%s", paramname);
    if (n < 0 || n >= (int)sizeof(r.charBuff)) {
        r.skipped_snprintf = 1;
        r.charBuff[0] = 0;
        return r;
    }

    /* Build keyParams contribution */
    if (i > 0) {
        strcat(r.keyParams_contrib, ",");
    }
    strcat(r.keyParams_contrib, paramname);

    return r;
}

/* ------------------------------------------------------------------ */
/* Tests                                                               */
/* ------------------------------------------------------------------ */

static void test_clamp_within_limit(void) {
    if (clamp_pCnt(10) == 10)
        PASS("pCnt=10 stays 10");
    else
        FAIL("pCnt=10 stays 10", "got %d", clamp_pCnt(10));
}

static void test_clamp_at_limit(void) {
    if (clamp_pCnt(30) == 30)
        PASS("pCnt=30 stays 30");
    else
        FAIL("pCnt=30 stays 30", "got %d", clamp_pCnt(30));
}

static void test_clamp_exceeds_limit(void) {
    int clamped = clamp_pCnt(31);
    if (clamped == PTOOLS_MAX_PARAMS)
        PASS("pCnt=31 clamped to PTOOLS_MAX_PARAMS (30)");
    else
        FAIL("pCnt=31 clamped to 30", "got %d", clamped);
}

static void test_clamp_large(void) {
    int clamped = clamp_pCnt(9999);
    if (clamped == PTOOLS_MAX_PARAMS)
        PASS("pCnt=9999 clamped to PTOOLS_MAX_PARAMS (30)");
    else
        FAIL("pCnt=9999 clamped to 30", "got %d", clamped);
}

static void test_short_paramname_accepted(void) {
    param_result_t r = validate_param("mykey", "", 0, 1);
    if (!r.skipped_namelen && !r.skipped_keybuf && !r.skipped_snprintf
        && strcmp(r.charBuff, "keymykey") == 0
        && strcmp(r.keyParams_contrib, "mykey") == 0)
        PASS("short paramname accepted, charBuff = 'keymykey'");
    else
        FAIL("short paramname accepted",
             "skips=(%d,%d,%d) charBuff='%s'",
             r.skipped_namelen, r.skipped_keybuf, r.skipped_snprintf,
             r.charBuff);
}

static void test_paramname_exactly_254_accepted(void) {
    char name[255];
    memset(name, 'a', 254);
    name[254] = '\0';
    param_result_t r = validate_param(name, "", 0, PTOOLS_MAX_PARAMS);
    if (!r.skipped_namelen && !r.skipped_keybuf && !r.skipped_snprintf)
        PASS("paramname len=254 accepted (boundary)");
    else
        FAIL("paramname len=254 accepted",
             "skips=(%d,%d,%d)", r.skipped_namelen, r.skipped_keybuf, r.skipped_snprintf);
}

static void test_paramname_255_rejected(void) {
    char name[256];
    memset(name, 'a', 255);
    name[255] = '\0';
    param_result_t r = validate_param(name, "", 0, PTOOLS_MAX_PARAMS);
    if (r.skipped_namelen)
        PASS("paramname len=255 rejected (> 254)");
    else
        FAIL("paramname len=255 rejected", "was accepted (charBuff='%.20s...')", r.charBuff);
}

static void test_paramname_overflow_rejected(void) {
    /* 1024-byte name — well above 254 */
    char name[1025];
    memset(name, 'B', 1024);
    name[1024] = '\0';
    param_result_t r = validate_param(name, "", 0, PTOOLS_MAX_PARAMS);
    if (r.skipped_namelen)
        PASS("paramname len=1024 rejected (overflow guard)");
    else
        FAIL("paramname len=1024 rejected", "was accepted");
}

static void test_charBuff_snprintf_fits(void) {
    /* "key" (3) + 254-char name = 257 chars + NUL = 258 → exactly fits in charBuff[258] */
    char name[255];
    memset(name, 'c', 254);
    name[254] = '\0';
    param_result_t r = validate_param(name, "", 0, PTOOLS_MAX_PARAMS);
    if (!r.skipped_snprintf && strlen(r.charBuff) == 257)
        PASS("charBuff snprintf fits: 'key' + 254-char name = 257 chars");
    else
        FAIL("charBuff snprintf fits", "skipped=%d len=%zu", r.skipped_snprintf, strlen(r.charBuff));
}

static void test_keyparams_strcat_length_check(void) {
    /*
     * With pCnt=1, keyParams buffer is 258*1=258 bytes.
     * If keyParams is already 257 bytes full and we try to add a 2-byte name,
     * needed = 2+1 = 3, used=257, used+needed=260 > 258 → must be skipped.
     */
    char big_existing[258];
    memset(big_existing, 'x', 257);
    big_existing[257] = '\0';

    param_result_t r = validate_param("ab", big_existing, 1, 1);
    if (r.skipped_keybuf)
        PASS("keyParams full: strcat length check rejects overflow");
    else
        FAIL("keyParams full strcat check", "param was accepted");
}

static void test_second_param_keyparams_comma(void) {
    /* Second param (i=1) should contribute ",name" to keyParams */
    param_result_t r = validate_param("foo", "bar", 1, 2);
    if (!r.skipped_namelen && !r.skipped_keybuf
        && strcmp(r.keyParams_contrib, ",foo") == 0
        && strcmp(r.charBuff, "keyfoo") == 0)
        PASS("second param gets comma prefix in keyParams");
    else
        FAIL("second param comma prefix",
             "contrib='%s' charBuff='%s'", r.keyParams_contrib, r.charBuff);
}

int main(void) {
    test_clamp_within_limit();
    test_clamp_at_limit();
    test_clamp_exceeds_limit();
    test_clamp_large();
    test_short_paramname_accepted();
    test_paramname_exactly_254_accepted();
    test_paramname_255_rejected();
    test_paramname_overflow_rejected();
    test_charBuff_snprintf_fits();
    test_keyparams_strcat_length_check();
    test_second_param_keyparams_comma();

    printf("\n%d passed, %d failed\n", passes, failures);
    return failures ? 1 : 0;
}
