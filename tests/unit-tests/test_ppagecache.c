/*
 * Test: ppagecache_helpers.c — priority tiers, CRC verification, URL seam
 *
 * Covers:
 *  1. ppagecache_compute_page_priority: boundary conditions between all five
 *     tiers (0–4) and representative interior values.
 *  2. ppagecache_verify_crc: known-good buffer, single-bit flip, zero-length.
 *  3. ppagecache_get_download_urls: weak override injects canned URL list.
 */

#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "ppagecache_helpers.h"

/* ------------------------------------------------------------------ */
static int passes = 0, failures = 0;
#define PASS(n)      do { printf("PASS: %s\n", n); passes++; } while (0)
#define FAIL(n, ...) do { printf("FAIL: %s — ", n); printf(__VA_ARGS__); printf("\n"); failures++; } while (0)

/* ------------------------------------------------------------------ */
/* Test 1: priority tier boundary conditions                            */
/* ------------------------------------------------------------------ */
static void test_priority_tiers(void) {
    /* Tier 0: usecnt < 2 */
    if (ppagecache_compute_page_priority(0)  != 0 ||
        ppagecache_compute_page_priority(1)  != 0)
        FAIL("tier 0 (usecnt 0,1)", "got %d/%d",
             ppagecache_compute_page_priority(0),
             ppagecache_compute_page_priority(1));
    else
        PASS("tier 0: usecnt in [0,2)");

    /* Tier 1: usecnt in [2, 4) */
    if (ppagecache_compute_page_priority(2)  != 1 ||
        ppagecache_compute_page_priority(3)  != 1)
        FAIL("tier 1 (usecnt 2,3)", "got %d/%d",
             ppagecache_compute_page_priority(2),
             ppagecache_compute_page_priority(3));
    else
        PASS("tier 1: usecnt in [2,4)");

    /* Tier 2: usecnt in [4, 8) */
    if (ppagecache_compute_page_priority(4)  != 2 ||
        ppagecache_compute_page_priority(7)  != 2)
        FAIL("tier 2 (usecnt 4,7)", "got %d/%d",
             ppagecache_compute_page_priority(4),
             ppagecache_compute_page_priority(7));
    else
        PASS("tier 2: usecnt in [4,8)");

    /* Tier 3: usecnt in [8, 16) */
    if (ppagecache_compute_page_priority(8)  != 3 ||
        ppagecache_compute_page_priority(15) != 3)
        FAIL("tier 3 (usecnt 8,15)", "got %d/%d",
             ppagecache_compute_page_priority(8),
             ppagecache_compute_page_priority(15));
    else
        PASS("tier 3: usecnt in [8,16)");

    /* Tier 4: usecnt >= 16 */
    if (ppagecache_compute_page_priority(16) != 4 ||
        ppagecache_compute_page_priority(255)!= 4 ||
        ppagecache_compute_page_priority(UINT32_MAX) != 4)
        FAIL("tier 4 (usecnt >=16)", "got %d/%d/%d",
             ppagecache_compute_page_priority(16),
             ppagecache_compute_page_priority(255),
             ppagecache_compute_page_priority(UINT32_MAX));
    else
        PASS("tier 4: usecnt >= 16 including UINT32_MAX");
}

/* ------------------------------------------------------------------ */
/* Test 2: CRC verification                                             */
/* ------------------------------------------------------------------ */
static void test_verify_crc(void) {
    /* Build a known buffer */
    const char buf[64] = "Hello pagecache CRC test buffer 0123456789abcdef!";
    uint32_t good_crc = pcrc32c_compute(PSYNC_CRC_INITIAL, buf, sizeof(buf));

    /* Known-good: must pass */
    if (ppagecache_verify_crc(buf, sizeof(buf), good_crc) != 0)
        FAIL("verify_crc: known-good buffer", "returned non-zero");
    else
        PASS("verify_crc: known-good buffer passes");

    /* Single-byte corruption: must fail */
    char corrupt[64];
    memcpy(corrupt, buf, sizeof(corrupt));
    corrupt[7] ^= 0x01;  /* flip one bit */
    if (ppagecache_verify_crc(corrupt, sizeof(corrupt), good_crc) != -1)
        FAIL("verify_crc: corrupted buffer", "returned 0 (expected -1)");
    else
        PASS("verify_crc: single-bit flip detected");

    /* Wrong stored CRC */
    if (ppagecache_verify_crc(buf, sizeof(buf), good_crc + 1) != -1)
        FAIL("verify_crc: wrong stored CRC", "returned 0 (expected -1)");
    else
        PASS("verify_crc: wrong stored_crc detected");

    /* Zero-length buffer: CRC of empty == PSYNC_CRC_INITIAL == 0 */
    uint32_t empty_crc = pcrc32c_compute(PSYNC_CRC_INITIAL, buf, 0);
    if (ppagecache_verify_crc(buf, 0, empty_crc) != 0)
        FAIL("verify_crc: zero-length buffer", "returned non-zero");
    else
        PASS("verify_crc: zero-length buffer passes");
}

/* ------------------------------------------------------------------ */
/* Test 3: ppagecache_get_download_urls weak override                  */
/* ------------------------------------------------------------------ */

/* Override the weak default: inject two canned URLs */
static char *g_canned_urls[] = {
    "https://content1.example.com/file",
    "https://content2.example.com/file",
    NULL
};

char **ppagecache_get_download_urls(psync_fileid_t fileid, uint64_t hash,
                                    size_t *nout) {
    (void)fileid;
    (void)hash;
    if (nout) *nout = 2;
    return g_canned_urls;
}

static void test_download_url_override(void) {
    size_t n = 0;
    char **urls = ppagecache_get_download_urls(9999, 0xdeadbeef, &n);
    if (!urls || n != 2)
        { FAIL("url override: count", "n=%zu urls=%p", n, (void*)urls); return; }
    if (strcmp(urls[0], "https://content1.example.com/file") != 0 ||
        strcmp(urls[1], "https://content2.example.com/file") != 0)
        FAIL("url override: content", "url0=%s url1=%s", urls[0], urls[1]);
    else if (urls[2] != NULL)
        FAIL("url override: NULL terminator", "urls[2]=%p", (void*)urls[2]);
    else
        PASS("ppagecache_get_download_urls: weak override returns canned URLs");
}

/* ------------------------------------------------------------------ */
int main(void) {
    test_priority_tiers();
    test_verify_crc();
    test_download_url_override();

    printf("\n%d passed, %d failed\n", passes, failures);
    return failures ? 1 : 0;
}
