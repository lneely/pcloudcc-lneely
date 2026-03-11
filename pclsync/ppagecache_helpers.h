/*
 * ppagecache_helpers.h — pure, separately-compilable helpers extracted from
 * ppagecache.c to enable unit testing without the full page-cache stack.
 *
 * Included by ppagecache.c and by tests/unit-tests/test_ppagecache.c.
 */
#ifndef PPAGECACHE_HELPERS_H
#define PPAGECACHE_HELPERS_H

#include <stddef.h>
#include <stdint.h>

#include "pcrc32c.h"    /* PSYNC_CRC_INITIAL, pcrc32c_compute */
#include "pfoldersync.h" /* psync_fileid_t */

/*
 * LRU tier thresholds (must match the pagecache_entry_cmp_usecnt_lastuse*
 * comparators in ppagecache.c).
 */
#define PPAGECACHE_TIER1_THRESHOLD  2u
#define PPAGECACHE_TIER2_THRESHOLD  4u
#define PPAGECACHE_TIER3_THRESHOLD  8u
#define PPAGECACHE_TIER4_THRESHOLD 16u

/*
 * ppagecache_compute_page_priority — assign an eviction-priority tier to a
 * cached page based on its access count.
 *
 *   tier 0  usecnt <  2  — cold, evict first
 *   tier 1  usecnt <  4
 *   tier 2  usecnt <  8
 *   tier 3  usecnt < 16
 *   tier 4  usecnt >= 16 — hot, keep longest
 *
 * Pure function: no side effects, no I/O.
 */
uint8_t ppagecache_compute_page_priority(uint32_t usecnt);

/*
 * ppagecache_verify_crc — verify the CRC32c of `size` bytes at `data`
 * against `stored_crc`.
 *
 * Returns  0 if the CRC matches (page is intact).
 * Returns -1 if the CRC differs (page is corrupt).
 *
 * Pure function: no side effects.
 */
int ppagecache_verify_crc(const void *data, size_t size, uint32_t stored_crc);

/*
 * ppagecache_get_download_urls — weak seam for injecting canned download
 * URLs in tests.  The default implementation returns NULL (caller falls
 * through to the real API).  Tests override this to return a
 * NULL-terminated string array without making network calls.
 *
 * On success sets *nout to the number of URLs and returns a pointer to
 * a NULL-terminated array of C strings.  The array is valid until the next
 * call or until the override frees it.
 */
__attribute__((weak))
char **ppagecache_get_download_urls(psync_fileid_t fileid, uint64_t hash,
                                    size_t *nout);

#endif /* PPAGECACHE_HELPERS_H */
