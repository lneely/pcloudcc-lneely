/*
 * ppagecache_helpers.c — pure helpers extracted from ppagecache.c.
 *
 * Only deps: pcrc32c.h (CRC computation) and pfoldersync.h (psync_fileid_t).
 * No psql, no networking, no threading — safe to link into unit tests.
 */

#include "ppagecache_helpers.h"

/* ------------------------------------------------------------------ */
/* Priority / LRU tier                                                  */
/* ------------------------------------------------------------------ */

uint8_t ppagecache_compute_page_priority(uint32_t usecnt) {
    if (usecnt >= PPAGECACHE_TIER4_THRESHOLD) return 4;
    if (usecnt >= PPAGECACHE_TIER3_THRESHOLD) return 3;
    if (usecnt >= PPAGECACHE_TIER2_THRESHOLD) return 2;
    if (usecnt >= PPAGECACHE_TIER1_THRESHOLD) return 1;
    return 0;
}

/* ------------------------------------------------------------------ */
/* CRC verification                                                     */
/* ------------------------------------------------------------------ */

int ppagecache_verify_crc(const void *data, size_t size, uint32_t stored_crc) {
    uint32_t computed = pcrc32c_compute(PSYNC_CRC_INITIAL, data, size);
    return (computed == stored_crc) ? 0 : -1;
}

/* ------------------------------------------------------------------ */
/* HTTP status classification                                           */
/* ------------------------------------------------------------------ */

int ppagecache_http_status_should_retry(int status) {
    if (status == 0)
        return 0;
    if (status == 410 || status == 404 || status == -1)
        return 1;
    return -1;
}

/* ------------------------------------------------------------------ */
/* Download-URL seam (weak default: no-op)                             */
/* ------------------------------------------------------------------ */

__attribute__((weak))
char **ppagecache_get_download_urls(psync_fileid_t fileid, uint64_t hash,
                                    size_t *nout) {
    (void)fileid;
    (void)hash;
    if (nout) *nout = 0;
    return NULL;  /* caller falls through to real API */
}
