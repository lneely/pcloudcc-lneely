#ifndef __PUTIL_H
#define __PUTIL_H

#include <stdint.h>
#include <string.h>
#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <time.h>

#include "pcompiler.h"

#define NTO_STR(s) TO_STR(s)
#define TO_STR(s) #s
#define VAR_ARRAY(name, type, size) type name[size]
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#define rot(x, k) (((x) << (k)) | ((x) >> (32 - (k))))

extern const char base64_table[];

void putil_wipe(void *mem, size_t sz);
void time_format(time_t tm, unsigned long ns, char *result);
char *psync_strdup(const char *str) PSYNC_MALLOC PSYNC_NONNULL(1);
char *psync_strnormalize_filename(const char *str) PSYNC_MALLOC PSYNC_NONNULL(1);
char *psync_strndup(const char *str, size_t len) PSYNC_MALLOC PSYNC_NONNULL(1);
char *psync_strcat(const char *str, ...) PSYNC_MALLOC PSYNC_SENTINEL;
int psync_slprintf(char *str, size_t size, const char *format, ...) PSYNC_NONNULL(1, 3);
unsigned char *psync_base32_encode(const unsigned char *str, size_t length, size_t *ret_length);
unsigned char *psync_base32_decode(const unsigned char *str, size_t length, size_t *ret_length);
unsigned char *psync_base64_encode(const unsigned char *str, size_t length, size_t *ret_length);
unsigned char *psync_base64_decode(const unsigned char *str, size_t length, size_t *ret_length);
int psync_is_valid_utf8(const char *str);
uint64_t psync_ato64(const char *str);
uint32_t psync_ato32(const char *str);

static inline size_t psync_strlcpy(char *dst, const char *src, size_t size) {
  size_t len;
  len = strlen(src);
  if (likely(len < size)) {
    memcpy(dst, src, len + 1);
    return len;
  } else if (likely(size)) {
    memcpy(dst, src, size - 1);
    dst[size - 1] = 0;
    return size - 1;
  } else
    return 0;
}


#ifdef __cplusplus
}
#endif

#endif
