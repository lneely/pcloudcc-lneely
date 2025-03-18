#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <sys/random.h>

#include "pdbg.h"
#include "putil.h"

static char normalize_table[256];

const char base64_table[] = {
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
    'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
    'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '-', '_'};

static const char base64_reverse_table[256] = {
    -2, -2, -2, -2, -2, -2, -2, -2, -2, -1, -1, -2, -2, -1, -2, -2, -2, -2, -2,
    -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -1, -2, -2, -2, -2, -2,
    -2, -2, -2, -2, -2, 62, -2, 62, -2, 63, 52, 53, 54, 55, 56, 57, 58, 59, 60,
    61, -2, -2, -2, -1, -2, -2, -2, 0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10,
    11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -2, -2, -2, -2,
    63, -2, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42,
    43, 44, 45, 46, 47, 48, 49, 50, 51, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
    -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
    -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
    -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
    -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
    -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
    -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
    -2, -2, -2, -2, -2, -2, -2, -2, -2};

__attribute((constructor)) static void init() {
    unsigned long i;  
    for (i = 0; i < 256; i++) {
        normalize_table[i] = i;
    }
    normalize_table[':'] = '_';
    normalize_table['/'] = '_';
    normalize_table['\\'] = '_';
}

// putil_wipe wipes a segment of memory mem of size sz using a DoD 5220.22-M
// compliant 3-pass wipe.
void putil_wipe(void *mem, size_t sz) {
    if (!mem || sz == 0) { return; }

    volatile unsigned char *p = (volatile unsigned char *)mem;

    memset((void*)p, 0x00, sz);
    memset((void*)p, 0xFF, sz);

    ssize_t result = getrandom((void*)p, sz, 0);
    if (result != (ssize_t)sz) {
        if (result == -1) {
            pdbg_logf(D_WARNING, "getrandom() failed: %s.", strerror(errno));
        } else {
            pdbg_logf(D_WARNING, "getrandom() returned partial data.");
        }

        pdbg_logf(D_WARNING, "falling back to less secure third pass. This may occur due to insufficient entropy, early boot state, or kernel incompatibility.");
        srand((unsigned int)(time(NULL) ^ (uintptr_t)&srand));
		for (size_t i = 0; i < sz; i++) {
		    p[i] = (unsigned char)rand();
		}
    }
}

void time_format(time_t tm, unsigned long ns, char *result) {
  static const char month_names[12][4] = {"Jan", "Feb", "Mar", "Apr",
                                          "May", "Jun", "Jul", "Aug",
                                          "Sep", "Oct", "Nov", "Dec"};
  static const char day_names[7][4] = {"Sun", "Mon", "Tue", "Wed",
                                       "Thu", "Fri", "Sat"};
  struct tm dt;
  unsigned long y;
  ns /= 1000000;
  gmtime_r(&tm, &dt);
  memcpy(result, day_names[dt.tm_wday], 3);
  result += 3;
  *result++ = ',';
  *result++ = ' ';
  *result++ = dt.tm_mday / 10 + '0';
  *result++ = dt.tm_mday % 10 + '0';
  *result++ = ' ';
  memcpy(result, month_names[dt.tm_mon], 3);
  result += 3;
  *result++ = ' ';
  y = dt.tm_year + 1900;
  *result++ = '0' + y / 1000;
  y = y % 1000;
  *result++ = '0' + y / 100;
  y = y % 100;
  *result++ = '0' + y / 10;
  y = y % 10;
  *result++ = '0' + y;
  *result++ = ' ';
  *result++ = dt.tm_hour / 10 + '0';
  *result++ = dt.tm_hour % 10 + '0';
  *result++ = ':';
  *result++ = dt.tm_min / 10 + '0';
  *result++ = dt.tm_min % 10 + '0';
  *result++ = ':';
  *result++ = dt.tm_sec / 10 + '0';
  *result++ = dt.tm_sec % 10 + '0';
  *result++ = '.';
  *result++ = ns / 100 + '0';
  *result++ = (ns / 10) % 10 + '0';
  *result++ = ns % 10 + '0';
  memcpy(result, " +0000", 7); // copies the null byte
}

char *psync_strdup(const char *str) {
  size_t len;
  len = strlen(str) + 1;
  return (char *)memcpy(malloc(sizeof(char) * len), str, len);
}

char *psync_strnormalize_filename(const char *str) {
  size_t len, i;
  char *ptr;
  len = strlen(str) + 1;
  ptr = malloc(sizeof(char) * len);
  for (i = 0; i < len; i++)
    ptr[i] = normalize_table[(unsigned char)str[i]];
  return ptr;
}

char *psync_strndup(const char *str, size_t len) {
  char *ptr;
  ptr = (char *)memcpy(malloc(sizeof(char) * len + 1), str, len);
  ptr[len] = 0;
  return ptr;
}

char *psync_strcat(const char *str, ...) {
  size_t i, size, len;
  const char *strs[64];
  size_t lengths[64];
  const char *ptr;
  char *ptr2, *ptr3;
  va_list ap;
  va_start(ap, str);
  strs[0] = str;
  len = strlen(str);
  lengths[0] = len;
  size = len + 1;
  i = 1;
  while ((ptr = va_arg(ap, const char *))) {
    pdbg_assert(i < ARRAY_SIZE(strs));
    len = strlen(ptr);
    lengths[i] = len;
    strs[i++] = ptr;
    size += len;
  }
  va_end(ap);
  ptr2 = ptr3 = (char *)malloc(size);
  for (size = 0; size < i; size++) {
    memcpy(ptr2, strs[size], lengths[size]);
    ptr2 += lengths[size];
  }
  *ptr2 = 0;
  return ptr3;
}

int psync_slprintf(char *str, size_t size, const char *format, ...) {
  va_list ap;
  int ret;
  va_start(ap, format);
  ret = vsnprintf(str, size, format, ap);
  va_end(ap);
  if (pdbg_unlikely(ret >= size))
    str[size - 1] = 0;
  return ret;
}

unsigned char *psync_base32_encode(const unsigned char *str, size_t length,
                                   size_t *ret_length) {
  static const unsigned char *table =
      (const unsigned char *)"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  unsigned char *result;
  unsigned char *p;
  uint32_t bits, buff;

  result = (unsigned char *)malloc(((length + 4) / 5) * 8 + 1);
  p = result;

  bits = 0;
  buff = 0; // don't really have to initialize this one, but a compiler that
            // will detect that this is safe is yet to be born

  while (length) {
    if (bits < 5) {
      buff = (buff << 8) | (*str++);
      length--;
      bits += 8;
    }
    bits -= 5;
    *p++ = table[0x1f & (buff >> bits)];
  }

  while (bits) {
    if (bits < 5) {
      buff <<= (5 - bits);
      bits = 5;
    }
    bits -= 5;
    *p++ = table[0x1f & (buff >> bits)];
  }

  *ret_length = p - result;
  *p = 0;
  return result;
}

unsigned char *psync_base32_decode(const unsigned char *str, size_t length,
                                   size_t *ret_length) {
  unsigned char *result, *p;
  uint32_t bits, buff;
  unsigned char ch;
  result = (unsigned char *)malloc((length + 7) / 8 * 5 + 1);
  p = result;
  bits = 0;
  buff = 0;
  while (length) {
    ch = *str++;
    length--;
    if (ch >= 'A' && ch <= 'Z')
      ch = (ch & 0x1f) - 1;
    else if (ch >= '2' && ch <= '7')
      ch -= '2' - 26;
    else {
      free(result);
      return NULL;
    }
    buff = (buff << 5) + ch;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      *p++ = buff >> bits;
    }
  }
  *p = 0;
  *ret_length = p - result;
  return result;
}

unsigned char *psync_base64_encode(const unsigned char *str, size_t length,
                                   size_t *ret_length) {
  const unsigned char *current = str;
  unsigned char *p;
  unsigned char *result;

  result = (unsigned char *)malloc(((length + 2) / 3) * 4 + 1);
  p = result;

  while (length > 2) {
    *p++ = base64_table[current[0] >> 2];
    *p++ = base64_table[((current[0] & 0x03) << 4) + (current[1] >> 4)];
    *p++ = base64_table[((current[1] & 0x0f) << 2) + (current[2] >> 6)];
    *p++ = base64_table[current[2] & 0x3f];
    current += 3;
    length -= 3;
  }

  if (length != 0) {
    *p++ = base64_table[current[0] >> 2];
    if (length > 1) {
      *p++ = base64_table[((current[0] & 0x03) << 4) + (current[1] >> 4)];
      *p++ = base64_table[(current[1] & 0x0f) << 2];
    } else
      *p++ = base64_table[(current[0] & 0x03) << 4];
  }

  *ret_length = p - result;
  *p = 0;
  return result;
}

unsigned char *psync_base64_decode(const unsigned char *str, size_t length,
                                   size_t *ret_length) {
  const unsigned char *current = str;
  unsigned char *result;
  size_t i = 0, j = 0;
  ssize_t ch;

  result = (unsigned char *)malloc((length + 3) / 4 * 3 + 1);

  while (length-- > 0) {
    ch = base64_reverse_table[*current++];
    if (ch == -1)
      continue;
    else if (ch == -2) {
      free(result);
      return NULL;
    }
    switch (i % 4) {
    case 0:
      result[j] = ch << 2;
      break;
    case 1:
      result[j++] |= ch >> 4;
      result[j] = (ch & 0x0f) << 4;
      break;
    case 2:
      result[j++] |= ch >> 2;
      result[j] = (ch & 0x03) << 6;
      break;
    case 3:
      result[j++] |= ch;
      break;
    }
    i++;
  }
  *ret_length = j;
  result[j] = 0;
  return result;
}

int psync_is_valid_utf8(const char *str) {
  static const int8_t trailing[] = {
      0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
      0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
      0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
      0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
      0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
      0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
      0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
      0,  0,  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
      -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
      -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
      -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 1,  1,  1,  1,  1,  1,
      1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,
      1,  1,  1,  1,  1,  1,  1,  1,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,
      2,  2,  2,  2,  2,  2,  3,  3,  3,  3,  3,  3,  3,  3,  -1, -1, -1, -1,
      -1, -1, -1, -1};
  int8_t t;
  while (*str) {
    t = trailing[(unsigned char)*str++];
    if (unlikely(t)) {
      if (t < 0)
        return 0;
      while (t--)
        if ((((unsigned char)*str++) & 0xc0) != 0x80)
          return 0;
    }
  }
  return 1;
}

uint64_t psync_ato64(const char *str) {
  uint64_t n = 0;
  while (*str >= '0' && *str <= '9')
    n = n * 10 + (*str++) - '0';
  return n;
}

uint32_t psync_ato32(const char *str) {
  uint32_t n = 0;
  while (*str >= '0' && *str <= '9')
    n = n * 10 + (*str++) - '0';
  return n;
}
