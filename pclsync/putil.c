#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/random.h>

#include "pdbg.h"
#include "putil.h"

// wipe a segment of memory mem of size sz using a DoD 5220.22-M compliant
// 3-pass wipe. the first pass overwrites the memory with zeroes, the second
// with ones, and the third with random data using the urandom entropy
// source. if the urandom source fails, it falls back to a simple
// (non-cryptographically-secure) RNG.
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

