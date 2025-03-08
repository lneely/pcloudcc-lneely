/*
  Copyright (c) 2013-2015 pCloud Ltd.  All rights reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met: Redistributions of source code must retain the above
  copyright notice, this list of conditions and the following
  disclaimer.  Redistributions in binary form must reproduce the above
  copyright notice, this list of conditions and the following
  disclaimer in the documentation and/or other materials provided with
  the distribution.  Neither the name of pCloud Ltd nor the names of
  its contributors may be used to endorse or promote products derived
  from this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
  FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL pCloud
  Ltd BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
  EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
  PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
  PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
  OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
  USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
  DAMAGE.
*/

#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "debug.h"

static void time_format(time_t tm, char *result) {
  static const char month_names[12][4] = {"Jan", "Feb", "Mar", "Apr",
                                          "May", "Jun", "Jul", "Aug",
                                          "Sep", "Oct", "Nov", "Dec"};
  static const char day_names[7][4] = {"Sun", "Mon", "Tue", "Wed",
                                       "Thu", "Fri", "Sat"};
  struct tm dt;
  int unsigned y;
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
  memcpy(result, " +0000", 7); // copies the null byte
}

void pc_debug(const char *file, const char *function, int unsigned line,
              int unsigned level, const char *fmt, ...) {
  static const struct {
    int unsigned level;
    const char *name;
  } debug_levels[] = DEBUG_LEVELS;
  static FILE *log = NULL;
  char dttime[32], format[512];
  va_list ap;
  const char *errname;
  int unsigned i;
  unsigned int pid;
  time_t currenttime;
  errname = "BAD_ERROR_CODE";
  for (i = 0; i < sizeof(debug_levels) / sizeof(debug_levels[0]); i++)
    if (debug_levels[i].level == level) {
      errname = debug_levels[i].name;
      break;
    }
  if (!log) {
    log = fopen(DEBUG_FILE, "a+");
    if (!log)
      return;
  }
  time(&currenttime);
  time_format(currenttime, dttime);
#if !defined(MINGW) && !defined(_WIN32)
  pid = (unsigned int)pthread_self();
#else
  pid = (unsigned int)pthread_self().p;
#endif
  snprintf(format, sizeof(format), "%s pid %u %s: %s:%u (function %s): %s\n",
           dttime, pid, errname, file, line, function, fmt);
  format[sizeof(format) - 1] = 0;
  va_start(ap, fmt);
  vfprintf(log, format, ap);
  va_end(ap);
  fflush(log);
}
