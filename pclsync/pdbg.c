#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "pdbg.h"
#include "ppath.h"
#include "putil.h"

extern PSYNC_THREAD const char *psync_thread_name; 

char *psync_debug_path() {
    char *home = ppath_home();
    if (!home) {
        return NULL;
    }

    const char *subdir = "/.pcloud/debug.log";
    size_t len = strlen(home) + strlen(subdir) + 1;
    char *sockpath = (char *)malloc(len);
    if (!sockpath) {
        return NULL;
    }

    snprintf(sockpath, len, "%s%s", home, subdir);
    return sockpath;
}

int psync_debug(const char *file, const char *function, int unsigned line, int unsigned level, const char *fmt, ...) {
  if (!IS_DEBUG)
    return 1;

  static const struct {
    unsigned long level;
    const char *name;
  } debug_levels[] = DEBUG_LEVELS;
  static FILE *log = NULL;
  struct timespec ts;
  char dttime[36], format[512];
  va_list ap;
  const char *errname;
  unsigned long i;
  unsigned int u;
  pthread_t threadid;
  errname = "BAD_ERROR_CODE";
  for (i = 0; i < ARRAY_SIZE(debug_levels); i++)
    if (debug_levels[i].level == level) {
      errname = debug_levels[i].name;
      break;
    }
  if (unlikely(!log)) {
    char *path = psync_debug_path();
    log = fopen(path, "a+");
    free(path);
    if (!log)
      return 1;
  }
  clock_gettime(CLOCK_REALTIME, &ts);
  time_format(ts.tv_sec, ts.tv_nsec, dttime);
  threadid = pthread_self();
  memcpy(&u, &threadid, sizeof(u));
  snprintf(format, sizeof(format), "%s %u %s %s: %s:%u (function %s): %s\n",
           dttime, u, psync_thread_name, errname, file, line, function, fmt);
  format[sizeof(format) - 1] = 0;
  va_start(ap, fmt);
  vfprintf(log, format, ap);
  va_end(ap);
  fflush(log);
  return 1;
}