#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#include "pdbg.h"
#include "ppath.h"
#include "putil.h"

extern PSYNC_THREAD const char *psync_thread_name;

static FILE *log_file = NULL;
static FILE *fs_event_log = NULL;
static int fs_event_log_initialized = 0;
static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;
static volatile sig_atomic_t log_reopen_requested = 0;

/* Runtime debug level - defaults to D_INFO */
unsigned int pdbg_runtime_level = D_INFO;
static int pdbg_level_initialized = 0;

/* Forward declaration */
static void do_reopen_log(void);

/* Initialize debug level from environment variable */
static void pdbg_init_level(void) {
    if (pdbg_level_initialized)
        return;

    pdbg_level_initialized = 1;

    const char *level_str = getenv("PCLOUD_LOG_LEVEL");
    if (!level_str || level_str[0] == '\0') {
        pdbg_runtime_level = D_INFO; /* default to INFO */
        return;
    }

    /* Parse log level string (case-insensitive) */
    if (strcasecmp(level_str, "NONE") == 0) {
        pdbg_runtime_level = D_NONE;
    } else if (strcasecmp(level_str, "BUG") == 0 || strcasecmp(level_str, "DEBUG") == 0) {
        pdbg_runtime_level = D_BUG;
    } else if (strcasecmp(level_str, "CRITICAL") == 0) {
        pdbg_runtime_level = D_CRITICAL;
    } else if (strcasecmp(level_str, "ERROR") == 0) {
        pdbg_runtime_level = D_ERROR;
    } else if (strcasecmp(level_str, "WARNING") == 0 || strcasecmp(level_str, "WARN") == 0) {
        pdbg_runtime_level = D_WARNING;
    } else if (strcasecmp(level_str, "INFO") == 0) {
        pdbg_runtime_level = D_INFO;
    } else if (strcasecmp(level_str, "NOTICE") == 0) {
        pdbg_runtime_level = D_NOTICE;
    } else {
        /* Invalid level, default to INFO */
        pdbg_runtime_level = D_INFO;
    }
}

char *psync_debug_path() {
    const char *custom_path = getenv("PCLOUD_LOG_PATH");
    if (custom_path && custom_path[0] != '\0') {
        size_t len = strlen(custom_path) + 1;
        char *path = (char *)malloc(len);
        if (!path) {
            return NULL;
        }
        snprintf(path, len, "%s", custom_path);
        return path;
    }

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

char *psync_fs_event_log_path() {
    const char *custom_path = getenv("PCLOUD_FS_EVENT_LOG");
    if (custom_path && custom_path[0] != '\0') {
        size_t len = strlen(custom_path) + 1;
        char *path = (char *)malloc(len);
        if (!path) {
            return NULL;
        }
        snprintf(path, len, "%s", custom_path);
        return path;
    }
    return NULL;
}

int pdbg_printf(const char *file, const char *function, int unsigned line, int unsigned level, const char *fmt, ...) {
  /* Initialize debug level from environment on first call */
  pdbg_init_level();

  if (!IS_DEBUG)
    return 1;

  static const struct {
    unsigned long level;
    const char *name;
  } debug_levels[] = DEBUG_LEVELS;
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

  pthread_mutex_lock(&log_mutex);

  /* Check if log rotation was requested via signal */
  if (unlikely(log_reopen_requested)) {
    log_reopen_requested = 0;
    do_reopen_log();
  }

  if (unlikely(!log_file)) {
    char *path = psync_debug_path();
    log_file = fopen(path, "a+");
    free(path);
    if (!log_file) {
      pthread_mutex_unlock(&log_mutex);
      return 1;
    }
  }

  /* Create empty fs event log file on first call if configured */
  if (unlikely(!fs_event_log_initialized)) {
    fs_event_log_initialized = 1;
    char *path = psync_fs_event_log_path();
    if (path) {
      /* Create empty file if it doesn't exist, or open existing */
      FILE *f = fopen(path, "a+");
      if (f) {
        fclose(f);
      }
      free(path);
    }
  }

  clock_gettime(CLOCK_REALTIME, &ts);
  time_format(ts.tv_sec, ts.tv_nsec, dttime);
  threadid = pthread_self();
  memcpy(&u, &threadid, sizeof(u));
  snprintf(format, sizeof(format), "%s %u %s %s: %s:%u (function %s): %s\n",
           dttime, u, psync_thread_name, errname, file, line, function, fmt);
  format[sizeof(format) - 1] = 0;
  va_start(ap, fmt);
  vfprintf(log_file, format, ap);
  va_end(ap);
  fflush(log_file);
  pthread_mutex_unlock(&log_mutex);
  return 1;
}

/* Called from signal handler - must be signal-safe (no malloc/file ops) */
void pdbg_reopen_log() {
  log_reopen_requested = 1;
}

/* Internal function to actually reopen the log - called from safe context */
static void do_reopen_log() {
  char *path;
  FILE *new_log;

  /* Close existing log file if open */
  if (log_file) {
    fclose(log_file);
    log_file = NULL;
  }

  /* Open new log file */
  path = psync_debug_path();
  if (path) {
    new_log = fopen(path, "a+");
    free(path);
    if (new_log) {
      log_file = new_log;
      /* Log a message about the rotation */
      fprintf(log_file, "Log file reopened for rotation\n");
      fflush(log_file);
    }
  }

  /* Also reopen fs event log if it was open */
  if (fs_event_log) {
    fclose(fs_event_log);
    fs_event_log = NULL;

    path = psync_fs_event_log_path();
    if (path) {
      new_log = fopen(path, "a+");
      free(path);
      if (new_log) {
        fs_event_log = new_log;
      }
    }
  }
}

/* Write a filesystem event to the fs-event log with timestamp */
void pdbg_write_fs_event(const char *fmt, ...) {
  struct timespec ts;
  char dttime[36];
  va_list ap;

  pthread_mutex_lock(&log_mutex);

  /* Check if log rotation was requested */
  if (unlikely(log_reopen_requested)) {
    log_reopen_requested = 0;
    do_reopen_log();
  }

  /* Open fs event log if not already open */
  if (unlikely(!fs_event_log)) {
    char *path = psync_fs_event_log_path();
    if (!path) {
      /* FS event log not configured, skip */
      pthread_mutex_unlock(&log_mutex);
      return;
    }
    fs_event_log = fopen(path, "a+");
    free(path);
    if (!fs_event_log) {
      pthread_mutex_unlock(&log_mutex);
      return;
    }
  }

  /* Get timestamp */
  clock_gettime(CLOCK_REALTIME, &ts);
  time_format(ts.tv_sec, ts.tv_nsec, dttime);

  /* Write timestamp followed by event message */
  fprintf(fs_event_log, "%s ", dttime);
  va_start(ap, fmt);
  vfprintf(fs_event_log, fmt, ap);
  va_end(ap);
  fprintf(fs_event_log, "\n");
  fflush(fs_event_log);

  pthread_mutex_unlock(&log_mutex);
}