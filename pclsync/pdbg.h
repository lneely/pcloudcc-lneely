#ifndef __PDBG_H
#define __PDBG_H

#ifdef __cplusplus
extern "C" {
#endif

#include "pcompiler.h"
#include "pstatus.h"
#include "psynclib.h" // need for macros...


#define D_NONE 0
#define D_BUG 10
#define D_CRITICAL 20
#define D_ERROR 30
#define D_WARNING 40
#define D_NOTICE 50

#define DEBUG_LEVELS {{D_BUG, "BUG"}, {D_CRITICAL, "CRITICAL ERROR"}, {D_ERROR, "ERROR"}, {D_WARNING, "WARNING"}, {D_NOTICE, "NOTICE" } }

#ifndef DEBUG_LEVEL
#define DEBUG_LEVEL D_NOTICE
#endif

#define IS_DEBUG (DEBUG_LEVEL >= D_WARNING)

#if defined(assert)
#undef assert
#endif

#define debug(level, ...)                                                      \
  do {                                                                         \
    if (level <= DEBUG_LEVEL)                                                  \
      psync_debug(__FILE__, __FUNCTION__, __LINE__, level, __VA_ARGS__);       \
  } while (0)
#define assert(cond)                                                           \
  do {                                                                         \
    if (D_WARNING <= DEBUG_LEVEL && unlikely(!(cond))) {                       \
      debug(D_WARNING, "assertion %s failed, aborting", TO_STR(cond));         \
      abort();                                                                 \
    }                                                                          \
  } while (0)
#define assertw(cond)                                                          \
  do {                                                                         \
    if (D_WARNING <= DEBUG_LEVEL && unlikely(!(cond))) {                       \
      debug(D_WARNING, "assertion %s failed", TO_STR(cond));                   \
    }                                                                          \
  } while (0)
#define debug_execute(level, expr)                                             \
  do {                                                                         \
    if (level <= DEBUG_LEVEL)                                                  \
      (expr);                                                                  \
  } while (0)

#if IS_DEBUG
#define likely_log(x)                                                          \
  (likely(x) ? 1                                                               \
             : psync_debug(__FILE__, __FUNCTION__, __LINE__, D_WARNING,        \
                           "assertion likely_log(%s) failed", TO_STR(x)) *     \
                   0)

#define unlikely_log(x)                                                        \
  (unlikely(x) ? psync_debug(__FILE__, __FUNCTION__, __LINE__, D_WARNING,      \
                             "assertion unlikely_log(%s) failed", TO_STR(x))   \
               : 0)
#define PRINT_RETURN(x)                                                        \
  ((x) * psync_debug(__FILE__, __FUNCTION__, __LINE__, D_NOTICE,               \
                     "returning %d", (int)(x)))
#define PRINT_RETURN_CONST(x)                                                  \
  ((x) *                                                                       \
   psync_debug(__FILE__, __FUNCTION__, __LINE__, D_NOTICE, "returning " #x))
#define PRINT_RETURN_FORMAT(x, format, ...)                                    \
  ((x) * psync_debug(__FILE__, __FUNCTION__, __LINE__, D_NOTICE,               \
                     "returning %d" format, (int)(x), __VA_ARGS__))
#define PRINT_NEG_RETURN(x)                                                    \
  ((x < 0) ? (x) * psync_debug(__FILE__, __FUNCTION__, __LINE__, D_WARNING,    \
                               "returning %d", (int)(x))                       \
           : (x))
#define PRINT_NEG_RETURN_FORMAT(x, format, ...)                                \
  ((x < 0) ? (x) * psync_debug(__FILE__, __FUNCTION__, __LINE__, D_WARNING,    \
                               "returning %d " format, (int)(x), __VA_ARGS__)  \
           : (x))
#else
#define likely_log likely
#define unlikely_log unlikely
#define PRINT_RETURN(x) (x)
#define PRINT_RETURN_CONST(x) (x)
#define PRINT_RETURN_FORMAT(x, format, ...) (x)
#define PRINT_NEG_RETURN(x) (x)
#define PRINT_NEG_RETURN_FORMAT(x, format, ...) (x)
#endif

int psync_debug(const char *file, const char *function, int unsigned line, int unsigned level, const char *fmt, ...) PSYNC_COLD PSYNC_FORMAT(printf, 5, 6) PSYNC_NONNULL(5);

#ifdef __cplusplus
}
#endif

#endif