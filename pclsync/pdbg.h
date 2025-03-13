#ifndef __PDBG_H
#define __PDBG_H

#ifdef __cplusplus
extern "C" {
#endif

#include "pcompiler.h"
#include "putil.h" // need for macros...
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

#define pdbg_logf(level, ...)                                                      \
  do {                                                                         \
    if (level <= DEBUG_LEVEL)                                                  \
      pdbg_printf(__FILE__, __FUNCTION__, __LINE__, level, __VA_ARGS__);       \
  } while (0)
#define pdbg_assert(cond)                                                           \
  do {                                                                         \
    if (D_WARNING <= DEBUG_LEVEL && unlikely(!(cond))) {                       \
      pdbg_logf(D_WARNING, "assertion %s failed, aborting", TO_STR(cond));         \
      abort();                                                                 \
    }                                                                          \
  } while (0)
#define pdbg_assertw(cond)                                                          \
  do {                                                                         \
    if (D_WARNING <= DEBUG_LEVEL && unlikely(!(cond))) {                       \
      pdbg_logf(D_WARNING, "assertion %s failed", TO_STR(cond));                   \
    }                                                                          \
  } while (0)
#define pdbg_run(level, expr)                                             \
  do {                                                                         \
    if (level <= DEBUG_LEVEL)                                                  \
      (expr);                                                                  \
  } while (0)

#if IS_DEBUG
#define pdbg_likely(x)                                                          \
  (likely(x) ? 1                                                               \
             : pdbg_printf(__FILE__, __FUNCTION__, __LINE__, D_WARNING,        \
                           "assertion pdbg_likely(%s) failed", TO_STR(x)) *     \
                   0)

#define unpdbg_likely(x)                                                        \
  (unlikely(x) ? pdbg_printf(__FILE__, __FUNCTION__, __LINE__, D_WARNING,      \
                             "assertion unpdbg_likely(%s) failed", TO_STR(x))   \
               : 0)
#define pdbg_return(x)                                                        \
  ((x) * pdbg_printf(__FILE__, __FUNCTION__, __LINE__, D_NOTICE,               \
                     "returning %d", (int)(x)))
#define pdbg_return_const(x)                                                  \
  ((x) *                                                                       \
   pdbg_printf(__FILE__, __FUNCTION__, __LINE__, D_NOTICE, "returning " #x))
#define pdbg_returnf(x, format, ...)                                    \
  ((x) * pdbg_printf(__FILE__, __FUNCTION__, __LINE__, D_NOTICE,               \
                     "returning %d" format, (int)(x), __VA_ARGS__))
#define pdbg_return_neg(x)                                                    \
  ((x < 0) ? (x) * pdbg_printf(__FILE__, __FUNCTION__, __LINE__, D_WARNING,    \
                               "returning %d", (int)(x))                       \
           : (x))
#define pdbg_returnf_neg(x, format, ...)                                \
  ((x < 0) ? (x) * pdbg_printf(__FILE__, __FUNCTION__, __LINE__, D_WARNING,    \
                               "returning %d " format, (int)(x), __VA_ARGS__)  \
           : (x))
#else
#define likely_log likely
#define unlikely_log unlikely
#define pdbg_return(x) (x)
#define pdbg_return_const(x) (x)
#define pdbg_returnf(x, format, ...) (x)
#define pdbg_return_neg(x) (x)
#define pdbg_returnf_neg(x, format, ...) (x)
#endif

int pdbg_printf(const char *file, const char *function, int unsigned line, int unsigned level, const char *fmt, ...) PSYNC_COLD PSYNC_FORMAT(printf, 5, 6) PSYNC_NONNULL(5);

#ifdef __cplusplus
}
#endif

#endif