// debug/psock_debug.c - debug implementations for psock debug helpers

#include <time.h>

#include "pdbg.h"
#include "psock.h"

void psock_debug_log_wait_latency(const struct timespec *start) {
  struct timespec end;
  unsigned long msec;
  clock_gettime(CLOCK_REALTIME, &end);
  msec = (end.tv_sec - start->tv_sec) * 1000 + end.tv_nsec / 1000000 -
         start->tv_nsec / 1000000;
  if (msec >= 30000)
    pdbg_logf(D_WARNING, "got response from socket after %lu milliseconds", msec);
  else if (msec >= 5000)
    pdbg_logf(D_NOTICE, "got response from socket after %lu milliseconds", msec);
}
