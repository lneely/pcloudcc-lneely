#include <pthread.h>
#include <stdlib.h>

#include "psettings.h"
#include "pmem.h"
#include "prun.h"
#include "pdbg.h"

// required by thread_entry
extern PSYNC_THREAD const char *psync_thread_name; 

typedef struct {
  union {
    thread0_run run0; /* used when ptr == NULL */
    thread1_run run1; /* used when ptr != NULL */
  } fn;
  void *ptr;
  const char *name;
} thread_data;

static void *thread_entry(void *data) {
  thread_data *td = (thread_data *)data;
  psync_thread_name = td->name;

  if (td->ptr) {
    td->fn.run1(td->ptr);
  } else {
    td->fn.run0();
  }

  pmem_free(PMEM_SUBSYS_OTHER, data);
  return NULL;
}

static int start_thread_common(const char *name, thread_data *data) {
  pthread_t thread;
  pthread_attr_t attr;
  int ret;

  pthread_attr_init(&attr);
  pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
  pthread_attr_setstacksize(&attr, PSYNC_STACK_SIZE);
  ret = pthread_create(&thread, &attr, thread_entry, data);
  pthread_attr_destroy(&attr);

  if (ret) {
    pdbg_logf(D_ERROR, "pthread_create failed for thread %s: %d", name, ret);
    pmem_free(PMEM_SUBSYS_OTHER, data);
  }
  return ret;
}

void prun_thread(const char *name, thread0_run run) {
  thread_data *data = pmem_malloc(PMEM_SUBSYS_OTHER, sizeof(thread_data));
  if (!data) {
    pdbg_logf(D_ERROR, "malloc failed for thread %s", name);
    return;
  }
  data->fn.run0 = run;
  data->ptr = NULL;
  data->name = name;
  start_thread_common(name, data);
}

void prun_thread1(const char *name, thread1_run run, void *ptr) {
  thread_data *data = pmem_malloc(PMEM_SUBSYS_OTHER, sizeof(thread_data));
  if (!data) {
    pdbg_logf(D_ERROR, "malloc failed for thread %s", name);
    return;
  }
  data->fn.run1 = run;
  data->ptr = ptr;
  data->name = name;
  start_thread_common(name, data);
}