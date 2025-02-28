#include <pthread.h>

#include "plibs.h"
#include "psettings.h"
#include "psynclib.h"
#include "prun.h"

typedef struct {
  thread0_run run;
  const char *name;
} thread0_data;

typedef struct {
  thread1_run run;
  void *ptr;
  const char *name;
} thread1_data;

static void *thread_entry(void *data) {
  thread0_run run;
  run = ((thread0_data *)data)->run;
  psync_thread_name = ((thread0_data *)data)->name;
  psync_free(data);
  run();
  return NULL;
}

static void *thread1_entry(void *data) {
  thread1_run run;
  void *ptr;
  run = ((thread1_data *)data)->run;
  ptr = ((thread1_data *)data)->ptr;
  psync_thread_name = ((thread1_data *)data)->name;
  psync_free(data);
  run(ptr);
  return NULL;
}

void prun_thread(const char *name, thread0_run run) {
  thread0_data *data;
  pthread_t thread;
  pthread_attr_t attr;
  data = psync_new(thread0_data);
  data->run = run;
  data->name = name;
  pthread_attr_init(&attr);
  pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
  pthread_attr_setstacksize(&attr, PSYNC_STACK_SIZE);
  pthread_create(&thread, &attr, thread_entry, data);
  pthread_attr_destroy(&attr);
}

void prun_thread1(const char *name, thread1_run run, void *ptr) {
  thread1_data *data;
  pthread_t thread;
  pthread_attr_t attr;
  data = psync_new(thread1_data);
  data->run = run;
  data->ptr = ptr;
  data->name = name;
  pthread_attr_init(&attr);
  pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
  pthread_attr_setstacksize(&attr, PSYNC_STACK_SIZE);
  pthread_create(&thread, &attr, thread1_entry, data);
  pthread_attr_destroy(&attr);
}
