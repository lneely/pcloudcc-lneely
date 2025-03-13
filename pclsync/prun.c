#include <pthread.h>

#include "plibs.h"
#include "psettings.h"
#include "psynclib.h"
#include "prun.h"

// required by thread_entry
extern PSYNC_THREAD const char *psync_thread_name; 

typedef struct {
  thread1_run run;
  void *ptr;
  const char *name;
} thread_data;

static void *thread_entry(void *data) {
  thread_data *td = (thread_data *)data;
  psync_thread_name = td->name;
  
  if (td->ptr) {
    td->run(td->ptr);
  } else {
    ((thread0_run)td->run)();
  }
  
  free(data);
  return NULL;
}

// Common function for both thread types
static void start_thread(const char *name, void *run, void *ptr) {
  thread_data *data;
  pthread_t thread;
  pthread_attr_t attr;
  
  data = malloc(sizeof(thread_data));
  data->run = run;
  data->ptr = ptr;
  data->name = name;
  
  pthread_attr_init(&attr);
  pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
  pthread_attr_setstacksize(&attr, PSYNC_STACK_SIZE);
  pthread_create(&thread, &attr, thread_entry, data);
  pthread_attr_destroy(&attr);
}

void prun_thread(const char *name, thread0_run run) {
  start_thread(name, (thread1_run)run, NULL);
}

void prun_thread1(const char *name, thread1_run run, void *ptr) {
  start_thread(name, run, ptr);
}