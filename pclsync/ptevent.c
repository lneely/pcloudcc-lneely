#include "pdbg.h"
#include "prun.h"
#include "ptevent.h"
#include <pthread.h>

static pthread_mutex_t data_event_fptr_mutex = PTHREAD_MUTEX_INITIALIZER;
data_event_callback data_event_fptr = NULL;

static void proc_send_data_event(void *ptr) {
  event_data_struct *data = (event_data_struct *)ptr;

  pdbg_logf(D_NOTICE,
        "Sending data event Event id: [%d] Str1: [%s], Str1: [%s], Uint1:[%lu] "
        "Uint2:[%lu]",
        data->eventid, data->str1, data->str2, data->uint1, data->uint2);

  pthread_mutex_lock(&data_event_fptr_mutex);
  if (data_event_fptr) {
    data_event_fptr(data->eventid, (char *)data->str1, (char *)data->str2,
                    data->uint1, data->uint2);
  }
  pthread_mutex_unlock(&data_event_fptr_mutex);

  pmem_free(PMEM_SUBSYS_OTHER, (void *)data->str1);
  pmem_free(PMEM_SUBSYS_OTHER, (void *)data->str2);
  pmem_free(PMEM_SUBSYS_OTHER, ptr);
}

void ptevent_init(void *ptr) {
  pthread_mutex_lock(&data_event_fptr_mutex);
  data_event_fptr = (data_event_callback)ptr;
  pthread_mutex_unlock(&data_event_fptr_mutex);
  pdbg_logf(D_NOTICE, "Data event handler set.");
}

void ptevent_process(event_data_struct *data) {
  event_data_struct *event_data;

  pthread_mutex_lock(&data_event_fptr_mutex);
  int has_callback = (data_event_fptr != NULL);
  pthread_mutex_unlock(&data_event_fptr_mutex);

  if (has_callback) {
    event_data = pmem_malloc(PMEM_SUBSYS_OTHER, sizeof(event_data_struct));
    event_data->eventid = data->eventid;
    event_data->uint1 = data->uint1;
    event_data->uint2 = data->uint2;
    event_data->str1 = data->str1 ? strdup(data->str1) : NULL;
    event_data->str2 = data->str2 ? strdup(data->str2) : NULL;

    prun_thread1("Data Event", proc_send_data_event, event_data);
  } else {
    pdbg_logf(D_ERROR, "Data event callback function not set.");
  }
}

