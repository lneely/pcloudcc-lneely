#include "pdbg.h"
#include "prun.h"
#include "ptevent.h"

data_event_callback data_event_fptr = NULL;

static void proc_send_data_event(void *ptr) {
  event_data_struct *data = (event_data_struct *)ptr;

  pdbg_logf(D_NOTICE,
        "Sending data event Event id: [%d] Str1: [%s], Str1: [%s], Uint1:[%lu] "
        "Uint2:[%lu]",
        data->eventid, data->str1, data->str2, data->uint1, data->uint2);

  data_event_fptr(data->eventid, (char *)data->str1, (char *)data->str2,
                  data->uint1, data->uint2);

  free(ptr);
}

void ptevent_init(void *ptr) {
  data_event_fptr = (data_event_callback)ptr;
  pdbg_logf(D_NOTICE, "Data event handler set.");
}

void ptevent_process(event_data_struct *data) {
  event_data_struct *event_data;

  if (data_event_fptr) {
    event_data = malloc(sizeof(event_data_struct));
    event_data->eventid = data->eventid;
    event_data->uint1 = data->uint1;
    event_data->uint2 = data->uint2;
    event_data->str1 = strdup(data->str1);
    event_data->str2 = strdup(data->str2);

    prun_thread1("Data Event", proc_send_data_event, event_data);
  } else {
    pdbg_logf(D_ERROR, "Data event callback function not set.");
  }
}

