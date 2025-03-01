// pqevent is a queue-based event system that processes events sequentially.
// Events are added to a queue and handled by a single consumer thread.
// Supports various event data types through a union structure.

#ifndef __PQEVENT_H
#define __PQEVENT_H

#include "psynclib.h"

void pqevent_process(pevent_callback_t callback);
void pqevent_queue_eventid(psync_eventtype_t eventid);
void pqevent_queue_event(psync_eventtype_t eventid, void *eventdata);
void pqevent_queue_sync_event_id(psync_eventtype_t eventid, psync_syncid_t syncid, const char *localpath, psync_fileorfolderid_t remoteid);
void pqevent_queue_sync_event_path(psync_eventtype_t eventid, psync_syncid_t syncid, const char *localpath, psync_fileorfolderid_t remoteid, const char *remotepath);

#endif