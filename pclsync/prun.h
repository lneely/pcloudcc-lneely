#ifndef __PRUN_H
#define __PRUN_H

#include "pcompiler.h"

extern PSYNC_THREAD const char *psync_thread_name;

typedef void (*thread0_run)();
typedef void (*thread1_run)(void *);

void prun_thread(const char *name, thread0_run run);
void prun_thread1(const char *name, thread1_run run, void *ptr);

#endif