#ifndef PSIGNAL_H
#define PSIGNAL_H

#include <signal.h>

void psignal_register(int signum);
int psignal_check_pending(void);

#endif
