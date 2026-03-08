#ifndef PSIGNAL_H
#define PSIGNAL_H

#include <signal.h>

#ifdef __cplusplus
extern "C" {
#endif

void psignal_register(int signum);
int psignal_check_pending(void);

#ifdef __cplusplus
}
#endif

#endif
