#ifndef PSIGNAL_H
#define PSIGNAL_H

#include <signal.h>

#ifdef __cplusplus
extern "C" {
#endif

void psignal_register(int signum);
int psignal_check_pending(void);
void psignal_set_custom_handler(int sig, void (*handler)(int));

#ifdef __cplusplus
}
#endif

#endif
