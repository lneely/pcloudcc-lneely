#ifndef PSIGNAL_H
#define PSIGNAL_H

#include <signal.h>

#ifdef __cplusplus
extern "C" {
#endif

void psignal_register(int signum);
int psignal_check_pending(void);
void psignal_set_custom_handler(int sig, void (*handler)(int));
void psignal_register_cleanup(void (*fn)(void));
void panic(const char *msg) __attribute__((noreturn));
int psignal_init_signalfd(void);
int psignal_read_signalfd(int fd);

#ifdef __cplusplus
}
#endif

#endif
