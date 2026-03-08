#include "psignal.h"
#include <signal.h>
#include <stddef.h>

static volatile sig_atomic_t sigint_flag = 0;
static volatile sig_atomic_t sigterm_flag = 0;
static volatile sig_atomic_t sighup_flag = 0;

static void sigint_handler(int sig) {
  sigint_flag = 1;
}

static void sigterm_handler(int sig) {
  sigterm_flag = 1;
}

static void sighup_handler(int sig) {
  sighup_flag = 1;
}

void psignal_set_custom_handler(int sig, void (*handler)(int)) {
  struct sigaction sa;

  if (sigaction(sig, NULL, &sa) != 0)
    return;

  if (sa.sa_handler == SIG_DFL) {
    sa.sa_handler = handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    if (sigaction(sig, &sa, NULL) != 0) {
      return;
    }
  }
}

void psignal_register(int signum) {
  void (*handler)(int) = NULL;
  
  if (signum == SIGINT) {
    handler = sigint_handler;
  } else if (signum == SIGTERM) {
    handler = sigterm_handler;
  } else if (signum == SIGHUP) {
    handler = sighup_handler;
  } else {
    return;
  }
  
  psignal_set_custom_handler(signum, handler);
}

int psignal_check_pending(void) {
  sig_atomic_t int_flag = sigint_flag;
  sig_atomic_t term_flag = sigterm_flag;
  sig_atomic_t hup_flag = sighup_flag;
  
  if (int_flag) {
    sigint_flag = 0;
    return SIGINT;
  }
  if (term_flag) {
    sigterm_flag = 0;
    return SIGTERM;
  }
  if (hup_flag) {
    sighup_flag = 0;
    return SIGHUP;
  }
  return 0;
}
