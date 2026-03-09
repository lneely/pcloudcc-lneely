#include "psignal.h"
#include <execinfo.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define PSIGNAL_MAX_CLEANUPS 16
static void (*cleanup_fns[PSIGNAL_MAX_CLEANUPS])(void);
static int cleanup_count = 0;

void psignal_register_cleanup(void (*fn)(void)) {
  if (cleanup_count < PSIGNAL_MAX_CLEANUPS)
    cleanup_fns[cleanup_count++] = fn;
}

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

void panic(const char *msg) {
  void *frames[64];
  int nframes;
  char **symbols;
  
  fprintf(stderr, "PANIC: %s\n", msg);
  
  nframes = backtrace(frames, 64);
  symbols = backtrace_symbols(frames, nframes);
  
  if (symbols) {
    fprintf(stderr, "Backtrace:\n");
    for (int i = 0; i < nframes; i++) {
      fprintf(stderr, "  %s\n", symbols[i]);
    }
    free(symbols);
  }
  
  signal(SIGSEGV, SIG_DFL);
  signal(SIGABRT, SIG_DFL);
  signal(SIGBUS, SIG_DFL);

  for (int i = 0; i < cleanup_count; i++)
    cleanup_fns[i]();

  /* Use _exit() instead of abort(): _exit closes all file descriptors
   * immediately, releasing POSIX advisory locks (including SQLite's WAL
   * locks). abort() is intercepted by ASan which can hang indefinitely,
   * leaving the process as a zombie and the DB locked. */
  _exit(1);
}

static void panic_handler(int sig) {
  const char *msg;
  if (sig == SIGSEGV)
    msg = "Segmentation fault";
  else if (sig == SIGABRT)
    msg = "Abort";
  else if (sig == SIGBUS)
    msg = "Bus error";
  else
    msg = "Unknown signal";
  panic(msg);
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
  } else if (signum == SIGSEGV || signum == SIGABRT || signum == SIGBUS) {
    handler = panic_handler;
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
