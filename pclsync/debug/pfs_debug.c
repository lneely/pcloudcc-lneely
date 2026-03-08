// debug/pfs_debug.c - debug implementations for pfs debug helpers

#include <pthread.h>
#include <signal.h>
#include <string.h>

#include "pdbg.h"
#include "pfs.h"
#include "pfs_internal.h"
#include "pfstasks.h"
#include "prun.h"
#include "psql.h"

void pfs_debug_init_file_mutex(pthread_mutex_t *m) {
  pthread_mutexattr_t attr;
  pthread_mutexattr_init(&attr);
  pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ERRORCHECK);
  pthread_mutex_init(m, &attr);
  pthread_mutexattr_destroy(&attr);
}

static void pfs_do_dump_internals() {
  psync_openfile_t *of;
  pdbg_logf(D_NOTICE, "dumping internal state");
  psql_rdlock();
  ptree_for_each_element(of, openfiles, psync_openfile_t, tree)
      pdbg_logf(D_NOTICE, "open file %s fileid %ld folderid %ld",
                of->currentname, (long)of->fileid,
                (long)of->currentfolder->folderid);
  pfs_task_dump_state();
  psql_rdunlock();
}

void pfs_debug_dump_internals() { pfs_do_dump_internals(); }

static void pfs_usr1_handler(int sig) {
  prun_thread("dump signal", pfs_do_dump_internals);
}

void pfs_debug_register_signal_handlers() {
  struct sigaction sa;
  memset(&sa, 0, sizeof(struct sigaction));
  sigemptyset(&sa.sa_mask);
  sa.sa_handler = pfs_usr1_handler;
  sa.sa_flags = 0;
  sigaction(SIGUSR1, &sa, NULL);
}

void pfs_debug_check_lock_order(const char *file, unsigned long line) {
  if (!psql_locked()) {
    pdbg_logf(D_ERROR, "lock ordering violation: pfs_lock_file called without psql_lock at %s:%lu", file, line);
    abort();
  }
}
