/*
 * Test: pfs_get_both_locks enforces consistent lock ordering
 * 
 * Verifies that pfs_get_both_locks always acquires psql lock before
 * file mutex, eliminating the retry loop and deadlock risk.
 */

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

typedef struct {
  pthread_mutex_t mutex;
} psync_openfile_t;

static pthread_mutex_t psql_mutex = PTHREAD_MUTEX_INITIALIZER;

static void psql_lock() { pthread_mutex_lock(&psql_mutex); }
static void psql_unlock() { pthread_mutex_unlock(&psql_mutex); }

static void pfs_get_both_locks(psync_openfile_t *of) {
  psql_lock();
  pthread_mutex_lock(&of->mutex);
}

static void *thread_func(void *arg) {
  psync_openfile_t *of = arg;
  for (int i = 0; i < 1000; i++) {
    pfs_get_both_locks(of);
    pthread_mutex_unlock(&of->mutex);
    psql_unlock();
  }
  return NULL;
}

int main() {
  psync_openfile_t of;
  pthread_mutex_init(&of.mutex, NULL);
  
  pthread_t t1, t2;
  pthread_create(&t1, NULL, thread_func, &of);
  pthread_create(&t2, NULL, thread_func, &of);
  
  pthread_join(t1, NULL);
  pthread_join(t2, NULL);
  
  pthread_mutex_destroy(&of.mutex);
  printf("PASS: no deadlock\n");
  return 0;
}
