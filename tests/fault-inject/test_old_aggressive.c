/*
 * Test: OLD pfs_get_both_locks with retry loop (deadlock-prone)
 * 
 * This reproduces the old implementation with more aggressive contention.
 */

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>

typedef struct {
  pthread_mutex_t mutex;
} psync_openfile_t;

static pthread_mutex_t psql_mutex = PTHREAD_MUTEX_INITIALIZER;

static void psql_lock() { pthread_mutex_lock(&psql_mutex); }
static void psql_unlock() { pthread_mutex_unlock(&psql_mutex); }
static int psql_trylock() { return pthread_mutex_trylock(&psql_mutex); }

static void pfs_get_both_locks_OLD(psync_openfile_t *of) {
retry:
  psql_lock();
  if (pthread_mutex_trylock(&of->mutex)) {
    psql_unlock();
    pthread_mutex_lock(&of->mutex);
    if (psql_trylock()) {
      pthread_mutex_unlock(&of->mutex);
      usleep(1000);
      goto retry;
    }
  }
}

static volatile int timeout_flag = 0;
static volatile int iteration_count = 0;

static void *timeout_thread(void *arg) {
  sleep(10);
  timeout_flag = 1;
  printf("TIMEOUT: deadlock detected after 10 seconds (iterations: %d)\n", iteration_count);
  exit(1);
  return NULL;
}

static void *thread_func(void *arg) {
  psync_openfile_t *of = arg;
  for (int i = 0; i < 10000; i++) {
    if (timeout_flag) break;
    pfs_get_both_locks_OLD(of);
    __sync_fetch_and_add(&iteration_count, 1);
    pthread_mutex_unlock(&of->mutex);
    psql_unlock();
    // No sleep - maximize contention
  }
  return NULL;
}

int main() {
  psync_openfile_t of;
  pthread_mutex_init(&of.mutex, NULL);
  
  pthread_t timeout_t;
  pthread_create(&timeout_t, NULL, timeout_thread, NULL);
  pthread_detach(timeout_t);
  
  pthread_t threads[8];
  for (int i = 0; i < 8; i++) {
    pthread_create(&threads[i], NULL, thread_func, &of);
  }
  
  for (int i = 0; i < 8; i++) {
    pthread_join(threads[i], NULL);
  }
  
  pthread_mutex_destroy(&of.mutex);
  printf("UNEXPECTED: old code completed without deadlock (iterations: %d)\n", iteration_count);
  return 0;
}
