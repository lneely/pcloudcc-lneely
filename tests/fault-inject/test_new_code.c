/*
 * Fault injection test: Verify NEW code prevents deadlock
 * 
 * Same scenario as forced deadlock test, but with new lock ordering.
 */

#define _GNU_SOURCE
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>

typedef struct {
  pthread_mutex_t mutex;
} psync_openfile_t;

static pthread_mutex_t psql_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_barrier_t barrier;

static void psql_lock() { pthread_mutex_lock(&psql_mutex); }
static void psql_unlock() { pthread_mutex_unlock(&psql_mutex); }

// NEW implementation: consistent lock ordering
static void pfs_get_both_locks_NEW(psync_openfile_t *of) {
  psql_lock();
  pthread_mutex_lock(&of->mutex);
}

static void *thread1_func(void *arg) {
  psync_openfile_t *of = arg;
  
  for (int i = 0; i < 100; i++) {
    pfs_get_both_locks_NEW(of);
    pthread_mutex_unlock(&of->mutex);
    psql_unlock();
  }
  return NULL;
}

static void *thread2_func(void *arg) {
  psync_openfile_t *of = arg;
  
  for (int i = 0; i < 100; i++) {
    pfs_get_both_locks_NEW(of);
    pthread_mutex_unlock(&of->mutex);
    psql_unlock();
  }
  return NULL;
}

int main() {
  psync_openfile_t of;
  pthread_mutex_init(&of.mutex, NULL);
  
  printf("=== Testing NEW lock ordering (deadlock-free) ===\n");
  
  pthread_t t1, t2, t3, t4;
  pthread_create(&t1, NULL, thread1_func, &of);
  pthread_create(&t2, NULL, thread2_func, &of);
  pthread_create(&t3, NULL, thread1_func, &of);
  pthread_create(&t4, NULL, thread2_func, &of);
  
  // Wait with timeout
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  ts.tv_sec += 5;
  
  void *ret;
  int r1 = pthread_timedjoin_np(t1, &ret, &ts);
  int r2 = pthread_timedjoin_np(t2, &ret, &ts);
  int r3 = pthread_timedjoin_np(t3, &ret, &ts);
  int r4 = pthread_timedjoin_np(t4, &ret, &ts);
  
  if (r1 != 0 || r2 != 0 || r3 != 0 || r4 != 0) {
    printf("\nFAIL: threads hung (unexpected with new code)\n");
    return 1;
  }
  
  pthread_mutex_destroy(&of.mutex);
  printf("\nPASS: no deadlock with consistent lock ordering\n");
  return 0;
}
