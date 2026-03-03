/*
 * Fault injection test: Force lock ordering violation in old code
 * 
 * This test uses strategic delays to force the deadlock scenario:
 * Thread 1: holds psql, tries file mutex
 * Thread 2: holds file mutex, tries psql
 */

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

typedef struct {
  pthread_mutex_t mutex;
} psync_openfile_t;

static pthread_mutex_t psql_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_barrier_t barrier;

static void psql_lock() { pthread_mutex_lock(&psql_mutex); }
static void psql_unlock() { pthread_mutex_unlock(&psql_mutex); }
static int psql_trylock() { return pthread_mutex_trylock(&psql_mutex); }

// OLD implementation with retry loop
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

static void *thread1_func(void *arg) {
  psync_openfile_t *of = arg;
  
  // T1: Acquire psql first
  psql_lock();
  printf("T1: acquired psql\n");
  
  // Wait for T2 to acquire file mutex
  pthread_barrier_wait(&barrier);
  usleep(10000);
  
  // T1: Try to acquire file mutex (will block - T2 holds it)
  printf("T1: trying file mutex...\n");
  pthread_mutex_lock(&of->mutex);
  printf("T1: acquired file mutex\n");
  
  pthread_mutex_unlock(&of->mutex);
  psql_unlock();
  return NULL;
}

static void *thread2_func(void *arg) {
  psync_openfile_t *of = arg;
  
  // T2: Acquire file mutex first
  pthread_mutex_lock(&of->mutex);
  printf("T2: acquired file mutex\n");
  
  // Signal T1 we have the file mutex
  pthread_barrier_wait(&barrier);
  usleep(10000);
  
  // T2: Try to acquire psql (will block - T1 holds it)
  printf("T2: trying psql...\n");
  psql_lock();
  printf("T2: acquired psql\n");
  
  psql_unlock();
  pthread_mutex_unlock(&of->mutex);
  return NULL;
}

int main() {
  psync_openfile_t of;
  pthread_mutex_init(&of.mutex, NULL);
  pthread_barrier_init(&barrier, NULL, 2);
  
  printf("=== Testing OLD lock ordering (deadlock scenario) ===\n");
  
  pthread_t t1, t2;
  pthread_create(&t1, NULL, thread1_func, &of);
  pthread_create(&t2, NULL, thread2_func, &of);
  
  // Wait with timeout
  sleep(5);
  
  // Check if threads are still running (deadlocked)
  void *ret1, *ret2;
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  ts.tv_sec += 1;
  
  int r1 = pthread_timedjoin_np(t1, &ret1, &ts);
  int r2 = pthread_timedjoin_np(t2, &ret2, &ts);
  
  if (r1 != 0 || r2 != 0) {
    printf("\nDEADLOCK CONFIRMED: threads hung with opposite lock ordering\n");
    pthread_cancel(t1);
    pthread_cancel(t2);
    return 1;
  }
  
  pthread_mutex_destroy(&of.mutex);
  pthread_barrier_destroy(&barrier);
  printf("\nPASS: no deadlock (unexpected)\n");
  return 0;
}
