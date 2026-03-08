/*
 * Test: Signal safety with pthread_mutex_timedlock (pcl-17t)
 *
 * Verifies that signal handlers do not deadlock when signals are raised
 * while holding mutexes, using the timeout mechanism from pthread_mutex_timedlock.
 */

#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <signal.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>

static pthread_mutex_t test_mutex = PTHREAD_MUTEX_INITIALIZER;
static volatile sig_atomic_t signal_received = 0;
static volatile sig_atomic_t handler_attempted_lock = 0;
static volatile sig_atomic_t handler_timeout = 0;

static void signal_handler(int sig) {
    (void)sig;
    signal_received = 1;
    handler_attempted_lock = 1;
    
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += 1;
    
    int ret = pthread_mutex_timedlock(&test_mutex, &ts);
    if (ret == ETIMEDOUT) {
        handler_timeout = 1;
    } else if (ret == 0) {
        pthread_mutex_unlock(&test_mutex);
    }
}

static int passes = 0, failures = 0;
#define PASS(n)      do { printf("PASS: %s\n", n); passes++; } while(0)
#define FAIL(n, ...) do { printf("FAIL: %s — ", n); printf(__VA_ARGS__); printf("\n"); failures++; } while(0)

static void test_signal_while_holding_lock(void) {
    signal_received = 0;
    handler_attempted_lock = 0;
    handler_timeout = 0;
    
    struct sigaction sa = {0};
    sa.sa_handler = signal_handler;
    sigaction(SIGUSR1, &sa, NULL);
    
    pthread_mutex_lock(&test_mutex);
    raise(SIGUSR1);
    usleep(10000);
    pthread_mutex_unlock(&test_mutex);
    
    if (signal_received && handler_attempted_lock && handler_timeout)
        PASS("signal raised while holding lock: handler timeout, no deadlock");
    else
        FAIL("signal while holding lock", "received=%d attempted=%d timeout=%d",
             signal_received, handler_attempted_lock, handler_timeout);
}

static void test_signal_handler_acquires_lock(void) {
    signal_received = 0;
    handler_attempted_lock = 0;
    handler_timeout = 0;
    
    struct sigaction sa = {0};
    sa.sa_handler = signal_handler;
    sigaction(SIGUSR1, &sa, NULL);
    
    raise(SIGUSR1);
    usleep(10000);
    
    if (signal_received && handler_attempted_lock && !handler_timeout)
        PASS("signal handler acquires lock when available");
    else
        FAIL("signal handler acquires lock", "received=%d attempted=%d timeout=%d",
             signal_received, handler_attempted_lock, handler_timeout);
}

static void test_no_deadlock_with_timeout(void) {
    signal_received = 0;
    handler_attempted_lock = 0;
    handler_timeout = 0;
    
    struct sigaction sa = {0};
    sa.sa_handler = signal_handler;
    sigaction(SIGUSR1, &sa, NULL);
    
    pthread_mutex_lock(&test_mutex);
    raise(SIGUSR1);
    usleep(1500000);
    pthread_mutex_unlock(&test_mutex);
    
    if (signal_received && handler_timeout)
        PASS("no deadlock: timeout mechanism prevents hang");
    else
        FAIL("no deadlock with timeout", "received=%d timeout=%d",
             signal_received, handler_timeout);
}

int main(void) {
    test_signal_while_holding_lock();
    test_signal_handler_acquires_lock();
    test_no_deadlock_with_timeout();
    
    printf("\n%d passed, %d failed\n", passes, failures);
    return failures ? 1 : 0;
}
