/*
 * Test: prun.c pthread_create failure frees data (pcl-aqb)
 *
 * Verifies the guards added in 46bf6b5:
 *   1. pthread_create failure → data freed, no leak
 *   2. malloc failure in prun_thread  → graceful return (no crash)
 *   3. malloc failure in prun_thread1 → graceful return (no crash)
 *   4. pthread_attr_destroy always called (even on create failure)
 *
 * Uses --wrap linker flag to intercept pthread_create, pthread_attr_destroy,
 * and malloc so we can inject failures and track resource lifecycle.
 */

#define _POSIX_C_SOURCE 199309L
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

extern void prun_thread(const char *name, void (*run)(void));
extern void prun_thread1(const char *name, void (*run)(void *), void *ptr);

int g_pthread_create_fail = 0;
int g_malloc_fail         = 0;
int g_malloc_calls        = 0;
int g_free_calls          = 0;
int g_attr_destroy_calls  = 0;
int g_thread_entry_calls  = 0;
void *g_last_malloc_ptr   = NULL;
void *g_last_free_ptr     = NULL;

int   __real_pthread_create(pthread_t *, const pthread_attr_t *,
                            void *(*)(void *), void *);
int   __real_pthread_attr_destroy(pthread_attr_t *);
void *__real_malloc(size_t);
void  __real_free(void *);

int __wrap_pthread_create(pthread_t *t, const pthread_attr_t *a,
                          void *(*fn)(void *), void *arg) {
    if (g_pthread_create_fail)
        return 11;
    g_thread_entry_calls++;
    return __real_pthread_create(t, a, fn, arg);
}

int __wrap_pthread_attr_destroy(pthread_attr_t *a) {
    g_attr_destroy_calls++;
    return __real_pthread_attr_destroy(a);
}

void *__wrap_malloc(size_t sz) {
    g_malloc_calls++;
    if (g_malloc_fail)
        return NULL;
    g_last_malloc_ptr = __real_malloc(sz);
    return g_last_malloc_ptr;
}

void __wrap_free(void *p) {
    g_free_calls++;
    g_last_free_ptr = p;
    __real_free(p);
}

static void dummy_run0(void) {}
static void dummy_run1(void *p) { (void)p; }

static int passes = 0, failures = 0;
#define PASS(n)    do { printf("PASS: %s\n", n); passes++; } while(0)
#define FAIL(n, ...) do { printf("FAIL: %s — ", n); printf(__VA_ARGS__); printf("\n"); failures++; } while(0)

static void reset(void) {
    g_pthread_create_fail = 0;
    g_malloc_fail         = 0;
    g_malloc_calls        = 0;
    g_free_calls          = 0;
    g_attr_destroy_calls  = 0;
    g_thread_entry_calls  = 0;
    g_last_malloc_ptr     = NULL;
    g_last_free_ptr       = NULL;
}

static void test_pthread_create_fail_frees_data(void) {
    reset();
    g_pthread_create_fail = 1;
    int before_malloc = g_malloc_calls;
    int before_free   = g_free_calls;
    prun_thread("test", dummy_run0);
    int mallocs = g_malloc_calls - before_malloc;
    int frees   = g_free_calls   - before_free;
    /* Verify no memory leak: frees >= mallocs */
    if (frees >= mallocs && mallocs >= 1)
        PASS("pthread_create failure: data freed (no leak)");
    else
        FAIL("pthread_create failure frees data", "mallocs=%d frees=%d", mallocs, frees);
}

static void test_attr_destroy_on_create_fail(void) {
    reset();
    g_pthread_create_fail = 1;
    int before = g_attr_destroy_calls;
    prun_thread("test", dummy_run0);
    if (g_attr_destroy_calls - before == 1)
        PASS("pthread_attr_destroy called on pthread_create failure");
    else
        FAIL("pthread_attr_destroy on create fail", "calls=%d", g_attr_destroy_calls - before);
}

static void test_malloc_fail_prun_thread(void) {
    reset();
    g_malloc_fail = 1;
    int before_free = g_free_calls;
    prun_thread("test", dummy_run0);
    int frees = g_free_calls - before_free;
    /* malloc fails, no allocation from prun_thread, accept small overhead */
    if (frees <= 2)
        PASS("malloc failure in prun_thread: graceful return");
    else
        FAIL("malloc failure in prun_thread", "free calls=%d", frees);
}

static void test_malloc_fail_prun_thread1(void) {
    reset();
    g_malloc_fail = 1;
    int dummy = 0;
    int before_free = g_free_calls;
    prun_thread1("test1", dummy_run1, &dummy);
    int frees = g_free_calls - before_free;
    /* malloc fails, no allocation from prun_thread1, accept small overhead */
    if (frees <= 2)
        PASS("malloc failure in prun_thread1: graceful return");
    else
        FAIL("malloc failure in prun_thread1", "free calls=%d", frees);
}

int main(void) {
    test_pthread_create_fail_frees_data();
    test_attr_destroy_on_create_fail();
    test_malloc_fail_prun_thread();
    test_malloc_fail_prun_thread1();
    printf("\n%d passed, %d failed\n", passes, failures);
    return failures ? 1 : 0;
}
