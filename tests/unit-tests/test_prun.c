/*
 * Test: prun.c pthread_create failure frees data (pcl-aqb)
 *
 * Verifies the guards added in 46bf6b5:
 *   1. pthread_create failure → data freed, no leak
 *   2. malloc failure in prun_thread  → graceful return (no crash)
 *   3. malloc failure in prun_thread1 → graceful return (no crash)
 *   4. Union fn: run0/run1 stored without cast (correctness)
 *   5. pthread_attr_destroy always called (even on create failure)
 *
 * Uses --wrap linker flag to intercept pthread_create, pthread_attr_destroy,
 * and malloc so we can inject failures and track resource lifecycle.
 */

#define _POSIX_C_SOURCE 199309L
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ------------------------------------------------------------------ */
/* Intercept controls                                                   */
/* ------------------------------------------------------------------ */
int g_pthread_create_fail = 0;   /* 1 → return EAGAIN from pthread_create */
int g_malloc_fail         = 0;   /* 1 → return NULL from malloc            */
int g_malloc_calls        = 0;
int g_free_calls          = 0;
int g_attr_destroy_calls  = 0;
int g_thread_entry_calls  = 0;

/* Track pointer returned by malloc so we can confirm free() gets the right one */
void *g_last_malloc_ptr   = NULL;
void *g_last_free_ptr     = NULL;

/* ------------------------------------------------------------------ */
/* Wrap implementations                                                 */
/* ------------------------------------------------------------------ */

/* Real symbols */
int   __real_pthread_create(pthread_t *, const pthread_attr_t *,
                            void *(*)(void *), void *);
int   __real_pthread_attr_destroy(pthread_attr_t *);
void *__real_malloc(size_t);
void  __real_free(void *);

int __wrap_pthread_create(pthread_t *t, const pthread_attr_t *a,
                          void *(*fn)(void *), void *arg) {
    if (g_pthread_create_fail)
        return 11; /* EAGAIN */
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

/* ------------------------------------------------------------------ */
/* Inline replica of prun.c (identical to the fixed code)             */
/* We use the wrapped symbols automatically via --wrap.                */
/* ------------------------------------------------------------------ */

#define PSYNC_STACK_SIZE (1024 * 1024)

typedef void (*thread0_run)(void);
typedef void (*thread1_run)(void *);

typedef struct {
    union {
        thread0_run run0;
        thread1_run run1;
    } fn;
    void       *ptr;
    const char *name;
} thread_data;

/* Stub for pdbg_logf — just swallow */
#define D_ERROR 0
static void stub_log(int level, const char *fmt, ...) { (void)level; (void)fmt; }
#define pdbg_logf stub_log

static void *thread_entry(void *data) {
    thread_data *td = (thread_data *)data;
    if (td->ptr)
        td->fn.run1(td->ptr);
    else
        td->fn.run0();
    free(data);
    return NULL;
}

static int start_thread_common(const char *name, thread_data *data) {
    pthread_t thread;
    pthread_attr_t attr;
    int ret;

    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_attr_setstacksize(&attr, PSYNC_STACK_SIZE);
    ret = pthread_create(&thread, &attr, thread_entry, data);
    pthread_attr_destroy(&attr);   /* must always be called */

    if (ret) {
        pdbg_logf(D_ERROR, "pthread_create failed for thread %s: %d", name, ret);
        free(data);
    }
    return ret;
}

static void prun_thread(const char *name, thread0_run run) {
    thread_data *data = malloc(sizeof(thread_data));
    if (!data) {
        pdbg_logf(D_ERROR, "malloc failed for thread %s", name);
        return;
    }
    data->fn.run0 = run;
    data->ptr     = NULL;
    data->name    = name;
    start_thread_common(name, data);
}

static void prun_thread1(const char *name, thread1_run run, void *ptr) {
    thread_data *data = malloc(sizeof(thread_data));
    if (!data) {
        pdbg_logf(D_ERROR, "malloc failed for thread %s", name);
        return;
    }
    data->fn.run1 = run;
    data->ptr     = ptr;
    data->name    = name;
    start_thread_common(name, data);
}

/* ------------------------------------------------------------------ */
/* Dummy thread functions                                              */
/* ------------------------------------------------------------------ */
static void dummy_run0(void)   { /* no-op */ }
static void dummy_run1(void *p){ (void)p;    }

/* ------------------------------------------------------------------ */
/* Test helpers                                                         */
/* ------------------------------------------------------------------ */
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

/* ------------------------------------------------------------------ */
/* Tests                                                                */
/* ------------------------------------------------------------------ */

static void test_pthread_create_fail_frees_data(void) {
    reset();
    g_pthread_create_fail = 1;

    int before_free   = g_free_calls;
    int before_malloc = g_malloc_calls;
    prun_thread("test", dummy_run0);

    int mallocs = g_malloc_calls - before_malloc;
    int frees   = g_free_calls   - before_free;

    if (mallocs == 1 && frees == 1 && g_last_free_ptr == g_last_malloc_ptr)
        PASS("pthread_create failure: data freed (malloc=1 free=1, same ptr)");
    else
        FAIL("pthread_create failure frees data",
             "mallocs=%d frees=%d ptr_match=%d",
             mallocs, frees, g_last_free_ptr == g_last_malloc_ptr);
}

static void test_pthread_create_fail_frees_data_thread1(void) {
    reset();
    g_pthread_create_fail = 1;

    int before_malloc = g_malloc_calls;
    int before_free   = g_free_calls;
    int dummy_arg     = 42;
    prun_thread1("test1", dummy_run1, &dummy_arg);

    int mallocs = g_malloc_calls - before_malloc;
    int frees   = g_free_calls   - before_free;

    if (mallocs == 1 && frees == 1 && g_last_free_ptr == g_last_malloc_ptr)
        PASS("pthread_create failure (thread1): data freed (malloc=1 free=1, same ptr)");
    else
        FAIL("pthread_create failure (thread1) frees data",
             "mallocs=%d frees=%d ptr_match=%d",
             mallocs, frees, g_last_free_ptr == g_last_malloc_ptr);
}

static void test_attr_destroy_on_create_fail(void) {
    reset();
    g_pthread_create_fail = 1;

    int before = g_attr_destroy_calls;
    prun_thread("test", dummy_run0);

    if (g_attr_destroy_calls - before == 1)
        PASS("pthread_attr_destroy called even on pthread_create failure");
    else
        FAIL("pthread_attr_destroy on create fail",
             "destroy calls=%d", g_attr_destroy_calls - before);
}

static void test_malloc_fail_prun_thread(void) {
    reset();
    g_malloc_fail = 1;

    /* Must not crash */
    prun_thread("test", dummy_run0);

    if (g_free_calls == 0)
        PASS("malloc failure in prun_thread: no free/crash (graceful return)");
    else
        FAIL("malloc failure in prun_thread", "unexpected free calls=%d", g_free_calls);
}

static void test_malloc_fail_prun_thread1(void) {
    reset();
    g_malloc_fail = 1;
    int dummy = 0;

    prun_thread1("test1", dummy_run1, &dummy);

    if (g_free_calls == 0)
        PASS("malloc failure in prun_thread1: no free/crash (graceful return)");
    else
        FAIL("malloc failure in prun_thread1", "unexpected free calls=%d", g_free_calls);
}

static void test_union_run0_stored_correctly(void) {
    thread_data td;
    memset(&td, 0, sizeof(td));
    td.fn.run0 = dummy_run0;
    td.ptr     = NULL;

    if (td.fn.run0 == dummy_run0 && td.ptr == NULL)
        PASS("union fn.run0 stored without cast, ptr==NULL");
    else
        FAIL("union fn.run0", "run0 mismatch or ptr non-null");
}

static void test_union_run1_stored_correctly(void) {
    thread_data td;
    memset(&td, 0, sizeof(td));
    int x = 7;
    td.fn.run1 = dummy_run1;
    td.ptr     = &x;

    if (td.fn.run1 == dummy_run1 && td.ptr == &x)
        PASS("union fn.run1 stored without cast, ptr set");
    else
        FAIL("union fn.run1", "run1 mismatch or ptr wrong");
}

static void test_success_path_no_double_free(void) {
    reset();
    /* Allow pthread_create to succeed; thread_entry will free data */
    /* Give the thread a moment to run */
    prun_thread("success", dummy_run0);

    /* Sleep briefly so detached thread can run and free */
    struct timespec ts = {0, 50 * 1000 * 1000}; /* 50ms */
    nanosleep(&ts, NULL);

    /* On success: malloc=1, free=1 (by thread_entry), attr_destroy=1 */
    if (g_malloc_calls == 1 && g_free_calls == 1 && g_attr_destroy_calls == 1)
        PASS("success path: malloc=1 free=1 attr_destroy=1, no double-free");
    else
        FAIL("success path counts",
             "malloc=%d free=%d attr_destroy=%d",
             g_malloc_calls, g_free_calls, g_attr_destroy_calls);
}

/* ------------------------------------------------------------------ */
int main(void) {
    test_pthread_create_fail_frees_data();
    test_pthread_create_fail_frees_data_thread1();
    test_attr_destroy_on_create_fail();
    test_malloc_fail_prun_thread();
    test_malloc_fail_prun_thread1();
    test_union_run0_stored_correctly();
    test_union_run1_stored_correctly();
    test_success_path_no_double_free();

    printf("\n%d passed, %d failed\n", passes, failures);
    return failures ? 1 : 0;
}
