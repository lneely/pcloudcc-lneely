/*
 * Test: ptools_set_backend_file_dates() errPtr freed between calls (pcl-dls)
 *
 * Verifies the fix in 11cecaa:
 *   - errPtr is freed (and NULLed) between the two ptools_backend_call() calls
 *   - errPtr is freed after the final call
 *   - No double-free occurs
 *   - NULL errPtr (no error on first call) is handled safely (no free of NULL)
 *
 * ptools_backend_call() needs a live backend so we replicate the exact
 * errPtr management pattern with a mock backend call and use --wrap=malloc/free
 * to track allocations.
 */

#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* ------------------------------------------------------------------ */
/* Allocation tracking via --wrap                                       */
/* ------------------------------------------------------------------ */
int   g_malloc_calls  = 0;
int   g_free_calls    = 0;
void *g_freed[64];
int   g_freed_count   = 0;
void *g_alloced[64];
int   g_alloced_count = 0;

void *__real_malloc(size_t);
void  __real_free(void *);

void *__wrap_malloc(size_t sz) {
    void *p = __real_malloc(sz);
    if (p && g_alloced_count < 64)
        g_alloced[g_alloced_count++] = p;
    g_malloc_calls++;
    return p;
}

void __wrap_free(void *p) {
    if (p && g_freed_count < 64)
        g_freed[g_freed_count++] = p;
    g_free_calls++;
    __real_free(p);
}

static void reset(void) {
    g_malloc_calls  = 0;
    g_free_calls    = 0;
    g_freed_count   = 0;
    g_alloced_count = 0;
    memset(g_freed,   0, sizeof(g_freed));
    memset(g_alloced, 0, sizeof(g_alloced));
}

static int was_freed(void *p) {
    for (int i = 0; i < g_freed_count; i++)
        if (g_freed[i] == p) return 1;
    return 0;
}

/* ------------------------------------------------------------------ */
/* Mock backend call                                                    */
/* Returns -1 and sets *errPtr when inject_error != 0.                */
/* ------------------------------------------------------------------ */
static int inject_error_call1 = 0;
static int inject_error_call2 = 0;

static int mock_backend_call_1(char **errPtr) {
    if (inject_error_call1) {
        *errPtr = (char *)malloc(32);
        if (*errPtr) strcpy(*errPtr, "ctime error");
        return -1;
    }
    /* success: errPtr unchanged (stays NULL or previous value) */
    return 0;
}

static int mock_backend_call_2(char **errPtr) {
    if (inject_error_call2) {
        *errPtr = (char *)malloc(32);
        if (*errPtr) strcpy(*errPtr, "mtime error");
        return -1;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* Replica of ptools_set_backend_file_dates() errPtr lifecycle (fixed) */
/* ------------------------------------------------------------------ */
static int run_fixed(void) {
    char *errPtr = NULL;
    int callRes;

    callRes = mock_backend_call_1(&errPtr);
    (void)callRes;

    /* Fix: free errPtr between calls */
    if (errPtr) {
        free(errPtr);
        errPtr = NULL;
    }

    callRes = mock_backend_call_2(&errPtr);
    (void)callRes;

    if (errPtr)
        free(errPtr);

    return 0;
}

/* ------------------------------------------------------------------ */
/* Replica of the OLD (unfixed) pattern — leaks errPtr between calls   */
/* ------------------------------------------------------------------ */
static int run_unfixed(void) {
    char *errPtr = NULL;
    int callRes;

    callRes = mock_backend_call_1(&errPtr);
    (void)callRes;

    /* BUG: errPtr NOT freed here — overwritten by call 2 */

    callRes = mock_backend_call_2(&errPtr);
    (void)callRes;

    if (errPtr)
        free(errPtr);

    return 0;
}

/* ------------------------------------------------------------------ */
static int passes = 0, failures = 0;
#define PASS(n)      do { printf("PASS: %s\n", n); passes++; } while(0)
#define FAIL(n, ...) do { printf("FAIL: %s — ", n); printf(__VA_ARGS__); printf("\n"); failures++; } while(0)

/* ------------------------------------------------------------------ */
/* Tests                                                                */
/* ------------------------------------------------------------------ */

/* Both calls succeed: no allocations, no frees */
static void test_both_succeed_no_leak(void) {
    reset();
    inject_error_call1 = 0;
    inject_error_call2 = 0;
    run_fixed();
    if (g_malloc_calls == 0 && g_free_calls == 0)
        PASS("both succeed: no malloc/free, no leak");
    else
        FAIL("both succeed no leak", "malloc=%d free=%d", g_malloc_calls, g_free_calls);
}

/* Call 1 sets errPtr, fixed code frees it before call 2 */
static void test_call1_error_freed_before_call2(void) {
    reset();
    inject_error_call1 = 1;
    inject_error_call2 = 0;
    run_fixed();

    /* 1 malloc (call1), 1 free (between calls) */
    void *p = g_alloced_count > 0 ? g_alloced[0] : NULL;
    if (g_malloc_calls == 1 && g_free_calls == 1 && p && was_freed(p))
        PASS("call1 error: errPtr freed before call2 (no leak)");
    else
        FAIL("call1 error freed before call2",
             "malloc=%d free=%d freed_ptr=%d", g_malloc_calls, g_free_calls, p ? was_freed(p) : -1);
}

/* Call 2 sets errPtr, freed after final call */
static void test_call2_error_freed_after(void) {
    reset();
    inject_error_call1 = 0;
    inject_error_call2 = 1;
    run_fixed();

    void *p = g_alloced_count > 0 ? g_alloced[0] : NULL;
    if (g_malloc_calls == 1 && g_free_calls == 1 && p && was_freed(p))
        PASS("call2 error: errPtr freed after final call (no leak)");
    else
        FAIL("call2 error freed after",
             "malloc=%d free=%d", g_malloc_calls, g_free_calls);
}

/* Both calls set errPtr: call1 ptr freed between, call2 ptr freed after */
static void test_both_error_both_freed(void) {
    reset();
    inject_error_call1 = 1;
    inject_error_call2 = 1;
    run_fixed();

    /* 2 mallocs, 2 frees, both pointers freed */
    void *p1 = g_alloced_count > 0 ? g_alloced[0] : NULL;
    void *p2 = g_alloced_count > 1 ? g_alloced[1] : NULL;
    if (g_malloc_calls == 2 && g_free_calls == 2
        && p1 && was_freed(p1) && p2 && was_freed(p2))
        PASS("both errors: both errPtrs freed, no leak, no double-free");
    else
        FAIL("both errors both freed",
             "malloc=%d free=%d p1_freed=%d p2_freed=%d",
             g_malloc_calls, g_free_calls,
             p1 ? was_freed(p1) : -1, p2 ? was_freed(p2) : -1);
}

/* Confirm the unfixed pattern LEAKS (documents what the fix corrects) */
static void test_unfixed_leaks(void) {
    reset();
    inject_error_call1 = 1;
    inject_error_call2 = 1;
    run_unfixed();

    /* 2 mallocs, only 1 free — p1 is leaked */
    void *p1 = g_alloced_count > 0 ? g_alloced[0] : NULL;
    void *p2 = g_alloced_count > 1 ? g_alloced[1] : NULL;
    if (g_malloc_calls == 2 && g_free_calls == 1
        && p1 && !was_freed(p1) && p2 && was_freed(p2))
        PASS("(unfixed pattern confirmed): call1 errPtr leaks when not freed between calls");
    else
        FAIL("unfixed pattern leak demonstration",
             "malloc=%d free=%d p1_freed=%d",
             g_malloc_calls, g_free_calls, p1 ? was_freed(p1) : -1);
}

/* NULL errPtr after free: second call on NULL is safe (no double-free) */
static void test_no_double_free(void) {
    reset();
    inject_error_call1 = 1;
    inject_error_call2 = 0;  /* call2 succeeds, errPtr stays NULL after mid-free */
    run_fixed();

    /* Only 1 malloc, 1 free */
    if (g_malloc_calls == 1 && g_free_calls == 1)
        PASS("no double-free: errPtr NULLed after mid-free, call2 success leaves it NULL");
    else
        FAIL("no double-free", "malloc=%d free=%d", g_malloc_calls, g_free_calls);
}

/* ------------------------------------------------------------------ */
int main(void) {
    test_both_succeed_no_leak();
    test_call1_error_freed_before_call2();
    test_call2_error_freed_after();
    test_both_error_both_freed();
    test_unfixed_leaks();
    test_no_double_free();

    printf("\n%d passed, %d failed\n", passes, failures);
    return failures ? 1 : 0;
}
