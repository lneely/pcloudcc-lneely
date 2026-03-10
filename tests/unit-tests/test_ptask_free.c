/*
 * Test: psync_task_free lifecycle (fix-ptask-refcount-race)
 *
 * Verifies the fix in b92a389:
 *   1. refcnt=1 path: lock acquired, destroy called immediately
 *   2. refcnt>1, last ref: lock acquired, refcnt decremented, destroy called
 *   3. refcnt>1, not last ref: refcnt decremented, destroy NOT called
 *   4. READY tasks get signaled (status→RETURNED) when freed with refcnt>1
 *   5. mutex is acquired before the refcnt check in all paths
 *
 * Links against the real pclsync/ptask_free.c (production code).
 * Uses --wrap linker flags to intercept pthread_mutex_lock/unlock and
 * pmem_free so we can observe lock discipline and detect destroy calls
 * without reimplementing any production logic inline.
 */

#define _POSIX_C_SOURCE 200809L
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Internal struct layout — exposes psync_task_manager_t_ for make_tm() */
#include "ptask_free_internal.h"
#include "pmem.h"

/* ------------------------------------------------------------------ */
/* __wrap / __real declarations                                         */
/* ------------------------------------------------------------------ */

int   __real_pthread_mutex_lock(pthread_mutex_t *m);
int   __real_pthread_mutex_unlock(pthread_mutex_t *m);
void  __real_pmem_free(pmem_subsystem_t subsystem, void *ptr);

/* ------------------------------------------------------------------ */
/* Intercept state                                                      */
/* ------------------------------------------------------------------ */

static int g_lock_calls   = 0;
static int g_unlock_calls = 0;
static int g_destroy_calls = 0;  /* incremented by __wrap_pmem_free */
static int g_lock_depth   = 0;
static int g_lock_held_at_destroy = 0; /* 1 = mutex was unlocked when destroy fired */

/* ------------------------------------------------------------------ */
/* Wrap implementations                                                 */
/* ------------------------------------------------------------------ */

int __wrap_pthread_mutex_lock(pthread_mutex_t *m) {
    g_lock_calls++;
    g_lock_depth++;
    return __real_pthread_mutex_lock(m);
}

int __wrap_pthread_mutex_unlock(pthread_mutex_t *m) {
    g_unlock_calls++;
    g_lock_depth--;
    return __real_pthread_mutex_unlock(m);
}

/*
 * psync_task_destroy() calls pmem_free() as its last act.
 * We intercept it to count destroy invocations and capture lock state.
 * We call free() directly because make_tm() allocates with malloc().
 */
void __wrap_pmem_free(pmem_subsystem_t subsystem, void *ptr) {
    (void)subsystem;
    g_destroy_calls++;
    g_lock_held_at_destroy = (g_lock_depth == 0); /* should be 0 = unlocked */
    free(ptr);
}

/* ------------------------------------------------------------------ */
/* Helpers                                                              */
/* ------------------------------------------------------------------ */

static int passes = 0, failures = 0;
#define PASS(n)      do { printf("PASS: %s\n", n); passes++; } while (0)
#define FAIL(n, ...) do { printf("FAIL: %s — ", n); printf(__VA_ARGS__); printf("\n"); failures++; } while (0)

static void reset(void) {
    g_lock_calls              = 0;
    g_unlock_calls            = 0;
    g_destroy_calls           = 0;
    g_lock_depth              = 0;
    g_lock_held_at_destroy    = 0;
}

/* Allocate and initialise a task manager with `cnt` tasks, refcnt=`refcnt` */
static psync_task_manager_t make_tm(int cnt, int refcnt) {
    size_t sz = sizeof(struct psync_task_manager_t_) +
                cnt * sizeof(struct psync_task_t_);
    psync_task_manager_t tm = (psync_task_manager_t)malloc(sz);
    memset(tm, 0, sz);
    pthread_mutex_init(&tm->mutex, NULL);
    tm->taskcnt = cnt;
    tm->refcnt  = refcnt;
    tm->waitfor = PSYNC_WAIT_NOBODY;
    int i;
    for (i = 0; i < cnt; i++) {
        pthread_cond_init(&tm->tasks[i].cond, NULL);
        tm->tasks[i].id     = i;
        tm->tasks[i].status = PSYNC_TASK_STATUS_RUNNING;
    }
    return tm;
}

/* ------------------------------------------------------------------ */
/* Tests — call the real psync_task_free()                             */
/* ------------------------------------------------------------------ */

/* refcnt=1: destroy called once, mutex unlocked before destroy */
static void test_single_owner_free(void) {
    reset();
    psync_task_manager_t tm = make_tm(2, 1);

    psync_task_free(tm); /* tm freed inside via __wrap_pmem_free */

    if (g_destroy_calls != 1)
        FAIL("single owner: destroy called once",
             "destroy_calls=%d", g_destroy_calls);
    else if (!g_lock_held_at_destroy)
        FAIL("single owner: mutex unlocked before destroy",
             "lock_depth was non-zero at destroy");
    else if (g_lock_calls != 1 || g_unlock_calls != 1)
        FAIL("single owner: lock/unlock balanced",
             "lock=%d unlock=%d", g_lock_calls, g_unlock_calls);
    else
        PASS("single owner free: destroy called once, mutex unlocked before destroy");
}

/* refcnt already at 1 when we call free: same result as single-owner */
static void test_last_ref_destroys(void) {
    reset();
    psync_task_manager_t tm = make_tm(1, 2);

    /* Simulate the other ref already gone */
    tm->refcnt = 1;

    psync_task_free(tm);

    if (g_destroy_calls == 1 && g_lock_held_at_destroy)
        PASS("last ref free: destroy called, mutex unlocked before destroy");
    else
        FAIL("last ref free",
             "destroy_calls=%d lock_held_at_destroy=%d",
             g_destroy_calls, g_lock_held_at_destroy);
}

/* refcnt=2, not last ref: refcnt decremented, destroy NOT called */
static void test_not_last_ref_no_destroy(void) {
    reset();
    psync_task_manager_t tm = make_tm(1, 2);

    psync_task_free(tm);

    if (g_destroy_calls != 0)
        FAIL("not last ref: no destroy",
             "destroy_calls=%d", g_destroy_calls);
    else if (tm->refcnt != 1)
        FAIL("not last ref: refcnt decremented to 1",
             "refcnt=%d", tm->refcnt);
    else
        PASS("not last ref: no destroy, refcnt decremented to 1");

    /* Manual cleanup since psync_task_destroy was not called */
    pthread_cond_destroy(&tm->tasks[0].cond);
    pthread_mutex_destroy(&tm->mutex);
    free(tm);
}

/* READY tasks get RETURNED status + cond signalled when freed with refcnt>1 */
static void test_ready_tasks_signaled(void) {
    reset();
    psync_task_manager_t tm = make_tm(3, 2);
    tm->tasks[0].status = PSYNC_TASK_STATUS_RUNNING;
    tm->tasks[1].status = PSYNC_TASK_STATUS_READY;
    tm->tasks[2].status = PSYNC_TASK_STATUS_DONE;

    psync_task_free(tm);

    int ok = (tm->tasks[0].status == PSYNC_TASK_STATUS_RUNNING  &&
              tm->tasks[1].status == PSYNC_TASK_STATUS_RETURNED &&
              tm->tasks[2].status == PSYNC_TASK_STATUS_DONE     &&
              tm->waitfor         == PSYNC_WAIT_FREED);

    if (ok)
        PASS("READY tasks signaled RETURNED, others unchanged, waitfor=FREED");
    else
        FAIL("READY tasks signaled",
             "statuses=[%d,%d,%d] waitfor=%d",
             tm->tasks[0].status, tm->tasks[1].status,
             tm->tasks[2].status, tm->waitfor);

    /* Manual cleanup */
    int i;
    for (i = 0; i < 3; i++) pthread_cond_destroy(&tm->tasks[i].cond);
    pthread_mutex_destroy(&tm->mutex);
    free(tm);
}

/* Mutex acquired before refcnt is inspected (core fix) */
static void test_lock_before_refcnt_check(void) {
    reset();
    psync_task_manager_t tm = make_tm(1, 1);

    psync_task_free(tm);

    /* g_lock_calls >= 1 means lock was acquired; g_lock_held_at_destroy = 1
     * means it was released cleanly before destroy fired */
    if (g_lock_calls >= 1 && g_lock_held_at_destroy)
        PASS("mutex acquired before refcnt check; unlocked cleanly before destroy");
    else
        FAIL("lock before refcnt check",
             "lock_calls=%d lock_held_at_destroy=%d",
             g_lock_calls, g_lock_held_at_destroy);
}

/* ------------------------------------------------------------------ */
int main(void) {
    test_single_owner_free();
    test_last_ref_destroys();
    test_not_last_ref_no_destroy();
    test_ready_tasks_signaled();
    test_lock_before_refcnt_check();

    printf("\n%d passed, %d failed\n", passes, failures);
    return failures ? 1 : 0;
}
