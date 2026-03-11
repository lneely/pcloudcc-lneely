/*
 * ptask_free.c — psync_task_manager_t lifecycle: destroy and free.
 *
 * Extracted from ptask.c as a separately compilable unit so that
 * tests/unit-tests/test_ptask_free.c can link against this file alone,
 * without dragging in ptask.c's heavyweight dependencies (papi, psql,
 * pdeflate, …).
 *
 * Fix: b92a389 — mutex is held during the refcnt check in all paths.
 */

#include <pthread.h>
#include <stddef.h>

#include "pmem.h"
#include "ptask_free_internal.h"

/* ------------------------------------------------------------------ */
/* Static helpers                                                       */
/* ------------------------------------------------------------------ */

static void psync_task_destroy(psync_task_manager_t tm) {
    int i;
    for (i = 0; i < tm->taskcnt; i++)
        pthread_cond_destroy(&tm->tasks[i].cond);
    pthread_mutex_destroy(&tm->mutex);
    pmem_free(PMEM_SUBSYS_OTHER, tm);
}

static void psync_task_dec_refcnt(psync_task_manager_t tm) {
    int refcnt;
    pthread_mutex_lock(&tm->mutex);
    refcnt = --tm->refcnt;
    pthread_mutex_unlock(&tm->mutex);
    if (!refcnt)
        psync_task_destroy(tm);
}

/* ------------------------------------------------------------------ */
/* Thread entry-point (non-static: referenced from psync_task_run_tasks
 * in ptask.c via the forward declaration in ptask_free_internal.h)    */
/* ------------------------------------------------------------------ */

void psync_task_entry(void *ptr) {
    struct psync_task_t_ *t = (struct psync_task_t_ *)ptr;
    t->callback(ptr, t->param);
    psync_task_dec_refcnt(psync_get_manager_of_task(t));
}

/* ------------------------------------------------------------------ */
/* Public API                                                           */
/* ------------------------------------------------------------------ */

void psync_task_free(psync_task_manager_t tm) {
    int refcnt, i;
    pthread_mutex_lock(&tm->mutex);
    if (tm->refcnt == 1) {
        pthread_mutex_unlock(&tm->mutex);
        psync_task_destroy(tm);
    } else {
        tm->waitfor = PSYNC_WAIT_FREED;
        for (i = 0; i < tm->taskcnt; i++)
            if (tm->tasks[i].status == PSYNC_TASK_STATUS_READY) {
                tm->tasks[i].status = PSYNC_TASK_STATUS_RETURNED;
                pthread_cond_signal(&tm->tasks[i].cond);
            }
        refcnt = --tm->refcnt;
        pthread_mutex_unlock(&tm->mutex);
        if (!refcnt)
            psync_task_destroy(tm);
    }
}
