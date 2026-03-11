/*
 * ptask_free_internal.h — internal layout of psync_task_manager_t.
 *
 * Included by:
 *   - pclsync/ptask_free.c  (production lifecycle code)
 *   - pclsync/ptask.c       (rest of the task subsystem)
 *   - tests/unit-tests/test_ptask_free.c  (struct-level access in tests)
 *
 * NOT part of the public API.  Do not include from general application code.
 */
#ifndef PTASK_FREE_INTERNAL_H
#define PTASK_FREE_INTERNAL_H

#include <pthread.h>
#include <stddef.h>

/*
 * Provide minimal forward declarations when this header is included
 * standalone (e.g. from the test).  When ptask.h has already been
 * included its include guard (_PSYNC_TASKS_H) suppresses the duplicates.
 */
#ifndef _PSYNC_TASKS_H
typedef void (*psync_task_callback_t)(void *, void *);
struct psync_task_manager_t_;
typedef struct psync_task_manager_t_ *psync_task_manager_t;
#endif

/* Task status values */
#define PSYNC_TASK_STATUS_RUNNING  0
#define PSYNC_TASK_STATUS_READY    1
#define PSYNC_TASK_STATUS_DONE     2
#define PSYNC_TASK_STATUS_RETURNED 3

/* waitfor sentinel values */
// #define PSYNC_WAIT_ANYBODY -1  /* unused, but may be useful later */
#define PSYNC_WAIT_NOBODY -2
#define PSYNC_WAIT_FREED  -3

struct psync_task_t_ {
    psync_task_callback_t callback;
    void *param;
    pthread_cond_t cond;
    int id;
    int status;
};

struct psync_task_manager_t_ {
    pthread_mutex_t mutex;
    int taskcnt;
    int refcnt;
    int waitfor;
    struct psync_task_t_ tasks[];
};

/*
 * Helper: given a pointer to an individual task, return the owning manager.
 * Declared static inline so both ptask.c and ptask_free.c can use it
 * without any linkage conflict.
 */
static inline psync_task_manager_t
psync_get_manager_of_task(struct psync_task_t_ *t) {
    return (psync_task_manager_t)(((char *)(t - t->id)) -
                                  offsetof(struct psync_task_manager_t_, tasks));
}

/* Defined in ptask_free.c; declared in ptask.h for normal callers. */
void psync_task_free(psync_task_manager_t tm);

/*
 * psync_task_entry is defined in ptask_free.c and used as a thread
 * entry-point in psync_task_run_tasks (ptask.c).
 */
void psync_task_entry(void *ptr);

#endif /* PTASK_FREE_INTERNAL_H */
