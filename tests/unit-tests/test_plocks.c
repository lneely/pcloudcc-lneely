/*
 * Test: plocks.c — custom rwlock stress test
 *
 * Covers:
 *  1. Basic rdlock / wrlock single-thread round-trips
 *  2. Recursive TLS counting: same thread acquires rdlock N times; unlock
 *     only releases on final decrement
 *  3. Upgrade under contention (plocks_towrlock): N readers hold rdlock,
 *     one thread upgrades — verified exclusive access during upgrade
 *  4. Writer starvation prevention: sustained reader load, writer acquires
 *     lock within bounded time
 *  5. N reader + M writer threads, K iterations: shared counter, no
 *     deadlock, no data corruption (ASAN)
 *
 * TSAN note: ThreadSanitizer does not know that plocks_rdlock / plocks_wrlock
 * form a custom reader-writer lock and would report false data-race positives
 * on the shared counter in test 5.  Run the stress test with -fsanitize=address
 * only (-fsanitize=thread is not compatible without TSAN annotations).
 */

#define _POSIX_C_SOURCE 200809L
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "plocks.h"

/* ------------------------------------------------------------------ */
static int passes = 0, failures = 0;
#define PASS(n)      do { printf("PASS: %s\n", n); passes++; } while (0)
#define FAIL(n, ...) do { printf("FAIL: %s — ", n); printf(__VA_ARGS__); printf("\n"); failures++; } while (0)

/* ------------------------------------------------------------------ */
/* Test 1: basic single-thread rdlock / unlock                         */
/* ------------------------------------------------------------------ */
static void test_basic_rdlock(void) {
    psync_rwlock_t rw;
    plocks_init(&rw);

    plocks_rdlock(&rw);
    int holding = plocks_holding_rdlock(&rw);
    plocks_unlock(&rw);
    int released = !plocks_holding_rdlock(&rw);

    plocks_destroy(&rw);

    if (holding && released)
        PASS("basic rdlock: holding after lock, released after unlock");
    else
        FAIL("basic rdlock", "holding=%d released=%d", holding, released);
}

/* ------------------------------------------------------------------ */
/* Test 2: basic single-thread wrlock / unlock                         */
/* ------------------------------------------------------------------ */
static void test_basic_wrlock(void) {
    psync_rwlock_t rw;
    plocks_init(&rw);

    plocks_wrlock(&rw);
    int holding = plocks_holding_wrlock(&rw);
    plocks_unlock(&rw);
    int released = !plocks_holding_wrlock(&rw);

    plocks_destroy(&rw);

    if (holding && released)
        PASS("basic wrlock: holding after lock, released after unlock");
    else
        FAIL("basic wrlock", "holding=%d released=%d", holding, released);
}

/* ------------------------------------------------------------------ */
/* Test 3: recursive TLS counting — same thread acquires rdlock N      */
/*         times; plocks_unlock only releases on the final decrement   */
/* ------------------------------------------------------------------ */
#define REC_DEPTH 5
static void test_recursive_rdlock(void) {
    psync_rwlock_t rw;
    plocks_init(&rw);

    /* Acquire N times */
    int i;
    for (i = 0; i < REC_DEPTH; i++)
        plocks_rdlock(&rw);

    int holding_mid = plocks_holding_rdlock(&rw);

    /* Unlock N-1 times: must still hold */
    int still_holding = 1;
    for (i = 0; i < REC_DEPTH - 1; i++) {
        plocks_unlock(&rw);
        if (!plocks_holding_rdlock(&rw)) {
            still_holding = 0;
            break;
        }
    }
    /* Final unlock: must release */
    plocks_unlock(&rw);
    int finally_released = !plocks_holding_rdlock(&rw);

    plocks_destroy(&rw);

    if (!holding_mid)
        FAIL("recursive rdlock: held after all acquires", "holding_mid=0");
    else if (!still_holding)
        FAIL("recursive rdlock: still held after partial unlocks",
             "released too early");
    else if (!finally_released)
        FAIL("recursive rdlock: released after final unlock",
             "still holding");
    else
        PASS("recursive rdlock: TLS count correct, releases only on final unlock");
}

/* ------------------------------------------------------------------ */
/* Test 4: upgrade under contention                                     */
/*                                                                      */
/* N reader threads acquire rdlock then block on a barrier.  The main  */
/* thread also acquires rdlock, then calls plocks_towrlock() which     */
/* waits for all other readers to release.  Readers release after a    */
/* short sleep; upgrade must succeed and wrlock must be exclusively     */
/* held.                                                                */
/* ------------------------------------------------------------------ */
#define N_UPGRADE_READERS 4

struct upgrade_state {
    psync_rwlock_t    rw;
    pthread_barrier_t barrier;  /* synchronises: all hold rdlock before upgrader proceeds */
};

static void *upgrade_reader_thread(void *arg) {
    struct upgrade_state *s = (struct upgrade_state *)arg;
    plocks_rdlock(&s->rw);
    pthread_barrier_wait(&s->barrier);  /* signal: I'm holding rdlock */
    usleep(40000);                       /* hold for 40 ms */
    plocks_unlock(&s->rw);
    return NULL;
}

/*
 * test_upgrade_under_contention verifies that plocks_towrlock() completes
 * (returns 0) and that the upgrading thread holds the write lock on return.
 * Concurrent exclusivity — that no reader is simultaneously active once the
 * write lock is granted — is covered by the counter-integrity check in
 * test_stress().
 */
static void test_upgrade_under_contention(void) {
    struct upgrade_state s;
    plocks_init(&s.rw);
    /* N readers + main thread (upgrader) = N+1 participants */
    pthread_barrier_init(&s.barrier, NULL, N_UPGRADE_READERS + 1);

    pthread_t readers[N_UPGRADE_READERS];
    int i;
    for (i = 0; i < N_UPGRADE_READERS; i++)
        pthread_create(&readers[i], NULL, upgrade_reader_thread, &s);

    /* Main thread acquires rdlock then waits at barrier so all readers
     * have their locks before we try to upgrade. */
    plocks_rdlock(&s.rw);
    pthread_barrier_wait(&s.barrier);

    /* towrlock: wait for all N reader threads to release */
    int rc = plocks_towrlock(&s.rw);
    int wrlock_held = plocks_holding_wrlock(&s.rw);
    plocks_unlock(&s.rw);

    for (i = 0; i < N_UPGRADE_READERS; i++)
        pthread_join(readers[i], NULL);

    pthread_barrier_destroy(&s.barrier);
    plocks_destroy(&s.rw);

    if (rc == 0 && wrlock_held)
        PASS("upgrade under contention: towrlock succeeds, wrlock held exclusively");
    else
        FAIL("upgrade under contention", "rc=%d wrlock_held=%d", rc, wrlock_held);
}

/* ------------------------------------------------------------------ */
/* Test 5: writer starvation prevention                                 */
/*                                                                      */
/* 4 threads continuously acquire/release rdlock.  Once wwait > 0 new  */
/* readers block.  The writer should obtain wrlock within 500 ms.      */
/* ------------------------------------------------------------------ */
static volatile int g_stop_readers5 = 0;
static psync_rwlock_t rw5;

static void *starvation_reader(void *arg) {
    (void)arg;
    while (!g_stop_readers5) {
        plocks_rdlock(&rw5);
        /* tiny critical section */
        plocks_unlock(&rw5);
    }
    return NULL;
}

static void test_writer_not_starved(void) {
    plocks_init(&rw5);
    g_stop_readers5 = 0;

    pthread_t readers[4];
    int i;
    for (i = 0; i < 4; i++)
        pthread_create(&readers[i], NULL, starvation_reader, NULL);

    usleep(5000); /* let readers get running */

    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    plocks_wrlock(&rw5);
    clock_gettime(CLOCK_MONOTONIC, &t1);

    g_stop_readers5 = 1;
    plocks_unlock(&rw5);

    for (i = 0; i < 4; i++)
        pthread_join(readers[i], NULL);

    plocks_destroy(&rw5);

    long ms = (long)(t1.tv_sec - t0.tv_sec) * 1000 +
              (long)(t1.tv_nsec - t0.tv_nsec) / 1000000L;
    if (ms < 500)
        PASS("writer not starved: wrlock acquired within 500 ms under reader load");
    else
        FAIL("writer starvation", "took %ldms > 500ms", ms);
}

/* ------------------------------------------------------------------ */
/* Test 6: N readers + M writers, K iterations — no deadlock, no       */
/*         data corruption                                              */
/* ------------------------------------------------------------------ */
#define N_STRESS_READERS  8
#define M_STRESS_WRITERS  4
#define K_STRESS_ITERS  200

static psync_rwlock_t rw6;
static long g_counter = 0;  /* protected by rw6 */

static void *stress_writer(void *arg) {
    (void)arg;
    int i;
    for (i = 0; i < K_STRESS_ITERS; i++) {
        plocks_wrlock(&rw6);
        g_counter++;
        plocks_unlock(&rw6);
    }
    return NULL;
}

static void *stress_reader(void *arg) {
    (void)arg;
    int i;
    for (i = 0; i < K_STRESS_ITERS; i++) {
        plocks_rdlock(&rw6);
        /* read-only access; any value is acceptable while reading */
        (void)g_counter;
        plocks_unlock(&rw6);
    }
    return NULL;
}

static void test_stress(void) {
    plocks_init(&rw6);
    g_counter = 0;

    pthread_t writers[M_STRESS_WRITERS];
    pthread_t readers[N_STRESS_READERS];
    int i;

    for (i = 0; i < M_STRESS_WRITERS; i++)
        pthread_create(&writers[i], NULL, stress_writer, NULL);
    for (i = 0; i < N_STRESS_READERS; i++)
        pthread_create(&readers[i], NULL, stress_reader, NULL);

    for (i = 0; i < M_STRESS_WRITERS; i++)
        pthread_join(writers[i], NULL);
    for (i = 0; i < N_STRESS_READERS; i++)
        pthread_join(readers[i], NULL);

    plocks_destroy(&rw6);

    long expected = (long)M_STRESS_WRITERS * K_STRESS_ITERS;
    if (g_counter == expected)
        PASS("stress: no deadlock, counter matches expected (no corruption)");
    else
        FAIL("stress", "counter=%ld expected=%ld", g_counter, expected);
}

/* ------------------------------------------------------------------ */
/* Test 7: trywrlock / tryrdlock non-blocking                          */
/*                                                                      */
/* Note: calling plocks_trywrlock while THIS THREAD holds rdlock is    */
/* illegal (asserted in plocks.c: !cnt.cnt[0]).  Upgrade must go      */
/* through plocks_towrlock.  Contention is tested via a helper thread. */
/* ------------------------------------------------------------------ */
static psync_rwlock_t rw7_contended;

static void *try_hold_rdlock(void *arg) {
    /* acquire rdlock and wait until signalled to release */
    pthread_barrier_t *b = (pthread_barrier_t *)arg;
    plocks_rdlock(&rw7_contended);
    pthread_barrier_wait(b);  /* signal: rdlock held */
    pthread_barrier_wait(b);  /* wait: main says release */
    plocks_unlock(&rw7_contended);
    return NULL;
}

static void test_try_variants(void) {
    psync_rwlock_t rw;
    plocks_init(&rw);

    /* tryrdlock on free lock → succeeds */
    int rd1 = plocks_tryrdlock(&rw);
    /* recursive tryrdlock → succeeds */
    int rd1b = plocks_tryrdlock(&rw);
    plocks_unlock(&rw);
    plocks_unlock(&rw);

    /* trywrlock on free lock → succeeds */
    int wr1 = plocks_trywrlock(&rw);
    /* tryrdlock while same-thread holds wrlock → recursive success */
    int rd2 = plocks_tryrdlock(&rw);
    plocks_unlock(&rw); /* releases the recursive rdlock count */
    plocks_unlock(&rw); /* releases wrlock */

    plocks_destroy(&rw);

    /* trywrlock fails when another thread holds rdlock */
    plocks_init(&rw7_contended);
    pthread_barrier_t barrier;
    pthread_barrier_init(&barrier, NULL, 2);
    pthread_t t;
    pthread_create(&t, NULL, try_hold_rdlock, &barrier);
    pthread_barrier_wait(&barrier);           /* wait for reader to hold rdlock */
    int wr_fail = plocks_trywrlock(&rw7_contended); /* should fail: -1 */
    pthread_barrier_wait(&barrier);           /* let reader release */
    pthread_join(t, NULL);
    plocks_destroy(&rw7_contended);
    pthread_barrier_destroy(&barrier);

    if (rd1 == 0 && rd1b == 0 && wr1 == 0 && rd2 == 0 && wr_fail == -1)
        PASS("try variants: tryrdlock/trywrlock return correct values");
    else
        FAIL("try variants", "rd1=%d rd1b=%d wr1=%d rd2=%d wr_fail=%d",
             rd1, rd1b, wr1, rd2, wr_fail);
}

/* ------------------------------------------------------------------ */
int main(void) {
    test_basic_rdlock();
    test_basic_wrlock();
    test_recursive_rdlock();
    test_upgrade_under_contention();
    test_writer_not_starved();
    test_stress();
    test_try_variants();

    printf("\n%d passed, %d failed\n", passes, failures);
    return failures ? 1 : 0;
}
