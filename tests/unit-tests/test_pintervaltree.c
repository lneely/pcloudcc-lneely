/*
 * Test: pintervaltree.c — interval tree (add, remove, merge, split, cut_end)
 *
 * Exercises psync_interval_tree_add, _remove, _cut_end, _free, and the
 * inline helpers first_interval_containing_or_after / get_first / get_next.
 * Memory is managed by pintervaltree.c via pmem; tests call _free() at the
 * end of each case to avoid leaks.
 */

#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdint.h>

#include "pintervaltree.h"

/* ------------------------------------------------------------------ */
/* Helpers                                                              */
/* ------------------------------------------------------------------ */

static int passes = 0, failures = 0;
#define PASS(n)      do { printf("PASS: %s\n", n); passes++; } while (0)
#define FAIL(n, ...) do { printf("FAIL: %s — ", n); printf(__VA_ARGS__); printf("\n"); failures++; } while (0)

static int count_intervals(psync_interval_tree_t *tree) {
    int n = 0;
    psync_interval_tree_t *it;
    psync_interval_tree_for_each(it, tree) n++;
    return n;
}

/* Find an interval with exact [from, to] */
static int has_interval(psync_interval_tree_t *tree, uint64_t from, uint64_t to) {
    psync_interval_tree_t *it;
    psync_interval_tree_for_each(it, tree)
        if (it->from == from && it->to == to) return 1;
    return 0;
}

/* ------------------------------------------------------------------ */
/* Tests                                                                */
/* ------------------------------------------------------------------ */

/* Add a single interval; verify it's stored correctly */
static void test_add_single(void) {
    psync_interval_tree_t *tree = NULL;
    psync_interval_tree_add(&tree, 10, 20);
    if (!tree)
        { FAIL("add single: tree non-null", "tree is NULL"); return; }
    if (count_intervals(tree) != 1)
        FAIL("add single: count", "expected 1 got %d", count_intervals(tree));
    else if (!has_interval(tree, 10, 20))
        FAIL("add single: [10,20] present", "not found");
    else
        PASS("add single interval [10,20]");
    psync_interval_tree_free(tree);
}

/* Two non-overlapping, non-adjacent intervals: no merging */
static void test_add_non_overlapping(void) {
    psync_interval_tree_t *tree = NULL;
    psync_interval_tree_add(&tree, 10, 20);
    psync_interval_tree_add(&tree, 30, 40);
    if (count_intervals(tree) != 2)
        FAIL("non-overlapping: count", "expected 2 got %d", count_intervals(tree));
    else if (!has_interval(tree, 10, 20) || !has_interval(tree, 30, 40))
        FAIL("non-overlapping: both present", "one missing");
    else
        PASS("two non-overlapping intervals stored separately");
    psync_interval_tree_free(tree);
}

/* Overlapping: [10,20] then [15,30] → merged to [10,30] */
static void test_add_overlapping_merge(void) {
    psync_interval_tree_t *tree = NULL;
    psync_interval_tree_add(&tree, 10, 20);
    psync_interval_tree_add(&tree, 15, 30);
    if (count_intervals(tree) != 1)
        FAIL("overlapping merge: count", "expected 1 got %d", count_intervals(tree));
    else if (!has_interval(tree, 10, 30))
        FAIL("overlapping merge: [10,30]", "not found");
    else
        PASS("overlapping intervals merged to [10,30]");
    psync_interval_tree_free(tree);
}

/* Adjacent: [10,20] then [20,30] → merged to [10,30] */
static void test_add_adjacent_merge(void) {
    psync_interval_tree_t *tree = NULL;
    psync_interval_tree_add(&tree, 10, 20);
    psync_interval_tree_add(&tree, 20, 30);
    if (count_intervals(tree) != 1)
        FAIL("adjacent merge: count", "expected 1 got %d", count_intervals(tree));
    else if (!has_interval(tree, 10, 30))
        FAIL("adjacent merge: [10,30]", "not found");
    else
        PASS("adjacent intervals [10,20]+[20,30] merged to [10,30]");
    psync_interval_tree_free(tree);
}

/* Contained: add [10,30], then add [15,20] → no change (subset already covered) */
static void test_add_contained(void) {
    psync_interval_tree_t *tree = NULL;
    psync_interval_tree_add(&tree, 10, 30);
    psync_interval_tree_add(&tree, 15, 20);
    if (count_intervals(tree) != 1)
        FAIL("contained: count", "expected 1 got %d", count_intervals(tree));
    else if (!has_interval(tree, 10, 30))
        FAIL("contained: [10,30] unchanged", "not found");
    else
        PASS("adding contained interval is a no-op");
    psync_interval_tree_free(tree);
}

/* Spanning: add [15,25], then add [10,30] → becomes [10,30] */
static void test_add_spanning(void) {
    psync_interval_tree_t *tree = NULL;
    psync_interval_tree_add(&tree, 15, 25);
    psync_interval_tree_add(&tree, 10, 30);
    if (count_intervals(tree) != 1)
        FAIL("spanning: count", "expected 1 got %d", count_intervals(tree));
    else if (!has_interval(tree, 10, 30))
        FAIL("spanning: [10,30]", "not found");
    else
        PASS("spanning interval replaces smaller existing interval");
    psync_interval_tree_free(tree);
}

/* Merge multiple intervals: [5,10]+[10,15]+[15,20] → [5,20] */
static void test_add_chain_merge(void) {
    psync_interval_tree_t *tree = NULL;
    psync_interval_tree_add(&tree, 5,  10);
    psync_interval_tree_add(&tree, 10, 15);
    psync_interval_tree_add(&tree, 15, 20);
    if (count_intervals(tree) != 1)
        FAIL("chain merge: count", "expected 1 got %d", count_intervals(tree));
    else if (!has_interval(tree, 5, 20))
        FAIL("chain merge: [5,20]", "not found");
    else
        PASS("three adjacent intervals merged into [5,20]");
    psync_interval_tree_free(tree);
}

/* Remove middle: [10,30] → remove [15,20] → [10,15] and [20,30] */
static void test_remove_middle_split(void) {
    psync_interval_tree_t *tree = NULL;
    psync_interval_tree_add(&tree, 10, 30);
    psync_interval_tree_remove(&tree, 15, 20);
    if (count_intervals(tree) != 2)
        FAIL("remove middle: count", "expected 2 got %d", count_intervals(tree));
    else if (!has_interval(tree, 10, 15) || !has_interval(tree, 20, 30))
        FAIL("remove middle: split halves",
             "[10,15]=%d [20,30]=%d",
             has_interval(tree, 10, 15), has_interval(tree, 20, 30));
    else
        PASS("remove middle splits [10,30] into [10,15] and [20,30]");
    psync_interval_tree_free(tree);
}

/* Remove exact interval: [10,20] → remove [10,20] → empty */
static void test_remove_exact(void) {
    psync_interval_tree_t *tree = NULL;
    psync_interval_tree_add(&tree, 10, 20);
    psync_interval_tree_remove(&tree, 10, 20);
    if (count_intervals(tree) != 0)
        FAIL("remove exact: empty", "expected 0 got %d", count_intervals(tree));
    else
        PASS("remove exact interval leaves tree empty");
    /* tree may be NULL here; free handles NULL */
    psync_interval_tree_free(tree);
}

/* Remove left overlap: [10,30] → remove [5,15] → [15,30] */
static void test_remove_left_overlap(void) {
    psync_interval_tree_t *tree = NULL;
    psync_interval_tree_add(&tree, 10, 30);
    psync_interval_tree_remove(&tree, 5, 15);
    if (count_intervals(tree) != 1)
        FAIL("remove left: count", "expected 1 got %d", count_intervals(tree));
    else if (!has_interval(tree, 15, 30))
        FAIL("remove left: [15,30]", "not found");
    else
        PASS("remove left overlap: [10,30] clipped to [15,30]");
    psync_interval_tree_free(tree);
}

/* Remove right overlap: [10,30] → remove [25,35] → [10,25] */
static void test_remove_right_overlap(void) {
    psync_interval_tree_t *tree = NULL;
    psync_interval_tree_add(&tree, 10, 30);
    psync_interval_tree_remove(&tree, 25, 35);
    if (count_intervals(tree) != 1)
        FAIL("remove right: count", "expected 1 got %d", count_intervals(tree));
    else if (!has_interval(tree, 10, 25))
        FAIL("remove right: [10,25]", "not found");
    else
        PASS("remove right overlap: [10,30] clipped to [10,25]");
    psync_interval_tree_free(tree);
}

/* Remove spanning: [10,20]+[30,40] → remove [5,45] → empty */
static void test_remove_spanning(void) {
    psync_interval_tree_t *tree = NULL;
    psync_interval_tree_add(&tree, 10, 20);
    psync_interval_tree_add(&tree, 30, 40);
    psync_interval_tree_remove(&tree, 5, 45);
    if (count_intervals(tree) != 0)
        FAIL("remove spanning: empty", "expected 0 got %d", count_intervals(tree));
    else
        PASS("remove spanning erases all intervals");
    psync_interval_tree_free(tree);
}

/* cut_end: [10,20]+[30,40]+[50,60] → cut_end(35) → [10,20]+[30,35] */
static void test_cut_end(void) {
    psync_interval_tree_t *tree = NULL;
    psync_interval_tree_add(&tree, 10, 20);
    psync_interval_tree_add(&tree, 30, 40);
    psync_interval_tree_add(&tree, 50, 60);
    psync_interval_tree_cut_end(&tree, 35);
    if (count_intervals(tree) != 2)
        FAIL("cut_end: count", "expected 2 got %d", count_intervals(tree));
    else if (!has_interval(tree, 10, 20) || !has_interval(tree, 30, 35))
        FAIL("cut_end: [10,20] and [30,35]",
             "[10,20]=%d [30,35]=%d",
             has_interval(tree, 10, 20), has_interval(tree, 30, 35));
    else
        PASS("cut_end(35) leaves [10,20]+[30,35]");
    psync_interval_tree_free(tree);
}

/* cut_end at 0: all intervals removed */
static void test_cut_end_all(void) {
    psync_interval_tree_t *tree = NULL;
    psync_interval_tree_add(&tree, 10, 20);
    psync_interval_tree_add(&tree, 30, 40);
    psync_interval_tree_cut_end(&tree, 0);
    if (count_intervals(tree) != 0)
        FAIL("cut_end(0): all removed", "expected 0 got %d", count_intervals(tree));
    else
        PASS("cut_end(0) removes all intervals");
    psync_interval_tree_free(tree);
}

/* first_interval_containing_or_after: find first interval containing a point */
static void test_first_containing_or_after(void) {
    psync_interval_tree_t *tree = NULL;
    psync_interval_tree_add(&tree, 10, 20);
    psync_interval_tree_add(&tree, 30, 40);
    psync_interval_tree_add(&tree, 50, 60);

    /* point within first interval */
    psync_interval_tree_t *r = psync_interval_tree_first_interval_containing_or_after(tree, 15);
    if (!r || r->from != 10 || r->to != 20)
        FAIL("containing_or_after: point inside", "from=%llu to=%llu",
             r ? (unsigned long long)r->from : 0, r ? (unsigned long long)r->to : 0);
    else
        PASS("first_containing_or_after: point inside interval");

    /* point between intervals → returns next interval */
    r = psync_interval_tree_first_interval_containing_or_after(tree, 25);
    if (!r || r->from != 30 || r->to != 40)
        FAIL("containing_or_after: gap → next", "from=%llu to=%llu",
             r ? (unsigned long long)r->from : 0, r ? (unsigned long long)r->to : 0);
    else
        PASS("first_containing_or_after: gap returns next interval");

    /* point past all intervals → NULL */
    r = psync_interval_tree_first_interval_containing_or_after(tree, 70);
    if (r != NULL)
        FAIL("containing_or_after: past end → NULL", "got non-null");
    else
        PASS("first_containing_or_after: past end returns NULL");

    psync_interval_tree_free(tree);
}

/* free on NULL is safe */
static void test_free_null(void) {
    psync_interval_tree_free(NULL);
    PASS("free(NULL) does not crash");
}

/* ------------------------------------------------------------------ */
int main(void) {
    test_add_single();
    test_add_non_overlapping();
    test_add_overlapping_merge();
    test_add_adjacent_merge();
    test_add_contained();
    test_add_spanning();
    test_add_chain_merge();
    test_remove_middle_split();
    test_remove_exact();
    test_remove_left_overlap();
    test_remove_right_overlap();
    test_remove_spanning();
    test_cut_end();
    test_cut_end_all();
    test_first_containing_or_after();
    test_free_null();

    printf("\n%d passed, %d failed\n", passes, failures);
    return failures ? 1 : 0;
}
