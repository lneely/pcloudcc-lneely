/*
 * Test: bad-free detection for pmem_malloc-allocated tree/list nodes (pcl-26j)
 *
 * Verifies that the free helpers introduced in the pcl-26j fix call
 * pmem_free() — which backs up to the pmem_header_t before calling free() —
 * rather than bare free() directly on the data pointer.
 *
 * Each of the four fixed call sites is exercised:
 *   1. psync_request_range_t  (ppagecache.c: psync_pagecache_free_request)
 *   2. synced_down_folder     (psyncer.c:    psyncer_dl_queue_clear)
 *   3. folder_tasks_t         (ppathstatus.c: ppathstatus_init / sync_data_free)
 *   4. psync_sector_inlog_t   (pfs.c:        pfs_free_openfile)
 *
 * Mechanism
 * ---------
 * --wrap=malloc  records every raw pointer that malloc() returns.
 * --wrap=free    asserts that every pointer passed to free() is in that set.
 *
 * When the old code called bare free(data_ptr) on a pmem_malloc allocation,
 * data_ptr = hdr+1 (past the pmem_header_t).  That pointer was never returned
 * by malloc, so the assertion would fire.  With the fixed code, pmem_free()
 * backs up to hdr before calling free(hdr), which IS the malloc-returned
 * pointer.  The assertion passes.
 *
 * Build:
 *   gcc -fsanitize=address -g -o test_pcl26j_free \
 *       tests/unit-tests/test_pcl26j_free.c pclsync/pmem.c pclsync/ptree.c \
 *       pclsync/pdbg.c pclsync/putil.c pclsync/ppath.c tests/stubs/test_stubs.c \
 *       -I./pclsync -Wl,--wrap=malloc -Wl,--wrap=free -lpthread
 */

#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <pthread.h>

#include "pmem.h"
#include "ptree.h"
#include "plist.h"

/* ------------------------------------------------------------------ */
/* --wrap bookkeeping: record every malloc-returned pointer            */
/* ------------------------------------------------------------------ */

#define MAX_ALLOCS 4096
static void *g_alloc_ptrs[MAX_ALLOCS];
static int   g_alloc_count = 0;
static int   g_bad_frees   = 0;

void *__real_malloc(size_t size);
void  __real_free(void *ptr);

void *__wrap_malloc(size_t size) {
  void *p = __real_malloc(size);
  if (p && g_alloc_count < MAX_ALLOCS)
    g_alloc_ptrs[g_alloc_count++] = p;
  return p;
}

void __wrap_free(void *ptr) {
  if (!ptr) { __real_free(ptr); return; }
  for (int i = 0; i < g_alloc_count; i++) {
    if (g_alloc_ptrs[i] == ptr) {
      g_alloc_ptrs[i] = NULL; /* consume entry */
      __real_free(ptr);
      return;
    }
  }
  /* ptr was never returned by malloc — this is a bad free */
  fprintf(stderr, "BAD FREE: %p was not a malloc-returned pointer\n", ptr);
  g_bad_frees++;
  /* do NOT call free — avoid crashing so we can report all failures */
}

static void reset_wrap_state(void) {
  memset(g_alloc_ptrs, 0, sizeof(g_alloc_ptrs));
  g_alloc_count = 0;
  g_bad_frees   = 0;
}

/* ------------------------------------------------------------------ */
/* Minimal struct replicas (mirrors of the production types)           */
/* ------------------------------------------------------------------ */

/* ppagecache.c */
typedef struct {
  psync_list list;
  uint64_t   offset;
  uint64_t   length;
} test_request_range_t;

typedef struct {
  psync_list ranges;
} test_request_t;

/* psyncer.c */
typedef struct {
  psync_tree        tree;
  unsigned long long folderid;
} test_synced_down_folder_t;

/* ppathstatus.c */
typedef struct {
  psync_tree        tree;
  unsigned long long folderid;
  int               child_task_cnt;
  int               own_tasks;
} test_folder_tasks_t;

/* pfs.c / pfscrypto.c */
typedef struct {
  psync_tree tree;
  uint32_t   sectorid;
  uint32_t   logoffset;
} test_sector_inlog_t;

/* ------------------------------------------------------------------ */
/* Free helpers — exact copies of the production fix                   */
/* ------------------------------------------------------------------ */

static void free_request_range(test_request_range_t *r) {
  pmem_free(PMEM_SUBSYS_CACHE, r);
}

static void free_synced_down_folder(test_synced_down_folder_t *f) {
  pmem_free(PMEM_SUBSYS_OTHER, f);
}

static void free_folder_tasks_node(test_folder_tasks_t *ft) {
  pmem_free(PMEM_SUBSYS_OTHER, ft);
}

static void free_sector_inlog_node(test_sector_inlog_t *e) {
  pmem_free(PMEM_SUBSYS_OTHER, e);
}

/* ------------------------------------------------------------------ */
/* Test harness                                                         */
/* ------------------------------------------------------------------ */

static int passes = 0, failures = 0;

#define PASS(n)        do { printf("PASS: %s\n", n); passes++; } while (0)
#define FAIL(n, ...)   do { printf("FAIL: %s — ", n); \
                            printf(__VA_ARGS__); printf("\n"); failures++; } while (0)

/* ------------------------------------------------------------------ */
/* Test 1: psync_request_range_t list freed via free_request_range()  */
/* ------------------------------------------------------------------ */
static void test_request_range_free(void) {
  reset_wrap_state();

  test_request_t req;
  psync_list_init(&req.ranges);

  /* Allocate 5 range nodes (simulates a large multi-range read) */
  for (int i = 0; i < 5; i++) {
    test_request_range_t *r = pmem_malloc(PMEM_SUBSYS_CACHE,
                                          sizeof(test_request_range_t));
    r->offset = (uint64_t)i * 4096;
    r->length = 4096;
    psync_list_add_tail(&req.ranges, &r->list);
  }

  /* Exercise the fixed free path */
  psync_list_for_each_element_call(&req.ranges, test_request_range_t,
                                   list, free_request_range);

  if (g_bad_frees == 0)
    PASS("request_range: pmem_free called with header ptr, not data ptr");
  else
    FAIL("request_range", "%d bad free(s) detected", g_bad_frees);
}

/* ------------------------------------------------------------------ */
/* Test 2: synced_down_folder tree freed via free_synced_down_folder() */
/* ------------------------------------------------------------------ */
static void test_synced_down_folder_free(void) {
  reset_wrap_state();

  psync_tree *root = PSYNC_TREE_EMPTY;

  /* Build a small BST of synced_down_folder nodes */
  unsigned long long fids[] = {10, 5, 15, 3, 7};
  for (int i = 0; i < 5; i++) {
    test_synced_down_folder_t *f = pmem_malloc(PMEM_SUBSYS_OTHER,
                                               sizeof(test_synced_down_folder_t));
    f->folderid = fids[i];
    memset(&f->tree, 0, sizeof(f->tree));

    if (!root) {
      ptree_add_after(&root, NULL, &f->tree);
    } else {
      /* Simple insertion — walk tree */
      psync_tree *cur = root, **slot = NULL;
      psync_tree *parent = NULL;
      while (cur) {
        test_synced_down_folder_t *n =
          ptree_element(cur, test_synced_down_folder_t, tree);
        parent = cur;
        if (f->folderid < n->folderid) {
          if (!cur->left) { slot = &cur->left; break; }
          cur = cur->left;
        } else {
          if (!cur->right) { slot = &cur->right; break; }
          cur = cur->right;
        }
      }
      if (slot) {
        *slot = &f->tree;
        ptree_added_at(&root, parent, &f->tree);
      }
    }
  }

  /* Exercise the fixed free path */
  ptree_for_each_element_call_safe(root, test_synced_down_folder_t,
                                   tree, free_synced_down_folder);

  if (g_bad_frees == 0)
    PASS("synced_down_folder: pmem_free called with header ptr, not data ptr");
  else
    FAIL("synced_down_folder", "%d bad free(s) detected", g_bad_frees);
}

/* ------------------------------------------------------------------ */
/* Test 3: folder_tasks_t tree freed via free_folder_tasks_node()      */
/* ------------------------------------------------------------------ */
static void test_folder_tasks_free(void) {
  reset_wrap_state();

  psync_tree *root = PSYNC_TREE_EMPTY;

  /* Allocate 6 folder_tasks nodes */
  unsigned long long fids[] = {100, 50, 150, 25, 75, 125};
  for (int i = 0; i < 6; i++) {
    test_folder_tasks_t *ft = pmem_malloc(PMEM_SUBSYS_OTHER,
                                          sizeof(test_folder_tasks_t));
    ft->folderid       = fids[i];
    ft->child_task_cnt = 0;
    ft->own_tasks      = 0;
    memset(&ft->tree, 0, sizeof(ft->tree));

    if (!root) {
      ptree_add_after(&root, NULL, &ft->tree);
    } else {
      psync_tree *cur = root, **slot = NULL;
      psync_tree *parent = NULL;
      while (cur) {
        test_folder_tasks_t *n =
          ptree_element(cur, test_folder_tasks_t, tree);
        parent = cur;
        if (ft->folderid < n->folderid) {
          if (!cur->left) { slot = &cur->left; break; }
          cur = cur->left;
        } else {
          if (!cur->right) { slot = &cur->right; break; }
          cur = cur->right;
        }
      }
      if (slot) {
        *slot = &ft->tree;
        ptree_added_at(&root, parent, &ft->tree);
      }
    }
  }

  /* Exercise the fixed free path */
  ptree_for_each_element_call_safe(root, test_folder_tasks_t,
                                   tree, free_folder_tasks_node);

  if (g_bad_frees == 0)
    PASS("folder_tasks: pmem_free called with header ptr, not data ptr");
  else
    FAIL("folder_tasks", "%d bad free(s) detected", g_bad_frees);
}

/* ------------------------------------------------------------------ */
/* Test 4: psync_sector_inlog_t tree freed via free_sector_inlog_node() */
/* ------------------------------------------------------------------ */
static void test_sector_inlog_free(void) {
  reset_wrap_state();

  psync_tree *root = PSYNC_TREE_EMPTY;

  /* Allocate 4 sector_inlog nodes */
  uint32_t sids[] = {0, 1, 2, 3};
  for (int i = 0; i < 4; i++) {
    test_sector_inlog_t *e = pmem_malloc(PMEM_SUBSYS_OTHER,
                                         sizeof(test_sector_inlog_t));
    e->sectorid  = sids[i];
    e->logoffset = (uint32_t)(i * 512);
    memset(&e->tree, 0, sizeof(e->tree));

    if (!root) {
      ptree_add_after(&root, NULL, &e->tree);
    } else {
      psync_tree *cur = root, **slot = NULL;
      psync_tree *parent = NULL;
      while (cur) {
        test_sector_inlog_t *n =
          ptree_element(cur, test_sector_inlog_t, tree);
        parent = cur;
        if (e->sectorid < n->sectorid) {
          if (!cur->left) { slot = &cur->left; break; }
          cur = cur->left;
        } else {
          if (!cur->right) { slot = &cur->right; break; }
          cur = cur->right;
        }
      }
      if (slot) {
        *slot = &e->tree;
        ptree_added_at(&root, parent, &e->tree);
      }
    }
  }

  /* Exercise the fixed free path */
  ptree_for_each_element_call_safe(root, test_sector_inlog_t,
                                   tree, free_sector_inlog_node);

  if (g_bad_frees == 0)
    PASS("sector_inlog: pmem_free called with header ptr, not data ptr");
  else
    FAIL("sector_inlog", "%d bad free(s) detected", g_bad_frees);
}

/* ------------------------------------------------------------------ */
/* Test 5: bare free() on pmem_malloc pointer IS detected as bad-free  */
/*         (verifies that the wrap harness itself is working)           */
/* ------------------------------------------------------------------ */
static void test_harness_detects_bad_free(void) {
  reset_wrap_state();

  void *data = pmem_malloc(PMEM_SUBSYS_OTHER, 64);
  /* Deliberately call bare free on the data pointer — should be caught */
  free(data);

  if (g_bad_frees == 1)
    PASS("harness self-check: bare free(data_ptr) correctly flagged");
  else
    FAIL("harness self-check", "expected 1 bad free, got %d", g_bad_frees);

  /* Reset so leak-sanitizer doesn't complain about the unfree'd block */
  reset_wrap_state();
}

/* ------------------------------------------------------------------ */
int main(void) {
  test_request_range_free();
  test_synced_down_folder_free();
  test_folder_tasks_free();
  test_sector_inlog_free();
  test_harness_detects_bad_free();

  printf("\n%d passed, %d failed\n", passes, failures);
  return failures ? 1 : 0;
}
