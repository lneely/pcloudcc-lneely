/*
 * Test: ptree.c — AVL balanced BST
 *
 * Tests insert, lookup, delete, and in-order traversal using a simple
 * integer-keyed node type.  ptree itself manages no memory; nodes are
 * stack-allocated here so no cleanup is needed.
 */

#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <string.h>

#include "ptree.h"

/* ------------------------------------------------------------------ */
/* Node type                                                            */
/* ------------------------------------------------------------------ */

typedef struct {
    psync_tree tree;
    int        key;
} inode_t;

static int icmp(const psync_tree *a, const psync_tree *b) {
    int ka = ptree_element(a, inode_t, tree)->key;
    int kb = ptree_element(b, inode_t, tree)->key;
    return (ka > kb) - (ka < kb);
}

static void inode_init(inode_t *n, int key) {
    memset(&n->tree, 0, sizeof(n->tree));
    n->key = key;
}

/* BST lookup by key */
static inode_t *find_key(psync_tree *root, int key) {
    while (root) {
        inode_t *n = ptree_element(root, inode_t, tree);
        if      (key < n->key) root = root->left;
        else if (key > n->key) root = root->right;
        else                   return n;
    }
    return NULL;
}

/* ------------------------------------------------------------------ */
/* Test harness                                                         */
/* ------------------------------------------------------------------ */

static int passes = 0, failures = 0;
#define PASS(n)      do { printf("PASS: %s\n", n); passes++; } while (0)
#define FAIL(n, ...) do { printf("FAIL: %s — ", n); printf(__VA_ARGS__); printf("\n"); failures++; } while (0)

/* ------------------------------------------------------------------ */
/* Tests                                                                */
/* ------------------------------------------------------------------ */

/* Single node: first == last == the node, next/prev return NULL */
static void test_single_node(void) {
    inode_t n;
    psync_tree *root = NULL;
    inode_init(&n, 42);
    ptree_add(&root, &n.tree, icmp);
    if (root == NULL)
        { FAIL("single insert: root non-null", "root is NULL"); return; }
    psync_tree *f = ptree_get_first(root);
    psync_tree *l = ptree_get_last(root);
    if (f != &n.tree || l != &n.tree)
        FAIL("single: first == last == node", "first=%p last=%p node=%p",
             (void*)f, (void*)l, (void*)&n.tree);
    else if (ptree_get_next(f) != NULL)
        FAIL("single: next of only node is NULL", "got non-null");
    else if (ptree_get_prev(l) != NULL)
        FAIL("single: prev of only node is NULL", "got non-null");
    else
        PASS("single node insert/first/last/next/prev");
}

/* In-order traversal gives keys in ascending order for any insert order */
static void test_traversal_sorted(void) {
    int keys[] = { 5, 3, 8, 1, 4, 7, 9, 2 };
    int n = (int)(sizeof(keys) / sizeof(keys[0]));
    inode_t nodes[8];
    psync_tree *root = NULL;
    int i;
    for (i = 0; i < n; i++) {
        inode_init(&nodes[i], keys[i]);
        ptree_add(&root, &nodes[i].tree, icmp);
    }
    /* collect traversal */
    psync_tree *tr = ptree_get_first(root);
    int prev_key = -1, count = 0, ok = 1;
    while (tr) {
        int k = ptree_element(tr, inode_t, tree)->key;
        if (k <= prev_key) { ok = 0; break; }
        prev_key = k;
        count++;
        tr = ptree_get_next(tr);
    }
    if (!ok)
        FAIL("traversal sorted", "out-of-order key %d after %d", prev_key, prev_key);
    else if (count != n)
        FAIL("traversal sorted: count", "expected %d, got %d", n, count);
    else
        PASS("traversal in sorted order after arbitrary inserts");
}

/* Reverse-order insert stresses AVL rebalancing */
static void test_reverse_insert_traversal(void) {
    int n = 7;
    inode_t nodes[7];
    psync_tree *root = NULL;
    int i;
    for (i = n; i >= 1; i--) {
        inode_init(&nodes[i-1], i);
        ptree_add(&root, &nodes[i-1].tree, icmp);
    }
    psync_tree *tr = ptree_get_first(root);
    int prev = 0, count = 0, ok = 1;
    while (tr) {
        int k = ptree_element(tr, inode_t, tree)->key;
        if (k != prev + 1) { ok = 0; break; }
        prev = k;
        count++;
        tr = ptree_get_next(tr);
    }
    if (!ok || count != n)
        FAIL("reverse insert traversal", "ok=%d count=%d expected %d", ok, count, n);
    else
        PASS("reverse insert: AVL rebalanced, traversal still sorted");
}

/* Lookup by key finds the right node (or NULL for missing) */
static void test_lookup(void) {
    int keys[] = { 10, 5, 15, 3, 7 };
    int n = (int)(sizeof(keys) / sizeof(keys[0]));
    inode_t nodes[5];
    psync_tree *root = NULL;
    int i;
    for (i = 0; i < n; i++) {
        inode_init(&nodes[i], keys[i]);
        ptree_add(&root, &nodes[i].tree, icmp);
    }
    int ok = 1;
    for (i = 0; i < n; i++) {
        inode_t *found = find_key(root, keys[i]);
        if (!found || found->key != keys[i]) { ok = 0; break; }
    }
    if (!ok)
        FAIL("lookup: existing keys", "key not found");
    else if (find_key(root, 99) != NULL)
        FAIL("lookup: absent key returns NULL", "got non-null for key 99");
    else
        PASS("lookup: finds all inserted keys, NULL for missing");
}

/* Delete a leaf node */
static void test_delete_leaf(void) {
    int keys[] = { 5, 3, 7 };
    inode_t nodes[3];
    psync_tree *root = NULL;
    int i;
    for (i = 0; i < 3; i++) {
        inode_init(&nodes[i], keys[i]);
        ptree_add(&root, &nodes[i].tree, icmp);
    }
    /* delete leaf (key=3) */
    ptree_del(&root, &nodes[1].tree);
    if (find_key(root, 3) != NULL)
        FAIL("delete leaf: key gone", "key 3 still found");
    else if (find_key(root, 5) == NULL || find_key(root, 7) == NULL)
        FAIL("delete leaf: others remain", "5 or 7 missing");
    else {
        /* traversal gives 5, 7 */
        psync_tree *tr = ptree_get_first(root);
        int a = ptree_element(tr, inode_t, tree)->key;
        tr = ptree_get_next(tr);
        int b = ptree_element(tr, inode_t, tree)->key;
        tr = ptree_get_next(tr);
        if (a == 5 && b == 7 && tr == NULL)
            PASS("delete leaf: correct traversal afterward");
        else
            FAIL("delete leaf: traversal wrong", "a=%d b=%d next=%p", a, b, (void*)tr);
    }
}

/* Delete root when root has two children */
static void test_delete_root(void) {
    inode_t nodes[5];
    psync_tree *root = NULL;
    int keys[] = { 10, 5, 15, 3, 8 };
    int n = 5, i;
    for (i = 0; i < n; i++) {
        inode_init(&nodes[i], keys[i]);
        ptree_add(&root, &nodes[i].tree, icmp);
    }
    inode_t *old_root = ptree_element(root, inode_t, tree);
    ptree_del(&root, &old_root->tree);
    /* old root key must be absent */
    if (find_key(root, old_root->key) != NULL)
        { FAIL("delete root: root key gone", "still present"); return; }
    /* remaining keys must all be present */
    int missing = 0;
    for (i = 0; i < n; i++)
        if (keys[i] != old_root->key && find_key(root, keys[i]) == NULL)
            { missing = keys[i]; break; }
    if (missing)
        FAIL("delete root: remaining keys", "key %d missing", missing);
    else {
        /* traversal still sorted */
        psync_tree *tr = ptree_get_first(root);
        int prev = -1, cnt = 0, ok = 1;
        while (tr) {
            int k = ptree_element(tr, inode_t, tree)->key;
            if (k <= prev) { ok = 0; break; }
            prev = k; cnt++;
            tr = ptree_get_next(tr);
        }
        if (!ok || cnt != n - 1)
            FAIL("delete root: traversal", "ok=%d cnt=%d expected %d", ok, cnt, n-1);
        else
            PASS("delete root: correct traversal after root deletion");
    }
}

/* Delete all nodes one by one; tree must be empty at the end */
static void test_delete_all(void) {
    int keys[] = { 4, 2, 6, 1, 3, 5, 7 };
    int n = (int)(sizeof(keys) / sizeof(keys[0]));
    inode_t nodes[7];
    psync_tree *root = NULL;
    int i;
    for (i = 0; i < n; i++) {
        inode_init(&nodes[i], keys[i]);
        ptree_add(&root, &nodes[i].tree, icmp);
    }
    for (i = 0; i < n; i++) {
        inode_t *nd = find_key(root, keys[i]);
        if (!nd) { FAIL("delete all: find before delete", "key %d missing", keys[i]); return; }
        ptree_del(&root, &nd->tree);
    }
    if (root != NULL)
        FAIL("delete all: root is NULL after all deletes", "root=%p", (void*)root);
    else if (ptree_get_first(root) != NULL)
        FAIL("delete all: first is NULL", "non-null");
    else
        PASS("delete all: tree empty after deleting all nodes");
}

/* ptree_for_each visits every node exactly once */
static void test_for_each_macro(void) {
    int keys[] = { 9, 2, 5, 1, 8, 4 };
    int n = (int)(sizeof(keys) / sizeof(keys[0]));
    inode_t nodes[6];
    psync_tree *root = NULL;
    int i;
    for (i = 0; i < n; i++) {
        inode_init(&nodes[i], keys[i]);
        ptree_add(&root, &nodes[i].tree, icmp);
    }
    int seen[6] = {0};
    psync_tree *tr;
    ptree_for_each(tr, root) {
        inode_t *nd = ptree_element(tr, inode_t, tree);
        for (i = 0; i < n; i++)
            if (keys[i] == nd->key) { seen[i]++; break; }
    }
    int ok = 1;
    for (i = 0; i < n; i++)
        if (seen[i] != 1) { ok = 0; break; }
    if (ok)
        PASS("ptree_for_each visits every node exactly once");
    else
        FAIL("ptree_for_each", "some node visited wrong number of times");
}

/* ------------------------------------------------------------------ */
int main(void) {
    test_single_node();
    test_traversal_sorted();
    test_reverse_insert_traversal();
    test_lookup();
    test_delete_leaf();
    test_delete_root();
    test_delete_all();
    test_for_each_macro();

    printf("\n%d passed, %d failed\n", passes, failures);
    return failures ? 1 : 0;
}
