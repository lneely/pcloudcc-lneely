/*
 * Test: psync_debug_path() path validation (pcl-aex)
 *
 * Verifies the guards added in 7360bf4:
 *   - psync_debug_path() falls back to default when PCLOUD_LOG_PATH is unsafe
 *   - psync_debug_path() honours a safe PCLOUD_LOG_PATH
 *   - Relative paths rejected
 *   - Paths with '..' components rejected
 *   - Paths outside $HOME and /tmp rejected
 */

#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern char *psync_debug_path(void);
extern void pmem_free(int subsys, void *ptr);
#define PMEM_SUBSYS_OTHER 0

static int passes = 0, failures = 0;
#define PASS(n)      do { printf("PASS: %s\n", n); passes++; } while(0)
#define FAIL(n, ...) do { printf("FAIL: %s — ", n); printf(__VA_ARGS__); printf("\n"); failures++; } while(0)

int main(void) {
    setenv("HOME", "/home/testuser", 1);
    char *path;

    /* Unsafe env → fallback to default */
    setenv("PCLOUD_LOG_PATH", "relative/path.log", 1);
    path = psync_debug_path();
    if (path && strstr(path, "/.pcloud/debug.log"))
        PASS("env: relative path → fallback");
    else
        FAIL("env: relative path → fallback", "got %s", path ? path : "NULL");
    if (path) pmem_free(PMEM_SUBSYS_OTHER, path);

    setenv("PCLOUD_LOG_PATH", "/home/testuser/../etc/passwd", 1);
    path = psync_debug_path();
    if (path && strstr(path, "/.pcloud/debug.log"))
        PASS("env: dotdot path → fallback");
    else
        FAIL("env: dotdot path → fallback", "got %s", path ? path : "NULL");
    if (path) pmem_free(PMEM_SUBSYS_OTHER, path);

    setenv("PCLOUD_LOG_PATH", "/etc/evil.log", 1);
    path = psync_debug_path();
    if (path && strstr(path, "/.pcloud/debug.log"))
        PASS("env: outside HOME/tmp → fallback");
    else
        FAIL("env: outside HOME/tmp → fallback", "got %s", path ? path : "NULL");
    if (path) pmem_free(PMEM_SUBSYS_OTHER, path);

    unsetenv("PCLOUD_LOG_PATH");
    path = psync_debug_path();
    if (path && strstr(path, "/.pcloud/debug.log"))
        PASS("env: unset → default");
    else
        FAIL("env: unset → default", "got %s", path ? path : "NULL");
    if (path) pmem_free(PMEM_SUBSYS_OTHER, path);

    /* Safe env → accepted */
    setenv("PCLOUD_LOG_PATH", "/home/testuser/myapp.log", 1);
    path = psync_debug_path();
    if (path && strcmp(path, "/home/testuser/myapp.log") == 0)
        PASS("env: HOME path → accepted");
    else
        FAIL("env: HOME path → accepted", "got %s", path ? path : "NULL");
    if (path) pmem_free(PMEM_SUBSYS_OTHER, path);

    setenv("PCLOUD_LOG_PATH", "/tmp/myapp.log", 1);
    path = psync_debug_path();
    if (path && strcmp(path, "/tmp/myapp.log") == 0)
        PASS("env: /tmp path → accepted");
    else
        FAIL("env: /tmp path → accepted", "got %s", path ? path : "NULL");
    if (path) pmem_free(PMEM_SUBSYS_OTHER, path);

    printf("\n%d passed, %d failed\n", passes, failures);
    return failures ? 1 : 0;
}
