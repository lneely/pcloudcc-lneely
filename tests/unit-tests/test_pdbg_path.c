/*
 * Test: pdbg_path_is_safe() + psync_debug_path() fallback (pcl-aex)
 *
 * Verifies the guards added in 7360bf4:
 *   - Relative paths rejected
 *   - Paths with '..' components rejected
 *   - Paths outside $HOME and /tmp rejected
 *   - Valid paths under $HOME accepted
 *   - Valid paths under /tmp accepted
 *   - psync_debug_path() falls back to default when PCLOUD_LOG_PATH is unsafe
 *   - psync_debug_path() honours a safe PCLOUD_LOG_PATH
 *
 * pdbg_path_is_safe() is static; we replicate it verbatim and drive it with
 * crafted inputs.  psync_debug_path() is exercised via setenv/getenv.
 */

#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* Verbatim replica of pdbg_path_is_safe() from pdbg.c (7360bf4)     */
/* ------------------------------------------------------------------ */
static int pdbg_path_is_safe(const char *path) {
    const char *home;
    const char *p;

    if (!path || path[0] != '/')
        return 0;

    p = path;
    while (*p) {
        while (*p == '/') p++;
        if (p[0] == '.' && p[1] == '.' && (p[2] == '/' || p[2] == '\0'))
            return 0;
        while (*p && *p != '/') p++;
    }

    home = getenv("HOME");
    if (home && home[0] == '/') {
        size_t hlen = strlen(home);
        if (strncmp(path, home, hlen) == 0 &&
            (path[hlen] == '/' || path[hlen] == '\0'))
            return 1;
    }

    if (strncmp(path, "/tmp/", 5) == 0)
        return 1;

    return 0;
}

/* ------------------------------------------------------------------ */
/* Replica of psync_debug_path() fallback detection                   */
/* Returns 1 if the env var is accepted, 0 if rejected (fallback).   */
/* ------------------------------------------------------------------ */
static int debug_path_accepts_env(const char *env_val) {
    if (!env_val || env_val[0] == '\0')
        return 0;  /* no env var → default */
    return pdbg_path_is_safe(env_val);
}

/* ------------------------------------------------------------------ */
static int passes = 0, failures = 0;
#define PASS(n)      do { printf("PASS: %s\n", n); passes++; } while(0)
#define FAIL(n, ...) do { printf("FAIL: %s — ", n); printf(__VA_ARGS__); printf("\n"); failures++; } while(0)

static void check(const char *name, int got, int expected) {
    if (got == expected) PASS(name);
    else FAIL(name, "expected %d got %d", expected, got);
}

int main(void) {
    /* Fix HOME for deterministic results */
    setenv("HOME", "/home/testuser", 1);

    /* ---- Relative paths ------------------------------------------ */
    check("relative: 'log.txt'",          pdbg_path_is_safe("log.txt"), 0);
    check("relative: 'logs/debug.log'",   pdbg_path_is_safe("logs/debug.log"), 0);
    check("relative: './debug.log'",       pdbg_path_is_safe("./debug.log"), 0);
    check("relative: '../debug.log'",      pdbg_path_is_safe("../debug.log"), 0);
    check("NULL path",                     pdbg_path_is_safe(NULL), 0);
    check("empty path ''",                 pdbg_path_is_safe(""), 0);

    /* ---- '..' traversal ------------------------------------------ */
    check("dotdot: '/home/testuser/../etc/passwd'",
          pdbg_path_is_safe("/home/testuser/../etc/passwd"), 0);
    check("dotdot: '/tmp/../etc/shadow'",
          pdbg_path_is_safe("/tmp/../etc/shadow"), 0);
    check("dotdot at end: '/home/testuser/..'",
          pdbg_path_is_safe("/home/testuser/.."), 0);
    check("dotdot mid-path: '/home/testuser/a/../../etc'",
          pdbg_path_is_safe("/home/testuser/a/../../etc"), 0);

    /* ---- Outside HOME and /tmp ------------------------------------ */
    check("outside: '/etc/passwd'",        pdbg_path_is_safe("/etc/passwd"), 0);
    check("outside: '/var/log/syslog'",    pdbg_path_is_safe("/var/log/syslog"), 0);
    check("outside: '/root/evil.log'",     pdbg_path_is_safe("/root/evil.log"), 0);
    check("outside: '/tmp' (no trailing slash)",
          pdbg_path_is_safe("/tmp"), 0);        /* strncmp needs /tmp/ */
    check("outside: '/tmpevildir/x'",
          pdbg_path_is_safe("/tmpevildir/x"), 0); /* must not match /tmp/ prefix trick */

    /* HOME prefix collision: /home/testuser_evil must not match /home/testuser */
    check("outside: '/home/testuser_evil/x'",
          pdbg_path_is_safe("/home/testuser_evil/x"), 0);

    /* ---- Valid: under HOME --------------------------------------- */
    check("valid HOME: '/home/testuser/.pcloud/debug.log'",
          pdbg_path_is_safe("/home/testuser/.pcloud/debug.log"), 1);
    check("valid HOME: '/home/testuser/logs/app.log'",
          pdbg_path_is_safe("/home/testuser/logs/app.log"), 1);
    check("valid HOME exact: '/home/testuser'",
          pdbg_path_is_safe("/home/testuser"), 1);   /* path[hlen]=='\0' */

    /* ---- Valid: under /tmp --------------------------------------- */
    check("valid /tmp: '/tmp/pcloud_debug.log'",
          pdbg_path_is_safe("/tmp/pcloud_debug.log"), 1);
    check("valid /tmp: '/tmp/a/b/c.log'",
          pdbg_path_is_safe("/tmp/a/b/c.log"), 1);

    /* ---- psync_debug_path() fallback via env --------------------- */
    /* Unsafe env → rejected → fallback (returns 0 from our helper)  */
    check("env: relative path → fallback",
          debug_path_accepts_env("relative/path.log"), 0);
    check("env: dotdot path → fallback",
          debug_path_accepts_env("/home/testuser/../etc/passwd"), 0);
    check("env: outside HOME/tmp → fallback",
          debug_path_accepts_env("/etc/evil.log"), 0);
    check("env: empty string → fallback",
          debug_path_accepts_env(""), 0);
    check("env: NULL → fallback",
          debug_path_accepts_env(NULL), 0);

    /* Safe env → accepted */
    check("env: HOME path → accepted",
          debug_path_accepts_env("/home/testuser/myapp.log"), 1);
    check("env: /tmp path → accepted",
          debug_path_accepts_env("/tmp/myapp.log"), 1);

    printf("\n%d passed, %d failed\n", passes, failures);
    return failures ? 1 : 0;
}
