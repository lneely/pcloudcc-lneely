/*
 * Test: pfsupload_send.c — task serialisation via --wrap=papi_send
 *
 * Tests that the send functions dispatch the correct pCloud API command and
 * pass the expected parameters.
 *
 * Strategy: --wrap=papi_send intercepts every call to the underlying
 * papi_send() function (which papi_send_no_res() expands to).  The wrapper
 * records the command name and parameter array so tests can verify correct
 * serialisation without a real network socket.
 *
 * socketpair() is used to construct a valid psock_t for the api argument;
 * because papi_send is fully wrapped the socket is never actually written
 * to in these tests.
 *
 * get_urls() is declared __attribute__((weak)) in pfsupload_send.c; this
 * test file provides its own definition which overrides the weak default so
 * large-upload paths can return canned URL data in future tests.
 */

#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/socket.h>

#include "pfsupload_send.h"

/* ------------------------------------------------------------------ */
/* get_urls() override — canned response for large-upload paths        */
/* ------------------------------------------------------------------ */

char **get_urls(uint64_t uploadid, size_t *nout) {
    (void)uploadid;
    static char *urls[] = { "https://upload.example.com/1", NULL };
    if (nout) *nout = 1;
    return urls;
}

/* ------------------------------------------------------------------ */
/* __wrap_papi_send — capture command + params, return PTR_OK          */
/* ------------------------------------------------------------------ */

static const char  *g_last_cmd    = NULL;
static const binparam *g_last_params = NULL;
static size_t       g_last_nparams = 0;
static int          g_wrap_rc     = 1; /* 1 = return PTR_OK, 0 = return NULL */

binresult *__real_papi_send(psock_t *sock, const char *command, size_t cmdlen,
                             const binparam *params, size_t paramcnt,
                             int64_t datalen, int readres);

binresult *__wrap_papi_send(psock_t *sock, const char *command, size_t cmdlen,
                             const binparam *params, size_t paramcnt,
                             int64_t datalen, int readres) {
    (void)sock; (void)cmdlen; (void)datalen; (void)readres;
    g_last_cmd     = command;
    g_last_params  = params;
    g_last_nparams = paramcnt;
    return g_wrap_rc ? PTR_OK : NULL;
}

/* ------------------------------------------------------------------ */
/* Helpers                                                              */
/* ------------------------------------------------------------------ */

static int passes = 0, failures = 0;
#define PASS(n)      do { printf("PASS: %s\n", n); passes++; } while (0)
#define FAIL(n, ...) do { printf("FAIL: %s — ", n); printf(__VA_ARGS__); printf("\n"); failures++; } while (0)

static void reset_wrap(void) {
    g_last_cmd    = NULL;
    g_last_params = NULL;
    g_last_nparams = 0;
    g_wrap_rc     = 1;
}

/* Find a string parameter by name; returns its value or NULL */
static const char *find_str_param(const char *name) {
    if (!g_last_params) return NULL;
    size_t nlen = strlen(name);
    for (size_t i = 0; i < g_last_nparams; i++) {
        if (g_last_params[i].paramtype == PARAM_STR &&
            g_last_params[i].paramnamelen == nlen &&
            strncmp(g_last_params[i].paramname, name, nlen) == 0)
            return g_last_params[i].str;
    }
    return NULL;
}

/* Find a numeric parameter by name */
static int find_num_param(const char *name, uint64_t *out) {
    if (!g_last_params) return 0;
    for (size_t i = 0; i < g_last_nparams; i++) {
        if (g_last_params[i].paramtype == PARAM_NUM &&
            g_last_params[i].paramnamelen == strlen(name) &&
            strncmp(g_last_params[i].paramname, name, strlen(name)) == 0) {
            *out = g_last_params[i].num;
            return 1;
        }
    }
    return 0;
}

/* Build a minimal fake psock_t wrapping one end of a socketpair.
 * The caller provides a stack-allocated psock_t; no static storage is used
 * so multiple calls within the same test function are safe. */
static void make_fake_api(psock_t *out, int sv[2]) {
    socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
    memset(out, 0, sizeof(*out));
    out->sock = sv[1];
}

/* ------------------------------------------------------------------ */
/* Test helpers: init a minimal fsupload_task_t                        */
/* ------------------------------------------------------------------ */

static void task_init(fsupload_task_t *t) {
    memset(t, 0, sizeof(*t));
}

/* ------------------------------------------------------------------ */
/* Tests                                                                */
/* ------------------------------------------------------------------ */

/* mkdir (non-encrypted): correct API command and folderid/name params */
static void test_send_mkdir_basic(void) {
    reset_wrap();
    int sv[2];
    psock_t api_s; make_fake_api(&api_s, sv); psock_t *api = &api_s;

    fsupload_task_t task;
    task_init(&task);
    task.folderid = 12345;
    task.text1    = "mydir";
    task.text2    = NULL;   /* non-encrypted */
    task.int1     = 1000;   /* ctime */

    int rc = pfsupload_send_mkdir(api, &task);
    close(sv[0]); close(sv[1]);

    if (rc != 0)
        { FAIL("mkdir basic: rc=0", "rc=%d", rc); return; }
    if (!g_last_cmd || strcmp(g_last_cmd, "createfolderifnotexists") != 0)
        { FAIL("mkdir basic: command", "cmd=%s", g_last_cmd ? g_last_cmd : "(null)"); return; }
    uint64_t folderid = 0;
    if (!find_num_param("folderid", &folderid) || folderid != 12345)
        FAIL("mkdir basic: folderid param", "folderid=%llu", (unsigned long long)folderid);
    else
        PASS("mkdir (non-encrypted): command=createfolderifnotexists, folderid correct");
}

/* mkdir (encrypted): same command, plus encrypted=1 and key param */
static void test_send_mkdir_encrypted(void) {
    reset_wrap();
    int sv[2];
    psock_t api_s; make_fake_api(&api_s, sv); psock_t *api = &api_s;

    fsupload_task_t task;
    task_init(&task);
    task.folderid = 99;
    task.text1    = "encdir";
    task.text2    = "base64key==";  /* non-NULL → encrypted path */
    task.int1     = 2000;

    int rc = pfsupload_send_mkdir(api, &task);
    close(sv[0]); close(sv[1]);

    if (rc != 0)
        { FAIL("mkdir enc: rc=0", "rc=%d", rc); return; }
    if (!g_last_cmd || strcmp(g_last_cmd, "createfolderifnotexists") != 0)
        { FAIL("mkdir enc: command", "cmd=%s", g_last_cmd ? g_last_cmd : "(null)"); return; }
    /* key param should be present */
    const char *key = find_str_param("key");
    if (!key || strcmp(key, "base64key==") != 0)
        FAIL("mkdir enc: key param", "key=%s", key ? key : "(null)");
    else
        PASS("mkdir (encrypted): command correct, key param present");
}

/* rmdir: correct API command and folderid from sfolderid */
static void test_send_rmdir(void) {
    reset_wrap();
    int sv[2];
    psock_t api_s; make_fake_api(&api_s, sv); psock_t *api = &api_s;

    fsupload_task_t task;
    task_init(&task);
    task.folderid  = 1;     /* parent (not sent in rmdir) */
    task.sfolderid = 42;    /* the folder to delete */
    task.text1     = "gone";

    int rc = pfsupload_send_rmdir(api, &task);
    close(sv[0]); close(sv[1]);

    if (rc != 0)
        { FAIL("rmdir: rc=0", "rc=%d", rc); return; }
    if (!g_last_cmd || strcmp(g_last_cmd, "deletefolder") != 0)
        { FAIL("rmdir: command", "cmd=%s", g_last_cmd ? g_last_cmd : "(null)"); return; }
    uint64_t folderid = 0;
    if (!find_num_param("folderid", &folderid) || folderid != 42)
        FAIL("rmdir: folderid=sfolderid", "folderid=%llu", (unsigned long long)folderid);
    else
        PASS("rmdir: command=deletefolder, folderid=sfolderid");
}

/* API error path: papi_send returns NULL → send function returns -1 */
static void test_api_error_path(void) {
    reset_wrap();
    g_wrap_rc = 0;  /* simulate papi_send failure */
    int sv[2];
    psock_t api_s; make_fake_api(&api_s, sv); psock_t *api = &api_s;

    fsupload_task_t task;
    task_init(&task);
    task.folderid = 1;
    task.text1    = "fail";
    task.text2    = NULL;

    int rc_mkdir = pfsupload_send_mkdir(api, &task);
    int rc_rmdir = pfsupload_send_rmdir(api, &task);
    close(sv[0]); close(sv[1]);

    if (rc_mkdir == -1 && rc_rmdir == -1)
        PASS("API error path: papi_send failure → send functions return -1");
    else
        FAIL("API error path", "mkdir=%d rmdir=%d (expected -1)", rc_mkdir, rc_rmdir);
}

/* get_urls() override is callable (verifies weak symbol override) */
static void test_get_urls_override(void) {
    size_t n = 0;
    char **urls = get_urls(1234, &n);
    if (urls && n == 1 && urls[0] && strstr(urls[0], "example.com"))
        PASS("get_urls() override: weak symbol replaced by test implementation");
    else
        FAIL("get_urls() override", "urls=%p n=%zu", (void*)urls, n);
}

/* ------------------------------------------------------------------ */
int main(void) {
    test_send_mkdir_basic();
    test_send_mkdir_encrypted();
    test_send_rmdir();
    test_api_error_path();
    test_get_urls_override();

    printf("\n%d passed, %d failed\n", passes, failures);
    return failures ? 1 : 0;
}
