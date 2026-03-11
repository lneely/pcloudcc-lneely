/*
 * pfsupload_send.c — task serialisation layer for the fstask upload subsystem.
 *
 * Contains the pure "send" functions: build the pCloud API request from an
 * fsupload_task_t and write it to the API socket.  No psql calls, no file
 * I/O, no threading — this is the only part of pfsupload.c that unit tests
 * need to exercise for serialisation testing.
 *
 * Extracted from pfsupload.c so tests can link against this file alone
 * without pulling in pfsupload.c's heavyweight transitive dependencies.
 */

#include "pdbg.h"
#include "pfsupload_send.h"
#include "plibs.h"   /* psync_my_auth */

/* ------------------------------------------------------------------ */
/* Weak default: get_urls() — override in tests to inject fake URLs    */
/* ------------------------------------------------------------------ */

/*
 * Returns upload URLs for the given uploadid.
 * The default implementation would call the pCloud API; declare it weak
 * so tests can supply a stub without linking the full API stack.
 */
__attribute__((weak)) char **get_urls(uint64_t uploadid, size_t *nout) {
    (void)uploadid;
    if (nout) *nout = 0;
    return NULL;
}

/* ------------------------------------------------------------------ */
/* Send functions                                                       */
/* ------------------------------------------------------------------ */

int pfsupload_send_mkdir(psock_t *api, fsupload_task_t *task) {
    if (task->text2) {
        binparam params[] = {
            PAPI_STR("auth",        psync_my_auth),
            PAPI_NUM("folderid",    task->folderid),
            PAPI_STR("name",        task->text1),
            PAPI_STR("timeformat",  "timestamp"),
            PAPI_BOOL("encrypted",  1),
            PAPI_STR("key",         task->text2),
            PAPI_NUM("ctime",       task->int1)};
        if (pdbg_likely(papi_send_no_res(api, "createfolderifnotexists",
                                         params) == PTR_OK))
            return 0;
        return -1;
    } else {
        binparam params[] = {
            PAPI_STR("auth",       psync_my_auth),
            PAPI_NUM("folderid",   task->folderid),
            PAPI_STR("name",       task->text1),
            PAPI_STR("timeformat", "timestamp"),
            PAPI_NUM("ctime",      task->int1)};
        if (pdbg_likely(papi_send_no_res(api, "createfolderifnotexists",
                                         params) == PTR_OK))
            return 0;
        return -1;
    }
}

int pfsupload_send_rmdir(psock_t *api, fsupload_task_t *task) {
    binparam params[] = {
        PAPI_STR("auth",       psync_my_auth),
        PAPI_NUM("folderid",   task->sfolderid),
        PAPI_STR("timeformat", "timestamp")};
    if (pdbg_likely(papi_send_no_res(api, "deletefolder", params) == PTR_OK))
        return 0;
    return -1;
}
