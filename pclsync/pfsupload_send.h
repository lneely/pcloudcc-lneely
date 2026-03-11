/*
 * pfsupload_send.h — task-send layer for the fstask upload subsystem.
 *
 * Exposes the task serialisation functions (mkdir, rmdir) and the task
 * struct so unit tests can call them directly via a fake psock_t without
 * dragging in pfsupload.c's heavy dependencies (psql, pcache, pdiff, …).
 *
 * get_urls() is declared __attribute__((weak)) so tests can inject canned
 * upload-URL responses for large-upload code paths.
 */
#ifndef PFSUPLOAD_SEND_H
#define PFSUPLOAD_SEND_H

#include <stdint.h>

#include "papi.h"     /* binresult, PAPI_STR/NUM, psock_t (via psock.h) */
#include "pfoldersync.h" /* psync_folderid_t, psync_fileid_t */
#include "plist.h"    /* psync_list */

typedef struct {
    psync_list       list;
    binresult       *res;
    uint64_t         id;
    uint64_t         type;
    psync_folderid_t folderid;
    psync_folderid_t sfolderid;
    psync_fileid_t   fileid;
    const char      *text1;
    const char      *text2;
    int64_t          int1;
    int64_t          int2;
    unsigned char    ccreat;
    unsigned char    needprocessing;
    unsigned char    status;
} fsupload_task_t;

/*
 * get_urls() — weak symbol: returns a NULL-terminated array of upload-URL
 * strings for the given uploadid.  The default implementation calls the
 * real pCloud API; override in tests to inject canned responses.
 */
__attribute__((weak)) char **get_urls(uint64_t uploadid, size_t *nout);

/* Non-static send functions — callable from tests via --wrap=papi_send */
int pfsupload_send_mkdir(psock_t *api, fsupload_task_t *task);
int pfsupload_send_rmdir(psock_t *api, fsupload_task_t *task);

#endif /* PFSUPLOAD_SEND_H */
