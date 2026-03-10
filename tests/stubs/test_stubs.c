#define _POSIX_C_SOURCE 200809L
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Include headers before implementation */
#include "../pclsync/pmem.h"
#include "../pclsync/pdbg.h"
#include "../pclsync/ppath.h"
#include "../pclsync/putil.h"

/* Thread-local storage stub */
__thread const char *psync_thread_name = "test";

/* pmem stubs */
void *pmem_malloc(pmem_subsystem_t subsystem, size_t size) {
    (void)subsystem;
    return malloc(size);
}

void pmem_free(pmem_subsystem_t subsystem, void *ptr) {
    (void)subsystem;
    free(ptr);
}

/* ppath stub */
char *ppath_home(void) {
    const char *home = getenv("HOME");
    if (!home) return NULL;
    return strdup(home);
}

/* putil stubs */
void putil_time_format(time_t tm, unsigned long ns, char *result) {
    struct tm t;
    localtime_r(&tm, &t);
    snprintf(result, 36, "%04d-%02d-%02d %02d:%02d:%02d.%09lu",
             t.tm_year + 1900, t.tm_mon + 1, t.tm_mday,
             t.tm_hour, t.tm_min, t.tm_sec, ns);
}

void putil_wipe(void *mem, size_t sz) {
    if (!mem || sz == 0) return;
    volatile unsigned char *p = (volatile unsigned char *)mem;
    memset((void*)p, 0x00, sz);
    memset((void*)p, 0xFF, sz);
    memset((void*)p, 0x00, sz);
}

/* prpc stub */
char *prpc_sockpath(void) {
    char *home = ppath_home();
    if (!home) return NULL;
    const char *subdir = "/.pcloud/prpc.sock";
    size_t len = strlen(home) + strlen(subdir) + 1;
    char *sockpath = (char *)pmem_malloc(PMEM_SUBSYS_OTHER, len);
    if (!sockpath) {
        free(home);
        return NULL;
    }
    snprintf(sockpath, len, "%s%s", home, subdir);
    free(home);
    return sockpath;
}

#ifdef __cplusplus
}
#endif

/* Include actual pdbg.c implementation */
#include "../pclsync/pdbg.c"
