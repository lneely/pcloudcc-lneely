#define _POSIX_C_SOURCE 200809L
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Thread-local storage stub */
__thread const char *psync_thread_name = "test";
__thread uint32_t psync_error = 0;

/* Global stubs */
const char *psync_my_auth = "test_auth";
const char *apiserver = "https://api.pcloud.com";
unsigned int pdbg_runtime_level = 0;

/* pmem stubs */
void *pmem_malloc(int subsystem, size_t size) {
    (void)subsystem;
    return malloc(size);
}

void pmem_free(int subsystem, void *ptr) {
    (void)subsystem;
    free(ptr);
}

/* putil stub */
void putil_wipe(void *mem, size_t sz) {
    if (!mem || sz == 0) return;
    volatile unsigned char *p = (volatile unsigned char *)mem;
    memset((void*)p, 0x00, sz);
    memset((void*)p, 0xFF, sz);
    memset((void*)p, 0x00, sz);
}

/* prpc stub */
char *prpc_sockpath(void) {
    const char *home = getenv("HOME");
    if (!home) return NULL;
    size_t len = strlen(home) + 20;
    char *path = (char *)malloc(len);
    if (!path) return NULL;
    snprintf(path, len, "%s/.pcloud/prpc.sock", home);
    return path;
}

/* pdbg stub */
int pdbg_printf(const char *file, const char *function, unsigned int line, unsigned int level, const char *fmt, ...) {
    (void)file;
    (void)function;
    (void)line;
    (void)level;
    (void)fmt;
    return 1;
}

#ifdef __cplusplus
}
#endif
