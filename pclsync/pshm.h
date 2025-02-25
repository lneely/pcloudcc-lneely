#ifndef __PSHM_H

#define __PSHM_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stddef.h>
#include <sys/ipc.h>

#define PSYNC_SHM_SIZE 4096

// shm is used to get the return values from the underlying pcloud functions
// called by the overlay client. this is needed for cases such as
// list_sync_folders, where the result should be presented to the user in the
// CLI.
typedef struct _psync_shm {
  void *data;         // overlay callback return value
  size_t datasz;      // overlay return value size
  volatile int flag;  // new data available
} psync_shm;

void pshm_write(const void *data, size_t datasz);
bool pshm_read(void **data, size_t *datasz);
int pshm_cleanup();

#ifdef __cplusplus
}
#endif

#endif