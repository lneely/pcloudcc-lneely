#ifndef __PPATH_H
#define __PPATH_H

#include <fcntl.h>
#include <stdint.h>


typedef struct {
  const char *name;
  const char *path;
  struct stat stat;
} psync_pstat;

typedef struct {
  const char *name;
  uint8_t isfolder;
} psync_pstat_fast;

typedef void (*psync_list_dir_callback)(void *, psync_pstat *);
typedef void (*psync_list_dir_callback_fast)(void *, psync_pstat_fast *);

int psync_list_dir(const char *path, psync_list_dir_callback callback, void *ptr);
int psync_list_dir_fast(const char *path, psync_list_dir_callback_fast callback, void *ptr);
char *psync_get_home_dir();
char *psync_get_pcloud_path();
char *psync_get_private_dir(char *name);
char *psync_get_private_tmp_dir();
char *psync_get_default_database_path();
int64_t psync_get_free_space_by_path(const char *path);

#endif