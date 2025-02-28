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

int ppath_ls(const char *path, psync_list_dir_callback callback, void *ptr);
int ppath_ls_fast(const char *path, psync_list_dir_callback_fast callback, void *ptr);
char *ppath_home();
char *ppath_pcloud();
char *ppath_private(char *name);
char *ppath_private_tmp();
char *ppath_default_db();
int64_t ppath_free_space(const char *path);

#endif