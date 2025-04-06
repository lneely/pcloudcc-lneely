#ifndef __PPATH_H
#define __PPATH_H

#include <fcntl.h>
#include <stdint.h>
#include <sys/stat.h>

typedef struct {
  const char *name;
  const char *path;
  struct stat stat;
} ppath_stat;

typedef struct {
  const char *name;
  uint8_t isfolder;
} ppath_fast_stat;

typedef void (*ppath_ls_cb)(void *, ppath_stat *);
typedef void (*ppath_ls_fast_cb)(void *, ppath_fast_stat *);

char *ppath_default_db();
int64_t ppath_free_space(const char *path);
char *ppath_home();
int ppath_ls(const char *path, ppath_ls_cb callback, void *ptr);
int ppath_ls_fast(const char *path, ppath_ls_fast_cb callback, void *ptr);
char *ppath_pcloud();
char *ppath_private(char *name);
char *ppath_private_tmp();

#endif
