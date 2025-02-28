#include <dirent.h>
#include <pwd.h>
#include <stddef.h>
#include <sys/statvfs.h>

#include "ppath.h"
#include "pcompiler.h"
#include "plibs.h"
#include "psettings.h"

static char *psync_get_pcloud_path_nc() {
  struct stat st;
  const char *dir;
  dir = getenv("HOME");
  if (unlikely_log(!dir) || unlikely_log(stat(dir, &st)) ||
      unlikely_log(!psync_stat_mode_ok(&st, 7))) {
    struct passwd pwd;
    struct passwd *result;
    char buff[4096];
    if (unlikely_log(getpwuid_r(getuid(), &pwd, buff, sizeof(buff), &result)) ||
        unlikely_log(stat(result->pw_dir, &st)) ||
        unlikely_log(!psync_stat_mode_ok(&st, 7)))
      return NULL;
    dir = result->pw_dir;
  }
  return psync_strcat(dir, "/", PSYNC_DEFAULT_POSIX_DIR,
                      NULL);
}


static char *psync_get_default_database_path_old() {
  struct stat st;
  const char *dir;
  dir = getenv("HOME");
  if (unlikely_log(!dir) || unlikely_log(stat(dir, &st)) ||
      unlikely_log(!psync_stat_mode_ok(&st, 7))) {
    struct passwd pwd;
    struct passwd *result;
    char buff[4096];
    if (unlikely_log(getpwuid_r(getuid(), &pwd, buff, sizeof(buff), &result)) ||
        unlikely_log(stat(result->pw_dir, &st)) ||
        unlikely_log(!psync_stat_mode_ok(&st, 7)))
      return NULL;
    dir = result->pw_dir;
  }
  return psync_strcat(dir, "/",
                      PSYNC_DEFAULT_POSIX_DBNAME, NULL);
}


int psync_list_dir(const char *path, psync_list_dir_callback callback,
                   void *ptr) {
  psync_pstat pst;
  DIR *dh;
  char *cpath;
  size_t pl, entrylen;
  long namelen;
  struct dirent *entry; // XXX: still useful?
  struct dirent *de;
  dh = opendir(path);
  if (unlikely(!dh)) {
    debug(D_WARNING, "could not open directory %s", path);
    goto err1;
  }
  pl = strlen(path);
  namelen = pathconf(path, _PC_NAME_MAX);
  if (unlikely_log(namelen == -1))
    namelen = 255;
  if (namelen < sizeof(de->d_name) - 1)
    namelen = sizeof(de->d_name) - 1;
  entrylen = offsetof(struct dirent, d_name) + namelen + 1;
  cpath = (char *)psync_malloc(pl + namelen + 2);
  entry = (struct dirent *)psync_malloc(entrylen);
  memcpy(cpath, path, pl);
  if (!pl || cpath[pl - 1] != '/')
    cpath[pl++] = '/';
  pst.path = cpath;

  while ((de = readdir(dh))) {
    if (de->d_name[0] != '.' ||
        (de->d_name[1] != 0 && (de->d_name[1] != '.' || de->d_name[2] != 0))) {
      psync_strlcpy(cpath + pl, de->d_name, namelen + 1);
      if (likely_log(!lstat(cpath, &pst.stat)) &&
          (S_ISREG(pst.stat.st_mode) || S_ISDIR(pst.stat.st_mode))) {
        pst.name = de->d_name;
        callback(ptr, &pst);
      }
    }
  }

  psync_free(entry);
  psync_free(cpath);
  closedir(dh);
  return 0;
err1:
  psync_error = PERROR_LOCAL_FOLDER_NOT_FOUND;
  return -1;
}

int psync_list_dir_fast(const char *path, psync_list_dir_callback_fast callback,
                        void *ptr) {
  psync_pstat_fast pst;
  struct stat st;
  DIR *dh;
  char *cpath;
  size_t pl, entrylen;
  long namelen;
  struct dirent *entry; // XXX: still useful?
  struct dirent *de;
  dh = opendir(path);
  if (unlikely_log(!dh))
    goto err1;
  pl = strlen(path);
  namelen = pathconf(path, _PC_NAME_MAX);
  if (namelen == -1)
    namelen = 255;
  if (namelen < sizeof(de->d_name) - 1)
    namelen = sizeof(de->d_name) - 1;
  entrylen = offsetof(struct dirent, d_name) + namelen + 1;
  cpath = (char *)psync_malloc(pl + namelen + 2);
  entry = (struct dirent *)psync_malloc(entrylen);
  memcpy(cpath, path, pl);
  if (!pl || cpath[pl - 1] != '/')
    cpath[pl++] = '/';
  // while (!readdir_r(dh, entry, &de) && de) { // DELETEME: deprecated
  while ((de = readdir(dh))) {
    if (de->d_name[0] != '.' ||
        (de->d_name[1] != 0 && (de->d_name[1] != '.' || de->d_name[2] != 0))) {

#if defined(DT_UNKNOWN) && defined(DT_DIR) && defined(DT_REG)
      pst.name = de->d_name;
      if (de->d_type == DT_UNKNOWN) {
        psync_strlcpy(cpath + pl, de->d_name, namelen + 1);
        if (unlikely_log(lstat(cpath, &st)))
          continue;
        pst.isfolder = S_ISDIR(st.st_mode);
      } else if (de->d_type == DT_DIR)
        pst.isfolder = 1;
      else if (de->d_type == DT_REG)
        pst.isfolder = 0;
      else
        continue;
      callback(ptr, &pst);
#else
#include "ppath.h"

      psync_strlcpy(cpath + pl, de->d_name, namelen + 1);
      if (likely_log(!lstat(cpath, &st))) {
        pst.name = de->d_name;
        pst.isfolder = S_ISDIR(st.st_mode);
        callback(ptr, &pst);
      }
#endif
    }
  }
  psync_free(entry);
  psync_free(cpath);
  closedir(dh);
  return 0;
err1:
  psync_error = PERROR_LOCAL_FOLDER_NOT_FOUND;
  return -1;
}

char *psync_get_home_dir() {
  struct stat st;
  const char *dir;
  dir = getenv("HOME");
  if (unlikely_log(!dir) || unlikely_log(stat(dir, &st)) ||
      unlikely_log(!psync_stat_mode_ok(&st, 7))) {
    struct passwd pwd;
    struct passwd *result;
    char buff[4096];
    if (unlikely_log(getpwuid_r(getuid(), &pwd, buff, sizeof(buff), &result)) ||
        unlikely_log(stat(result->pw_dir, &st)) ||
        unlikely_log(!psync_stat_mode_ok(&st, 7)))
      return NULL;
    dir = result->pw_dir;
  }
  return psync_strdup(dir);
}


int64_t psync_get_free_space_by_path(const char *path) {
  struct statvfs buf;
  if (unlikely_log(statvfs(path, &buf)))
    return -1;
  else
    return (int64_t)buf.f_bavail * (int64_t)buf.f_frsize;
}

char *psync_get_pcloud_path() {
  char *path;
  struct stat st;
  path = psync_get_pcloud_path_nc();
  if (unlikely_log(!path))
    return NULL;
  if (stat(path, &st) && unlikely_log(mkdir(path, PSYNC_DEFAULT_POSIX_FOLDER_MODE))) {
    psync_free(path);
    return NULL;
  }
  return path;
}

char *psync_get_private_dir(char *name) {
  char *path, *rpath;
  struct stat st;
  path = psync_get_pcloud_path();
  if (!path)
    return NULL;
  rpath = psync_strcat(path, "/", name, NULL);
  free(path);
  if (stat(rpath, &st) && mkdir(path, PSYNC_DEFAULT_POSIX_FOLDER_MODE)) {
    psync_free(rpath);
    return NULL;
  }
  return rpath;
}

char *psync_get_private_tmp_dir() {
  return psync_get_private_dir(PSYNC_DEFAULT_TMP_DIR);
}

char *psync_get_default_database_path() {
  char *dirpath, *path;
  struct stat st;
  dirpath = psync_get_pcloud_path();
  if (!dirpath)
    return NULL;
  path = psync_strcat(dirpath, "/", PSYNC_DEFAULT_DB_NAME,
                      NULL);
  psync_free(dirpath);
  if (stat(path, &st) &&
      (dirpath = psync_get_default_database_path_old())) {
    if (!stat(dirpath, &st)) {
      if (psync_sql_reopen(dirpath)) {
        psync_free(path);
        return dirpath;
      } else
        psync_file_rename(dirpath, path);
    }
    psync_free(dirpath);
  }
  return path;
}
