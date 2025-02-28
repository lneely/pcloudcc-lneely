#include <dirent.h>
#include <pwd.h>
#include <stddef.h>
#include <sys/statvfs.h>

#include "ppath.h"
#include "pcompiler.h"
#include "plibs.h"
#include "psettings.h"

char *ppath_default_db() {
  char *pcdir, *dbp, *home, *oldp;
  struct stat st;
  
  pcdir = ppath_pcloud();
  if (!pcdir) {
    return NULL;
  }
    
  dbp = psync_strcat(pcdir, "/", PSYNC_DEFAULT_DB_NAME, NULL);
  psync_free(pcdir);
  
  if (stat(dbp, &st)) {
    // Inline the old database path function here
    if ((home = ppath_home())) {
      oldp = psync_strcat(home, "/", PSYNC_DEFAULT_POSIX_DBNAME, NULL);
      psync_free(home);
      
      if (oldp) {
        if (!stat(oldp, &st)) {
          if (psync_sql_reopen(oldp)) {
            psync_free(dbp);
            return oldp;
          } else {
            psync_file_rename(oldp, dbp);
          }
        }
        psync_free(oldp);
      }
    }
  }
  
  return dbp;
}

int64_t ppath_free_space(const char *path) {
  struct statvfs buf;
  if (unlikely_log(statvfs(path, &buf)))
    return -1;
  else
    return (int64_t)buf.f_bavail * (int64_t)buf.f_frsize;
}

char *ppath_home() {
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

int ppath_ls(const char *path, ppath_ls_cb callback, void *ptr) {
  ppath_stat pst;
  DIR *dh;
  char *cpath;
  size_t pl;
  struct dirent *de;
  
  dh = opendir(path);
  if (unlikely(!dh)) {
    debug(D_WARNING, "could not open directory %s", path);
    psync_error = PERROR_LOCAL_FOLDER_NOT_FOUND;
    return -1;
  }
  
  pl = strlen(path);
  cpath = (char *)psync_malloc(pl + NAME_MAX + 2);
  memcpy(cpath, path, pl);
  if (!pl || cpath[pl - 1] != '/')
    cpath[pl++] = '/';
  
  pst.path = cpath;
  
  while ((de = readdir(dh))) {
    // Skip . and .. entries
    if (de->d_name[0] == '.' && 
        (de->d_name[1] == 0 || (de->d_name[1] == '.' && de->d_name[2] == 0)))
      continue;
      
    psync_strlcpy(cpath + pl, de->d_name, NAME_MAX + 1);
    
    if (likely_log(!lstat(cpath, &pst.stat)) &&
        (S_ISREG(pst.stat.st_mode) || S_ISDIR(pst.stat.st_mode))) {
      pst.name = de->d_name;
      callback(ptr, &pst);
    }
  }
  
  psync_free(cpath);
  closedir(dh);
  return 0;
}

int ppath_ls_fast(const char *path, ppath_ls_fast_cb callback, void *ptr) {
  ppath_fast_stat pst;
  struct stat st;
  DIR *dh;
  char *cpath;
  size_t pl;
  struct dirent *de;
  
  dh = opendir(path);
  if (unlikely_log(!dh)) {
    psync_error = PERROR_LOCAL_FOLDER_NOT_FOUND;
    return -1;
  }
  
  pl = strlen(path);
  cpath = (char *)psync_malloc(pl + NAME_MAX + 2);
  memcpy(cpath, path, pl);
  if (!pl || cpath[pl - 1] != '/')
    cpath[pl++] = '/';
  
  while ((de = readdir(dh))) {
    // Skip . and .. entries
    if (de->d_name[0] == '.' && 
        (de->d_name[1] == 0 || (de->d_name[1] == '.' && de->d_name[2] == 0)))
      continue;
      
    pst.name = de->d_name;
    
    if (de->d_type == DT_DIR) {
      pst.isfolder = 1;
      callback(ptr, &pst);
    } 
    else if (de->d_type == DT_REG) {
      pst.isfolder = 0;
      callback(ptr, &pst);
    }
    else if (de->d_type == DT_UNKNOWN) {
      // Fall back to lstat for unknown file types
      psync_strlcpy(cpath + pl, de->d_name, NAME_MAX + 1);
      if (!unlikely_log(lstat(cpath, &st))) {
        pst.isfolder = S_ISDIR(st.st_mode);
        callback(ptr, &pst);
      }
    }
    // Ignore other file types
  }
  
  psync_free(cpath);
  closedir(dh);
  return 0;
}

char *ppath_pcloud() {
  char *homedir, *path;
  struct stat st;
  
  if (!(homedir = ppath_home())) {
    return NULL;
  }

  path = psync_strcat(homedir, "/", PSYNC_DEFAULT_POSIX_DIR, NULL);
  psync_free(homedir);
  if (unlikely_log(!path)) {
    return NULL; 
  }

  if (stat(path, &st) && unlikely_log(mkdir(path, PSYNC_DEFAULT_POSIX_FOLDER_MODE))) {
    psync_free(path);
    return NULL;
  } 
  return path;
}

char *ppath_private(char *name) {
  char *path, *rpath;
  struct stat st;
  path = ppath_pcloud();
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

char *ppath_private_tmp() {
  return ppath_private(PSYNC_DEFAULT_TMP_DIR);
}
