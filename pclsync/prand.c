#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/sysinfo.h>
#include <sys/utsname.h>
#include <unistd.h>

#include "plibs.h"
#include "ppath.h"
#include "prand.h"
#include "psettings.h"
#include "psql.h"

static void add_file(const char *fn, psync_lhash_ctx *hctx, size_t max) {
  char buff[4096];
  ssize_t rd;
  int fd, mode;
  mode = O_RDONLY;
#if defined(O_NONBLOCK)
  mode += O_NONBLOCK;
#elif defined(O_NDELAY)
  mode += O_NDELAY;
#endif
  fd = open(fn, mode);
  if (fd != -1) {
    if (!max || max > sizeof(buff))
      max = sizeof(buff);
    rd = read(fd, buff, max);
    if (rd > 0)
      psync_lhash_update(hctx, buff, rd);
    close(fd);
  }
}

static void load_sql(psync_lhash_ctx *hctx, psync_sql_res *res) {
  psync_variant_row row;
  struct timespec tm;
  int i;
  while ((row = psql_fetch(res))) {
    for (i = 0; i < res->column_count; i++)
      if (row[i].type == PSYNC_TSTRING)
        psync_lhash_update(hctx, row[i].str, row[i].length);
    psync_lhash_update(hctx, row, sizeof(psync_variant) * res->column_count);
  }
  psql_free(res);
  clock_gettime(CLOCK_REALTIME, &tm);
  psync_lhash_update(hctx, &tm, sizeof(tm));
}

static void rehash_cnt(unsigned char *hashbin, unsigned long cnt) {
  psync_lhash_ctx hctx;
  unsigned long i;
  struct timespec tm;
  for (i = 0; i < cnt; i++) {
    psync_lhash_init(&hctx);
    if ((i & 511) == 0) {
      clock_gettime(CLOCK_REALTIME, &tm);
      psync_lhash_update(&hctx, &tm, sizeof(tm));
    } else
      psync_lhash_update(&hctx, &i, sizeof(i));
    psync_lhash_update(&hctx, hashbin, PSYNC_LHASH_DIGEST_LEN);
    psync_lhash_final(hashbin, &hctx);
  }
}

void prand_seed(unsigned char *seed, const void *addent, size_t aelen,
                int fast) {
  static unsigned char lastseed[PSYNC_LHASH_DIGEST_LEN];
  psync_lhash_ctx hctx;
  struct timespec tm;
  struct stat st;
  struct sysinfo si;
  char *home;
  void *ptr;
  unsigned long i, j;
  int64_t i64;
  pthread_t threadid;
  unsigned char lsc[64][PSYNC_LHASH_DIGEST_LEN];
  pdbg_logf(D_NOTICE, "in");
  struct utsname un;
  struct statvfs stfs;
  char **env;
  pid_t pid;
  clock_gettime(CLOCK_REALTIME, &tm);
  psync_lhash_init(&hctx);
  psync_lhash_update(&hctx, &tm, sizeof(tm));
  if (pdbg_likely(!uname(&un)))
    psync_lhash_update(&hctx, &un, sizeof(un));
  pid = getpid();
  psync_lhash_update(&hctx, &pid, sizeof(pid));
  if (!statvfs("/", &stfs))
    psync_lhash_update(&hctx, &stfs, sizeof(stfs));
  for (env = environ; *env != NULL; env++)
    psync_lhash_update(&hctx, *env, strlen(*env));
#if defined(_POSIX_TIMERS) && _POSIX_TIMERS > 0 &&                             \
    defined(_POSIX_MONOTONIC_CLOCK)
  if (pdbg_likely(!clock_gettime(CLOCK_MONOTONIC, &tm)))
    psync_lhash_update(&hctx, &tm, sizeof(tm));
#endif

  add_file("/dev/urandom", &hctx, PSYNC_HASH_DIGEST_LEN);

  if (pdbg_likely(!sysinfo(&si))) {
    psync_lhash_update(&hctx, &si, sizeof(si));
  }
  add_file("/proc/stat", &hctx, 0);
  add_file("/proc/vmstat", &hctx, 0);
  add_file("/proc/meminfo", &hctx, 0);
  add_file("/proc/modules", &hctx, 0);
  add_file("/proc/mounts", &hctx, 0);
  add_file("/proc/diskstats", &hctx, 0);
  add_file("/proc/interrupts", &hctx, 0);
  add_file("/proc/net/dev", &hctx, 0);
  add_file("/proc/net/arp", &hctx, 0);

  threadid = pthread_self();
  psync_lhash_update(&hctx, &threadid, sizeof(threadid));
  ptr = (void *)&ptr;
  psync_lhash_update(&hctx, &ptr, sizeof(ptr));
  ptr = (void *)prand_seed;
  psync_lhash_update(&hctx, &ptr, sizeof(ptr));
  ptr = (void *)pthread_self;
  psync_lhash_update(&hctx, &ptr, sizeof(ptr));
  ptr = (void *)malloc;
  psync_lhash_update(&hctx, &ptr, sizeof(ptr));
  ptr = (void *)&lastseed;
  psync_lhash_update(&hctx, &ptr, sizeof(ptr));
  home = ppath_home();
  if (home) {
    i64 = ppath_free_space(home);
    psync_lhash_update(&hctx, &i64, sizeof(i64));
    psync_lhash_update(&hctx, home, strlen(home));
    if (pdbg_likely(!stat(home, &st)))
      psync_lhash_update(&hctx, &st, sizeof(st));
    free(home);
  }
  if (!fast) {
    pdbg_logf(D_NOTICE, "getting seed from database");
    psync_sql_res *res;
    struct timespec tm;
    unsigned char rnd[PSYNC_LHASH_DIGEST_LEN];
    clock_gettime(CLOCK_REALTIME, &tm);
    psync_lhash_update(&hctx, &tm, sizeof(tm));
    res = psql_query_rdlock("SELECT * FROM setting ORDER BY RANDOM()");
    load_sql(&hctx, res);
    res = psql_query_rdlock(
        "SELECT * FROM resolver ORDER BY RANDOM() LIMIT 50");
    load_sql(&hctx, res);
    psql_statement(
        "REPLACE INTO setting (id, value) VALUES ('random', RANDOM())");
    clock_gettime(CLOCK_REALTIME, &tm);
    psync_lhash_update(&hctx, &tm, sizeof(tm));
    psql_sync();
    clock_gettime(CLOCK_REALTIME, &tm);
    psync_lhash_update(&hctx, &tm, sizeof(tm));
    sqlite3_randomness(sizeof(rnd), rnd);
    psync_lhash_update(&hctx, rnd, sizeof(rnd));
    pdbg_logf(D_NOTICE, "got seed from database");
  }
  if (aelen)
    psync_lhash_update(&hctx, addent, aelen);
  pdbg_logf(D_NOTICE, "adding bulk data");
  for (i = 0; i < ARRAY_SIZE(lsc); i++) {
    memcpy(&lsc[i], lastseed, PSYNC_LHASH_DIGEST_LEN);
    for (j = 0; j < PSYNC_LHASH_DIGEST_LEN; j++)
      lsc[i][j] ^= (unsigned char)i;
  }
  for (j = fast ? 3 : 0; j < 5; j++) {
    for (i = 0; i < 100; i++) {
      psync_lhash_update(&hctx, &i, sizeof(i));
      psync_lhash_update(&hctx, &j, sizeof(j));
      psync_lhash_update(&hctx, lsc, sizeof(lsc));
    }
    clock_gettime(CLOCK_REALTIME, &tm);
    psync_lhash_update(&hctx, &tm, sizeof(tm));
  }
  psync_lhash_final(seed, &hctx);
  memcpy(lastseed, seed, PSYNC_LHASH_DIGEST_LEN);

  pdbg_logf(D_NOTICE, "storing in db");
  psync_sql_res *res;
  unsigned char hashbin[PSYNC_LHASH_DIGEST_LEN];
  char hashhex[PSYNC_LHASH_DIGEST_HEXLEN], nm[16];
  memcpy(hashbin, seed, PSYNC_LHASH_DIGEST_LEN);
  rehash_cnt(hashbin, 2000);
  psync_binhex(hashhex, hashbin, PSYNC_LHASH_DIGEST_LEN);
  res = psql_prepare(
      "REPLACE INTO setting (id, value) VALUES ('randomhash', ?)");
  psql_bind_lstr(res, 1, hashhex, PSYNC_LHASH_DIGEST_HEXLEN);
  psql_run_free(res);
  rehash_cnt(hashbin, 2000);
  psync_binhex(hashhex, hashbin, PSYNC_LHASH_DIGEST_LEN);
  memcpy(nm, "randomhash", 10);
  nm[10] = hashhex[0];
  nm[11] = 0;
  res = psql_prepare(
      "REPLACE INTO setting (id, value) VALUES (?, ?)");
  psql_bind_lstr(res, 1, nm, 11);
  psql_bind_lstr(res, 2, hashhex, PSYNC_LHASH_DIGEST_HEXLEN);
  psql_run_free(res);

  pdbg_logf(D_NOTICE, "out");
}
