#ifndef __PSYS_H
#define __PSYS_H

#include <stdint.h>
#include <sys/types.h>
#include <time.h>

uid_t psys_get_uid();
gid_t psys_get_gid();
gid_t *psys_get_gids();
int psys_get_gids_cnt();

void psys_init();
time_t psys_time_seconds();
uint64_t psys_time_milliseconds();
void psys_sleep_milliseconds(uint64_t millisec);
void psys_sleep_milliseconds_fast(uint64_t millisec);

#endif
