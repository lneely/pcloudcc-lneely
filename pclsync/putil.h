#ifndef __PUTIL_H
#define __PUTIL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <time.h>

#define NTO_STR(s) TO_STR(s)
#define TO_STR(s) #s
#define VAR_ARRAY(name, type, size) type name[size]
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

void putil_wipe(void *mem, size_t sz);
void time_format(time_t tm, unsigned long ns, char *result);

#ifdef __cplusplus
}
#endif

#endif
