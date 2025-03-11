#ifndef __PUTIL_H
#define __PUTIL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>

#define NTO_STR(s) TO_STR(s)
#define TO_STR(s) #s
#define VAR_ARRAY(name, type, size) type name[size]

void putil_wipe(void *mem, size_t sz);

#ifdef __cplusplus
}
#endif

#endif
