#ifndef __PRAND_H
#define __PRAND_H

#include <stddef.h>

void prand_seed(unsigned char *seed, const void *addent, size_t aelen, int fast);

#endif