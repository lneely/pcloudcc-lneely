#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/random.h>

#include "plibs.h"

// wipe a segment of memory mem of size sz using a DoD 5220.22-M compliant
// 3-pass wipe. the first pass overwrites the memory with zeroes, the second
// with ones, and the third with random data using the urandom entropy
// source. if the urandom source fails, it falls back to a simple
// (non-cryptographically-secure) RNG.
void putil_wipe(void *mem, size_t sz) {
    if (!mem || sz == 0) { return; }

    volatile unsigned char *p = (volatile unsigned char *)mem;

    memset((void*)p, 0x00, sz);
    memset((void*)p, 0xFF, sz);

    ssize_t result = getrandom((void*)p, sz, 0);
    if (result != (ssize_t)sz) {
        if (result == -1) {
            debug(D_WARNING, "getrandom() failed: %s.", strerror(errno));
        } else {
            debug(D_WARNING, "getrandom() returned partial data.");
        }

        debug(D_WARNING, "falling back to less secure third pass. This may occur due to insufficient entropy, early boot state, or kernel incompatibility.");
        srand((unsigned int)(time(NULL) ^ (uintptr_t)&srand));
		for (size_t i = 0; i < sz; i++) {
		    p[i] = (unsigned char)rand();
		}
    }
}
