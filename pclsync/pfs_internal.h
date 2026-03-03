// pfs_internal.h - internal state shared between pfs.c and debug/pfs_debug.c
// Do NOT include this header from any file other than pfs.c and debug/pfs_debug.c.

#ifndef PFS_INTERNAL_H
#define PFS_INTERNAL_H

#include "ptree.h"

extern psync_tree *openfiles;

#endif
