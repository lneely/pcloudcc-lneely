// psql_internal.h - internal state shared between psql.c and debug/psql_debug.c
// Do NOT include this header from any file other than psql.c and debug/psql_debug.c.

#ifndef PSQL_INTERNAL_H
#define PSQL_INTERNAL_H

#include <pthread.h>
#include <sqlite3.h>

#include "plocks.h"
#include "plist.h"

extern sqlite3 *psync_db;
extern psync_rwlock_t dblock;
extern int in_transaction;
extern int transaction_failed;
extern psync_list commitcbs;

#endif
