// defines the messaging protocol for pclsync

#ifndef __POVERLAY_PROTOCOL_H
#define __POVERLAY_PROTOCOL_H

#include <stddef.h>
#include <stdint.h>

#ifndef POVERLAY_SOCK_PATH
#define POVERLAY_SOCK_PATH "/tmp/pcloud_unix_soc.sock"
#endif

typedef struct _message {
  uint32_t type;
  uint64_t length;
  char value[];
} message;

#endif